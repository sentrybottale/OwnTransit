package pairrelay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

// PeerDNSName is the exact route-bound outer admission identity. The receiver
// owns the issuing CA; the relay may verify but never receives its private key.
func PeerDNSName(role Role, peerID protocol.ID, receiverID protocol.ID, routeID protocol.RouteID) (string, error) {
	if (role != RoleReceiver && role != RoleClient) || zeroID(peerID) || zeroID(receiverID) || zeroRoute(routeID) ||
		(role == RoleReceiver && peerID != receiverID) {
		return "", ErrProtocol
	}
	label := "client"
	if role == RoleReceiver {
		label = "receiver"
	}
	return "i-" + peerID.String() + ".r-" + routeID.String() + "." + label + ".pairrelay.v2.owntransit.invalid", nil
}

func parseAdmissionCA(encoded []byte, now time.Time) (*x509.Certificate, *x509.CertPool, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if len(encoded) == 0 || len(encoded) > MaxAdmissionCABytes || now.IsZero() {
		return nil, nil, zero, ErrProtocol
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		!bytes.Equal(pem.EncodeToMemory(block), encoded) {
		return nil, nil, zero, ErrProtocol
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.MaxPathLen != 0 ||
		!certificate.MaxPathLenZero || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		certificate.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, nil, zero, ErrProtocol
	}
	if _, ok := certificate.PublicKey.(ed25519.PublicKey); !ok || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
		certificate.CheckSignatureFrom(certificate) != nil {
		return nil, nil, zero, ErrProtocol
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return certificate, pool, sha256.Sum256(encoded), nil
}

func validateTLSMaterial(material TLSMaterial, now time.Time) error {
	if material.ServerName == "" || !validDNSName(material.ServerName) {
		return ErrProtocol
	}
	_, roots, _, err := parseAdmissionCA(material.CAPEM, now)
	if err != nil {
		return err
	}
	return validateLocalCertificate(material.Certificate, roots, material.ServerName, x509.ExtKeyUsageServerAuth, now)
}

func validateLocalCertificate(certificate tls.Certificate, roots *x509.CertPool, name string, usage x509.ExtKeyUsage, now time.Time) error {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil || roots == nil || !validDNSName(name) || now.IsZero() {
		return ErrProtocol
	}
	leaf := certificate.Leaf
	var err error
	if leaf == nil {
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	}
	if err != nil || leaf == nil || !bytes.Equal(leaf.Raw, certificate.Certificate[0]) {
		return ErrProtocol
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return ErrProtocol
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(publicDER, leaf.RawSubjectPublicKeyInfo) {
		return ErrProtocol
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range certificate.Certificate[1:] {
		parsed, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return ErrProtocol
		}
		intermediates.AddCert(parsed)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: name,
		KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: now,
	})
	if err != nil || len(chains) == 0 {
		return ErrProtocol
	}
	pin, err := identity.HashSPKI(leaf)
	if err != nil {
		return ErrProtocol
	}
	return (identity.PeerProfile{
		ExpectedDNSName: name, RequiredEKU: usage, ALPN: OuterALPN,
		AllowedSPKIs: identity.PinSet{pin: {}},
	}).VerifyConnection(tls.ConnectionState{
		Version: tls.VersionTLS13, NegotiatedProtocol: OuterALPN,
		PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: chains,
	})
}

func relayTLSConfig(material TLSMaterial, admissionPool *x509.CertPool, role Role, peerID, receiverID protocol.ID, routeID protocol.RouteID) (*tls.Config, error) {
	name, err := PeerDNSName(role, peerID, receiverID, routeID)
	if err != nil || admissionPool == nil {
		return nil, ErrProtocol
	}
	verify := func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
			return ErrUnauthorized
		}
		pin, err := identity.HashSPKI(state.PeerCertificates[0])
		if err != nil {
			return ErrUnauthorized
		}
		if err := (identity.PeerProfile{
			ExpectedDNSName: name, ExpectedServerName: material.ServerName,
			RequiredEKU: x509.ExtKeyUsageClientAuth, ALPN: OuterALPN,
			AllowedSPKIs: identity.PinSet{pin: {}},
		}).VerifyConnection(state); err != nil {
			return ErrUnauthorized
		}
		return nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{material.Certificate}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: admissionPool, NextProtos: []string{OuterALPN}, SessionTicketsDisabled: true,
		VerifyConnection: verify,
	}, nil
}

func endpointTLSForDescriptor(config EndpointConfig, descriptor Descriptor, role Role, now time.Time) (*tls.Config, error) {
	_, admissionRoots, admissionHash, err := parseAdmissionCA(config.AdmissionCAPEM, now)
	if err != nil || !bytes.Equal(config.AdmissionCAPEM, descriptor.AdmissionCAPEM) {
		return nil, ErrProtocol
	}
	_ = admissionHash
	localName, err := PeerDNSName(role, config.PeerID, descriptor.ReceiverID, descriptor.RouteID)
	if err != nil || validateLocalCertificate(config.Certificate, admissionRoots, localName, x509.ExtKeyUsageClientAuth, now) != nil {
		return nil, ErrProtocol
	}
	_, relayRoots, _, err := parseAdmissionCA(config.RelayCAPEM, now)
	expectedRelayPin, pinErr := identity.ParseSPKIPin(config.RelayServerSPKI)
	if err != nil || pinErr != nil || !validDNSName(config.RelayServerName) {
		return nil, ErrProtocol
	}
	verify := func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
			return ErrUnauthorized
		}
		pin, err := identity.HashSPKI(state.PeerCertificates[0])
		if err != nil || pin != expectedRelayPin {
			return ErrUnauthorized
		}
		if err := (identity.PeerProfile{
			ExpectedDNSName: config.RelayServerName, RequiredEKU: x509.ExtKeyUsageServerAuth,
			ALPN: OuterALPN, AllowedSPKIs: identity.PinSet{expectedRelayPin: {}},
		}).VerifyConnection(state); err != nil {
			return ErrUnauthorized
		}
		return nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{config.Certificate}, RootCAs: relayRoots,
		ServerName: config.RelayServerName, NextProtos: []string{OuterALPN},
		SessionTicketsDisabled: true, ClientSessionCache: nil, VerifyConnection: verify,
	}, nil
}

func validateRelayURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || raw != strings.ToLower(raw) || parsed.Scheme != "wss" || parsed.Host == "" ||
		parsed.Host != parsed.Hostname() || parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != Path || parsed.String() != raw ||
		net.ParseIP(parsed.Hostname()) != nil || !validDNSName(parsed.Hostname()) {
		return ErrProtocol
	}
	return nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func defaultWebSocketDial(ctx context.Context, rawURL string) (net.Conn, error) {
	if ctx == nil || validateRelayURL(rawURL) != nil {
		return nil, ErrProtocol
	}
	parsed, _ := url.Parse(rawURL)
	host := parsed.Hostname()
	lookupCtx, cancelLookup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelLookup()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrUnavailable
	}
	var selected netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if !publicRelayAddress(address) {
			return nil, ErrUnavailable
		}
		if !selected.IsValid() {
			selected = address
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host},
	}
	transport.DialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(host, "443") {
			return nil, ErrUnavailable
		}
		connection, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(selected.String(), "443"))
		if err != nil {
			return nil, ErrUnavailable
		}
		peer, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = connection.Close()
			return nil, ErrUnavailable
		}
		connected, ok := netip.AddrFromSlice(peer.IP)
		if !ok || connected.Unmap() != selected || !publicRelayAddress(connected.Unmap()) {
			_ = connection.Close()
			return nil, ErrUnavailable
		}
		return connection, nil
	}
	httpClient := &http.Client{
		Transport: transport, Jar: nil, Timeout: 0,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, response, err := websocket.Dial(handshakeCtx, rawURL, &websocket.DialOptions{
		HTTPClient: httpClient, Subprotocols: []string{WebSocketSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrUnavailable
	}
	if ws.Subprotocol() != WebSocketSubprotocol {
		_ = ws.CloseNow()
		return nil, ErrProtocol
	}
	ws.SetReadLimit(maxWirePayload + wireHeaderSize)
	return websocket.NetConn(ctx, ws, websocket.MessageBinary), nil
}

func publicRelayAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified()
}
