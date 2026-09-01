// Package tlsprofile constructs immutable TLS 1.3-only configurations for
// OwnTransit's two independent mTLS boundaries.
package tlsprofile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

const maximumCapabilityRootPEM = 64 << 10

// MaterialReader returns one already-authenticated runtime-generation member
// by its exact configured path. It exists only for descriptor-pinned lifecycle
// generations; ordinary path-based configuration continues through the
// no-follow, mode-checking identity loaders.
type MaterialReader func(path string) ([]byte, error)

// Client builds a mutually authenticated TLS client profile using only the
// configured private trust root and locally pinned server identity. The local
// leaf is validated before this function returns and before callers can open a
// network connection.
func Client(value config.ClientTLS, expectedLocalDNSName, alpn string) (*tls.Config, error) {
	return client(value, expectedLocalDNSName, alpn, nil)
}

// ClientFromMaterial constructs a client profile without reopening credential
// pathnames from an authenticated lifecycle generation.
func ClientFromMaterial(value config.ClientTLS, expectedLocalDNSName, alpn string, reader MaterialReader) (*tls.Config, error) {
	if reader == nil {
		return nil, errors.New("tlsprofile: runtime material reader is required")
	}
	return client(value, expectedLocalDNSName, alpn, reader)
}

func client(value config.ClientTLS, expectedLocalDNSName, alpn string, reader MaterialReader) (*tls.Config, error) {
	certificate, err := loadKeyPair(value.CertFile, value.KeyFile, reader)
	if err != nil {
		return nil, err
	}
	if err := validateLocalCertificate(certificate, value.IssuerCAFile, value.LocalDNSName, expectedLocalDNSName, x509.ExtKeyUsageClientAuth, reader); err != nil {
		return nil, err
	}
	roots, err := loadCertPool(value.CAFile, reader)
	if err != nil {
		return nil, err
	}
	pins, err := identity.ParsePinAllowlist(value.SPKIPins)
	if err != nil {
		return nil, err
	}
	profile := identity.PeerProfile{
		ExpectedDNSName: value.ServerName,
		RequiredEKU:     x509.ExtKeyUsageServerAuth,
		ALPN:            alpn,
		AllowedSPKIs:    pins,
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{certificate},
		RootCAs:                roots,
		ServerName:             value.ServerName,
		NextProtos:             []string{alpn},
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
		InsecureSkipVerify:     false,
		VerifyConnection:       profile.VerifyConnection,
	}, nil
}

// Server builds a TLS server profile that admits only one of the locally
// enumerated client identities. The map key is the exact client DNS SAN.
func Server(value config.ServerTLS, serverName, alpn string, peers map[string]identity.PinSet) (*tls.Config, error) {
	return server(value, serverName, alpn, peers, nil)
}

// ServerFromMaterial constructs a server profile without reopening credential
// pathnames from an authenticated lifecycle generation.
func ServerFromMaterial(value config.ServerTLS, serverName, alpn string, peers map[string]identity.PinSet, reader MaterialReader) (*tls.Config, error) {
	if reader == nil {
		return nil, errors.New("tlsprofile: runtime material reader is required")
	}
	return server(value, serverName, alpn, peers, reader)
}

func server(value config.ServerTLS, serverName, alpn string, peers map[string]identity.PinSet, reader MaterialReader) (*tls.Config, error) {
	if serverName == "" || alpn == "" || len(peers) == 0 {
		return nil, errors.New("tlsprofile: server name, ALPN, and peers are required")
	}
	certificate, err := loadKeyPair(value.CertFile, value.KeyFile, reader)
	if err != nil {
		return nil, err
	}
	if err := validateLocalCertificate(certificate, value.IssuerCAFile, value.LocalDNSName, serverName, x509.ExtKeyUsageServerAuth, reader); err != nil {
		return nil, err
	}
	roots, err := loadCertPool(value.ClientCAFile, reader)
	if err != nil {
		return nil, err
	}
	peerCopy := make(map[string]identity.PinSet, len(peers))
	for name, pins := range peers {
		if name == "" || len(pins) == 0 {
			return nil, errors.New("tlsprofile: empty peer identity or pin set")
		}
		copyPins := make(identity.PinSet, len(pins))
		for pin := range pins {
			copyPins[pin] = struct{}{}
		}
		peerCopy[name] = copyPins
	}
	verify := func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("tlsprofile: client did not present a leaf")
		}
		leaf := state.PeerCertificates[0]
		if len(leaf.DNSNames) != 1 {
			return errors.New("tlsprofile: client DNS identity is not exact")
		}
		pins, ok := peerCopy[leaf.DNSNames[0]]
		if !ok {
			return errors.New("tlsprofile: client identity is not locally authorized")
		}
		profile := identity.PeerProfile{
			ExpectedDNSName:    leaf.DNSNames[0],
			ExpectedServerName: serverName,
			RequiredEKU:        x509.ExtKeyUsageClientAuth,
			ALPN:               alpn,
			AllowedSPKIs:       pins,
		}
		return profile.VerifyConnection(state)
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{certificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              roots,
		NextProtos:             []string{alpn},
		SessionTicketsDisabled: true,
		VerifyConnection:       verify,
	}, nil
}

// CapabilityServer builds the route-scoped inner connector profile. Normal
// x509 verification under the locally installed route root proves that the
// client holds a capability key. The strict SAN then binds that capability to
// this connector installation and route. No relay input and no positive
// per-client SPKI list participates in authorization.
func CapabilityServer(value config.ConnectorInnerTLS, connectorID protocol.ID, route protocol.RouteID) (*tls.Config, error) {
	return capabilityServer(value, connectorID, route, nil)
}

// CapabilityServerFromMaterial constructs the route-capability server profile
// entirely from one held lifecycle generation.
func CapabilityServerFromMaterial(value config.ConnectorInnerTLS, connectorID protocol.ID, route protocol.RouteID, reader MaterialReader) (*tls.Config, error) {
	if reader == nil {
		return nil, errors.New("tlsprofile: runtime material reader is required")
	}
	return capabilityServer(value, connectorID, route, reader)
}

func capabilityServer(value config.ConnectorInnerTLS, connectorID protocol.ID, route protocol.RouteID, reader MaterialReader) (*tls.Config, error) {
	if connectorID == (protocol.ID{}) || route == (protocol.RouteID{}) {
		return nil, errors.New("tlsprofile: capability connector and route IDs must be nonzero")
	}
	serverName := config.CapabilityConnectorDNSName(connectorID, route)
	if value.LocalDNSName != serverName || value.ServerName != serverName {
		return nil, fmt.Errorf("tlsprofile: capability server identity must be exactly %q", serverName)
	}
	certificate, err := loadKeyPair(value.CertFile, value.KeyFile, reader)
	if err != nil {
		return nil, err
	}
	if err := validateLocalCertificate(certificate, value.IssuerCAFile, value.LocalDNSName, serverName, x509.ExtKeyUsageServerAuth, reader); err != nil {
		return nil, err
	}
	roots, err := loadCapabilityRoots(value.ClientCAFiles, value.ClientCARotation, time.Now(), reader)
	if err != nil {
		return nil, err
	}

	revokedIDs := make(map[protocol.ID]struct{}, len(value.RevokedClientIDs))
	for index, encoded := range value.RevokedClientIDs {
		id, parseErr := protocol.ParseID(encoded)
		if parseErr != nil || id == (protocol.ID{}) {
			return nil, fmt.Errorf("tlsprofile: revoked client ID %d is invalid", index)
		}
		if _, duplicate := revokedIDs[id]; duplicate {
			return nil, fmt.Errorf("tlsprofile: revoked client ID %d is duplicated", index)
		}
		revokedIDs[id] = struct{}{}
	}
	var revokedSPKIs identity.PinSet
	if len(value.RevokedClientSPKIs) != 0 {
		revokedSPKIs, err = identity.ParsePinAllowlist(value.RevokedClientSPKIs)
		if err != nil {
			return nil, fmt.Errorf("tlsprofile: revoked client SPKIs: %w", err)
		}
	}

	verify := func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
			return errors.New("tlsprofile: capability client did not present a leaf")
		}
		leaf := state.PeerCertificates[0]
		if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || leaf.PublicKeyAlgorithm != x509.Ed25519 {
			return errors.New("tlsprofile: capability client key must be Ed25519")
		}
		if len(leaf.DNSNames) != 1 {
			return errors.New("tlsprofile: capability client DNS identity is not exact")
		}
		clientID, certificateConnectorID, certificateRoute, _, parseErr := config.ParseClientCapabilityDNSName(leaf.DNSNames[0])
		if parseErr != nil {
			return fmt.Errorf("tlsprofile: capability client identity: %w", parseErr)
		}
		if certificateConnectorID != connectorID || certificateRoute != route {
			return errors.New("tlsprofile: capability is bound to a different connector or route")
		}
		hash, hashErr := identity.HashSPKI(leaf)
		if hashErr != nil {
			return hashErr
		}
		// PeerProfile supplies the exact TLS, EKU, KU, CA, verified-chain, and
		// raw single-SAN checks. This singleton contains the already-presented
		// key only to reuse structural validation; it is not a configured pin
		// and grants no additional authorization beyond the route CA.
		profile := identity.PeerProfile{
			ExpectedDNSName:    leaf.DNSNames[0],
			ExpectedServerName: serverName,
			RequiredEKU:        x509.ExtKeyUsageClientAuth,
			ALPN:               config.CapabilityInnerALPN,
			AllowedSPKIs:       identity.PinSet{hash: {}},
		}
		if verifyErr := profile.VerifyConnection(state); verifyErr != nil {
			return verifyErr
		}
		if _, revoked := revokedIDs[clientID]; revoked {
			return errors.New("tlsprofile: capability client installation is revoked")
		}
		if revokedSPKIs.Contains(hash) {
			return errors.New("tlsprofile: capability client key is revoked")
		}
		return nil
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{certificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              roots,
		NextProtos:             []string{config.CapabilityInnerALPN},
		SessionTicketsDisabled: true,
		VerifyConnection:       verify,
	}, nil
}

func loadCapabilityRoots(paths []string, rotation bool, now time.Time, reader MaterialReader) (*x509.CertPool, error) {
	if len(paths) == 0 || len(paths) > config.MaxCapabilityClientCAs {
		return nil, fmt.Errorf("tlsprofile: capability roots must contain 1..%d files", config.MaxCapabilityClientCAs)
	}
	if rotation != (len(paths) == 2) {
		return nil, errors.New("tlsprofile: capability root rotation must be explicit exactly during two-root overlap")
	}
	pool := x509.NewCertPool()
	certificates := make([]*x509.Certificate, 0, len(paths))
	seenPaths := make(map[string]struct{}, len(paths))
	for index, path := range paths {
		if path == "" {
			return nil, fmt.Errorf("tlsprofile: capability root %d path is empty", index)
		}
		if _, duplicate := seenPaths[path]; duplicate {
			return nil, fmt.Errorf("tlsprofile: capability root %d duplicates a path", index)
		}
		seenPaths[path] = struct{}{}
		certificate, err := loadCapabilityRoot(path, now, reader)
		if err != nil {
			return nil, fmt.Errorf("tlsprofile: capability root %d: %w", index, err)
		}
		for _, existing := range certificates {
			if bytes.Equal(existing.Raw, certificate.Raw) {
				return nil, fmt.Errorf("tlsprofile: capability root %d duplicates a certificate", index)
			}
		}
		certificates = append(certificates, certificate)
		pool.AddCert(certificate)
	}
	return pool, nil
}

func loadCapabilityRoot(path string, now time.Time, reader MaterialReader) (*x509.Certificate, error) {
	if reader != nil {
		contents, err := reader(path)
		if err != nil {
			return nil, fmt.Errorf("read held root material %q: %w", path, err)
		}
		return parseCapabilityRoot(contents, now, path)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open root file %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened root file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumCapabilityRootPEM {
		return nil, fmt.Errorf("root file %q must be a bounded regular non-symlink file", path)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumCapabilityRootPEM+1))
	if err != nil {
		return nil, fmt.Errorf("read root file %q: %w", path, err)
	}
	if len(contents) < 1 || len(contents) > maximumCapabilityRootPEM {
		return nil, fmt.Errorf("root file %q changed size while being read", path)
	}
	return parseCapabilityRoot(contents, now, path)
}

func parseCapabilityRoot(contents []byte, now time.Time, label string) (*x509.Certificate, error) {
	if len(contents) < 1 || len(contents) > maximumCapabilityRootPEM {
		return nil, fmt.Errorf("root material %q must be bounded", label)
	}
	block, trailing := pem.Decode(bytes.TrimSpace(contents))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, fmt.Errorf("root material %q must contain exactly one headerless certificate PEM block", label)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root material %q: %w", label, err)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 {
		return nil, errors.New("capability root must be a path-length-zero CA")
	}
	if certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return nil, errors.New("capability root must have only certificate-signing and CRL-signing key usages")
	}
	if _, ok := certificate.PublicKey.(ed25519.PublicKey); !ok || certificate.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, errors.New("capability root key must be Ed25519")
	}
	if certificate.SignatureAlgorithm != x509.PureEd25519 {
		return nil, errors.New("capability root signature must be Ed25519")
	}
	if len(certificate.ExtKeyUsage) != 0 || len(certificate.UnknownExtKeyUsage) != 0 || len(certificate.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("capability root contains an endpoint or unhandled extended usage")
	}
	if len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.URIs) != 0 {
		return nil, errors.New("capability root must not contain a subject alternative name")
	}
	if now.IsZero() || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, errors.New("capability root is not valid at the current time")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return nil, fmt.Errorf("capability root is not self-signed: %w", err)
	}
	return certificate, nil
}

func validateLocalCertificate(certificate tls.Certificate, issuerCAFile, configuredDNSName, expectedDNSName string, usage x509.ExtKeyUsage, reader MaterialReader) error {
	if (issuerCAFile == "") != (configuredDNSName == "") {
		return errors.New("tlsprofile: issuer CA and local DNS name must be configured together")
	}
	if configuredDNSName != "" {
		if expectedDNSName != "" && configuredDNSName != expectedDNSName {
			return fmt.Errorf("tlsprofile: configured local DNS name %q does not match expected identity %q", configuredDNSName, expectedDNSName)
		}
		expectedDNSName = configuredDNSName
	}
	if expectedDNSName == "" {
		// Compatibility for old POC client profiles is deliberately limited to
		// the certificate's one exact DNS SAN. Runtime clients additionally bind
		// the outer and inner names to one derived installation ID.
		if certificate.Leaf == nil || len(certificate.Leaf.DNSNames) != 1 {
			return errors.New("tlsprofile: legacy local certificate must contain one exact DNS identity")
		}
		expectedDNSName = certificate.Leaf.DNSNames[0]
	}

	var issuerRoots *x509.CertPool
	if issuerCAFile != "" {
		var err error
		issuerRoots, err = loadCertPool(issuerCAFile, reader)
		if err != nil {
			return fmt.Errorf("tlsprofile: local issuer: %w", err)
		}
	}
	if err := identity.ValidateLocalCertificate(certificate, issuerRoots, expectedDNSName, usage, time.Now()); err != nil {
		return fmt.Errorf("tlsprofile: local certificate: %w", err)
	}
	return nil
}

func loadKeyPair(certificatePath, keyPath string, reader MaterialReader) (tls.Certificate, error) {
	if reader == nil {
		return identity.LoadKeyPair(certificatePath, keyPath)
	}
	certificatePEM, err := reader(certificatePath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsprofile: read held certificate material: %w", err)
	}
	keyPEM, err := reader(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsprofile: read held private-key material: %w", err)
	}
	return identity.ParseKeyPair(certificatePEM, keyPEM)
}

func loadCertPool(path string, reader MaterialReader) (*x509.CertPool, error) {
	if reader == nil {
		return identity.LoadCertPool(path)
	}
	contents, err := reader(path)
	if err != nil {
		return nil, fmt.Errorf("tlsprofile: read held certificate-pool material: %w", err)
	}
	return identity.ParseCertPool(contents)
}

func ParsePeers(peers []config.AuthorizedPeer) (map[string]identity.PinSet, error) {
	result := make(map[string]identity.PinSet, len(peers))
	for index, peer := range peers {
		pins, err := identity.ParsePinAllowlist(peer.SPKIPins)
		if err != nil {
			return nil, fmt.Errorf("tlsprofile: peer %d pins: %w", index, err)
		}
		if _, duplicate := result[peer.DNSName]; duplicate {
			return nil, fmt.Errorf("tlsprofile: duplicate peer identity %q", peer.DNSName)
		}
		result[peer.DNSName] = pins
	}
	return result, nil
}

// PeerIdentity returns the exact DNS identity and SPKI hash from an already
// verified connection. It does not itself authorize the peer.
func PeerIdentity(state tls.ConnectionState) (string, identity.SPKIHash, error) {
	if len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].DNSNames) != 1 {
		return "", identity.SPKIHash{}, errors.New("tlsprofile: missing exact peer DNS identity")
	}
	hash, err := identity.HashSPKI(state.PeerCertificates[0])
	if err != nil {
		return "", identity.SPKIHash{}, err
	}
	return state.PeerCertificates[0].DNSNames[0], hash, nil
}
