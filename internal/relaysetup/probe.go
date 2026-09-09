package relaysetup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/transport"
)

var errProbeForbidden = errors.New("this VPS's verified HTTPS WebSocket probe received HTTP 403")

// These private dependencies exist only for isolated transport fixtures. No
// command, environment or relay input can select alternate trust or addresses.
type adminProbeNetwork struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  *x509.CertPool
}

func adminProbeServer(ctx context.Context, rawURL string) (pairrelay.ServerInfo, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	return adminProbeWithNetwork(ctx, rawURL, adminProbeNetwork{lookup: net.DefaultResolver.LookupNetIP, dial: dialer.DialContext})
}
func adminProbeWithNetwork(ctx context.Context, rawURL string, network adminProbeNetwork) (pairrelay.ServerInfo, error) {
	if canonical, err := PublicURL(rawURL); err != nil || canonical != rawURL {
		return pairrelay.ServerInfo{}, pairrelay.ErrProtocol
	}
	forbidden := false
	client, err := pairrelay.NewPublicClient(rawURL, func(dialCtx context.Context, target string) (net.Conn, error) {
		// Classification belongs to this exact attempt, never to a preceding
		// response which could hide a later TLS/protocol failure.
		forbidden = false
		connection, err := dialAdminProbe(dialCtx, target, network)
		forbidden = errors.Is(err, errProbeForbidden)
		return connection, err
	})
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	info, err := client.FetchServerInfo(ctx)
	if forbidden {
		return pairrelay.ServerInfo{}, errProbeForbidden
	}
	return info, err
}
func adminPublicAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified()
}
func dialAdminProbe(ctx context.Context, rawURL string, network adminProbeNetwork) (net.Conn, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || network.lookup == nil || network.dial == nil {
		return nil, pairrelay.ErrTransport
	}
	host := parsed.Hostname()
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	addresses, err := network.lookup(lookupCtx, "ip", host)
	cancel()
	if err != nil || len(addresses) == 0 {
		return nil, pairrelay.ErrTransport
	}
	var selected netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if !adminPublicAddress(address) {
			return nil, pairrelay.ErrTransport
		}
		if !selected.IsValid() {
			selected = address
		}
	}
	httpTransport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: host, RootCAs: network.roots},
	}
	defer httpTransport.CloseIdleConnections()
	httpTransport.DialContext = func(dialCtx context.Context, kind, address string) (net.Conn, error) {
		if kind != "tcp" || address != net.JoinHostPort(host, "443") {
			return nil, pairrelay.ErrTransport
		}
		connection, err := network.dial(dialCtx, "tcp", net.JoinHostPort(selected.String(), "443"))
		if err != nil {
			return nil, pairrelay.ErrTransport
		}
		peer, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok {
			connection.Close()
			return nil, pairrelay.ErrTransport
		}
		actual, ok := netip.AddrFromSlice(peer.IP)
		if !ok || actual.Unmap() != selected || !adminPublicAddress(actual.Unmap()) {
			connection.Close()
			return nil, pairrelay.ErrTransport
		}
		return connection, nil
	}
	client := &http.Client{Transport: httpTransport, Jar: nil, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, response, err := websocket.Dial(handshakeCtx, rawURL, &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{pairrelay.WebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if authenticatedForbidden(response, parsed) {
			return nil, errProbeForbidden
		}
		return nil, pairrelay.ErrTransport
	}
	if ws.Subprotocol() != pairrelay.WebSocketSubprotocol {
		ws.CloseNow()
		return nil, pairrelay.ErrProtocol
	}
	// This administration client fetches only bounded public server info.
	return transport.WrapWebSocket(ctx, ws, pairrelay.MaxAdmissionCABytes+4096+12)
}
func authenticatedForbidden(response *http.Response, expected *url.URL) bool {
	return response != nil && response.StatusCode == http.StatusForbidden && response.TLS != nil && response.TLS.HandshakeComplete && response.TLS.Version == tls.VersionTLS13 && len(response.TLS.VerifiedChains) > 0 && response.Request != nil && response.Request.Method == http.MethodGet && response.Request.URL != nil && response.Request.URL.Scheme == "https" && response.Request.URL.Host == expected.Host && response.Request.URL.Path == expected.Path && response.Request.URL.RawPath == "" && response.Request.URL.RawQuery == "" && response.Request.URL.Fragment == ""
}
