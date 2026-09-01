// Package carrier creates the untrusted WebSocket carrier used by endpoints.
// The returned stream must always be wrapped in OwnTransit outer TLS.
package carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/transport"
)

type Dialer struct {
	rawURL         string
	allowCleartext bool
	timeout        time.Duration
	httpClient     *http.Client
}

func NewDialer(rawURL, caFile string, allowCleartext bool, timeout time.Duration) (*Dialer, error) {
	var roots *x509.CertPool
	var err error
	if caFile != "" {
		roots, err = identity.LoadCertPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("carrier: private carrier CA: %w", err)
		}
	}
	return newDialer(rawURL, allowCleartext, timeout, roots)
}

// NewDialerFromMaterial constructs the public WebSocket dialer from bounded
// CA bytes already authenticated by a held lifecycle generation. An empty CA
// keeps the normal WebPKI root behavior.
func NewDialerFromMaterial(rawURL string, caPEM []byte, allowCleartext bool, timeout time.Duration) (*Dialer, error) {
	var roots *x509.CertPool
	var err error
	if len(caPEM) != 0 {
		roots, err = identity.ParseCertPool(caPEM)
		if err != nil {
			return nil, fmt.Errorf("carrier: private carrier CA: %w", err)
		}
	}
	return newDialer(rawURL, allowCleartext, timeout, roots)
}

func newDialer(rawURL string, allowCleartext bool, timeout time.Duration, roots *x509.CertPool) (*Dialer, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("carrier: timeout must be positive")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		(parsed.Scheme != "wss" && !(parsed.Scheme == "ws" && allowCleartext)) {
		return nil, fmt.Errorf("carrier: invalid or forbidden WebSocket URL")
	}
	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
	}
	if roots != nil {
		tlsConfig.RootCAs = roots
	}
	networkDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	httpTransport := &http.Transport{
		Proxy:                 nil,
		DialContext:           networkDialer.DialContext,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		MaxConnsPerHost:       64,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	dialer := &Dialer{
		rawURL:         rawURL,
		allowCleartext: allowCleartext,
		timeout:        timeout,
		httpClient:     &http.Client{Transport: httpTransport},
	}
	return dialer, nil
}

func (dialer *Dialer) Dial(ctx context.Context) (net.Conn, error) {
	connection, response, err := transport.DialWebSocket(ctx, dialer.rawURL, transport.WebSocketDialOptions{
		WebSocketOptions: transport.WebSocketOptions{AllowCleartext: dialer.allowCleartext},
		HTTPClient:       dialer.httpClient,
		HandshakeTimeout: dialer.timeout,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, err
	}
	return connection, nil
}
