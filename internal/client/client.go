// Package client implements the local OpenSSH ProxyCommand side of OwnTransit.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/tlsprofile"
)

// CarrierDialer returns one WebSocket byte stream. Authentication for this
// carrier is intentionally not trusted for OwnTransit authorization.
type CarrierDialer interface {
	Dial(context.Context) (net.Conn, error)
}

type Service struct {
	config     config.Client
	route      protocol.RouteID
	dialer     CarrierDialer
	outerTLS   *tls.Config
	innerTLS   *tls.Config
	preflight  func() error
	bufferPool sync.Pool
}

func New(value config.Client, dialer CarrierDialer) (*Service, error) {
	return newService(value, dialer, nil, nil)
}

// NewFromMaterial snapshots a client from one authenticated lifecycle
// generation without reopening credential pathnames.
func NewFromMaterial(value config.Client, dialer CarrierDialer, reader tlsprofile.MaterialReader, finalCheck func() error) (*Service, error) {
	if reader == nil || finalCheck == nil {
		return nil, errors.New("client: runtime material reader and final selection check are required")
	}
	return newService(value, dialer, reader, finalCheck)
}

func newService(value config.Client, dialer CarrierDialer, reader tlsprofile.MaterialReader, preflight func() error) (*Service, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	if dialer == nil {
		return nil, errors.New("client: carrier dialer is required")
	}
	route, err := protocol.ParseRouteID(value.RouteID)
	if err != nil {
		return nil, err
	}
	expectedOuterName := ""
	expectedInnerName := ""
	innerALPN := ""
	var configuredInstallationID protocol.ID
	if value.InstallationID != "" {
		configuredInstallationID, err = protocol.ParseID(value.InstallationID)
		if err != nil {
			return nil, fmt.Errorf("client: installation ID: %w", err)
		}
		expectedOuterName = config.OuterClientDNSName(configuredInstallationID)
	}
	switch value.InnerProfile {
	case config.InnerProfileRouteCapability:
		connectorID, parseErr := protocol.ParseID(value.ConnectorInstallationID)
		if parseErr != nil {
			return nil, fmt.Errorf("client: connector installation ID: %w", parseErr)
		}
		expectedInnerName = config.ClientCapabilityDNSName(configuredInstallationID, connectorID, route, value.CredentialEpoch)
		innerALPN = config.CapabilityInnerALPN
	case config.InnerProfileLegacyExactPins:
		if configuredInstallationID != (protocol.ID{}) {
			expectedInnerName = config.ClientDNSName(configuredInstallationID)
		}
		innerALPN = config.InnerALPN
	default:
		return nil, errors.New("client: unsupported inner profile")
	}
	loadTLS := tlsprofile.Client
	if reader != nil {
		loadTLS = func(value config.ClientTLS, expectedName, alpn string) (*tls.Config, error) {
			return tlsprofile.ClientFromMaterial(value, expectedName, alpn, reader)
		}
	}
	outerTLS, err := loadTLS(value.OuterTLS, expectedOuterName, config.RelayALPN)
	if err != nil {
		return nil, fmt.Errorf("client: outer TLS: %w", err)
	}
	innerTLS, err := loadTLS(value.InnerTLS, expectedInnerName, innerALPN)
	if err != nil {
		return nil, fmt.Errorf("client: inner TLS: %w", err)
	}
	if value.InnerProfile == config.InnerProfileLegacyExactPins {
		installationID, parseErr := config.ParseClientInstallationID(localCertificateDNSName(outerTLS), localCertificateDNSName(innerTLS))
		if parseErr != nil {
			return nil, fmt.Errorf("client: local identities: %w", parseErr)
		}
		if configuredInstallationID != (protocol.ID{}) && configuredInstallationID != installationID {
			return nil, errors.New("client: local certificates do not match installation_id")
		}
	}
	service := &Service{config: value, route: route, dialer: dialer, outerTLS: outerTLS, innerTLS: innerTLS, preflight: preflight}
	service.bufferPool.New = func() any {
		buffer := make([]byte, 32<<10)
		return &buffer
	}
	return service, nil
}

func localCertificateDNSName(profile *tls.Config) string {
	if profile == nil || len(profile.Certificates) != 1 || profile.Certificates[0].Leaf == nil ||
		len(profile.Certificates[0].Leaf.DNSNames) != 1 {
		return ""
	}
	return profile.Certificates[0].Leaf.DNSNames[0]
}

// Proxy carries one SSH process stream. It never reconnects or replays after
// any failure. Only bytes following the authenticated READY marker reach out.
func (service *Service) Proxy(ctx context.Context, in io.Reader, out io.Writer) error {
	if ctx == nil || in == nil || out == nil {
		return errors.New("client: context, input, and output are required")
	}
	inner, err := service.connectReady(ctx)
	if err != nil {
		return err
	}
	defer inner.Close()
	return service.copySSH(inner, in, out)
}

// Probe completes the same outer admission, route request, inner TLS endpoint
// authorization and authenticated connector READY marker as Proxy, then closes
// without sending or accepting SSH authentication bytes. It proves only the
// OwnTransit carrier and the connector's build-fixed local dial.
func (service *Service) Probe(ctx context.Context) error {
	if ctx == nil {
		return errors.New("client: context is required")
	}
	inner, err := service.connectReady(ctx)
	if err != nil {
		return err
	}
	return finishProbe(inner)
}

// finishProbe runs only after the authenticated READY marker. The relay is
// allowed to abort either carrier during teardown, so an EOF or closed-network
// result cannot invalidate the completed readiness proof. Other close errors
// remain visible and every pre-READY failure is handled by connectReady.
func finishProbe(inner io.Closer) error {
	if err := inner.Close(); err != nil && !isClosed(err) {
		return err
	}
	return nil
}

func (service *Service) connectReady(ctx context.Context) (*tls.Conn, error) {
	if service.preflight != nil {
		if err := service.preflight(); err != nil {
			return nil, fmt.Errorf("client: final runtime selection check: %w", err)
		}
	}
	carrier, err := service.dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: carrier connection failed: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = carrier.Close()
		}
	}()

	outer := tls.Client(carrier, service.outerTLS)
	if err := explicitHandshake(ctx, outer, service.config.HandshakeTimeout.Value()); err != nil {
		return nil, fmt.Errorf("client: outer handshake failed: %w", err)
	}
	if err := outer.SetWriteDeadline(time.Now().Add(service.config.ConnectTimeout.Value())); err != nil {
		return nil, err
	}
	if err := protocol.WriteFrame(outer, protocol.ClientOpen{Route: service.route}); err != nil {
		return nil, fmt.Errorf("client: route request failed: %w", err)
	}
	if err := outer.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}

	inner := tls.Client(outer, service.innerTLS)
	if err := explicitHandshake(ctx, inner, service.config.HandshakeTimeout.Value()); err != nil {
		return nil, fmt.Errorf("client: inner handshake failed: %w", err)
	}
	if err := inner.SetReadDeadline(time.Now().Add(service.config.ReadyTimeout.Value())); err != nil {
		return nil, err
	}
	if err := protocol.ReadReady(inner); err != nil {
		return nil, fmt.Errorf("client: connector readiness failed: %w", err)
	}
	if err := inner.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	keep = true
	return inner, nil
}

func explicitHandshake(ctx context.Context, connection *tls.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	handshakeContext, cancel := context.WithDeadline(ctx, deadline)
	err := connection.HandshakeContext(handshakeContext)
	cancel()
	clearErr := connection.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

type copyResult struct {
	direction byte
	err       error
}

func (service *Service) copySSH(inner *tls.Conn, in io.Reader, out io.Writer) error {
	results := make(chan copyResult, 2)
	copyOne := func(direction byte, destination io.Writer, source io.Reader) {
		buffer := service.bufferPool.Get().(*[]byte)
		_, err := io.CopyBuffer(destination, source, *buffer)
		service.bufferPool.Put(buffer)
		results <- copyResult{direction: direction, err: err}
	}
	go copyOne('i', inner, in)
	go copyOne('o', out, inner)
	first := <-results

	if first.direction == 'i' && first.err == nil {
		// stdin EOF means OpenSSH has finished sending. Preserve a bounded chance
		// for the authenticated remote EOF/response before closing the tunnel.
		_ = inner.CloseWrite()
		_ = inner.SetReadDeadline(time.Now().Add(service.config.DrainTimeout.Value()))
		select {
		case second := <-results:
			if second.err != nil && !isClosed(second.err) {
				return second.err
			}
		case <-time.After(service.config.DrainTimeout.Value()):
		}
		return nil
	}

	_ = inner.Close()
	if first.err != nil && !isClosed(first.err) {
		return first.err
	}
	return nil
}

func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}
