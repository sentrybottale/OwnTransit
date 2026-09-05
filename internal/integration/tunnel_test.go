package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/client"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/connector"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/relay"
	"github.com/sentrybottale/owntransit/internal/tlsprofile"
)

const testCredentialEpoch = 1

var (
	testSSHPayload = []byte("SSH relay-confidential request 8b6678eafb72")
	testSSHReply   = []byte("SSH relay-confidential response f348c38257f1")
)

// TestTunnelThroughProductionRelay proves the complete v1 data path using the
// production client, relay, and connector services. The local dialer asserts
// that the connector asks only for the build-fixed loopback SSH endpoint.
func TestTunnelThroughProductionRelay(t *testing.T) {
	fixture := newTunnelFixture(t)
	service, err := relay.New(fixture.relay)
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	dialer := &productionRelayDialer{service: service}
	runTunnel(t, fixture, dialer)
}

// TestTunnelConfidentialFromMaliciousRelay replaces the production relay with
// a rendezvous that owns the outer-TLS server key and records the exact bytes
// exposed after both outer TLS legs terminate. It can still pair the endpoints,
// but the independently keyed inner TLS stream must conceal the SSH bytes.
func TestTunnelConfidentialFromMaliciousRelay(t *testing.T) {
	fixture := newTunnelFixture(t)
	rendezvous := newMaliciousRendezvous(t, fixture)
	runTunnel(t, fixture, rendezvous)

	visible := rendezvous.visibleBytes()
	if len(visible) == 0 {
		t.Fatal("malicious relay recorded no inner stream bytes")
	}
	for _, plaintext := range [][]byte{testSSHPayload, testSSHReply} {
		if bytes.Contains(visible, plaintext) {
			t.Fatalf("malicious relay observed SSH plaintext %q", plaintext)
		}
	}
}

type tunnelFixture struct {
	relay          config.Relay
	connector      config.Connector
	client         config.Client
	relayServerTLS *tls.Config
	route          protocol.RouteID
}

func newTunnelFixture(t *testing.T) tunnelFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	const validity = 24 * time.Hour
	route := mustRouteID(t)
	clientID := mustID(t)
	connectorID := mustID(t)

	outerCA := mustCA(t, "integration outer CA", now, validity)
	capabilityCA := mustCA(t, "integration route capability CA", now, validity)
	connectorCA := mustCA(t, "integration connector CA", now, validity)

	relayLeaf := mustLeaf(t, outerCA, config.RelayDNSName, x509.ExtKeyUsageServerAuth, now, validity)
	outerConnectorName := config.OuterConnectorDNSName(route)
	outerConnectorLeaf := mustLeaf(t, outerCA, outerConnectorName, x509.ExtKeyUsageClientAuth, now, validity)
	outerClientName := config.OuterClientDNSName(clientID)
	outerClientLeaf := mustLeaf(t, outerCA, outerClientName, x509.ExtKeyUsageClientAuth, now, validity)
	innerConnectorName := config.CapabilityConnectorDNSName(connectorID, route)
	innerConnectorLeaf := mustLeaf(t, connectorCA, innerConnectorName, x509.ExtKeyUsageServerAuth, now, validity)
	innerClientName := config.ClientCapabilityDNSName(clientID, connectorID, route, testCredentialEpoch)
	innerClientLeaf := mustLeaf(t, capabilityCA, innerClientName, x509.ExtKeyUsageClientAuth, now, validity)

	directory := t.TempDir()
	outerCAPath := writeFile(t, directory, "outer-ca.pem", outerCA.CertPEM, 0o600)
	capabilityCAPath := writeFile(t, directory, "capability-ca.pem", capabilityCA.CertPEM, 0o600)
	connectorCAPath := writeFile(t, directory, "connector-ca.pem", connectorCA.CertPEM, 0o600)
	relayCert, relayKey := writeMaterial(t, directory, "relay", relayLeaf)
	outerConnectorCert, outerConnectorKey := writeMaterial(t, directory, "outer-connector", outerConnectorLeaf)
	outerClientCert, outerClientKey := writeMaterial(t, directory, "outer-client", outerClientLeaf)
	innerConnectorCert, innerConnectorKey := writeMaterial(t, directory, "inner-connector", innerConnectorLeaf)
	innerClientCert, innerClientKey := writeMaterial(t, directory, "inner-client", innerClientLeaf)

	relayPin := mustPin(t, relayLeaf.Certificate)
	outerConnectorPin := mustPin(t, outerConnectorLeaf.Certificate)
	outerClientPin := mustPin(t, outerClientLeaf.Certificate)
	innerConnectorPin := mustPin(t, innerConnectorLeaf.Certificate)

	relayConfig := config.Relay{
		Listen: "127.0.0.1:9087",
		Path:   config.RelayPath,
		OuterTLS: config.ServerTLS{
			CertFile: relayCert, KeyFile: relayKey, ClientCAFile: outerCAPath,
			IssuerCAFile: outerCAPath, LocalDNSName: config.RelayDNSName,
		},
		Clients: []config.AuthorizedPeer{{DNSName: outerClientName, SPKIPins: []string{outerClientPin}}},
		Routes:  []config.RelayRoute{{RouteID: route.String(), DNSName: outerConnectorName, SPKIPins: []string{outerConnectorPin}}},
		Limits: config.RelayLimits{
			CarriersGlobal: 32, OuterHandshakes: 4,
			PendingGlobal: 4, PendingPerRoute: 4, PendingPerClient: 2,
			ActiveGlobal: 4, ActivePerRoute: 4, ActivePerClient: 2,
			Handshake: config.Duration(2 * time.Second), Preface: config.Duration(2 * time.Second),
			Join: config.Duration(2 * time.Second), Drain: config.Duration(250 * time.Millisecond),
			SessionIdle: config.Duration(5 * time.Second), SessionLifetime: config.Duration(10 * time.Second),
		},
	}

	connectorConfig := config.Connector{
		RelayURL: "ws://relay.example.invalid/connects", AllowInsecureCarrier: true,
		InstallationID: connectorID.String(), RouteID: route.String(), InnerProfile: config.InnerProfileRouteCapability,
		OuterTLS: config.ClientTLS{
			CertFile: outerConnectorCert, KeyFile: outerConnectorKey, CAFile: outerCAPath,
			ServerName: config.RelayDNSName, SPKIPins: []string{relayPin},
			IssuerCAFile: outerCAPath, LocalDNSName: outerConnectorName,
		},
		InnerTLS: config.ConnectorInnerTLS{
			CertFile: innerConnectorCert, KeyFile: innerConnectorKey,
			ClientCAFiles: []string{capabilityCAPath},
			IssuerCAFile:  connectorCAPath, LocalDNSName: innerConnectorName, ServerName: innerConnectorName,
		},
		SSHTarget: config.ConnectorSSHTarget,
		Limits: config.ConnectorLimits{
			Pending: 4, Active: 4, ActivePerClient: 2,
			ConnectTimeout: config.Duration(2 * time.Second), Handshake: config.Duration(2 * time.Second),
			LocalDial: config.Duration(2 * time.Second), Drain: config.Duration(250 * time.Millisecond),
			ReconnectMin: config.Duration(25 * time.Millisecond), ReconnectMax: config.Duration(100 * time.Millisecond),
			SessionIdle: config.Duration(5 * time.Second), SessionLifetime: config.Duration(10 * time.Second),
		},
	}

	clientConfig := config.Client{
		RelayURL: "ws://relay.example.invalid/connects", AllowInsecureCarrier: true,
		InstallationID: clientID.String(), ConnectorInstallationID: connectorID.String(),
		CredentialEpoch: testCredentialEpoch, RouteID: route.String(), InnerProfile: config.InnerProfileRouteCapability,
		OuterTLS: config.ClientTLS{
			CertFile: outerClientCert, KeyFile: outerClientKey, CAFile: outerCAPath,
			ServerName: config.RelayDNSName, SPKIPins: []string{relayPin},
			IssuerCAFile: outerCAPath, LocalDNSName: outerClientName,
		},
		InnerTLS: config.ClientTLS{
			CertFile: innerClientCert, KeyFile: innerClientKey, CAFile: connectorCAPath,
			ServerName: innerConnectorName, SPKIPins: []string{innerConnectorPin},
			IssuerCAFile: capabilityCAPath, LocalDNSName: innerClientName,
		},
		ConnectTimeout: config.Duration(2 * time.Second), HandshakeTimeout: config.Duration(2 * time.Second),
		ReadyTimeout: config.Duration(2 * time.Second), DrainTimeout: config.Duration(500 * time.Millisecond),
	}

	peers := map[string]identity.PinSet{
		outerClientName:    mustPinSet(t, outerClientPin),
		outerConnectorName: mustPinSet(t, outerConnectorPin),
	}
	relayServerTLS, err := tlsprofile.Server(relayConfig.OuterTLS, config.RelayDNSName, config.RelayALPN, peers)
	if err != nil {
		t.Fatalf("create malicious-relay outer TLS profile: %v", err)
	}
	return tunnelFixture{relay: relayConfig, connector: connectorConfig, client: clientConfig, relayServerTLS: relayServerTLS, route: route}
}

type carrierDialer interface {
	Dial(context.Context) (net.Conn, error)
}

func runTunnel(t *testing.T, fixture tunnelFixture, dialer carrierDialer) {
	t.Helper()
	local := newLoopbackSSHDialer(testSSHPayload, testSSHReply)
	registered := make(chan struct{}, 1)
	connectorService, err := connector.New(
		fixture.connector,
		connector.WithCarrierDialer(dialer),
		connector.WithLocalDialer(local),
		connector.WithStateSink(func(state connector.State) {
			if state == connector.StateRegistered {
				select {
				case registered <- struct{}{}:
				default:
				}
			}
		}),
	)
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}
	clientService, err := client.New(fixture.client, dialer)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	connectorContext, cancelConnector := context.WithCancel(context.Background())
	connectorDone := make(chan error, 1)
	go func() { connectorDone <- connectorService.Run(connectorContext) }()
	select {
	case <-registered:
	case <-time.After(4 * time.Second):
		cancelConnector()
		t.Fatal("connector did not register with relay")
	}

	proxyContext, cancelProxy := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancelProxy()
	var output bytes.Buffer
	proxyErr := clientService.Proxy(proxyContext, bytes.NewReader(testSSHPayload), &output)
	if err := local.result(); err != nil {
		cancelConnector()
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), testSSHReply) {
		cancelConnector()
		t.Fatalf("SSH reply = %q, want %q", output.Bytes(), testSSHReply)
	}
	// net.Pipe reports ErrClosedPipe when the fixture closes immediately after
	// its complete reply while TLS is finishing its half-close. Only classify
	// that test-transport shutdown after both exact payload checks succeeded;
	// truncated data and authentication/protocol errors still fail this test.
	if proxyErr != nil && !errors.Is(proxyErr, io.ErrClosedPipe) {
		cancelConnector()
		t.Fatalf("proxy SSH bytes: %v", proxyErr)
	}
	if calls := local.calls.Load(); calls != 1 {
		cancelConnector()
		t.Fatalf("fixed loopback dial count = %d, want 1", calls)
	}

	cancelConnector()
	select {
	case err := <-connectorDone:
		if err != nil {
			t.Fatalf("stop connector: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connector did not stop after cancellation")
	}
}

type productionRelayDialer struct {
	service *relay.Service
}

func (dialer *productionRelayDialer) Dial(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpoint, transit := net.Pipe()
	go dialer.service.Handle(ctx, transit)
	return endpoint, nil
}

type loopbackSSHDialer struct {
	want     []byte
	reply    []byte
	calls    atomic.Int32
	resultCh chan error
}

func newLoopbackSSHDialer(want, reply []byte) *loopbackSSHDialer {
	return &loopbackSSHDialer{
		want: append([]byte(nil), want...), reply: append([]byte(nil), reply...),
		resultCh: make(chan error, 1),
	}
}

func (dialer *loopbackSSHDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp4" || address != config.ConnectorSSHTarget {
		return nil, fmt.Errorf("connector requested %s %s instead of fixed tcp4 %s", network, address, config.ConnectorSSHTarget)
	}
	if dialer.calls.Add(1) != 1 {
		return nil, errors.New("connector dialed local SSH more than once")
	}
	connectorSide, sshSide := net.Pipe()
	go func() {
		defer sshSide.Close()
		_ = sshSide.SetDeadline(time.Now().Add(3 * time.Second))
		input := make([]byte, len(dialer.want))
		if _, err := io.ReadFull(sshSide, input); err != nil {
			dialer.resultCh <- fmt.Errorf("fake SSH server read: %w", err)
			return
		}
		if !bytes.Equal(input, dialer.want) {
			dialer.resultCh <- fmt.Errorf("fake SSH server received %q, want %q", input, dialer.want)
			return
		}
		if _, err := sshSide.Write(dialer.reply); err != nil {
			dialer.resultCh <- fmt.Errorf("fake SSH server write: %w", err)
			return
		}
		dialer.resultCh <- nil
	}()
	return connectorSide, nil
}

func (dialer *loopbackSSHDialer) result() error {
	select {
	case err := <-dialer.resultCh:
		return err
	case <-time.After(3 * time.Second):
		return errors.New("fake SSH server did not complete")
	}
}

type maliciousRendezvous struct {
	tlsConfig *tls.Config
	route     protocol.RouteID
	epoch     protocol.EpochID

	mu      sync.Mutex
	control *tls.Conn
	pending map[protocol.SessionID]chan *tls.Conn
	visible bytes.Buffer
	writeMu sync.Mutex
}

func newMaliciousRendezvous(t *testing.T, fixture tunnelFixture) *maliciousRendezvous {
	t.Helper()
	epoch, err := protocol.NewEpochID()
	if err != nil {
		t.Fatalf("create relay epoch: %v", err)
	}
	return &maliciousRendezvous{
		tlsConfig: fixture.relayServerTLS, route: fixture.route, epoch: epoch,
		pending: make(map[protocol.SessionID]chan *tls.Conn),
	}
}

func (relay *maliciousRendezvous) Dial(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpoint, transit := net.Pipe()
	go relay.handle(ctx, transit)
	return endpoint, nil
}

func (relay *maliciousRendezvous) handle(ctx context.Context, raw net.Conn) {
	owned := true
	defer func() {
		if owned {
			raw.Close()
		}
	}()
	outer := tls.Server(raw, relay.tlsConfig)
	handshakeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := outer.HandshakeContext(handshakeContext); err != nil {
		cancel()
		return
	}
	cancel()
	_ = outer.SetDeadline(time.Now().Add(2 * time.Second))
	frame, err := protocol.ReadFrame(outer)
	if err != nil {
		return
	}
	_ = outer.SetDeadline(time.Time{})

	switch value := frame.(type) {
	case protocol.ControlRegister:
		if value.Route != relay.route {
			return
		}
		relay.mu.Lock()
		if relay.control != nil {
			relay.mu.Unlock()
			return
		}
		relay.control = outer
		relay.mu.Unlock()
		if relay.writeControl(protocol.Registered{Epoch: relay.epoch}) != nil {
			return
		}
		relay.serveControl(ctx, outer)
	case protocol.ClientOpen:
		if value.Route != relay.route {
			return
		}
		session, sessionErr := protocol.NewSessionID()
		if sessionErr != nil {
			return
		}
		joined := make(chan *tls.Conn, 1)
		relay.mu.Lock()
		relay.pending[session] = joined
		relay.mu.Unlock()
		defer func() {
			relay.mu.Lock()
			delete(relay.pending, session)
			relay.mu.Unlock()
		}()
		if relay.writeControl(protocol.Open{Epoch: relay.epoch, Session: session}) != nil {
			return
		}
		select {
		case data := <-joined:
			owned = false
			relay.copyVisible(ctx, outer, data)
		case <-ctx.Done():
		}
	case protocol.DataJoin:
		if value.Route != relay.route || value.Epoch != relay.epoch {
			return
		}
		relay.mu.Lock()
		joined := relay.pending[value.Session]
		relay.mu.Unlock()
		if joined == nil {
			return
		}
		select {
		case joined <- outer:
			owned = false
		case <-ctx.Done():
		}
	}
}

func (relay *maliciousRendezvous) serveControl(ctx context.Context, control *tls.Conn) {
	defer func() {
		relay.mu.Lock()
		if relay.control == control {
			relay.control = nil
		}
		relay.mu.Unlock()
	}()
	for {
		_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
		frame, err := protocol.ReadFrame(control)
		if err != nil {
			return
		}
		switch value := frame.(type) {
		case protocol.Ping:
			if relay.writeControl(protocol.Pong{}) != nil {
				return
			}
		case protocol.Cancel:
			if value.Epoch != relay.epoch {
				return
			}
		case protocol.Pong:
		default:
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (relay *maliciousRendezvous) writeControl(frame protocol.Frame) error {
	relay.writeMu.Lock()
	defer relay.writeMu.Unlock()
	relay.mu.Lock()
	control := relay.control
	relay.mu.Unlock()
	if control == nil {
		return errors.New("malicious relay has no registered connector")
	}
	_ = control.SetWriteDeadline(time.Now().Add(2 * time.Second))
	err := protocol.WriteFrame(control, frame)
	clearErr := control.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

func (relay *maliciousRendezvous) copyVisible(ctx context.Context, clientSide, connectorSide net.Conn) {
	defer clientSide.Close()
	defer connectorSide.Close()
	done := make(chan struct{}, 2)
	copyOne := func(destination, source net.Conn) {
		buffer := make([]byte, 32<<10)
		for {
			count, err := source.Read(buffer)
			if count > 0 {
				relay.mu.Lock()
				relay.visible.Write(buffer[:count])
				relay.mu.Unlock()
				if _, writeErr := destination.Write(buffer[:count]); writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go copyOne(clientSide, connectorSide)
	go copyOne(connectorSide, clientSide)
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (relay *maliciousRendezvous) visibleBytes() []byte {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return append([]byte(nil), relay.visible.Bytes()...)
}

func mustCA(t *testing.T, name string, now time.Time, validity time.Duration) pki.Material {
	t.Helper()
	material, err := pki.NewCA(name, now, validity)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func mustLeaf(t *testing.T, ca pki.Material, name string, usage x509.ExtKeyUsage, now time.Time, validity time.Duration) pki.Material {
	t.Helper()
	material, err := pki.IssueLeaf(ca, name, usage, now, validity)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func writeMaterial(t *testing.T, directory, name string, material pki.Material) (string, string) {
	t.Helper()
	return writeFile(t, directory, name+".pem", material.CertPEM, 0o600),
		writeFile(t, directory, name+".key", material.KeyPEM, 0o600)
}

func writeFile(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustPin(t *testing.T, certificate *x509.Certificate) string {
	t.Helper()
	pin, err := identity.SPKIPin(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func mustPinSet(t *testing.T, encoded string) identity.PinSet {
	t.Helper()
	pin, err := identity.ParseSPKIPin(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return identity.PinSet{pin: {}}
}

func mustRouteID(t *testing.T) protocol.RouteID {
	t.Helper()
	value, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustID(t *testing.T) protocol.ID {
	t.Helper()
	value, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
