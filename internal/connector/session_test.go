package connector

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestInnerFailuresNeverReachLocalDial(t *testing.T) {
	tests := []struct {
		name   string
		client func(connectorFixture) *tls.Config
		raw    bool
	}{
		{name: "EOF before handshake"},
		{name: "plaintext instead of TLS", raw: true},
		{name: "missing client certificate", client: func(fixture connectorFixture) *tls.Config {
			return &tls.Config{
				MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				RootCAs: fixture.connectorRoots, ServerName: fixture.connectorServerName,
				NextProtos: []string{config.CapabilityInnerALPN}, SessionTicketsDisabled: true,
			}
		}},
		{name: "capability bound to another route", client: func(fixture connectorFixture) *tls.Config { return fixture.wrongBindingClientTLS }},
		{name: "wrong client EKU", client: func(fixture connectorFixture) *tls.Config { return fixture.wrongEKUClientTLS }},
		{name: "wrong ALPN", client: func(fixture connectorFixture) *tls.Config {
			profile := fixture.authorizedClientTLS.Clone()
			profile.NextProtos = []string{"wrong/1"}
			return profile
		}},
		{name: "TLS 1.2", client: func(fixture connectorFixture) *tls.Config {
			profile := fixture.authorizedClientTLS.Clone()
			profile.MinVersion = tls.VersionTLS12
			profile.MaxVersion = tls.VersionTLS12
			return profile
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newConnectorFixture(t)
			serverSide, clientSide := net.Pipe()
			deadline := time.Now().Add(2 * time.Second)
			_ = serverSide.SetDeadline(deadline)
			_ = clientSide.SetDeadline(deadline)
			serverResult := runInnerServer(fixture.service, serverSide)

			switch {
			case test.raw:
				_, _ = clientSide.Write([]byte("not tls"))
			case test.client != nil:
				client := tls.Client(clientSide, test.client(fixture))
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_ = client.HandshakeContext(ctx)
				cancel()
				_ = client.Close()
			default:
				_ = clientSide.Close()
			}
			_ = clientSide.Close()

			result := <-serverResult
			if result.err == nil || result.ready {
				t.Fatalf("serveInner returned ready=%v err=%v", result.ready, result.err)
			}
			if calls := fixture.local.calls.Load(); calls != 0 {
				t.Fatalf("local dial count = %d, want 0", calls)
			}
		})
	}
}

func TestCapabilityAcceptsFreshCAAuthorizedKeyWithoutConnectorAllowlist(t *testing.T) {
	fixture := newConnectorFixture(t)
	localConnector, localSSH := net.Pipe()
	fixture.local.mu.Lock()
	fixture.local.conn = localConnector
	fixture.local.err = nil
	fixture.local.mu.Unlock()

	serverSide, clientSide := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = serverSide.SetDeadline(deadline)
	_ = clientSide.SetDeadline(deadline)
	serverResult := runInnerServer(fixture.service, serverSide)
	client := tls.Client(clientSide, fixture.rotatedKeyClientTLS)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := client.HandshakeContext(ctx); err != nil {
		cancel()
		t.Fatalf("rotated capability handshake: %v", err)
	}
	cancel()
	if err := protocol.ReadReady(client); err != nil {
		t.Fatalf("read READY: %v", err)
	}
	_ = client.Close()
	_ = localSSH.Close()

	result := <-serverResult
	if !result.ready || fixture.local.calls.Load() != 1 {
		t.Fatalf("rotated route capability ready=%v calls=%d err=%v", result.ready, fixture.local.calls.Load(), result.err)
	}
}

func TestCapabilityRevocationFailsBeforeLocalDial(t *testing.T) {
	for _, revokeBy := range []string{"installation", "spki"} {
		t.Run(revokeBy, func(t *testing.T) {
			fixture := newConnectorFixture(t)
			leaf := fixture.authorizedClientTLS.Certificates[0].Leaf
			clientID, _, _, _, err := config.ParseClientCapabilityDNSName(leaf.DNSNames[0])
			if err != nil {
				t.Fatal(err)
			}
			value := fixture.value
			switch revokeBy {
			case "installation":
				value.InnerTLS.RevokedClientIDs = []string{clientID.String()}
			case "spki":
				hash, hashErr := identity.HashSPKI(leaf)
				if hashErr != nil {
					t.Fatal(hashErr)
				}
				value.InnerTLS.RevokedClientSPKIs = []string{identity.FormatSPKIPin(hash)}
			}
			local := &countingLocalDialer{err: net.ErrClosed}
			service, err := New(value, WithCarrierDialer(errorCarrierDialer{}), WithLocalDialer(local))
			if err != nil {
				t.Fatalf("New revoked connector: %v", err)
			}

			serverSide, clientSide := net.Pipe()
			deadline := time.Now().Add(2 * time.Second)
			_ = serverSide.SetDeadline(deadline)
			_ = clientSide.SetDeadline(deadline)
			serverResult := runInnerServer(service, serverSide)
			client := tls.Client(clientSide, fixture.authorizedClientTLS)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = client.HandshakeContext(ctx)
			cancel()
			_ = client.Close()

			result := <-serverResult
			if result.err == nil || result.ready || local.calls.Load() != 0 {
				t.Fatalf("revoked capability ready=%v calls=%d err=%v", result.ready, local.calls.Load(), result.err)
			}
		})
	}
}

func TestCapabilityActiveAccountIsBoundedAndDeletedAtZero(t *testing.T) {
	fixture := newConnectorFixture(t)
	leaf := fixture.authorizedClientTLS.Certificates[0].Leaf
	clientID, _, _, _, err := config.ParseClientCapabilityDNSName(leaf.DNSNames[0])
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.service.tryAcquireClientActive(clientID) {
		t.Fatal("first authenticated client slot was rejected")
	}
	if fixture.service.tryAcquireClientActive(clientID) {
		t.Fatal("one client consumed the connector's reserved final slot")
	}
	if len(fixture.service.clientActive) != 1 {
		t.Fatalf("active-account cardinality = %d, want 1", len(fixture.service.clientActive))
	}
	fixture.service.releaseClientActive(clientID)
	if len(fixture.service.clientActive) != 0 {
		t.Fatalf("zero-count active account was retained: %v", fixture.service.clientActive)
	}
}

func TestAuthorizedInnerClientDialsOnlyFixedLoopbackThenSendsReady(t *testing.T) {
	fixture := newConnectorFixture(t)
	localConnector, localSSH := net.Pipe()
	fixture.local.mu.Lock()
	fixture.local.conn = localConnector
	fixture.local.err = nil
	fixture.local.mu.Unlock()

	serverSide, clientSide := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = serverSide.SetDeadline(deadline)
	_ = clientSide.SetDeadline(deadline)
	serverResult := runInnerServer(fixture.service, serverSide)
	client := tls.Client(clientSide, fixture.authorizedClientTLS)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := client.HandshakeContext(ctx); err != nil {
		cancel()
		t.Fatalf("inner client handshake: %v", err)
	}
	cancel()
	if err := protocol.ReadReady(client); err != nil {
		t.Fatalf("read READY: %v", err)
	}
	_ = client.Close()
	_ = localSSH.Close()

	result := <-serverResult
	if !result.ready {
		t.Fatalf("serveInner did not reach READY: %v", result.err)
	}
	if calls := fixture.local.calls.Load(); calls != 1 {
		t.Fatalf("local dial count = %d, want 1", calls)
	}
	network, address := fixture.local.target()
	if network != fixedSSHNetwork || address != fixedSSHTarget {
		t.Fatalf("local dial target = %s %s, want %s %s", network, address, fixedSSHNetwork, fixedSSHTarget)
	}
}

func TestActiveLimitRejectsAuthorizedClientBeforeLocalDial(t *testing.T) {
	fixture := newConnectorFixture(t)
	for i := 0; i < cap(fixture.service.active); i++ {
		fixture.service.active <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(fixture.service.active); i++ {
			release(fixture.service.active)
		}
	}()

	serverSide, clientSide := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = serverSide.SetDeadline(deadline)
	_ = clientSide.SetDeadline(deadline)
	serverResult := runInnerServer(fixture.service, serverSide)
	client := tls.Client(clientSide, fixture.authorizedClientTLS)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = client.HandshakeContext(ctx)
	cancel()
	_ = client.Close()

	result := <-serverResult
	if result.err == nil || result.ready {
		t.Fatalf("serveInner returned ready=%v err=%v", result.ready, result.err)
	}
	if calls := fixture.local.calls.Load(); calls != 0 {
		t.Fatalf("local dial count = %d, want 0", calls)
	}
}

func TestOuterHandshakeFailureCannotDialLocalSSH(t *testing.T) {
	fixture := newConnectorFixture(t)
	connectorSide, relaySide := net.Pipe()
	fixture.service.carrier = &singleCarrierDialer{conn: connectorSide}
	go relaySide.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if connection, err := fixture.service.connectOuter(ctx); err == nil {
		connection.Close()
		t.Fatal("connectOuter accepted a closed unauthenticated carrier")
	}
	if calls := fixture.local.calls.Load(); calls != 0 {
		t.Fatalf("local dial count = %d, want 0", calls)
	}
}

func TestPreAuthenticationReadBudgetIsFinite(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	bounded := &preAuthConn{Conn: left, remaining: 3, limited: true}
	go func() {
		_, _ = right.Write([]byte("abcd"))
	}()
	buffer := make([]byte, 8)
	if count, err := bounded.Read(buffer); err != nil || count != 3 {
		t.Fatalf("first read = %d, %v; want 3, nil", count, err)
	}
	if _, err := bounded.Read(buffer); err != errInnerByteLimit {
		t.Fatalf("second read error = %v, want %v", err, errInnerByteLimit)
	}
	bounded.disableLimit()
	if count, err := bounded.Read(buffer); err != nil || count != 1 {
		t.Fatalf("unlimited read = %d, %v; want 1, nil", count, err)
	}
}

func TestNewRejectsAnyLocalTargetOtherThanLiteralLoopback(t *testing.T) {
	fixture := newConnectorFixture(t)
	for _, target := range []string{"localhost:2222", "127.0.0.1:22", "127.0.0.1:2222", "[::1]:2222", "192.0.2.1:2222"} {
		if target == fixedSSHTarget {
			continue
		}
		value := fixture.value
		value.SSHTarget = target
		if _, err := New(value, WithCarrierDialer(errorCarrierDialer{})); err == nil {
			t.Errorf("New accepted SSH target %q", target)
		}
	}
}
