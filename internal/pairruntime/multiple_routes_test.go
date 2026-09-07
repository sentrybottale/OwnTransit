//go:build darwin || linux

package pairruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/crypto/ssh"
)

func liveRouteSSH(t *testing.T, f *integrated) *ssh.Client {
	t.Helper()
	carrier, release := f.open(t)
	t.Cleanup(func() { carrier.Close(); release() })
	conn, channels, requests, err := ssh.NewClientConn(carrier, "fixture", &ssh.ClientConfig{
		User: "fixture", HostKeyCallback: ssh.FixedHostKey(f.sshSigner.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { client.Close() })
	return client
}

func routeExec(client *ssh.Client) error {
	s, err := client.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	out, err := s.Output("fixture")
	if err == nil && string(out) != "owntransit-e2e-ok\n" {
		return ErrState
	}
	return err
}

func TestMultipleIndependentRoutesShareRelayAndIsolateAlarm(t *testing.T) {
	testMultipleRoutes(t, false)
}

func TestMultipleClientsReachSameSSHServerWithIndependentAlarms(t *testing.T) {
	testMultipleRoutes(t, true)
}

func testMultipleRoutes(t *testing.T, sharedSSH bool) {
	first := newIntegratedWithLimits(t, pairrelay.Limits{HandshakeTimeout: time.Second, PairingTimeout: 2 * time.Second})
	_, _ = first.start(t)
	first.pair(t)
	firstLive := liveRouteSSH(t, first)

	// Adding/registering another receiver must preserve an already live route.
	second := newRouteOnRelay(t, first.relay, first.dial)
	if sharedSSH {
		// Both receiving tunnel instances reach the very same SSH fixture and
		// host key. Their OwnTransit authorities and client keys stay separate.
		second.sshSigner = first.sshSigner
		second.sshTarget = first.sshServer
	}
	stopSecond, secondDone := second.start(t)
	second.pair(t)
	if first.registration.ReceiverID == second.registration.ReceiverID || first.registration.RouteID == second.registration.RouteID {
		t.Fatal("test routes are not independent")
	}
	secondLive := liveRouteSSH(t, second)
	// SSH pins the intended fixture key. The shared-host case uses the same
	// SSH server while OwnTransit still authenticates independent inner peers.
	time.Sleep(2200 * time.Millisecond)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, client := range []*ssh.Client{firstLive, secondLive} {
		wg.Add(1)
		go func(client *ssh.Client) { defer wg.Done(); results <- routeExec(client) }(client)
	}
	wg.Wait()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if first.dials.Load() != 1 || second.dials.Load() != 1 {
		t.Fatal("streams reached an unexpected receiver")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := SetLocked(ctx, second.serverPath, true, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondDone:
	case <-ctx.Done():
		t.Fatal("alarmed receiver did not stop")
	}
	if err := routeExec(secondLive); err == nil {
		t.Fatal("alarmed route still carried SSH")
	}
	if err := routeExec(firstLive); err != nil {
		t.Fatal("another route's alarm closed the first stream", err)
	}
	first.assertSSH(t) // Fresh admission on the unaffected route also works.
	for _, path := range []string{first.serverPath, first.clientPath} {
		p, err := ReadPolicy(path)
		if err != nil || p.Locked {
			t.Fatal("alarm crossed route state")
		}
	}
	stopSecond()
}

func TestCrossedIndependentInnerPeersFailBeforeLocalSSH(t *testing.T) {
	first := newIntegrated(t)
	_, _ = first.start(t)
	first.pair(t)
	second := newRouteOnRelay(t, first.relay, first.dial)
	_, _ = second.start(t)
	second.pair(t)
	profile := func(f *integrated) (*tls.Config, Authorization) {
		root, err := securefs.OpenRoot(f.clientPath)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s, err := readClient(root)
		if err != nil {
			t.Fatal(err)
		}
		p, err := receiverpairing.ParsePairing(s.Pairing)
		if err != nil {
			t.Fatal(err)
		}
		a, err := ParseAuthorization(s.Authorization, scopeOf(p))
		if err != nil {
			t.Fatal(err)
		}
		c, err := ClientTLS(a, s.Keys, s.Trust)
		if err != nil {
			t.Fatal(err)
		}
		return c, a
	}
	client, authFirst := profile(first)
	_, authSecond := profile(second)
	snap, err := (ReceiverBackend{Path: second.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	server, err := ReceiverTLS(authSecond, snap.Meta.Leaves, snap.Trust)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	policy := leasewire.Options{Policy: func() (uint64, bool, error) { return 1, false, nil }}
	serverDone := make(chan error, 1)
	called := make(chan struct{}, 1)
	go func() {
		serverDone <- serveSession(ctx, right, server, authSecond.Scope, policy, func(context.Context, string, string) (net.Conn, error) {
			called <- struct{}{}
			return nil, errors.New("crossed route reached local dial")
		})
	}()
	if c, err := ClientSession(ctx, left, client, authFirst.Scope, policy); err == nil {
		c.Close()
		t.Fatal("client accepted another receiver's inner identity")
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("receiver accepted another route's client")
		}
	case <-ctx.Done():
		t.Fatal("crossed handshake did not terminate")
	}
	select {
	case <-called:
		t.Fatal("crossed peers reached local SSH")
	default:
	}
	first.assertSSH(t)
	second.assertSSH(t)
}
