//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

type integrated struct {
	relay                  *pairrelay.Relay
	dial                   pairrelay.DialFunc
	serverPath, clientPath string
	attempt                receiverpairing.Attempt
	registration           pairrelay.Registration
	dials                  atomic.Int32
	sshSigner              ssh.Signer
}

func privatePath(t *testing.T, name string) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// testing.TempDir's numbered child respects the caller's umask. Keep the
	// fixture parent private even under a developer's group-writable umask.
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, name)
}

func newIntegrated(t *testing.T) *integrated {
	t.Helper()
	now := time.Now()
	ca, err := pki.NewCA("relay test", now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.IssueLeaf(ca, "relay.paired.owntransit.invalid", x509.ExtKeyUsageServerAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := identity.ParseKeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	r, err := pairrelay.NewRelay(pairrelay.RelayConfig{TokenKey: key, RelayTLS: pairrelay.TLSMaterial{Certificate: cert, CAPEM: ca.CertPEM, ServerName: "relay.paired.owntransit.invalid"}, VerifyAdvertisement: func(b []byte, now time.Time) (pairrelay.Descriptor, error) {
		i, e := receiverpairing.VerifyAdvertisement(b, now)
		if e != nil {
			return pairrelay.Descriptor{}, e
		}
		r, e := protocol.ParseID(i.ReceiverID)
		if e != nil {
			return pairrelay.Descriptor{}, e
		}
		route, e := protocol.ParseRouteID(i.RouteID)
		return pairrelay.Descriptor{ReceiverID: r, RouteID: route, AdmissionCAPEM: []byte(i.Trust.OuterEndpointCAPEM)}, e
	}})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(r)
	t.Cleanup(httpServer.Close)
	t.Cleanup(func() { r.Close() })
	f := &integrated{relay: r, serverPath: privatePath(t, "receiver"), clientPath: privatePath(t, "client")}
	f.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		ws, _, err := websocket.Dial(ctx, httpServer.URL+pairrelay.Path, &websocket.DialOptions{Subprotocols: []string{pairrelay.WebSocketSubprotocol}})
		if err != nil {
			return nil, err
		}
		ws.SetReadLimit(2 << 20)
		return websocket.NetConn(ctx, ws, websocket.MessageBinary), nil
	}
	public, err := pairrelay.NewPublicClient("wss://relay.example/connects", f.dial)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := public.FetchServerInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.attempt, err = InitializeReceiver(f.serverPath, "wss://relay.example/connects", info)
	if err != nil {
		t.Fatal(err)
	}
	if err := public.PublishAdvertisement(ctx, f.attempt.Advertisement); err != nil {
		t.Fatal(err)
	}
	receiverID, err := protocol.ParseID(f.attempt.ReceiverID)
	if err != nil {
		t.Fatal(err)
	}
	f.registration, err = r.RegisterReceiver(receiverID, pairrelay.RouteLimits{PendingPairings: 4, PendingCarriers: 4, ActiveCarriers: 4, PairingBytes: pairrelay.MaxPairingBytes, SessionLifetime: time.Hour}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.sshSigner, err = ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *integrated) start(t *testing.T) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	go func() {
		defer a.Close()
		err := ServeAgent(a, a, ReceiverBackend{Path: f.serverPath})
		if err != nil && ctx.Err() == nil {
			t.Logf("agent ended: %v", err)
		}
	}()
	done := make(chan error, 1)
	go func() {
		defer b.Close()
		gate, e := Admission(f.serverPath)
		if e != nil {
			done <- e
			return
		}
		defer gate.Close()
		err := serveReceiver(ctx, &AgentClient{Input: b, Output: b}, f.dial, func(ctx context.Context, raw net.Conn, profile *tls.Config, scope Scope, policy leasewire.Options) error {
			return serveSession(ctx, raw, profile, scope, policy, func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp4" || address != config.ConnectorSSHTarget {
					return nil, ErrState
				}
				f.dials.Add(1)
				local, target := net.Pipe()
				go f.sshServer(target)
				return local, nil
			})
		})
		if err != nil && ctx.Err() == nil {
			t.Logf("worker ended: %v", err)
		}
		done <- err
	}()
	t.Cleanup(func() { cancel(); b.Close() })
	return cancel, done
}

// A generated, disposable SSH fixture proves SSH protocol authentication and
// an exec channel through the carrier. It is not an operator SSH configuration.
func (f *integrated) sshServer(raw net.Conn) {
	defer raw.Close()
	c := &ssh.ServerConfig{NoClientAuth: true}
	c.AddHostKey(f.sshSigner)
	connection, channels, requests, err := ssh.NewServerConn(raw, c)
	if err != nil {
		return
	}
	defer connection.Close()
	go ssh.DiscardRequests(requests)
	for ch := range channels {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			return
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				if req.Type == "exec" {
					req.Reply(true, nil)
					channel.Write([]byte("owntransit-e2e-ok\n"))
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
				req.Reply(false, nil)
			}
		}()
	}
}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *integrated) pair(t *testing.T) {
	t.Helper()
	eventually(t, func() bool {
		root, e := securefs.OpenRoot(f.serverPath)
		if e != nil {
			return false
		}
		defer root.Close()
		var m ReceiverMeta
		e = readRecord(root, "receiver.json", &m)
		return e == nil && len(m.Token) > 0
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := PairClient(ctx, f.clientPath, "wss://relay.example/connects", f.attempt.Code, f.registration, f.dial)
	// The exact persisted request resumes if the receiver's outbound mailbox was
	// not queued at the first attempt. No secret or identity is regenerated.
	if err != nil {
		for i := 0; i < 10 && err != nil; i++ {
			time.Sleep(100 * time.Millisecond)
			err = ResumeClient(ctx, f.clientPath, f.dial)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func (f *integrated) open(t *testing.T) (*leasewire.Conn, func()) {
	t.Helper()
	r1, e := securefs.OpenRoot(f.clientPath)
	if e != nil {
		t.Fatal(e)
	}
	cstate, e := readClient(r1)
	r1.Close()
	if e != nil {
		t.Fatal(e)
	}
	p, e := receiverpairing.ParsePairing(cstate.Pairing)
	if e != nil {
		t.Fatal(e)
	}
	a1, e := ParseAuthorization(cstate.Authorization, scopeOf(p))
	if e != nil {
		t.Fatal(e)
	}
	r2, e := securefs.OpenRoot(f.serverPath)
	if e != nil {
		t.Fatal(e)
	}
	var meta ReceiverMeta
	e = readRecord(r2, "receiver.json", &meta)
	r2.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := ReceiverTLS(a1, meta.Leaves, cstate.Trust); e != nil {
		t.Fatalf("receiver profile: %v", e)
	}
	ec, e := endpointConfig(cstate, a1, f.dial)
	if e != nil {
		t.Fatal(e)
	}
	ec.PeerID = ec.Descriptor.ReceiverID
	ec.Token = meta.Token
	ec.Certificate, e = identity.ParseKeyPair(meta.Leaves.Outer, meta.Leaves.Keys.Outer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := pairrelay.NewReceiver(ec); e != nil {
		t.Fatalf("outer receiver profile: %v", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// The context belongs to the full live stream, not just its opening handshake.
	var l *leasewire.Conn
	var release func()
	var err error
	for i := 0; i < 10; i++ {
		l, release, err = OpenClient(ctx, f.clientPath, f.dial)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return l, func() { l.Close(); release(); cancel() }
}

func (f *integrated) assertSSH(t *testing.T) {
	t.Helper()
	l, release := f.open(t)
	defer release()
	client, channels, requests, err := ssh.NewClientConn(l, "fixture", &ssh.ClientConfig{User: "fixture", HostKeyCallback: ssh.FixedHostKey(f.sshSigner.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	sshClient := ssh.NewClient(client, channels, requests)
	defer sshClient.Close()
	session, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.Output("fixture")
	if err != nil || string(output) != "owntransit-e2e-ok\n" {
		t.Fatalf("SSH exec: %q, %v", output, err)
	}
}

func TestPairThroughRelaySSHRestartClientKillAndReceiverKill(t *testing.T) {
	f := newIntegrated(t)
	stop, done := f.start(t)
	f.pair(t)
	if f.dials.Load() != 0 {
		t.Fatal("pairing dialed SSH")
	}
	f.assertSSH(t)
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver failed to stop")
	}
	_, _ = f.start(t)
	for _, path := range []string{f.serverPath, f.clientPath} {
		p, e := ReadPolicy(path)
		if e != nil || p.Locked {
			t.Fatal("ordinary restart created an alarm")
		}
	}
	f.assertSSH(t)
	l, release := f.open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	killed := make(chan error, 1)
	go func() { killed <- SetLocked(ctx, f.clientPath, false, true) }()
	select {
	case <-l.Done():
	case <-ctx.Done():
		t.Fatal("client lock left active carrier")
	}
	release()
	if err := <-killed; err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenClient(ctx, f.clientPath, f.dial); err == nil {
		t.Fatal("locked client opened carrier")
	}
	if err := SetLocked(ctx, f.clientPath, false, false); err == nil {
		t.Fatal("terminal client alarm was cleared")
	}
	// Recovery is a deliberately new tunnel, not re-enabling old identities.
	rebuilt := newIntegrated(t)
	_, _ = rebuilt.start(t)
	rebuilt.pair(t)
	if rebuilt.attempt.ReceiverID == f.attempt.ReceiverID {
		t.Fatal("rebuild reused receiver identity")
	}
	rebuilt.assertSSH(t)
	l, release = rebuilt.open(t)
	defer release()
	killContext, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer killCancel()
	if err := SetLocked(killContext, rebuilt.serverPath, true, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.Done():
	case <-killContext.Done():
		t.Fatal("receiver lock left live carrier")
	}
	if err := SetLocked(killContext, rebuilt.serverPath, true, false); err == nil {
		t.Fatal("terminal receiver alarm was cleared")
	}
	r, err := receiverpairing.Open(filepath.Join(rebuilt.serverPath, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.Status()
	if err != nil || !s.LocalLocked || !s.PeerRevoked {
		t.Fatal("receiver lock was not durable")
	}
}

func TestOlderClearablePolicyIsNotAccepted(t *testing.T) {
	path := privatePath(t, "old-policy")
	root, err := securefs.CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeRecord(root, "policy.json", Policy{Schema: "owntransit.paired-policy.v1", Generation: 1}, true); err != nil {
		t.Fatal(err)
	}
	// Current v2 readers reject old clearable state; old v1 readers likewise
	// reject the v2 schema. There is no automatic trust/policy reinterpretation.
	var p Policy
	if err := readRecord(root, "policy.json", &p); err != nil {
		t.Fatal(err)
	}
	if p.Schema == "owntransit.paired-policy.v2" {
		t.Fatal("old policy silently rewritten")
	}
	if _, err := ReadPolicy(path); err == nil {
		t.Fatal("clearable v1 policy accepted by terminal-alarm runtime")
	}
}

func TestCredentialRenewalPersistsAndRejectsWrongCSRScope(t *testing.T) {
	f := newIntegrated(t)
	_, _ = f.start(t)
	f.pair(t)
	root, err := securefs.OpenRoot(f.clientPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s, err := readClient(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	live, release := f.open(t)
	defer release()
	if err := renewClient(ctx, f.clientPath, root, &s, f.dial); err != nil {
		t.Fatal(err)
	}
	if err := live.WaitReady(ctx); err != nil {
		t.Fatal("credential renewal killed an authenticated stream")
	}
	p, err := receiverpairing.ParsePairing(s.Pairing)
	if err != nil || p.CredentialGeneration() != 2 {
		t.Fatal("renewal not committed")
	}
	f.assertSSH(t)
	auth, err := ParseAuthorization(s.Authorization, scopeOf(p))
	if err != nil {
		t.Fatal(err)
	}
	wrong := auth
	wrong.Scope.Generation++
	encoded, _ := json.Marshal(wrong)
	if _, err := ParseAuthorization(encoded, scopeOf(p)); err == nil {
		t.Fatal("wrong scope accepted")
	}
	backend := ReceiverBackend{Path: f.serverPath}
	snap, err := backend.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	r, err := receiverpairing.Open(filepath.Join(f.serverPath, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := r.LoadPrivateAuthority(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := NewCredentialRequest(receiverpairing.ClientIdentity{ReceiverID: p.ReceiverID(), RouteID: p.RouteID(), ClientID: p.ClientID(), CredentialGeneration: 3})
	if err != nil {
		t.Fatal(err)
	}
	peer := receiverpairing.PeerRequest{Kind: "renew", ReceiverID: p.ReceiverID(), RouteID: p.RouteID(), ClientID: p.ClientID(), CredentialGeneration: 2, PublicPayload: payload}
	if _, err := IssueCredentials(peer, issuer, snap.Meta.Leaves, time.Now()); err == nil {
		t.Fatal("wrong-generation CSR reached issuance")
	}
}

func TestInnerLegacyALPNRejectedBeforeSSHAndControlsStayOutOfData(t *testing.T) {
	f := newIntegrated(t)
	_, _ = f.start(t)
	f.pair(t)
	root, err := securefs.OpenRoot(f.clientPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s, err := readClient(root)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := receiverpairing.ParsePairing(s.Pairing)
	a, _ := ParseAuthorization(s.Authorization, scopeOf(p))
	profile, err := ClientTLS(a, s.Keys, s.Trust)
	if err != nil {
		t.Fatal(err)
	}
	profile.NextProtos = []string{config.CapabilityInnerALPN}
	x, y := net.Pipe()
	defer y.Close()
	if _, err := ClientSession(context.Background(), x, profile, a.Scope, leasewire.Options{Policy: func() (uint64, bool, error) { return 1, false, nil }}); err == nil {
		t.Fatal("legacy profile accepted")
	}
	if f.dials.Load() != 0 {
		t.Fatal("wrong ALPN dialed SSH")
	}
	l, release := f.open(t)
	defer release()
	got := make([]byte, 4)
	if _, err := io.ReadFull(l, got); err != nil || !bytes.Equal(got, []byte("SSH-")) {
		t.Fatalf("non-SSH bytes in client stream: %q %v", got, err)
	}
}
