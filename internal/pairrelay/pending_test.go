package pairrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/sentrybottale/owntransit/internal/transport"
)

// Reproduce a silent peer using real WebSocket and outer mTLS. Only fixture
// endpoint timing is shortened; no production option can change the bound.
func pendingFixture(t *testing.T, behavior string) (*Receiver, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	f := newRelayFixture(t)
	t.Cleanup(func() { _ = f.relay.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := f.public.PublishAdvertisement(ctx, f.advertisement); err != nil {
		t.Fatal(err)
	}
	registration, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, RouteLimits{PendingPairings: 2, PendingCarriers: 2, ActiveCarriers: 2, PairingBytes: MaxPairingBytes, SessionLifetime: time.Hour}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, pool, _, err := parseAdmissionCA(f.admissionCA.CertPEM, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := relayTLSConfig(f.relay.config.RelayTLS, pool, RoleReceiver, f.descriptor.ReceiverID, f.descriptor.ReceiverID, f.descriptor.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	admitted := make(chan struct{}, 8)
	stop := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{WebSocketSubprotocol}})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		raw, err := transport.WrapWebSocket(ctx, ws, maxWirePayload+wireHeaderSize)
		if err != nil {
			return
		}
		if behavior == "preface" {
			<-stop
			return
		}
		frame, err := readWireFrame(raw, maxWirePayload)
		if err != nil || requireKind(frame, kindRuntime) != nil {
			return
		}
		if behavior == "tls" {
			<-stop
			return
		}
		secured := tls.Server(raw, profile)
		handshake, done := context.WithTimeout(ctx, 2*time.Second)
		err = secured.HandshakeContext(handshake)
		done()
		if err != nil {
			return
		}
		admitted <- struct{}{}
		if behavior == "partial" {
			var encoded bytes.Buffer
			if writeWireFrame(&encoded, kindReady, nil, 0) != nil {
				return
			}
			_, _ = secured.Write(encoded.Bytes()[:2])
			<-stop
			return
		}
		if behavior == "silent" || behavior == "recover" && attempt == 1 {
			<-stop
			return
		}
		if writeWireFrame(secured, kindReady, nil, 0) != nil {
			return
		}
		_, _ = io.Copy(secured, secured)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(stop); cancel() })
	dial := func(c context.Context, _ string) (net.Conn, error) {
		ws, _, err := websocket.Dial(c, server.URL+Path, &websocket.DialOptions{Subprotocols: []string{WebSocketSubprotocol}})
		if err != nil {
			return nil, err
		}
		return transport.WrapWebSocket(c, ws, maxWirePayload+wireHeaderSize)
	}
	receiver, err := NewReceiver(EndpointConfig{URL: "wss://relay.example/connects", Token: registration.Token, Descriptor: f.descriptor, AdmissionCAPEM: f.admissionCA.CertPEM, PeerID: f.descriptor.ReceiverID, Certificate: issueEndpointLeaf(t, f.admissionCA, RoleReceiver, f.descriptor.ReceiverID, f.descriptor), RelayCAPEM: f.relayInfo.CAPEM, RelayServerName: f.relayInfo.ServerName, RelayServerSPKI: f.relayInfo.LeafSPKISHA256, Dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	if receiver.endpoint.pendingTimeout != 45*time.Second {
		t.Fatal("production pending bound changed")
	}
	receiver.endpoint.pendingTimeout = 250 * time.Millisecond
	return receiver, &attempts, admitted
}

func TestPendingOpenBoundsSilentTLSAndPartialReady(t *testing.T) {
	for _, behavior := range []string{"preface", "tls", "silent", "partial"} {
		t.Run(behavior, func(t *testing.T) {
			receiver, _, _ := pendingFixture(t, behavior)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			start := time.Now()
			c, err := receiver.Accept(ctx)
			if c != nil {
				c.Close()
				t.Fatal("unready stream returned")
			}
			if !errors.Is(err, ErrPendingTimeout) {
				t.Fatalf("expected local pending timeout, got %v", err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("pending attempt did not promptly release")
			}
		})
	}
}

func TestPendingOpenReconnectPreservesIdentityAndActiveStream(t *testing.T) {
	receiver, attempts, _ := pendingFixture(t, "recover")
	before := receiver.endpoint.config
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := receiver.Accept(ctx); c != nil || !errors.Is(err, ErrPendingTimeout) {
		t.Fatalf("silent attempt: %v", err)
	}
	c, err := receiver.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if attempts.Load() != 2 || !bytes.Equal(before.Token, receiver.endpoint.config.Token) || !bytes.Equal(before.Certificate.Certificate[0], receiver.endpoint.config.Certificate.Certificate[0]) {
		t.Fatal("reconnect changed retained identity or token")
	}
	// An old pending timer must not kill a promoted SSH carrier.
	time.Sleep(3 * receiver.endpoint.pendingTimeout)
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("opaque inner stream remains live")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("active stream closed by pending timer: %v", err)
	}
}

func TestPendingOpenParentCancellation(t *testing.T) {
	receiver, _, admitted := pendingFixture(t, "silent")
	receiver.endpoint.pendingTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := receiver.Accept(ctx); done <- err }()
	select {
	case <-admitted:
	case <-time.After(3 * time.Second):
		t.Fatal("no outer handshake")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel left pending carrier blocked")
	}
}

func TestPendingPromotionCannotResurrectExpiredGuard(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	p, err := guardPendingOpen(context.Background(), local, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if !errors.Is(p.promote(), ErrPendingTimeout) {
		t.Fatal("expired guard promoted")
	}
}

func TestPendingPromotionRaceDoesNotCloseTransferredStream(t *testing.T) {
	for i := 0; i < 40; i++ {
		local, peer := net.Pipe()
		p, err := guardPendingOpen(context.Background(), local, time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			time.Sleep(time.Millisecond)
		}
		err = p.promote()
		if err == nil {
			time.Sleep(2 * time.Millisecond)
			_ = local.SetDeadline(time.Now().Add(time.Second))
			wrote := make(chan error, 1)
			go func() { _, e := peer.Write([]byte{1}); wrote <- e }()
			var got [1]byte
			_, e := io.ReadFull(local, got[:])
			if e != nil || got[0] != 1 {
				t.Fatalf("timer closed promoted stream: %v", e)
			}
			if e := <-wrote; e != nil {
				t.Fatal(e)
			}
		} else if !errors.Is(err, ErrPendingTimeout) {
			t.Fatal(err)
		}
		local.Close()
		peer.Close()
	}
}
