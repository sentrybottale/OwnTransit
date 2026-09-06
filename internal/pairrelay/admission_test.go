package pairrelay

import (
	"context"
	"github.com/coder/websocket"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestIdleWebSocketReleasesAdmissionSlot(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.HandshakeTimeout = 80 * time.Millisecond
	server := httptest.NewServer(f.relay)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, server.URL+Path, &websocket.DialOptions{Subprotocols: []string{WebSocketSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(f.relay.connections) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("idle unauthenticated WebSocket kept its slot")
}

func TestPartialInitialFrameDeadline(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.HandshakeTimeout = 50 * time.Millisecond
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- f.relay.handleConnection(server) }()
	if _, err := client.Write([]byte("OTR")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("partial frame accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("partial read did not expire")
	}
}

func TestAdmissionBucketsBoundedAndReleased(t *testing.T) {
	var a admissionGuard
	now := time.Now()
	releases := make([]func(), 0)
	for i := 0; i < 8; i++ {
		release, ok := a.acquire("192.0.2.1:1234", now)
		if !ok {
			t.Fatal("early denial")
		}
		releases = append(releases, release)
	}
	if _, ok := a.acquire("192.0.2.1:9999", now); ok {
		t.Fatal("port changed the peer quota")
	}
	for _, release := range releases {
		release()
		release()
	}
	if _, ok := a.acquire("192.0.2.1:4321", now.Add(time.Second)); !ok {
		t.Fatal("released capacity was not reusable")
	}
	for i := 0; i < 1000; i++ {
		ip := net.IPv4(198, 51, byte(i/256), byte(i%256))
		release, ok := a.acquire(net.JoinHostPort(ip.String(), "1"), now.Add(time.Duration(i+2)*time.Second))
		if ok {
			release()
		}
	}
	if len(a.peers) > maxAdmissionPeers {
		t.Fatal("unbounded peer table")
	}
}

func TestAdmissionErrorWriteIsBounded(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.HandshakeTimeout = 50 * time.Millisecond
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- f.relay.handleConnection(server) }()
	if err := writeWireFrame(client, kindFetchServerInfo, nil, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("non-reading peer completed")
		}
	case <-time.After(time.Second):
		t.Fatal("public response write did not expire")
	}
}

func TestForwardedHeadersCannotBypassPeerQuota(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	server := httptest.NewServer(f.relay)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i := 0; i < 9; i++ {
		ws, response, err := websocket.Dial(ctx, server.URL+Path, &websocket.DialOptions{Subprotocols: []string{WebSocketSubprotocol}, HTTPHeader: http.Header{"X-Forwarded-For": []string{"192.0.2." + strconv.Itoa(i+1)}}})
		if i < 8 {
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()
		} else {
			if err == nil {
				ws.CloseNow()
				t.Fatal("forwarded header bypassed peer quota")
			}
			if response == nil || response.StatusCode != http.StatusTooManyRequests {
				t.Fatal("wrong quota rejection")
			}
		}
	}
}
