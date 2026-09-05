//go:build darwin || linux

package pairrelaycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
)

func TestInitServeRegisterAndRestart(t *testing.T) {
	probe, err := net.Listen("tcp4", HTTPListen)
	if err != nil {
		t.Skipf("fixed relay qualification port is unavailable: %v", err)
	}
	_ = probe.Close()
	now := time.Now().UTC().Truncate(time.Second)
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp(base, "ot-relay-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	statePath := filepath.Join(parent, "relay-state")
	summaryBytes, err := Init(statePath, now)
	if err != nil {
		t.Fatal(err)
	}
	var summary initSummary
	if err := json.Unmarshal(summaryBytes, &summary); err != nil || summary.Schema != "owntransit.pairrelay.state.v1" ||
		summary.HTTPListen != HTTPListen || summary.ServerName != RelayServerName || summary.RelayServerSPKI == "" {
		t.Fatalf("invalid init summary: %+v err=%v", summary, err)
	}
	if _, err := Init(statePath, now); err == nil {
		t.Fatal("init accepted an existing state root")
	}

	receiverRoot := filepath.Join(parent, "receiver")
	status, err := receiverpairing.Initialize(receiverpairing.InitializeOptions{
		RootPath: receiverRoot, RelayOrigin: "wss://relay.example/connects",
		RelayServerSPKI: summary.RelayServerSPKI, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := receiverpairing.Open(receiverRoot)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := receiver.CreateAttempt(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	receiverID, err := protocol.ParseID(status.ReceiverID)
	if err != nil {
		t.Fatal(err)
	}

	serveOnce := func() (context.CancelFunc, <-chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, statePath, io.Discard) }()
		waitForRelayHTTP(t)
		return cancel, done
	}
	public, err := pairrelay.NewPublicClient("wss://relay.example/connects", loopbackWebSocketDial)
	if err != nil {
		t.Fatal(err)
	}
	cancel, done := serveOnce()
	if err := Serve(context.Background(), statePath, io.Discard); err == nil {
		cancel()
		t.Fatal("second relay service acquired the held service lock")
	}
	if err := public.PublishAdvertisement(context.Background(), attempt.Advertisement); err != nil {
		cancel()
		t.Fatal(err)
	}
	code, err := Register(context.Background(), statePath, receiverID)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	registration, err := DecodeRegistration(code)
	if err != nil || registration.ReceiverID != receiverID || registration.RouteID == (protocol.RouteID{}) ||
		registration.ServerInfo.LeafSPKISHA256 != summary.RelayServerSPKI {
		cancel()
		t.Fatalf("invalid registration: %+v err=%v", registration, err)
	}
	automatic, err := public.FetchRegistration(context.Background(), attempt.Advertisement)
	if err != nil || !bytes.Equal(automatic, registration.Token) {
		cancel()
		t.Fatalf("automatic token differs: err=%v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	cancel, done = serveOnce()
	if err := public.PublishAdvertisement(context.Background(), attempt.Advertisement); err != nil {
		cancel()
		t.Fatal(err)
	}
	fetched, err := public.FetchAdvertisement(context.Background(), registration.Token)
	if err != nil || !bytes.Equal(fetched, attempt.Advertisement) {
		cancel()
		t.Fatalf("restarted relay rejected old stateless token: err=%v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(stateFiles) {
		t.Fatalf("durable relay state has %d entries, want %d", len(entries), len(stateFiles))
	}
	for index, name := range stateFiles {
		if entries[index].Name() != name {
			// os.ReadDir sorts names; compare as sets below when order differs.
			found := false
			for _, entry := range entries {
				found = found || entry.Name() == name
			}
			if !found {
				t.Fatalf("durable relay state is missing %s", name)
			}
		}
	}
}

func TestRegistrationEncodingIsCanonicalAndRejectsTamper(t *testing.T) {
	receiverID, _ := protocol.NewID()
	routeID, _ := protocol.NewRouteID()
	ca, err := pki.NewCA("OwnTransit registration test CA", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	registration := pairrelay.Registration{
		ReceiverID: receiverID, RouteID: routeID, Token: bytes.Repeat([]byte{0x42}, 64),
		ServerInfo: pairrelay.ServerInfo{
			ServerName: "relay.pairrelay.v2.owntransit.invalid", CAPEM: ca.CertPEM,
			LeafSPKISHA256: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
	}
	code, err := EncodeRegistration(registration)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRegistration(code)
	if err != nil || decoded.ReceiverID != receiverID || decoded.RouteID != routeID || !bytes.Equal(decoded.Token, registration.Token) {
		t.Fatalf("round trip differs: %+v err=%v", decoded, err)
	}
	for _, altered := range []string{code + " ", code[:len(code)-1] + "!", "otrelay2." + code[len(registrationPrefix):]} {
		if _, err := DecodeRegistration(altered); err == nil {
			t.Fatalf("accepted altered registration code %q", altered)
		}
	}
}

func waitForRelayHTTP(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp4", testHTTPDialAddress, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("relay HTTP listener did not start")
}

func loopbackWebSocketDial(ctx context.Context, _ string) (net.Conn, error) {
	ws, response, err := websocket.Dial(ctx, "ws://"+testHTTPDialAddress+pairrelay.Path, &websocket.DialOptions{
		Subprotocols: []string{pairrelay.WebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	ws.SetReadLimit(pairrelay.MaxPairingBytes + pairrelay.MaxAdmissionCABytes + pairrelay.MaxTokenBytes + 256)
	return websocket.NetConn(ctx, ws, websocket.MessageBinary), nil
}

const testHTTPDialAddress = "127.0.0.1:9087"
