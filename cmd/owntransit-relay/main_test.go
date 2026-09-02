package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/transport"
)

func TestRelayFinalSelectionFailurePreventsListen(t *testing.T) {
	sentinel := errors.New("active generation changed")
	var diagnostics bytes.Buffer
	err := serveRelay(config.Relay{
		Listen: "127.0.0.1:0", Path: config.RelayPath,
	}, nil, &diagnostics, func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("serveRelay final check = %v, want %v", err, sentinel)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("failed final check announced a listener: %q", diagnostics.String())
	}
}

func TestRelayPortConflictNeverAnnouncesReady(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var diagnostics bytes.Buffer
	err = serveRelayHTTP(
		context.Background(), listener.Addr().String(), http.NotFoundHandler(),
		&diagnostics, "owntransit-relay: bootstrap exchange ready", nil,
	)
	if err == nil || diagnostics.Len() != 0 {
		t.Fatalf("port conflict err=%v diagnostics=%q", err, diagnostics.String())
	}
}

func TestRelayVersionIsOfflineAndRoleBound(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	commands := productionRelayCommands()
	commands.checkConfig = func(string) error { return errors.New("unexpected config check") }
	commands.run = func(string, io.Writer) error { return errors.New("unexpected run") }

	if code := executeRelay([]string{"version"}, &output, &diagnostics, commands); code != 0 {
		t.Fatalf("executeRelay(version) = %d, diagnostics=%q", code, diagnostics.String())
	}
	var info buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	if info.Role != "relay" || info.ConnectorTarget != "" {
		t.Fatalf("unexpected relay version: %+v", info)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected diagnostics: %q", diagnostics.String())
	}
}

func TestRelayExplicitAndLegacyRunModes(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments []string
	}{
		{name: "explicit", arguments: []string{"run", "-config", "relay.json"}},
		{name: "legacy no subcommand", arguments: []string{"-config", "relay.json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			var diagnostics bytes.Buffer
			runPath := ""
			commands := relayCommands{
				version:     func(io.Writer) error { return errors.New("unexpected version") },
				checkConfig: func(string) error { return errors.New("unexpected config check") },
				run: func(configPath string, _ io.Writer) error {
					runPath = configPath
					return nil
				},
			}
			if code := executeRelay(test.arguments, &output, &diagnostics, commands); code != 0 {
				t.Fatalf("executeRelay(run) = %d, diagnostics=%q", code, diagnostics.String())
			}
			if runPath != "relay.json" || output.Len() != 0 || diagnostics.Len() != 0 {
				t.Fatalf("runPath=%q stdout=%q stderr=%q", runPath, output.String(), diagnostics.String())
			}
		})
	}
}

func TestRelayCheckConfigDoesNotRun(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	checkedPath := ""
	commands := relayCommands{
		version: func(io.Writer) error { return errors.New("unexpected version") },
		checkConfig: func(configPath string) error {
			checkedPath = configPath
			return nil
		},
		run: func(string, io.Writer) error { return errors.New("unexpected run") },
	}
	code := executeRelay([]string{"check-config", "-config", "relay.json"}, &output, &diagnostics, commands)
	if code != 0 || checkedPath != "relay.json" {
		t.Fatalf("executeRelay(check-config) = %d, path=%q, diagnostics=%q", code, checkedPath, diagnostics.String())
	}
	if output.String() != "owntransit-relay: configuration valid\n" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestRelayReadOnlyViewsUseHeldRuntime(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	runRoot, runAnchor := "", ""
	runGID := 0
	commands := relayCommands{
		run: func(string, io.Writer) error { return errors.New("pathname run must not execute") },
		runRuntime: func(root, anchor string, gid int, _ io.Writer) error {
			runRoot, runAnchor, runGID = root, anchor, gid
			return nil
		},
	}
	code := executeRelay([]string{
		"run", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234",
	}, &output, &diagnostics, commands)
	if code != 0 || runRoot != "/runtime" || runAnchor != "/anchor" || runGID != 1234 {
		t.Fatalf("runtime run = %d, root=%q anchor=%q gid=%d diagnostics=%q", code, runRoot, runAnchor, runGID, diagnostics.String())
	}
	if output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestRelayBootstrapExchangeRequiresOneCanonicalAllocationHash(t *testing.T) {
	allocationHash := strings.Repeat("a", 64)
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	calledWith := ""
	commands := relayCommands{
		runExchange: func(value string, _ io.Writer) error {
			calledWith = value
			return nil
		},
	}
	if code := executeRelay([]string{"exchange", "-allocation-sha256", allocationHash}, &output, &diagnostics, commands); code != 0 {
		t.Fatalf("executeRelay(exchange) = %d, diagnostics=%q", code, diagnostics.String())
	}
	if calledWith != allocationHash || output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("exchange hash=%q stdout=%q stderr=%q", calledWith, output.String(), diagnostics.String())
	}

	for _, arguments := range [][]string{
		{"exchange"},
		{"exchange", "-allocation-sha256", strings.Repeat("A", 64)},
		{"exchange", "-allocation-sha256", strings.Repeat("a", 63)},
		{"exchange", "-allocation-sha256", allocationHash, "-allocation-sha256", allocationHash},
		{"exchange", "-allocation-sha256", allocationHash, "unexpected"},
	} {
		output.Reset()
		diagnostics.Reset()
		calledWith = ""
		if code := executeRelay(arguments, &output, &diagnostics, commands); code != 2 || calledWith != "" || output.Len() != 0 {
			t.Fatalf("invalid exchange arguments=%v code=%d called=%q stdout=%q stderr=%q", arguments, code, calledWith, output.String(), diagnostics.String())
		}
	}
}

func TestBootstrapExchangeHandlerNeverAcceptsCarrierOrAliasedPaths(t *testing.T) {
	exchange, err := enrollmentexchange.NewContainerExchangeHandler(
		enrollmentexchange.NewMailboxStore(),
		strings.Repeat("b", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	handler := bootstrapExchangeHandler(context.Background(), exchange)
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		request.RemoteAddr = "10.88.0.1:43210"
		handler.ServeHTTP(output, request)
	}))
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/connects/enrollment"
	connection, _, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{
		Subprotocols: []string{enrollmentexchange.ExchangeWebSocketSubprotocol},
	})
	if err != nil {
		server.Close()
		t.Fatalf("bootstrap exchange wrapper rejected its canonical WebSocket: %v", err)
	}
	connection.CloseNow()
	server.Close()
	for _, target := range []string{
		"http://relay/connects",
		"http://relay/connects/",
		"http://relay/connects/enrollment?alias=1",
		"http://relay/other",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("bootstrap exchange accepted %q with status %d", target, response.Code)
		}
	}
}

func TestRelayRuntimeViewFailureAndConfigConflictNeverUsePathnameRun(t *testing.T) {
	for index, arguments := range [][]string{
		{"run", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234"},
		{"run", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234", "--config", "relay.json"},
	} {
		var output bytes.Buffer
		var diagnostics bytes.Buffer
		runtimeCalls := 0
		pathnameRunCalled := false
		commands := relayCommands{
			run: func(string, io.Writer) error {
				pathnameRunCalled = true
				return nil
			},
			runRuntime: func(string, string, int, io.Writer) error {
				runtimeCalls++
				return errors.New("invalid active state")
			},
		}
		code := executeRelay(arguments, &output, &diagnostics, commands)
		wantRuntimeCalls := 1 - index
		if code == 0 || pathnameRunCalled || runtimeCalls != wantRuntimeCalls || output.Len() != 0 {
			t.Fatalf("arguments=%v code=%d runtimeCalls=%d pathnameRun=%v stdout=%q stderr=%q", arguments, code, runtimeCalls, pathnameRunCalled, output.String(), diagnostics.String())
		}
	}
}

func TestExactCarrierRequestRejectsAnyQueryMarker(t *testing.T) {
	for _, target := range []string{"http://relay/connects?", "http://relay/connects?x=1", "http://relay/other"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if exactCarrierRequest(request, "/connects") {
			t.Fatalf("exactCarrierRequest accepted %q", target)
		}
	}
	if request := httptest.NewRequest(http.MethodGet, "http://relay/connects", nil); !exactCarrierRequest(request, "/connects") {
		t.Fatal("exactCarrierRequest rejected the exact path")
	}
}

func TestAcceptLeasedCarrierCapacityAndFailedUpgradeRelease(t *testing.T) {
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	fullResponse := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://relay/connects", nil)
	if connection, err := acceptLeasedCarrier(context.Background(), fullResponse, request, slots); connection != nil || err == nil {
		t.Fatalf("capacity result = %#v, %v; want nil connection and nonnil error", connection, err)
	}
	if fullResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d, want %d", fullResponse.Code, http.StatusServiceUnavailable)
	}
	<-slots

	// A syntactically invalid native handshake reaches AcceptWebSocket, fails,
	// and must release the slot immediately so a second request is not rejected
	// as capacity exhaustion.
	for attempt := 0; attempt < 2; attempt++ {
		response := httptest.NewRecorder()
		connection, err := acceptLeasedCarrier(context.Background(), response, request, slots)
		if connection != nil || !errors.Is(err, transport.ErrInvalidSubprotocol) {
			t.Fatalf("attempt %d = %#v, %v", attempt, connection, err)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d, want %d", attempt, response.Code, http.StatusBadRequest)
		}
		if len(slots) != 0 {
			t.Fatalf("attempt %d leaked a carrier slot", attempt)
		}
	}
}

func TestLeasedCarrierReleasesOnceAndPreservesAbort(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()

	aborted := 0
	released := 0
	carrier := &leasedCarrier{
		Conn: &abortTrackingConn{Conn: left, aborted: &aborted},
		release: func() {
			released++
		},
	}

	if err := carrier.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := carrier.Close(); err != nil {
		// net.Conn permits Close to report an error when it is already closed;
		// the lease still must remain single-release.
		t.Logf("second close: %v", err)
	}
	if aborted != 1 {
		t.Fatalf("abort count = %d, want 1", aborted)
	}
	if released != 1 {
		t.Fatalf("release count = %d, want 1", released)
	}
}

type abortTrackingConn struct {
	net.Conn
	aborted *int
}

func (connection *abortTrackingConn) Abort() error {
	*connection.aborted++
	return connection.Conn.Close()
}
