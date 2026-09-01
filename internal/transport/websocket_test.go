package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWebSocketStreamRoundTripAndChunksWrites(t *testing.T) {
	payload := bytes.Repeat([]byte("owntransit"), 17)
	serverDone := make(chan error, 1)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := AcceptWebSocket(context.Background(), w, r, WebSocketOptions{
			MaxMessageBytes: 8,
		})
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			serverDone <- fmt.Errorf("read stream: %w", err)
			return
		}
		if !bytes.Equal(got, payload) {
			serverDone <- errors.New("server received different bytes")
			return
		}
		if _, err := conn.Write(got); err != nil {
			serverDone <- fmt.Errorf("write stream: %w", err)
			return
		}
		serverDone <- nil
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := DialWebSocket(ctx, websocketTestURL(server.URL), WebSocketDialOptions{
		WebSocketOptions: WebSocketOptions{MaxMessageBytes: 8},
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}

	n, err := conn.Write(payload)
	if err != nil {
		conn.Close()
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		conn.Close()
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		conn.Close()
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		conn.Close()
		t.Fatal("round trip changed stream bytes")
	}
	_ = conn.Close()

	waitTestError(t, serverDone)
}

func TestAcceptWebSocketRejectsNonNativeHandshakes(t *testing.T) {
	tests := []struct {
		name         string
		header       http.Header
		subprotocols []string
		compression  websocket.CompressionMode
		wantStatus   int
		wantError    error
	}{
		{
			name:         "origin",
			header:       http.Header{"Origin": []string{"https://relay.example"}},
			subprotocols: []string{WebSocketSubprotocol},
			wantStatus:   http.StatusForbidden,
			wantError:    ErrOriginNotAllowed,
		},
		{
			name:       "missing subprotocol",
			wantStatus: http.StatusBadRequest,
			wantError:  ErrInvalidSubprotocol,
		},
		{
			name:         "additional subprotocol",
			subprotocols: []string{WebSocketSubprotocol, "other"},
			wantStatus:   http.StatusBadRequest,
			wantError:    ErrInvalidSubprotocol,
		},
		{
			name:         "extension",
			subprotocols: []string{WebSocketSubprotocol},
			compression:  websocket.CompressionNoContextTakeover,
			wantStatus:   http.StatusBadRequest,
			wantError:    ErrExtensionsNotAllowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptErr := make(chan error, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := AcceptWebSocket(context.Background(), w, r, WebSocketOptions{})
				acceptErr <- err
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ws, resp, err := websocket.Dial(ctx, websocketTestURL(server.URL), &websocket.DialOptions{
				HTTPClient:      server.Client(),
				HTTPHeader:      test.header,
				Subprotocols:    test.subprotocols,
				CompressionMode: test.compression,
			})
			if ws != nil {
				ws.CloseNow()
			}
			if err == nil {
				t.Fatal("handshake unexpectedly succeeded")
			}
			if resp == nil {
				t.Fatal("handshake returned no HTTP response")
			}
			if resp.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, test.wantStatus)
			}

			select {
			case err := <-acceptErr:
				if !errors.Is(err, test.wantError) {
					t.Fatalf("AcceptWebSocket error = %v, want %v", err, test.wantError)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for server rejection")
			}
		})
	}
}

func TestAcceptWebSocketRequiresTLS(t *testing.T) {
	acceptErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := AcceptWebSocket(context.Background(), w, r, WebSocketOptions{})
		acceptErr <- err
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"X-Forwarded-Proto": []string{"https"},
		},
		Subprotocols: []string{WebSocketSubprotocol},
	})
	if ws != nil {
		ws.CloseNow()
	}
	if err == nil {
		t.Fatal("plain WebSocket handshake unexpectedly succeeded")
	}
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("response = %#v, want HTTP %d", resp, http.StatusBadRequest)
	}
	if err := <-acceptErr; !errors.Is(err, ErrWSSRequired) {
		t.Fatalf("AcceptWebSocket error = %v, want %v", err, ErrWSSRequired)
	}
}

func TestWebSocketAllowsExplicitCleartextHop(t *testing.T) {
	payload := []byte("inner OwnTransit TLS bytes")
	serverDone := make(chan error, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := AcceptWebSocket(context.Background(), w, r, WebSocketOptions{
			AllowCleartext: true,
		})
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(got, payload) {
			serverDone <- errors.New("cleartext carrier hop changed bytes")
			return
		}
		serverDone <- nil
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/carrier"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := DialWebSocket(ctx, wsURL, WebSocketDialOptions{
		WebSocketOptions: WebSocketOptions{AllowCleartext: true},
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("DialWebSocket cleartext opt-in: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		t.Fatalf("Write: %v", err)
	}
	_ = conn.Close()
	waitTestError(t, serverDone)
}

func TestWebSocketStreamRejectsTextAndOversizedMessages(t *testing.T) {
	tests := []struct {
		name       string
		messageTyp websocket.MessageType
		payload    []byte
		wantError  error
	}{
		{
			name:       "text",
			messageTyp: websocket.MessageText,
			payload:    []byte("x"),
		},
		{
			name:       "oversized binary",
			messageTyp: websocket.MessageBinary,
			payload:    bytes.Repeat([]byte{'x'}, 9),
			wantError:  websocket.ErrMessageTooBig,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			readErr := make(chan error, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := AcceptWebSocket(context.Background(), w, r, WebSocketOptions{
					MaxMessageBytes: 8,
				})
				if err != nil {
					readErr <- err
					return
				}
				// coder/websocket enforces its message limit while consuming the
				// message, rather than rejecting solely from the frame header. Drain
				// until the adapter observes either the wrong type or size violation.
				_, err = io.Copy(io.Discard, conn)
				readErr <- err
				_ = conn.Close()
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ws, _, err := websocket.Dial(ctx, websocketTestURL(server.URL), &websocket.DialOptions{
				HTTPClient:   server.Client(),
				Subprotocols: []string{WebSocketSubprotocol},
			})
			if err != nil {
				t.Fatalf("websocket.Dial: %v", err)
			}
			if err := ws.Write(ctx, test.messageTyp, test.payload); err != nil {
				ws.CloseNow()
				t.Fatalf("Write: %v", err)
			}
			ws.CloseNow()

			select {
			case err := <-readErr:
				if err == nil {
					t.Fatal("server read unexpectedly succeeded")
				}
				if test.wantError != nil && !errors.Is(err, test.wantError) {
					t.Fatalf("read error = %v, want %v", err, test.wantError)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for server read failure")
			}
		})
	}
}

func TestDialWebSocketRejectsUnsafeURLsAndRedirects(t *testing.T) {
	unsafeURLs := []string{
		"ws://relay.example/carrier",
		"https://relay.example/carrier",
		"/carrier",
		"wss://user@relay.example/carrier",
		"wss://relay.example/carrier#fragment",
	}
	for _, rawURL := range unsafeURLs {
		t.Run(rawURL, func(t *testing.T) {
			_, _, err := DialWebSocket(context.Background(), rawURL, WebSocketDialOptions{})
			if !errors.Is(err, ErrWSSRequired) {
				t.Fatalf("DialWebSocket error = %v, want %v", err, ErrWSSRequired)
			}
		})
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/different", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := DialWebSocket(ctx, websocketTestURL(server.URL), WebSocketDialOptions{
		HTTPClient: server.Client(),
	})
	if err == nil {
		t.Fatal("redirect unexpectedly succeeded")
	}
	if resp == nil || resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("response = %#v, want HTTP %d", resp, http.StatusTemporaryRedirect)
	}
}

func TestWebSocketContextCancellationUnblocksRead(t *testing.T) {
	serverCtx, cancelServer := context.WithCancel(context.Background())
	readStarted := make(chan struct{})
	readErr := make(chan error, 1)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := AcceptWebSocket(serverCtx, w, r, WebSocketOptions{})
		if err != nil {
			readErr <- err
			return
		}
		close(readStarted)
		var one [1]byte
		_, err = conn.Read(one[:])
		readErr <- err
		_ = conn.Close()
	}))
	defer server.Close()

	client, _, err := DialWebSocket(context.Background(), websocketTestURL(server.URL), WebSocketDialOptions{
		HTTPClient: server.Client(),
	})
	if err != nil {
		cancelServer()
		t.Fatalf("DialWebSocket: %v", err)
	}
	defer client.Close()

	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		cancelServer()
		t.Fatal("timed out waiting for server read")
	}
	cancelServer()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not unblock read")
	}
}

func TestWebSocketReadDeadlineUnblocksRead(t *testing.T) {
	releaseServer := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := AcceptWebSocket(context.Background(), w, r, WebSocketOptions{})
		if err != nil {
			return
		}
		<-releaseServer
		_ = conn.Close()
	}))
	defer server.Close()

	client, _, err := DialWebSocket(context.Background(), websocketTestURL(server.URL), WebSocketDialOptions{
		HTTPClient: server.Client(),
	})
	if err != nil {
		close(releaseServer)
		t.Fatalf("DialWebSocket: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		client.Close()
		close(releaseServer)
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var one [1]byte
	_, err = client.Read(one[:])
	if err == nil {
		client.Close()
		close(releaseServer)
		t.Fatal("Read unexpectedly succeeded")
	}
	// coder/websocket cancels an active read when its net.Conn deadline fires.
	// Depending on whether the timer or the next read observes expiry first,
	// the wrapped cause is context.Canceled or context.DeadlineExceeded. Both
	// mean the documented fatal-deadline behavior occurred.
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		client.Close()
		close(releaseServer)
		t.Fatalf("Read error = %v, want a context deadline/cancellation error", err)
	}

	_ = client.Close()
	close(releaseServer)
}

func TestWebSocketOptionValidation(t *testing.T) {
	if _, err := websocketMessageLimit(-1); !errors.Is(err, ErrInvalidMessageLimit) {
		t.Fatalf("negative message limit error = %v", err)
	}
	if _, err := websocketMessageLimit(MaxWebSocketMessageBytes + 1); !errors.Is(err, ErrInvalidMessageLimit) {
		t.Fatalf("oversized message limit error = %v", err)
	}
	if got, err := websocketMessageLimit(0); err != nil || got != DefaultWebSocketMessageBytes {
		t.Fatalf("default message limit = %d, %v", got, err)
	}
	if _, err := websocketHandshakeTimeout(-1); !errors.Is(err, ErrInvalidHandshakeTimeout) {
		t.Fatalf("negative handshake timeout error = %v", err)
	}
	if _, err := websocketHandshakeTimeout(MaxWebSocketHandshakeTimeout + 1); !errors.Is(err, ErrInvalidHandshakeTimeout) {
		t.Fatalf("oversized handshake timeout error = %v", err)
	}
	if got, err := websocketHandshakeTimeout(0); err != nil || got != DefaultWebSocketHandshakeTimeout {
		t.Fatalf("default handshake timeout = %s, %v", got, err)
	}
}

func TestAbortDoesNotUseBlockingGracefulClose(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	gracefulStarted := make(chan struct{})
	releaseGraceful := make(chan struct{})
	aborted := make(chan struct{})
	stream := &webSocketStream{
		Conn: &blockingCloseConn{
			Conn:            left,
			gracefulStarted: gracefulStarted,
			release:         releaseGraceful,
		},
		maxMessageBytes: 8,
		stopContext:     func() bool { return true },
		abort: func() error {
			close(aborted)
			return left.Close()
		},
	}

	if err := Abort(stream); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	select {
	case <-aborted:
	default:
		t.Fatal("Abort did not invoke the immediate close path")
	}
	select {
	case <-gracefulStarted:
		t.Fatal("Abort invoked the blocking graceful Close path")
	default:
	}
	close(releaseGraceful)
}

type blockingCloseConn struct {
	net.Conn
	gracefulStarted chan struct{}
	release         chan struct{}
}

func (connection *blockingCloseConn) Close() error {
	close(connection.gracefulStarted)
	<-connection.release
	return connection.Conn.Close()
}

func websocketTestURL(serverURL string) string {
	return "wss" + strings.TrimPrefix(serverURL, "https") + "/carrier"
}

func waitTestError(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server")
	}
}
