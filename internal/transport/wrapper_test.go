package transport

import (
	"bytes"
	"context"
	"errors"
	"github.com/coder/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBoundedWrapperRejectsOversizedMessagesBothDirections(t *testing.T) {
	for _, clientReceives := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			t.Run(map[bool]string{false: "server", true: "client"}[clientReceives]+map[bool]string{false: "-whole", true: "-fragmented"}[fragmented], func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				outcome := make(chan error, 1)
				send := func(ws *websocket.Conn) {
					if fragmented {
						w, err := ws.Writer(ctx, websocket.MessageBinary)
						if err == nil {
							_, _ = w.Write(bytes.Repeat([]byte("a"), 800))
							_, _ = w.Write(bytes.Repeat([]byte("b"), 800))
							_ = w.Close()
						}
					} else {
						_ = ws.Write(ctx, websocket.MessageBinary, bytes.Repeat([]byte("x"), 1600))
					}
				}
				receive := func(ws *websocket.Conn) error {
					stream, err := WrapWebSocket(ctx, ws, 1024)
					if err != nil {
						return err
					}
					defer Abort(stream)
					_, err = io.ReadAll(stream)
					return err
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ws, err := websocket.Accept(w, r, nil)
					if err != nil {
						outcome <- err
						return
					}
					defer ws.CloseNow()
					if clientReceives {
						send(ws)
						_, _, _ = ws.Read(ctx)
					} else {
						outcome <- receive(ws)
					}
				}))
				defer srv.Close()
				ws, _, err := websocket.Dial(ctx, srv.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer ws.CloseNow()
				if clientReceives {
					err = receive(ws)
				} else {
					send(ws)
					select {
					case err = <-outcome:
					case <-ctx.Done():
						t.Fatal("oversized receiver did not close")
					}
				}
				if !errors.Is(err, websocket.ErrMessageTooBig) {
					t.Fatalf("read limit was not enforced: %v", err)
				}
			})
		}
	}
}

func TestBoundedWrapperChunksLargeValidStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("ssh-stream"), 16384)
	done := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			done <- err
			return
		}
		stream, err := WrapWebSocket(ctx, ws, 1024)
		if err != nil {
			done <- err
			return
		}
		defer Abort(stream)
		received := make([]byte, len(payload))
		_, err = io.ReadFull(stream, received)
		if err == nil && !bytes.Equal(payload, received) {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}))
	defer srv.Close()
	ws, _, err := websocket.Dial(ctx, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := WrapWebSocket(ctx, ws, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer Abort(stream)
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
