package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

type probeCloser func() error

func (close probeCloser) Close() error { return close() }

func TestFinishProbeAcceptsOnlyExpectedPostReadyClosure(t *testing.T) {
	sentinel := errors.New("unexpected close failure")
	tests := []struct {
		name    string
		close   error
		wantErr error
	}{
		{name: "clean"},
		{name: "wrapped EOF", close: fmt.Errorf("WebSocket peer aborted after READY: %w", io.EOF)},
		{name: "wrapped closed network", close: fmt.Errorf("carrier closed after READY: %w", net.ErrClosed)},
		{name: "unexpected EOF", close: io.ErrUnexpectedEOF, wantErr: io.ErrUnexpectedEOF},
		{name: "other failure", close: sentinel, wantErr: sentinel},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := finishProbe(probeCloser(func() error { return test.close }))
			if test.wantErr == nil && err != nil {
				t.Fatalf("finishProbe returned %v", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("finishProbe returned %v, want %v", err, test.wantErr)
			}
		})
	}
}
