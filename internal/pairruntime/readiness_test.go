//go:build darwin || linux

package pairruntime

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func TestReceiverReadinessNeedsAdvertisementOnlyBeforeRegistration(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "retained"}[registered], func(t *testing.T) {
			f := newIntegrated(t)
			backend := ReceiverBackend{Path: f.serverPath}
			if registered {
				if err := backend.SaveToken(f.registration.Token); err != nil {
					t.Fatal(err)
				}
				// A spent/expired initial advertisement must not prevent reconnection.
				root, err := securefs.OpenRoot(f.serverPath)
				if err != nil {
					t.Fatal(err)
				}
				var meta ReceiverMeta
				if err := readRecord(root, "receiver.json", &meta); err != nil {
					t.Fatal(err)
				}
				meta.Advertisement = nil
				if err := writeRecord(root, "receiver.json", meta, false); err != nil {
					t.Fatal(err)
				}
				root.Close()
			}
			ready := make(chan struct{}, 1)
			backend.OnReady = func() error { ready <- struct{}{}; return nil }
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			go func() { defer a.Close(); _ = ServeAgent(a, a, backend) }()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			_ = ServeReceiver(ctx, &AgentClient{Input: b, Output: b}, func(context.Context, string) (net.Conn, error) { return nil, pairrelay.ErrUnavailable })
			select {
			case <-ready:
				if !registered {
					t.Fatal("reported ready before advertisement delivery")
				}
			default:
				if registered {
					t.Fatal("retained registration incorrectly required old advertisement")
				}
			}
		})
	}
}

func TestReadyRPCRejectsBeforeSnapshotAndRepeatedNotification(t *testing.T) {
	for _, initialSnapshot := range []bool{false, true} {
		f := newIntegrated(t)
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() { defer a.Close(); done <- ServeAgent(a, a, ReceiverBackend{Path: f.serverPath}) }()
		agent := &AgentClient{Input: b, Output: b}
		if initialSnapshot {
			if _, err := agent.Snapshot(); err != nil {
				t.Fatal(err)
			}
			if err := agent.Ready(); err != nil {
				t.Fatal(err)
			}
		}
		if err := agent.Ready(); err == nil {
			t.Fatal("out-of-order or repeated readiness accepted")
		}
		b.Close()
		if err := <-done; err == nil {
			t.Fatal("invalid readiness did not terminate IPC")
		}
	}
}
