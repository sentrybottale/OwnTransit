package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestRunFinalSelectionFailurePreventsFirstCarrierDial(t *testing.T) {
	fixture := newConnectorFixture(t)
	sentinel := errors.New("active generation changed")
	dialer := &countingConnectorCarrierDialer{}
	fixture.service.preflight = func() error { return sentinel }
	fixture.service.carrier = dialer
	if err := fixture.service.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("Run preflight result = %v, want %v", err, sentinel)
	}
	if dialer.calls != 0 {
		t.Fatalf("carrier dialed %d times before failed final check", dialer.calls)
	}
}

type countingConnectorCarrierDialer struct{ calls int }

func (dialer *countingConnectorCarrierDialer) Dial(context.Context) (net.Conn, error) {
	dialer.calls++
	return nil, net.ErrClosed
}

func TestControlRegistersAuthenticallyAndMaintainsHeartbeat(t *testing.T) {
	fixture := newConnectorFixture(t)
	states := make(chan State, 1)
	fixture.service.state = func(state State) { states <- state }
	connectorSide, relaySide := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	_ = connectorSide.SetDeadline(deadline)
	_ = relaySide.SetDeadline(deadline)
	fixture.service.carrier = &singleCarrierDialer{conn: connectorSide}
	fixture.service.heartbeatInterval = 10 * time.Millisecond
	fixture.service.heartbeatTimeout = 200 * time.Millisecond
	epoch, err := protocol.NewEpochID()
	if err != nil {
		t.Fatal(err)
	}

	relayResult := make(chan error, 1)
	go func() {
		defer relaySide.Close()
		outer := tls.Server(relaySide, fixture.relayServerTLS)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := outer.HandshakeContext(ctx); err != nil {
			relayResult <- err
			return
		}
		frame, err := protocol.ReadFrame(outer)
		if err != nil {
			relayResult <- err
			return
		}
		registration, ok := frame.(protocol.ControlRegister)
		if !ok || registration.Route != fixture.service.route || registration.BootNonce == (protocol.BootNonce{}) {
			relayResult <- errors.New("invalid control registration")
			return
		}
		if err := protocol.WriteFrame(outer, protocol.Registered{Epoch: epoch}); err != nil {
			relayResult <- err
			return
		}
		frame, err = protocol.ReadFrame(outer)
		if err != nil {
			relayResult <- err
			return
		}
		if _, ok := frame.(protocol.Ping); !ok {
			relayResult <- errors.New("expected connector PING")
			return
		}
		if err := protocol.WriteFrame(outer, protocol.Pong{}); err != nil {
			relayResult <- err
			return
		}
		relayResult <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := fixture.service.runControl(ctx); err == nil {
		t.Fatal("runControl unexpectedly survived relay close")
	}
	if err := <-relayResult; err != nil {
		t.Fatalf("fake relay: %v", err)
	}
	select {
	case state := <-states:
		if state != StateRegistered {
			t.Fatalf("state = %q, want %q", state, StateRegistered)
		}
	default:
		t.Fatal("connector did not report authenticated registration")
	}
	if calls := fixture.local.calls.Load(); calls != 0 {
		t.Fatalf("local dial count = %d, want 0", calls)
	}
}

func TestFailedDataConnectionIsCanceledAndReleasesPendingSlot(t *testing.T) {
	fixture := newConnectorFixture(t)
	connectorSide, relaySide := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	_ = connectorSide.SetDeadline(deadline)
	_ = relaySide.SetDeadline(deadline)
	fixture.service.carrier = &singleCarrierDialer{
		conn: connectorSide,
		err:  errors.New("data carrier refused"),
	}
	fixture.service.heartbeatInterval = time.Hour
	fixture.service.heartbeatTimeout = 2 * time.Second
	epoch, err := protocol.NewEpochID()
	if err != nil {
		t.Fatal(err)
	}
	session, err := protocol.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}

	relayResult := make(chan error, 1)
	go func() {
		defer relaySide.Close()
		outer := tls.Server(relaySide, fixture.relayServerTLS)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := outer.HandshakeContext(ctx); err != nil {
			relayResult <- err
			return
		}
		if _, err := protocol.ReadFrame(outer); err != nil {
			relayResult <- err
			return
		}
		if err := protocol.WriteFrame(outer, protocol.Registered{Epoch: epoch}); err != nil {
			relayResult <- err
			return
		}
		if err := protocol.WriteFrame(outer, protocol.Open{Epoch: epoch, Session: session}); err != nil {
			relayResult <- err
			return
		}
		frame, err := protocol.ReadFrame(outer)
		if err != nil {
			relayResult <- err
			return
		}
		cancelFrame, ok := frame.(protocol.Cancel)
		if !ok || cancelFrame.Epoch != epoch || cancelFrame.Session != session {
			relayResult <- errors.New("invalid session cancellation")
			return
		}
		relayResult <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := fixture.service.runControl(ctx); err == nil {
		t.Fatal("runControl unexpectedly survived relay close")
	}
	fixture.service.workers.Wait()
	if err := <-relayResult; err != nil {
		t.Fatalf("fake relay: %v", err)
	}
	if got := len(fixture.service.pending); got != 0 {
		t.Fatalf("pending slots still held = %d", got)
	}
	fixture.service.sessionsMu.Lock()
	remaining := len(fixture.service.sessions)
	fixture.service.sessionsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("session entries still held = %d", remaining)
	}
	if calls := fixture.local.calls.Load(); calls != 0 {
		t.Fatalf("local dial count = %d, want 0", calls)
	}
}

func TestBurstLimitCancelsOnlyTheRejectedSession(t *testing.T) {
	fixture := newConnectorFixture(t)
	for index := 0; index < int(openBurst); index++ {
		if !fixture.service.limiter.Allow() {
			t.Fatalf("failed to consume initial limiter token %d", index)
		}
	}
	connectorSide, relaySide := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	_ = connectorSide.SetDeadline(deadline)
	_ = relaySide.SetDeadline(deadline)
	fixture.service.carrier = &singleCarrierDialer{conn: connectorSide}
	fixture.service.heartbeatInterval = time.Hour
	fixture.service.heartbeatTimeout = 2 * time.Second
	epoch, err := protocol.NewEpochID()
	if err != nil {
		t.Fatal(err)
	}
	session, err := protocol.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}

	relayResult := make(chan error, 1)
	go func() {
		defer relaySide.Close()
		outer := tls.Server(relaySide, fixture.relayServerTLS)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := outer.HandshakeContext(ctx); err != nil {
			relayResult <- err
			return
		}
		if _, err := protocol.ReadFrame(outer); err != nil {
			relayResult <- err
			return
		}
		if err := protocol.WriteFrame(outer, protocol.Registered{Epoch: epoch}); err != nil {
			relayResult <- err
			return
		}
		if err := protocol.WriteFrame(outer, protocol.Open{Epoch: epoch, Session: session}); err != nil {
			relayResult <- err
			return
		}
		frame, err := protocol.ReadFrame(outer)
		if err != nil {
			relayResult <- err
			return
		}
		canceled, ok := frame.(protocol.Cancel)
		if !ok || canceled.Epoch != epoch || canceled.Session != session {
			relayResult <- errors.New("burst rejection did not return the exact cancellation")
			return
		}
		if err := protocol.WriteFrame(outer, protocol.Ping{}); err != nil {
			relayResult <- err
			return
		}
		frame, err = protocol.ReadFrame(outer)
		if err != nil {
			relayResult <- err
			return
		}
		if _, ok := frame.(protocol.Pong); !ok {
			relayResult <- errors.New("control channel did not survive burst rejection")
			return
		}
		relayResult <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := fixture.service.runControl(ctx); err == nil {
		t.Fatal("runControl unexpectedly survived relay close")
	}
	if err := <-relayResult; err != nil {
		t.Fatalf("fake relay: %v", err)
	}
	if calls := fixture.local.calls.Load(); calls != 0 {
		t.Fatalf("local dial count = %d, want 0", calls)
	}
}
