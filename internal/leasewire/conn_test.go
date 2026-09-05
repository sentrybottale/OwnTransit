package leasewire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testContexts(t *testing.T) (Context, Context) {
	t.Helper()
	binding := make([]byte, 32)
	if _, err := rand.Read(binding); err != nil {
		t.Fatal(err)
	}
	return Context{"pair-1", "client-1", "connector-1", binding}, Context{"pair-1", "connector-1", "client-1", binding}
}

func testOptions() Options {
	return Options{LeaseDuration: 2 * time.Second, RenewEvery: 100 * time.Millisecond,
		Policy: func() (uint64, bool, error) { return 1, false, nil }}
}

func waitReady(t *testing.T, c *Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitClosed(t *testing.T, c *Conn, want error) {
	t.Helper()
	select {
	case <-c.Done():
		if want != nil && !errors.Is(c.Err(), want) {
			t.Fatalf("closed with %v, want %v", c.Err(), want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not close")
	}
}

func paired(t *testing.T, leftOptions, rightOptions Options) (*Conn, *Conn) {
	t.Helper()
	leftContext, rightContext := testContexts(t)
	leftRaw, rightRaw := net.Pipe()
	left, err := Wrap(context.Background(), leftRaw, leftContext, leftOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close() })
	right, err := Wrap(context.Background(), rightRaw, rightContext, rightOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = right.Close() })
	waitReady(t, left)
	waitReady(t, right)
	return left, right
}

func TestConcurrentDataAndRenewalsExposeOnlyData(t *testing.T) {
	left, right := paired(t, testOptions(), testOptions())
	const writers, repeats, blockSize = 8, 40, 1024
	var group sync.WaitGroup
	errorsFound := make(chan error, writers*2+2)
	for _, receiver := range []*Conn{left, right} {
		group.Add(1)
		go func() {
			defer group.Done()
			buffer := make([]byte, writers*repeats*blockSize)
			if _, err := io.ReadFull(receiver, buffer); err != nil {
				errorsFound <- err
				return
			}
			counts := make(map[byte]int)
			for _, value := range buffer {
				counts[value]++
			}
			for value := byte('a'); value < 'a'+writers; value++ {
				if counts[value] != repeats*blockSize {
					errorsFound <- ErrProtocol
					return
				}
			}
		}()
	}
	for _, sender := range []*Conn{left, right} {
		for i := 0; i < writers; i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				buffer := bytes.Repeat([]byte{byte('a' + i)}, blockSize)
				for n := 0; n < repeats; n++ {
					if _, err := sender.Write(buffer); err != nil {
						errorsFound <- err
						return
					}
				}
			}()
		}
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	// Remain connected through multiple automatic renewals with no DATA.
	select {
	case <-left.Done():
		t.Fatal(left.Err())
	case <-time.After(350 * time.Millisecond):
	}
	waitReady(t, left)
	waitReady(t, right)
}

func manual(t *testing.T, options Options) (*Conn, net.Conn, Context, frame) {
	t.Helper()
	localContext, peerContext := testContexts(t)
	raw, peer := net.Pipe()
	c, err := Wrap(context.Background(), raw, localContext, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	challenge, err := readFrame(peer)
	if err != nil || challenge.kind != kindChallenge {
		t.Fatalf("initial challenge: %+v %v", challenge, err)
	}
	return c, peer, peerContext, challenge
}

func makeGrant(peer Context, generation uint64, challenge frame) frame {
	data := make([]byte, grantSize)
	digest := contextDigest(peer, true)
	copy(data, digest[:])
	binary.BigEndian.PutUint64(data[32:40], generation)
	copy(data[40:48], challenge.data[32:40])
	copy(data[48:80], challenge.data[40:72])
	copy(data[80:], challenge.data[72:])
	return frame{kind: kindGrant, data: data}
}

func makeChallenge(t *testing.T, peer Context, generation uint64) frame {
	t.Helper()
	data := make([]byte, challengeSize)
	digest := contextDigest(peer, true)
	copy(data, digest[:])
	binary.BigEndian.PutUint64(data[32:40], generation)
	if _, err := rand.Read(data[40:72]); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(data[72:], uint64(MaxLeaseDuration))
	return frame{kind: kindChallenge, data: data}
}

func completeManual(t *testing.T, c *Conn, peer net.Conn, binding Context, challenge frame) {
	t.Helper()
	if err := writeFrame(peer, makeGrant(binding, 1, challenge)); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(peer, makeChallenge(t, binding, 1)); err != nil {
		t.Fatal(err)
	}
	grant, err := readFrame(peer)
	if err != nil || grant.kind != kindGrant {
		t.Fatalf("grant: %+v %v", grant, err)
	}
	waitReady(t, c)
}

func TestRejectWrongBindingsNonceAndGeneration(t *testing.T) {
	for _, name := range []string{"nonce", "session", "peer", "pair", "request-generation", "issuer-generation", "persisted-floor", "long-lease", "zero-lease"} {
		t.Run(name, func(t *testing.T) {
			options := testOptions()
			if name == "persisted-floor" {
				options.OnPeerGeneration = func(generation uint64) error {
					if generation < 2 {
						return ErrPolicy
					}
					return nil
				}
			}
			c, peer, binding, challenge := manual(t, options)
			switch name {
			case "session":
				binding.SessionBinding = bytes.Repeat([]byte{7}, 32)
			case "peer":
				binding.LocalID = "wrong-peer"
			case "pair":
				binding.PairID = "wrong-pair"
			}
			grant := makeGrant(binding, 1, challenge)
			switch name {
			case "nonce":
				grant.data[48] ^= 1
			case "request-generation":
				binary.BigEndian.PutUint64(grant.data[40:48], 2)
			case "issuer-generation":
				binary.BigEndian.PutUint64(grant.data[32:40], 0)
			case "long-lease":
				binary.BigEndian.PutUint64(grant.data[80:], uint64(options.LeaseDuration+time.Nanosecond))
			case "zero-lease":
				binary.BigEndian.PutUint64(grant.data[80:], 0)
			}
			_ = writeFrame(peer, grant)
			waitClosed(t, c, ErrProtocol)
			if c.WaitReady(context.Background()) == nil {
				t.Fatal("bad grant became ready")
			}
		})
	}
}

func TestDifferentLeasePoliciesUseTheShorterDuration(t *testing.T) {
	long, short := testOptions(), testOptions()
	long.LeaseDuration, long.RenewEvery = 2*time.Second, time.Second
	short.LeaseDuration, short.RenewEvery = 200*time.Millisecond, 50*time.Millisecond
	left, right := paired(t, long, short)
	left.mu.Lock()
	actual := left.leaseDeadline.Sub(left.challengeIssued)
	left.mu.Unlock()
	if actual != short.LeaseDuration {
		t.Fatalf("peer shorter lease ignored: %v", actual)
	}
	select {
	case <-left.Done():
		t.Fatal(left.Err())
	case <-time.After(350 * time.Millisecond):
	}
	waitReady(t, right)
	waitReady(t, left)
}

func TestRejectDataBeforeMutualGrants(t *testing.T) {
	c, peer, _, _ := manual(t, testOptions())
	_ = writeFrame(peer, frame{kind: kindData, data: []byte("never SSH")})
	waitClosed(t, c, ErrProtocol)
	buffer := make([]byte, 16)
	if n, err := c.Read(buffer); n != 0 || err == nil {
		t.Fatalf("early DATA leaked: %d %v", n, err)
	}
}

func TestWaitReadyRequiresBothDirections(t *testing.T) {
	c, peer, binding, challenge := manual(t, testOptions())
	if err := writeFrame(peer, makeGrant(binding, 1, challenge)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := c.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("one-way ready: %v", err)
	}
	if err := writeFrame(peer, makeChallenge(t, binding, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(peer); err != nil {
		t.Fatal(err)
	}
	waitReady(t, c)
}

func TestGrantReplayAndPeerGenerationRollback(t *testing.T) {
	for _, name := range []string{"replay", "generation"} {
		t.Run(name, func(t *testing.T) {
			c, peer, binding, challenge := manual(t, testOptions())
			completeManual(t, c, peer, binding, challenge)
			if name == "replay" {
				_ = writeFrame(peer, makeGrant(binding, 1, challenge))
			} else {
				if err := writeFrame(peer, makeChallenge(t, binding, 2)); err != nil {
					t.Fatal(err)
				}
				if _, err := readFrame(peer); err != nil {
					t.Fatal(err)
				}
				_ = writeFrame(peer, makeChallenge(t, binding, 1))
			}
			waitClosed(t, c, ErrProtocol)
		})
	}
}

func TestWithheldRenewalsExpireDespiteFlowingData(t *testing.T) {
	options := testOptions()
	options.LeaseDuration, options.RenewEvery = 250*time.Millisecond, 60*time.Millisecond
	c, peer, binding, challenge := manual(t, options)
	completeManual(t, c, peer, binding, challenge)
	go func() {
		for {
			if _, err := readFrame(peer); err != nil {
				return
			}
		}
	}() // Withhold GRANT responses.
	go func() {
		for {
			if err := writeFrame(peer, frame{kind: kindData, data: []byte("ssh-data")}); err != nil {
				return
			}
		}
	}()
	var received atomic.Int64
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		buffer := make([]byte, 64)
		for {
			n, err := c.Read(buffer)
			received.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	waitClosed(t, c, ErrExpired)
	<-finished
	if received.Load() == 0 {
		t.Fatal("test did not flow DATA")
	}
	if c.WaitReady(context.Background()) == nil {
		t.Fatal("expired connection reused historical readiness")
	}
}

func TestDelayedGrantRetainsIssuanceDeadline(t *testing.T) {
	options := testOptions()
	options.LeaseDuration, options.RenewEvery = 400*time.Millisecond, 100*time.Millisecond
	c, peer, binding, challenge := manual(t, options)
	c.mu.Lock()
	original := c.challengeDeadline
	c.mu.Unlock()
	timer := time.NewTimer(75 * time.Millisecond)
	<-timer.C
	completeManual(t, c, peer, binding, challenge)
	c.mu.Lock()
	actual := c.leaseDeadline
	c.mu.Unlock()
	if !actual.Equal(original) {
		t.Fatal("grant arrival extended deadline")
	}
}

func TestLocalPolicyLockAndGenerationChangeCloseActiveConnections(t *testing.T) {
	for _, name := range []string{"lock", "generation", "error", "direct"} {
		t.Run(name, func(t *testing.T) {
			var changed atomic.Bool
			options := testOptions()
			options.Policy = func() (uint64, bool, error) {
				if !changed.Load() {
					return 1, false, nil
				}
				switch name {
				case "lock":
					return 2, true, nil
				case "generation":
					return 2, false, nil
				default:
					return 1, false, io.ErrUnexpectedEOF
				}
			}
			left, right := paired(t, options, testOptions())
			want := ErrPolicy
			if name == "direct" {
				_ = left.Lock()
				want = ErrLocked
			} else {
				changed.Store(true)
				if name == "lock" {
					want = ErrLocked
				}
			}
			waitClosed(t, left, want)
			waitClosed(t, right, nil)
			if n, err := left.Write([]byte("forbidden")); n != 0 || err == nil {
				t.Fatalf("write after lock: %d %v", n, err)
			}
		})
	}
}

func TestAuthenticatedPeerLockIsTransient(t *testing.T) {
	var calls atomic.Int64
	options := testOptions()
	options.Policy = func() (uint64, bool, error) { calls.Add(1); return 1, false, nil }
	c, peer, binding, challenge := manual(t, options)
	completeManual(t, c, peer, binding, challenge)
	lock := make([]byte, lockSize)
	digest := contextDigest(binding, true)
	copy(lock, digest[:])
	binary.BigEndian.PutUint64(lock[32:], 2)
	_ = writeFrame(peer, frame{kind: kindLock, data: lock})
	waitClosed(t, c, ErrPeerLock)
	_, locked, err := options.Policy()
	if locked || err != nil || calls.Load() < 2 {
		t.Fatal("peer notice changed local policy")
	}
}

func TestReadDeadlineDoesNotStopLeaseRenewal(t *testing.T) {
	options := testOptions()
	options.LeaseDuration, options.RenewEvery = 200*time.Millisecond, 50*time.Millisecond
	left, right := paired(t, options, options)
	if err := left.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := left.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	timer := time.NewTimer(300 * time.Millisecond)
	<-timer.C
	if err := left.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := right.Write([]byte("x")); result <- err }()
	buffer := make([]byte, 1)
	if _, err := io.ReadFull(left, buffer); err != nil || buffer[0] != 'x' {
		t.Fatalf("post-deadline data: %v %v", buffer, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestWriteTimeoutCannotReleaseQueuedDataLater(t *testing.T) {
	c, peer, binding, challenge := manual(t, testOptions())
	completeManual(t, c, peer, binding, challenge)
	if err := c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// The peer stops reading, so this frame cannot complete.
	if _, err := c.Write([]byte("must not appear later")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write timeout: %v", err)
	}
	waitClosed(t, c, os.ErrDeadlineExceeded)
	if _, err := readFrame(peer); err == nil {
		t.Fatal("timed-out DATA was delivered later")
	}
}

func TestBlockedPolicyCannotPreventExpiry(t *testing.T) {
	var blocked atomic.Bool
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	options := testOptions()
	options.LeaseDuration, options.RenewEvery = 250*time.Millisecond, 60*time.Millisecond
	options.Policy = func() (uint64, bool, error) {
		if blocked.Load() {
			<-release
		}
		return 1, false, nil
	}
	c, peer, binding, challenge := manual(t, options)
	completeManual(t, c, peer, binding, challenge)
	blocked.Store(true)
	waitClosed(t, c, ErrExpired)
}

func TestClockDiscontinuitiesAndDeadlineBoundary(t *testing.T) {
	start := time.Now()
	for _, name := range []string{"backwards", "suspend", "forward", "expiry", "valid"} {
		t.Run(name, func(t *testing.T) {
			now := start.Add(10 * time.Millisecond)
			c := &Conn{now: func() time.Time { return now }, lastClock: start, lastWall: start.UnixNano(), initialDeadline: start.Add(time.Second)}
			want := error(nil)
			switch name {
			case "backwards":
				now = start.Add(-time.Millisecond)
				want = ErrClock
			case "suspend":
				c.lastWall -= int64(time.Second)
				want = ErrClock
			case "forward":
				now = start.Add(2 * time.Second)
				want = ErrExpired
			case "expiry":
				now = start.Add(time.Second)
				want = ErrExpired
			}
			_, err := c.liveLocked()
			if !errors.Is(err, want) {
				t.Fatalf("clock: %v, want %v", err, want)
			}
		})
	}
}

func TestCloseCancellationAndConcurrentDeadlines(t *testing.T) {
	left, right := paired(t, testOptions(), testOptions())
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for n := 0; n < 100; n++ {
				_ = left.SetDeadline(time.Time{})
				_ = left.SetReadDeadline(time.Now().Add(time.Second))
			}
		}()
	}
	readDone := make(chan error, 1)
	go func() { _, err := left.Read(make([]byte, 1)); readDone <- err }()
	_ = left.Close()
	_ = left.Close()
	group.Wait()
	if err := <-readDone; err == nil {
		t.Fatal("closed read succeeded")
	}
	waitClosed(t, right, nil)
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	defer b.Close()
	binding, _ := testContexts(t)
	c, err := Wrap(ctx, a, binding, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	waitClosed(t, c, context.Canceled)
}

func TestWrapRejectsInvalidInputs(t *testing.T) {
	binding, _ := testContexts(t)
	for _, name := range []string{"lease", "renew", "equal", "policy", "id", "binding", "locked", "zero-generation"} {
		t.Run(name, func(t *testing.T) {
			value, options := binding, testOptions()
			switch name {
			case "lease":
				options.LeaseDuration = MaxLeaseDuration + time.Nanosecond
			case "renew":
				options.RenewEvery = MaxRenewEvery + time.Nanosecond
			case "equal":
				options.RenewEvery = options.LeaseDuration
			case "policy":
				options.Policy = nil
			case "id":
				value.LocalID = "Bad ID"
			case "binding":
				value.SessionBinding = nil
			case "locked":
				options.Policy = func() (uint64, bool, error) { return 1, true, nil }
			case "zero-generation":
				options.Policy = func() (uint64, bool, error) { return 0, false, nil }
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			if c, err := Wrap(context.Background(), a, value, options); err == nil {
				_ = c.Close()
				t.Fatal("invalid options accepted")
			}
		})
	}
}
