package leasewire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"time"
)

const (
	MaxLeaseDuration = 60 * time.Second
	MaxRenewEvery    = 20 * time.Second
	watchInterval    = 25 * time.Millisecond
	policyInterval   = 100 * time.Millisecond
	clockTolerance   = 250 * time.Millisecond
)

// Options never conveys new peer trust. Policy reads current local durable
// state; it must be safe for concurrent callers and return promptly. A local
// lock operation should also call Conn.Lock to avoid waiting for policy polling.
// OnPeerGeneration may persist a high-water mark or reject a rollback. Its error
// closes the carrier and never changes the local lock. Callbacks must not call
// back into the connection.
type Options struct {
	LeaseDuration    time.Duration
	RenewEvery       time.Duration
	Policy           func() (generation uint64, locked bool, err error)
	OnPeerGeneration func(uint64) error
}

type request struct {
	frame
	result chan error
}

// Conn exposes DATA only. Closing or expiry discards buffered DATA. It owns
// transport, but not the connector's subsequently opened SSH socket: callers
// must watch Done and close that socket when authorization ends.
type Conn struct {
	raw                         net.Conn
	options                     Options
	now                         func() time.Time
	outbound, inbound           [32]byte
	localGeneration             uint64
	mu                          sync.Mutex
	err                         error
	lastClock                   time.Time
	lastWall                    int64
	initialDeadline             time.Time
	leaseDeadline               time.Time
	nextRenew                   time.Time
	pending                     bool
	nonce                       [32]byte
	challengeDeadline           time.Time
	challengeIssued             time.Time
	peerGeneration              uint64
	lastPeerNonce               [32]byte
	havePeerNonce               bool
	grantSent                   bool
	readyClosed                 bool
	readDeadline, writeDeadline time.Time
	deadlineChanged             chan struct{}
	done                        chan struct{}
	ready                       chan struct{}
	control                     chan request
	writes                      chan request
	data                        chan []byte
	readMu                      sync.Mutex
	readBuffer                  []byte
}

// Wrap takes ownership of an already authenticated transport on success. The
// caller must first verify TLS 1.3 mTLS, exact peer identity, ALPN, and the fresh
// TLS exporter binding. No pairing code is accepted here. Zero durations select
// a 60-second lease and renewal every 20 seconds; invalid bounds fail closed.
func Wrap(ctx context.Context, transport net.Conn, binding Context, options Options) (*Conn, error) {
	return wrapWithClock(ctx, transport, binding, options, time.Now)
}

func wrapWithClock(ctx context.Context, transport net.Conn, binding Context, options Options, now func() time.Time) (*Conn, error) {
	if ctx == nil || transport == nil || now == nil || options.Policy == nil {
		return nil, ErrPolicy
	}
	if err := binding.validate(); err != nil {
		return nil, err
	}
	if options.LeaseDuration == 0 {
		options.LeaseDuration = MaxLeaseDuration
	}
	if options.RenewEvery == 0 {
		options.RenewEvery = MaxRenewEvery
	}
	if options.LeaseDuration <= 0 || options.LeaseDuration > MaxLeaseDuration ||
		options.RenewEvery <= 0 || options.RenewEvery > MaxRenewEvery || options.RenewEvery >= options.LeaseDuration {
		return nil, ErrPolicy
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	generation, locked, err := options.Policy()
	if err != nil || generation == 0 {
		return nil, ErrPolicy
	}
	if locked {
		return nil, ErrLocked
	}
	start := now()
	c := &Conn{
		raw: transport, options: options, now: now, outbound: contextDigest(binding, true), inbound: contextDigest(binding, false),
		localGeneration: generation, lastClock: start, lastWall: start.UnixNano(), initialDeadline: start.Add(options.LeaseDuration),
		deadlineChanged: make(chan struct{}), done: make(chan struct{}), ready: make(chan struct{}),
		control: make(chan request, 4), writes: make(chan request, 8), data: make(chan []byte, 8),
	}
	if err := c.beginChallenge(); err != nil {
		return nil, err
	}
	go c.writeLoop()
	go c.readLoop()
	go c.watchLoop(ctx)
	go c.policyLoop()
	return c, nil
}

// WaitReady requires both a fresh grant from the peer and successful delivery
// of our grant on the authenticated transport. It rechecks current authority;
// a historical readiness event never permits an expired or closed connection.
func (c *Conn) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return ErrPolicy
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.Err()
	case <-c.ready:
		return c.authorized()
	}
}

// Done closes on every terminal condition. Missing grants and peer lock notices
// terminate this connection only; they never persist a local lock.
func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) stop(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	c.err = err
	close(c.done)
	c.mu.Unlock()
	// Do not let a TLS close_notify drain delay local cancellation.
	_ = c.raw.SetDeadline(time.Now())
	_ = c.raw.Close()
}

func (c *Conn) Close() error { c.stop(net.ErrClosed); return nil }

// Lock stops transport immediately. Durable policy must be changed by the
// caller. Delivery of a remote LOCK notice is deliberately not a prerequisite:
// peer lease expiry remains the cutoff bound under a malicious relay.
func (c *Conn) Lock() error { c.stop(ErrLocked); return nil }

func (c *Conn) checkPolicy() error {
	generation, locked, err := c.options.Policy()
	if locked {
		return ErrLocked
	}
	if err != nil || generation != c.localGeneration {
		return ErrPolicy
	}
	return nil
}

// clockLocked detects wall-clock discontinuities as well as monotonic expiry.
// The wall/elapsed cross-check makes ordinary suspend (where some platforms
// pause monotonic time) fail closed before forwarding resumes. No software
// clock can detect a full-machine rollback that restores all time and state.
func (c *Conn) clockLocked() (time.Time, error) {
	now := c.now()
	elapsed := now.Sub(c.lastClock)
	wall := time.Duration(now.UnixNano() - c.lastWall)
	if elapsed < 0 || wall < 0 || wall-elapsed > clockTolerance || elapsed-wall > clockTolerance {
		return now, ErrClock
	}
	c.lastClock = now
	c.lastWall = now.UnixNano()
	return now, nil
}

func (c *Conn) liveLocked() (time.Time, error) {
	if c.err != nil {
		return time.Time{}, c.err
	}
	now, err := c.clockLocked()
	if err != nil {
		return now, err
	}
	deadline := c.initialDeadline
	if !c.leaseDeadline.IsZero() {
		deadline = c.leaseDeadline
	}
	// Either clock may expire authority; neither can extend the other's
	// budget. This also covers repeated short suspends below the clock-jump
	// tolerance when a platform's monotonic clock pauses during suspend.
	if !now.Before(deadline) || now.UnixNano() >= deadline.UnixNano() {
		return now, ErrExpired
	}
	return now, nil
}

func (c *Conn) authorized() error {
	c.mu.Lock()
	_, err := c.liveLocked()
	if err == nil && (!c.readyClosed || c.leaseDeadline.IsZero()) {
		err = ErrProtocol
	}
	c.mu.Unlock()
	if err != nil {
		c.stop(err)
	}
	return err
}

func (c *Conn) markReadyLocked() {
	if !c.readyClosed && c.grantSent && !c.leaseDeadline.IsZero() {
		c.readyClosed = true
		close(c.ready)
	}
}

func (c *Conn) beginChallenge() error {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	c.mu.Lock()
	now, err := c.liveLocked()
	if err != nil || c.pending {
		c.mu.Unlock()
		return err
	}
	c.pending, c.nonce = true, nonce
	c.challengeIssued = now
	c.challengeDeadline = now.Add(c.options.LeaseDuration)
	c.nextRenew = now.Add(c.options.RenewEvery)
	c.mu.Unlock()
	data := make([]byte, challengeSize)
	copy(data, c.outbound[:])
	binary.BigEndian.PutUint64(data[32:40], c.localGeneration)
	copy(data[40:72], nonce[:])
	binary.BigEndian.PutUint64(data[72:], uint64(c.options.LeaseDuration))
	return c.enqueueControl(request{frame: frame{kind: kindChallenge, data: data}})
}

func (c *Conn) enqueueControl(value request) error {
	select {
	case <-c.done:
		return c.Err()
	case c.control <- value:
		return nil
	default:
		return ErrProtocol
	}
}

func (c *Conn) observePeer(generation uint64) error {
	c.mu.Lock()
	previous := c.peerGeneration
	c.mu.Unlock()
	if generation == 0 || generation < previous {
		return ErrProtocol
	}
	if generation == previous {
		return nil
	}
	if c.options.OnPeerGeneration != nil {
		if err := c.options.OnPeerGeneration(generation); err != nil {
			return ErrProtocol
		}
	}
	c.mu.Lock()
	c.peerGeneration = generation
	c.mu.Unlock()
	return nil
}

func (c *Conn) receiveControl(value frame) error {
	if !bytes.Equal(value.data[:32], c.inbound[:]) {
		return ErrProtocol
	}
	generation := binary.BigEndian.Uint64(value.data[32:40])
	if err := c.observePeer(generation); err != nil {
		return err
	}
	if value.kind == kindLock {
		return ErrPeerLock
	}
	if err := c.checkPolicy(); err != nil {
		return err
	}
	c.mu.Lock()
	now, err := c.liveLocked()
	if err != nil {
		c.mu.Unlock()
		return err
	}
	switch value.kind {
	case kindChallenge:
		var nonce [32]byte
		copy(nonce[:], value.data[40:72])
		requested := binary.BigEndian.Uint64(value.data[72:])
		if requested == 0 || requested > uint64(MaxLeaseDuration) || (c.havePeerNonce && nonce == c.lastPeerNonce) {
			c.mu.Unlock()
			return ErrProtocol
		}
		granted := time.Duration(requested)
		if granted > c.options.LeaseDuration {
			granted = c.options.LeaseDuration
		}
		c.lastPeerNonce, c.havePeerNonce = nonce, true
		c.mu.Unlock()
		data := make([]byte, grantSize)
		copy(data, c.outbound[:])
		binary.BigEndian.PutUint64(data[32:40], c.localGeneration)
		binary.BigEndian.PutUint64(data[40:48], generation)
		copy(data[48:80], nonce[:])
		binary.BigEndian.PutUint64(data[80:], uint64(granted))
		return c.enqueueControl(request{frame: frame{kind: kindGrant, data: data}})
	case kindGrant:
		granted := binary.BigEndian.Uint64(value.data[80:])
		if granted == 0 || granted > uint64(c.options.LeaseDuration) {
			c.mu.Unlock()
			return ErrProtocol
		}
		deadline := c.challengeIssued.Add(time.Duration(granted))
		if !c.pending || binary.BigEndian.Uint64(value.data[40:48]) != c.localGeneration ||
			!bytes.Equal(value.data[48:80], c.nonce[:]) || !now.Before(deadline) || now.UnixNano() >= deadline.UnixNano() {
			c.mu.Unlock()
			return ErrProtocol
		}
		// The deadline was fixed before sending the challenge. Neither arrival
		// time nor DATA activity can extend it.
		c.leaseDeadline = deadline
		// Honor a peer's shorter limit while preserving our configured upper
		// renewal interval. The next request remains anchored to issuance.
		if next := c.challengeIssued.Add(time.Duration(granted) / 3); next.Before(c.nextRenew) {
			c.nextRenew = next
		}
		c.pending = false
		c.markReadyLocked()
		c.mu.Unlock()
		return nil
	default:
		c.mu.Unlock()
		return ErrProtocol
	}
}

func (c *Conn) readLoop() {
	for {
		value, err := readFrame(c.raw)
		if err != nil {
			c.stop(err)
			return
		}
		if value.kind != kindData {
			if err := c.receiveControl(value); err != nil {
				c.stop(err)
				return
			}
			continue
		}
		if err := c.checkPolicy(); err != nil {
			c.stop(err)
			return
		}
		// The peer may consume our GRANT before its writer goroutine has
		// returned from Write and recorded grantSent. Its following DATA is
		// ordered after its GRANT to us; wait for the local writer's completion
		// without admitting any application bytes before mutual readiness.
		c.mu.Lock()
		haveLease := !c.leaseDeadline.IsZero()
		c.mu.Unlock()
		if !haveLease {
			c.stop(ErrProtocol)
			return
		}
		select {
		case <-c.ready:
		case <-c.done:
			return
		}
		if err := c.authorized(); err != nil {
			return
		}
		// Bounded backpressure: an application that stops consuming DATA may
		// also withhold controls behind it, but can never extend the lease.
		select {
		case c.data <- value.data:
		case <-c.done:
			return
		}
	}
}

func (c *Conn) writeLoop() {
	for {
		var value request
		select {
		case <-c.done:
			return
		case value = <-c.control:
		default:
			select {
			case <-c.done:
				return
			case value = <-c.control:
			case value = <-c.writes:
			}
		}
		err := c.checkPolicy()
		if err == nil && value.kind == kindData {
			err = c.authorized()
		}
		if err == nil {
			c.mu.Lock()
			_, err = c.liveLocked()
			deadline := c.initialDeadline
			if !c.leaseDeadline.IsZero() {
				deadline = c.leaseDeadline
			}
			c.mu.Unlock()
			if err == nil {
				err = c.raw.SetWriteDeadline(deadline)
			}
			if err == nil {
				err = writeFrame(c.raw, value.frame)
			}
		}
		if err == nil && value.kind == kindGrant {
			c.mu.Lock()
			c.grantSent = true
			c.markReadyLocked()
			c.mu.Unlock()
		}
		if value.result != nil {
			value.result <- err
		}
		if err != nil {
			c.stop(err)
			return
		}
	}
}

func (c *Conn) watchLoop(ctx context.Context) {
	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.stop(ctx.Err())
			return
		case <-c.done:
			return
		case <-ticker.C:
			c.mu.Lock()
			now, err := c.liveLocked()
			renew := err == nil && !c.pending && !now.Before(c.nextRenew)
			c.mu.Unlock()
			if err == nil && renew {
				err = c.beginChallenge()
			}
			if err != nil {
				c.stop(err)
				return
			}
		}
	}
}

func (c *Conn) policyLoop() {
	ticker := time.NewTicker(policyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.checkPolicy(); err != nil {
				c.stop(err)
				return
			}
		}
	}
}

// Read implements net.Conn without exposing control frames or DATA buffered
// before a later revocation. Read deadlines do not stop authorization controls.
func (c *Conn) Read(buffer []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(buffer) == 0 {
		return 0, nil
	}
	for {
		deadline, changed := c.deadline(false)
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.readBuffer) != 0 {
			if err := c.authorized(); err != nil {
				return 0, err
			}
			n := copy(buffer, c.readBuffer)
			c.readBuffer = c.readBuffer[n:]
			return n, nil
		}
		timer, timeout := deadlineTimer(deadline)
		select {
		case <-c.done:
			stopTimer(timer)
			return 0, c.Err()
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(timer)
		case data := <-c.data:
			stopTimer(timer)
			c.readBuffer = data
		}
	}
}

// Write serializes bounded DATA frames with controls. A write timeout closes
// transport so an abandoned queued frame can never later enter the SSH stream.
func (c *Conn) Write(buffer []byte) (int, error) {
	written := 0
	for len(buffer) != 0 {
		if err := c.waitWritable(); err != nil {
			return written, err
		}
		size := len(buffer)
		if size > maxData {
			size = maxData
		}
		value := request{frame: frame{kind: kindData, data: append([]byte(nil), buffer[:size]...)}, result: make(chan error, 1)}
		if err := c.submitData(value); err != nil {
			return written, err
		}
		written += size
		buffer = buffer[size:]
	}
	return written, nil
}

func (c *Conn) waitWritable() error {
	for {
		deadline, changed := c.deadline(true)
		timer, timeout := deadlineTimer(deadline)
		select {
		case <-c.done:
			stopTimer(timer)
			return c.Err()
		case <-c.ready:
			stopTimer(timer)
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return os.ErrDeadlineExceeded
			}
			return c.authorized()
		case <-changed:
			stopTimer(timer)
		case <-timeout:
			return os.ErrDeadlineExceeded
		}
	}
}

func (c *Conn) submitData(value request) error {
	queued := false
	for {
		deadline, changed := c.deadline(true)
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			c.stop(os.ErrDeadlineExceeded)
			return os.ErrDeadlineExceeded
		}
		timer, timeout := deadlineTimer(deadline)
		var queue chan request
		if !queued {
			queue = c.writes
		}
		select {
		case <-c.done:
			stopTimer(timer)
			return c.Err()
		case queue <- value:
			stopTimer(timer)
			queued = true
		case err := <-value.result:
			stopTimer(timer)
			return err
		case <-changed:
			stopTimer(timer)
		case <-timeout:
			c.stop(os.ErrDeadlineExceeded)
			return os.ErrDeadlineExceeded
		}
	}
}

func (c *Conn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

func (c *Conn) SetDeadline(deadline time.Time) error     { return c.setDeadline(deadline, true, true) }
func (c *Conn) SetReadDeadline(deadline time.Time) error { return c.setDeadline(deadline, true, false) }
func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	return c.setDeadline(deadline, false, true)
}

func (c *Conn) setDeadline(deadline time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if read {
		c.readDeadline = deadline
	}
	if write {
		c.writeDeadline = deadline
	}
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	return nil
}

func (c *Conn) deadline(write bool) (time.Time, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if write {
		return c.writeDeadline, c.deadlineChanged
	}
	return c.readDeadline, c.deadlineChanged
}

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer, timer.C
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

var _ net.Conn = (*Conn)(nil)
