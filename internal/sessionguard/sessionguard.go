// Package sessionguard applies finite idle and absolute-lifetime deadlines to
// an authenticated bidirectional byte stream.
package sessionguard

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var ErrLifetime = errors.New("authenticated session lifetime expired")

// Guard owns the shared deadline state for both halves of one stream. Any
// authenticated payload read in either direction refreshes the idle deadline,
// but never beyond the immutable absolute expiry.
type Guard struct {
	mu      sync.Mutex
	left    net.Conn
	right   net.Conn
	idle    time.Duration
	expires time.Time
	now     func() time.Time
}

func New(left, right net.Conn, idle, lifetime time.Duration) (*Guard, error) {
	return newWithClock(left, right, idle, lifetime, time.Now)
}

func newWithClock(left, right net.Conn, idle, lifetime time.Duration, now func() time.Time) (*Guard, error) {
	if left == nil || right == nil || now == nil {
		return nil, errors.New("session guard requires two connections and a clock")
	}
	if idle <= 0 || lifetime <= 0 || idle > lifetime {
		return nil, errors.New("session guard requires 0 < idle <= lifetime")
	}
	return &Guard{left: left, right: right, idle: idle, expires: now().Add(lifetime), now: now}, nil
}

// Arm installs the initial idle/absolute deadline before copy goroutines start.
func (guard *Guard) Arm() error {
	return guard.touch()
}

// Reader returns a reader that refreshes the shared idle deadline whenever it
// observes authenticated stream bytes.
func (guard *Guard) Reader(source io.Reader) io.Reader {
	return activityReader{source: source, guard: guard}
}

func (guard *Guard) touch() error {
	guard.mu.Lock()
	defer guard.mu.Unlock()

	now := guard.now()
	if !now.Before(guard.expires) {
		return ErrLifetime
	}
	deadline := now.Add(guard.idle)
	if deadline.After(guard.expires) {
		deadline = guard.expires
	}
	if err := guard.left.SetDeadline(deadline); err != nil {
		return err
	}
	return guard.right.SetDeadline(deadline)
}

type activityReader struct {
	source io.Reader
	guard  *Guard
}

func (reader activityReader) Read(buffer []byte) (int, error) {
	count, err := reader.source.Read(buffer)
	if count > 0 {
		if guardErr := reader.guard.touch(); guardErr != nil {
			return count, guardErr
		}
	}
	return count, err
}
