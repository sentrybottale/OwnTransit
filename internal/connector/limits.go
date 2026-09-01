package connector

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

const (
	openRate  = time.Second
	openBurst = 4.0
)

type openLimiter struct {
	mu     sync.Mutex
	now    func() time.Time
	last   time.Time
	tokens float64
}

func newOpenLimiter(now func() time.Time) *openLimiter {
	return &openLimiter{now: now, last: now(), tokens: openBurst}
}

// Allow implements a process-global one-token-per-second bucket with a burst
// of four. It intentionally survives control reconnects.
func (limiter *openLimiter) Allow() bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	if now.After(limiter.last) {
		limiter.tokens += float64(now.Sub(limiter.last)) / float64(openRate)
		if limiter.tokens > openBurst {
			limiter.tokens = openBurst
		}
		limiter.last = now
	}
	if limiter.tokens < 1 {
		return false
	}
	limiter.tokens--
	return true
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func jitterDuration(value time.Duration) time.Duration {
	if value <= 1 {
		return value
	}
	span := value / 2
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return value
	}
	offset := time.Duration(binary.BigEndian.Uint64(random[:]) % uint64(span+1))
	const maximumDuration = time.Duration(1<<63 - 1)
	if value > maximumDuration-offset {
		return value
	}
	return value + offset
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
