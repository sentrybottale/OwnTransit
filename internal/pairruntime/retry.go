//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
)

// One backoff per independent operation loop. Jitter is scheduling only, never
// cryptographic randomness. No retry may mutate endpoint trust or replay SSH.
type networkRetry struct{ failures uint }

func (r *networkRetry) reset() { r.failures = 0 }
func (r *networkRetry) delay(err error) time.Duration {
	base := time.Second << min(r.failures, 4)
	if r.failures < 4 {
		r.failures++
	}
	base = max(base, pairrelay.RetryDelay(err))
	return min(base+time.Duration(rand.Int64N(int64(base/4)+1)), 30*time.Second)
}
func (r *networkRetry) wait(ctx context.Context, err error) error {
	return pause(ctx, r.delay(err))
}

// A normal long pending wait is not a rapid failure loop. Do not accumulate
// backoff for a healthy idle rendezvous that simply expired without a client.
func (r *networkRetry) observed(start time.Time, err error) {
	if err == nil || time.Since(start) >= 10*time.Second && !errors.Is(err, pairrelay.ErrRateLimited) {
		r.reset()
	}
}

// Shared by the Target's loops; messages never contain raw peer/state errors.
type retryNotice struct {
	mu   sync.Mutex
	last time.Time
}

func (n *retryNotice) report(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.last.IsZero() && time.Since(n.last) < time.Minute {
		return
	}
	n.last = time.Now()
	if errors.Is(err, pairrelay.ErrRateLimited) {
		log.Print("OwnTransit Target: relay HTTP admission rate limited; backing off automatically. Pairing retained.")
	} else {
		log.Print("OwnTransit Target: relay connection unavailable; retrying automatically. Pairing retained.")
	}
}
