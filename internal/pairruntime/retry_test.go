//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
)

func TestRetryBackoffBoundsResetAndCancellation(t *testing.T) {
	var retry networkRetry
	for n := 0; n < 100; n++ {
		d := retry.delay(pairrelay.ErrTransport)
		base := time.Second << min(n, 4)
		if d < base || d > min(base+base/4, 30*time.Second) {
			t.Fatalf("unbounded/too fast retry %d: %v", n, d)
		}
	}
	retry.reset()
	if d := retry.delay(pairrelay.ErrTransport); d < time.Second || d > 1250*time.Millisecond {
		t.Fatal("no recovery reset")
	}
	retry.reset()
	if d := retry.delay(pairrelay.ErrRateLimited); d < 5*time.Second || d > 30*time.Second {
		t.Fatal("429 did not slow retry")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := retry.wait(ctx, pairrelay.ErrTransport); !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatal("retry blocked cancellation")
	}
}
