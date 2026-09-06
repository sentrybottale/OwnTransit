//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"time"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

// Concurrent SSH startups serialize only their local credential/token update.
// OpenClient's existing opening deadline and policy watcher bound this wait.
// Ownership/permission errors are never retried and an alarm still cancels it.
func clientOperationLock(ctx context.Context, root *securefs.Root) (*securefs.Lock, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lock, err := root.TryLock("client-operation.lock")
		if !errors.Is(err, securefs.ErrLocked) {
			return lock, err
		}
		if err := pause(ctx, 25*time.Millisecond); err != nil {
			return nil, err
		}
	}
}
