//go:build darwin || linux

// Package activationlock gives the cross-principal publication gate stable
// names without exposing a filesystem descriptor or caller-selected path. The
// shared/exclusive flock is acquired on the exact descriptor opened beneath a
// held securefs root.
package activationlock

import "github.com/sentrybottale/owntransit/internal/securefs"

const (
	FileName = "activation.lock"
	Contents = "owntransit-activation-lock-v1\n"
)

func AcquireShared(root *securefs.ReadOnlyRoot) (*securefs.ViewLock, error) {
	return root.TrySharedLock(FileName, []byte(Contents))
}

func AcquireExclusive(root *securefs.ViewWriter) (*securefs.ViewLock, error) {
	return root.TryExclusiveLock(FileName, []byte(Contents))
}
