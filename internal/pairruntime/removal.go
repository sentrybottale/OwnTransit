//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

var ErrRemoved = errors.New("pairruntime: tunnel removed locally; explicit restore is required")

const removalFile = "removed.json"

type removalRecord struct {
	Schema string `json:"schema"`
	Role   string `json:"role"`
	Phase  string `json:"phase"`
}

func readRemoval(root *securefs.Root) (removalRecord, bool, error) {
	var record removalRecord
	data, err := root.ReadFile(removalFile, 256)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if strictjson.Decode(data, &record) != nil {
		return record, false, ErrState
	}
	if record.Schema != "owntransit.local-removal.v1" || (record.Role != "client" && record.Role != "target") || (record.Phase != "removing" && record.Phase != "removed") {
		return record, false, ErrState
	}
	return record, true, nil
}

// IsRemoved includes interrupted removal. A malformed marker fails closed.
func IsRemoved(path string) (bool, error) {
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return false, err
	}
	defer root.Close()
	_, removed, err := readRemoval(root)
	return removed, err
}

// A sibling control directory survives all state generations. It shares the
// receiver rebuild lock, so removal/restore cannot race a trust replacement.
func localLifecycleLock(path string) (*securefs.Lock, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrState
	}
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	root.Close()
	control, err := securefs.OpenRoot(path + ".setup")
	if errors.Is(err, os.ErrNotExist) {
		control, err = securefs.CreateRoot(path + ".setup")
		if errors.Is(err, os.ErrExist) {
			control, err = securefs.OpenRoot(path + ".setup")
		}
	}
	if err != nil {
		return nil, err
	}
	defer control.Close()
	return control.TryLock("setup.lock")
}

func localRole(root *securefs.Root, path string, target bool) (string, error) {
	if target {
		r, err := receiverpairing.Open(filepath.Join(path, "authority"))
		if err != nil {
			return "", err
		}
		if _, err := r.Status(); err != nil {
			return "", err
		}
		return "target", nil
	}
	if _, err := readClient(root); err != nil {
		return "", err
	}
	return "client", nil
}

func drainLocal(ctx context.Context, root *securefs.Root) error {
	for {
		active, err := root.TryLock("active.lock")
		if err == nil {
			service, serviceErr := root.TryLock("service.lock")
			if serviceErr == nil {
				service.Close()
				return active.Close()
			}
			active.Close()
			err = serviceErr
		}
		if !errors.Is(err, securefs.ErrLocked) {
			return err
		}
		if err := pause(ctx, 25*time.Millisecond); err != nil {
			return err
		}
	}
}

// RemoveLocal detaches one local tunnel without an alarm, peer revocation or
// key deletion. The synced marker blocks all admission and policy watchers
// before stopping its exact owned service. Interrupted removal stays denied.
// stop must operate only on the previously validated local service selection.
func RemoveLocal(ctx context.Context, path string, target bool, stop func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	serial, err := localLifecycleLock(path)
	if err != nil {
		return err
	}
	defer serial.Close()
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	role, err := localRole(root, path, target)
	if err != nil {
		return err
	}
	if _, err := ReadRetainedPolicy(path); err != nil {
		return err
	}
	record, exists, err := readRemoval(root)
	if err != nil {
		return err
	}
	if exists && record.Role != role {
		return ErrState
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	record = removalRecord{Schema: "owntransit.local-removal.v1", Role: role, Phase: "removing"}
	if err := writeRecord(root, removalFile, record, !exists); err != nil {
		return err
	}
	if stop != nil {
		if err := stop(ctx); err != nil {
			return err
		}
	}
	if err := drainLocal(ctx, root); err != nil {
		return err
	}
	record.Phase = "removed"
	return writeRecord(root, removalFile, record, false)
}

// RestoreLocal is explicit and local. It preserves all retained keys, policy
// generations and terminal alarms. No network observation can restore a tunnel.
// A failed service start leaves retained active state available for a retry.
func RestoreLocal(ctx context.Context, path string, target bool, start func(context.Context) error) error {
	return restoreLocal(ctx, path, target, start, drainLocal)
}

func restoreLocal(ctx context.Context, path string, target bool, start func(context.Context) error, drain func(context.Context, *securefs.Root) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	serial, err := localLifecycleLock(path)
	if err != nil {
		return err
	}
	defer serial.Close()
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	role, err := localRole(root, path, target)
	if err != nil {
		return err
	}
	record, exists, err := readRemoval(root)
	if err != nil {
		return err
	}
	if !exists || record.Role != role || record.Phase != "removed" {
		return ErrState
	}
	if err := drain(ctx, root); err != nil {
		return err
	}
	if err := commitLocalRestore(ctx, root, path, target); err != nil {
		return err
	}
	if start != nil {
		return start(ctx)
	}
	return nil
}

// Recheck only after drainage, under the same policy mutation lock used by an
// alarm. The marker removal is the restore commit. Do not hold this lock while
// starting a service: a slow network must never delay a subsequent killswitch.
func commitLocalRestore(ctx context.Context, root *securefs.Root, path string, target bool) error {
	policyLock, err := root.TryLock("policy.lock")
	if err != nil {
		return err
	}
	defer policyLock.Close()
	policy, err := ReadRetainedPolicy(path)
	if err != nil {
		return err
	}
	if policy.Locked {
		return leasewire.ErrLocked
	}
	if target {
		r, err := receiverpairing.Open(filepath.Join(path, "authority"))
		if err != nil {
			return err
		}
		s, err := r.Status()
		if err != nil {
			return err
		}
		if s.LocalLocked || s.PeerLocked || s.PeerRevoked {
			return leasewire.ErrLocked
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return root.UnlinkFile(removalFile)
}
