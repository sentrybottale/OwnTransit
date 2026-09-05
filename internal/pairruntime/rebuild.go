//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

// RebuildReceiver is an explicit local trust replacement, never a reconnect
// path. Prepare a complete fresh identity before retiring the old one. Atomic
// directory exchange selects the new identity only after all old workers exit.
// Old state remains private and terminally locked; it is never a rollback target.
func RebuildReceiver(ctx context.Context, path, origin string, info pairrelay.ServerInfo, expectedPeer string) (receiverpairing.Attempt, string, error) {
	var empty receiverpairing.Attempt
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return empty, "", ErrState
	}
	controlPath := path + ".setup"
	control, err := securefs.OpenRoot(controlPath)
	if errors.Is(err, os.ErrNotExist) {
		control, err = securefs.CreateRoot(controlPath)
	}
	if err != nil {
		return empty, "", err
	}
	defer control.Close()
	serial, err := control.TryLock("setup.lock")
	if err != nil {
		return empty, "", err
	}
	defer serial.Close()
	// Opening the control root checks every ancestor without following links.
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return empty, "", err
	}
	defer parent.Close()
	stat, err := parent.Stat()
	if err != nil {
		return empty, "", err
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || stat.Mode().Perm()&0022 != 0 {
		return empty, "", ErrState
	}
	var old *securefs.Root
	if _, err = os.Lstat(path); err == nil {
		old, err = securefs.OpenRoot(path)
		if err != nil {
			return empty, "", err
		}
		defer old.Close()
		if _, err = ReadPolicy(path); err != nil {
			return empty, "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, "", err
	}
	id, err := protocol.NewRouteID()
	if err != nil {
		return empty, "", err
	}
	candidate := filepath.Join(controlPath, "generation-"+id.String())
	attempt, err := InitializeReceiver(candidate, origin, info)
	if err != nil {
		return empty, "", err
	}
	if err = ctx.Err(); err != nil {
		return empty, "", err
	}
	if old != nil {
		receiver, e := receiverpairing.Open(filepath.Join(path, "authority"))
		if e != nil {
			return empty, "", e
		}
		if _, e := receiver.RetireForReplacement(expectedPeer); e != nil {
			return empty, "", e
		}
		if err = SetLocked(ctx, path, false, true); err != nil {
			return empty, "", err
		}
		gate, e := old.TryLock("active.lock")
		if e != nil {
			return empty, "", e
		}
		defer gate.Close()
		service, e := old.TryLock("service.lock")
		if e != nil {
			return empty, "", e
		}
		defer service.Close()
	}
	// Both names are under the same protected parent; syscall flags prohibit
	// overwriting a concurrently created target on first initialization.
	err = publishReceiverDirectory(int(parent.Fd()), filepath.Base(controlPath)+"/"+filepath.Base(candidate), filepath.Base(path), old != nil)
	if err != nil {
		return empty, "", err
	}
	if err = control.Sync(); err != nil {
		return empty, "", err
	}
	if err = unix.Fsync(int(parent.Fd())); err != nil {
		return empty, "", err
	}
	retired := ""
	if old != nil {
		retired = candidate
	}
	return attempt, retired, nil
}
