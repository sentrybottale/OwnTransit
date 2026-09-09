//go:build linux

package relaysetup

import (
	"errors"
	"io"
	"os"

	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const packageManagerRoot = "/var/lib/owntransit-relay-manager"

type inheritedPackageLock struct{}

func (inheritedPackageLock) Close() error { return nil }

// LockPackage coordinates management commands with shared software installation
// and removal. Ordinary commands take a shared lock. A package-removal helper
// may borrow descriptor 9 only after verifying its exact protected inode; the
// installer keeps its own reference locked across helper return and file removal.
// Never unlock or close the borrowed descriptor here.
func LockPackage(inheritedFD int) (io.Closer, error) {
	if os.Geteuid() != 0 || (inheritedFD != 0 && inheritedFD != 9) {
		return nil, errors.New("relay package coordination requires root and a valid local lock handoff")
	}
	root, err := securefs.OpenRoot(packageManagerRoot)
	if inheritedFD == 0 && errors.Is(err, os.ErrNotExist) {
		root, err = securefs.CreateRoot(packageManagerRoot)
		if errors.Is(err, os.ErrExist) {
			root, err = securefs.OpenRoot(packageManagerRoot)
		}
	}
	if err != nil {
		return nil, errors.New("relay package coordination directory is unavailable or unsafe")
	}
	defer root.Close()
	if inheritedFD == 0 {
		lock, err := root.TrySharedLock("package.lock")
		if errors.Is(err, securefs.ErrLocked) {
			return nil, errors.New("a relay package operation is active; retry after it completes")
		}
		if err != nil {
			return nil, errors.New("relay package lock is unsafe or unavailable")
		}
		return lock, nil
	}
	data, err := root.ReadFile("package.lock", 1)
	if err != nil || len(data) != 0 {
		return nil, errors.New("invalid inherited relay package lock")
	}
	var named, inherited unix.Stat_t
	if unix.Lstat(packageManagerRoot+"/package.lock", &named) != nil || unix.Fstat(inheritedFD, &inherited) != nil {
		return nil, errors.New("invalid inherited relay package lock descriptor")
	}
	if named.Dev != inherited.Dev || named.Ino != inherited.Ino || inherited.Mode != unix.S_IFREG|0600 ||
		inherited.Uid != 0 || inherited.Gid != 0 || inherited.Nlink != 1 || inherited.Size != 0 {
		return nil, errors.New("inherited relay package lock does not match protected state")
	}
	flags, err := unix.FcntlInt(uintptr(inheritedFD), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR {
		return nil, errors.New("inherited relay package lock is not read-write")
	}
	if err := unix.Flock(inheritedFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("exclusive relay package lock handoff failed")
	}
	// The installer retains its own descriptor. Do not let subsequently spawned
	// systemctl/container commands inherit this helper's reference and prolong
	// the package lock after the installer exits. FD_CLOEXEC is descriptor-local.
	if _, err := unix.FcntlInt(uintptr(inheritedFD), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return nil, errors.New("could not confine inherited relay package lock")
	}
	return inheritedPackageLock{}, nil
}
