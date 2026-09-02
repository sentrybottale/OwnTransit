//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const darwinPackageMutationLockName = "package-mutation.v1.lock"

type darwinPackageMutationGuard struct {
	stage *os.File
	lock  *os.File
}

func acquireNativePackageMutationGuard(role string) (nativePackageMutationGuard, error) {
	if role != "client" && role != "provisioner" {
		return noOpPackageMutationGuard{}, nil
	}
	stage, err := openDarwinOwnedDirectory(darwinClientLauncherStageRoot, 0, 0, 0o700)
	if err != nil {
		return nil, err
	}
	fd, created, err := openDarwinMutationLock(int(stage.Fd()))
	if err != nil {
		_ = stage.Close()
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), darwinPackageMutationLockName)
	if lock == nil {
		_ = unix.Close(fd)
		_ = stage.Close()
		return nil, errors.New("retain Darwin package-mutation lock descriptor")
	}
	closeFailure := func(message string, cause error) (nativePackageMutationGuard, error) {
		_ = lock.Close()
		_ = stage.Close()
		return nil, fmt.Errorf("%s: %w", message, cause)
	}
	if created {
		if err := unix.Fchown(fd, 0, 0); err != nil {
			return closeFailure("own Darwin package-mutation lock", err)
		}
		if err := unix.Fchmod(fd, 0o600); err != nil {
			return closeFailure("protect Darwin package-mutation lock", err)
		}
		if err := lock.Sync(); err != nil {
			return closeFailure("sync Darwin package-mutation lock", err)
		}
		if err := stage.Sync(); err != nil {
			return closeFailure("sync Darwin launcher stage directory", err)
		}
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != 0 ||
		uint32(before.Mode)&0o7777 != 0o600 || before.Nlink != 1 || before.Size != 0 {
		_ = lock.Close()
		_ = stage.Close()
		return nil, errors.New("Darwin package-mutation lock metadata is invalid")
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return closeFailure("Darwin package-mutation lock ACL", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return closeFailure("another Darwin client package mutation is active", err)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameDarwinStat(before, after) {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = lock.Close()
		_ = stage.Close()
		return nil, errors.New("Darwin package-mutation lock changed during acquisition")
	}
	return &darwinPackageMutationGuard{stage: stage, lock: lock}, nil
}

func openDarwinMutationLock(stage int) (int, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		fd, err := unix.Openat(stage, darwinPackageMutationLockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == nil {
			return fd, false, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, false, fmt.Errorf("open Darwin package-mutation lock: %w", err)
		}
		fd, err = unix.Openat(stage, darwinPackageMutationLockName,
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return fd, true, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return -1, false, fmt.Errorf("create Darwin package-mutation lock: %w", err)
		}
	}
	return -1, false, errors.New("Darwin package-mutation lock raced repeatedly")
}

func (guard *darwinPackageMutationGuard) Close() error {
	if guard == nil || guard.lock == nil || guard.stage == nil {
		return errors.New("Darwin package-mutation guard is invalid")
	}
	fd := int(guard.lock.Fd())
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	lockCloseErr := guard.lock.Close()
	stageCloseErr := guard.stage.Close()
	guard.lock = nil
	guard.stage = nil
	if unlockErr != nil {
		return fmt.Errorf("unlock Darwin client package mutation: %w", unlockErr)
	}
	if lockCloseErr != nil {
		return fmt.Errorf("close Darwin package-mutation lock: %w", lockCloseErr)
	}
	return stageCloseErr
}
