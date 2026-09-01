//go:build darwin || linux

package packagetxn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// measureRunningExecutable measures the root-owned executable which invoked
// this lifecycle process. Production package activation never accepts a
// caller-provided digest or path as a substitute.
func measureRunningExecutable() (packageMeasurement, error) {
	path, err := os.Executable()
	if err != nil {
		return packageMeasurement{}, fmt.Errorf("resolve executable: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return packageMeasurement{}, fmt.Errorf("resolve executable links: %w", err)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return packageMeasurement{}, errors.New("executable path is not canonical and absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return packageMeasurement{}, fmt.Errorf("open executable: %w", err)
	}
	defer unix.Close(fd)
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return packageMeasurement{}, fmt.Errorf("inspect executable: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || uint64(before.Nlink) != 1 || before.Uid != uint32(unix.Geteuid()) ||
		before.Mode&0o022 != 0 || before.Size <= 0 || before.Size > 1<<30 {
		return packageMeasurement{}, errors.New("executable is not a protected single-link regular file")
	}
	if err := verifyPackageACL(fd, false); err != nil {
		return packageMeasurement{}, fmt.Errorf("executable ACL: %w", err)
	}
	digest, err := hashExactFD(fd, before.Size)
	if err != nil {
		return packageMeasurement{}, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return packageMeasurement{}, fmt.Errorf("reinspect executable: %w", err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Size != after.Size {
		return packageMeasurement{}, errors.New("executable changed while measured")
	}
	return packageMeasurement{Path: path, SHA256: digest, Size: before.Size}, nil
}
