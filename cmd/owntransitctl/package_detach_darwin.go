//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

func detachNativePackageRuntime(role string, identity packagetxn.RuntimeIdentity) error {
	if identity.Role != role || identity.OS != "darwin" || identity.Arch != "arm64" ||
		!validPackageReleaseID(identity.ReleaseID) || !validPackageDigest(identity.ArtifactSHA256) {
		return errors.New("Darwin package detach requires one authenticated current runtime")
	}
	bin, err := openDarwinOwnedDirectory(darwinClientFrontendDirectory, 0, 0, 0o755)
	if err != nil {
		return err
	}
	defer bin.Close()

	switch role {
	case "client":
		if !validPackageDigest(identity.LauncherSHA256) {
			return errors.New("Darwin client detach requires the authenticated launcher digest")
		}
		readerGID, err := nativePackageReaderGID(role)
		if err != nil || readerGID <= 0 {
			return errors.New("Darwin client detach cannot authenticate the reader GID")
		}
		if err := detachDarwinPublicFile(
			bin, darwinClientLauncherName, uint32(readerGID), identity.LauncherSHA256, maxDarwinClientLauncherBytes,
			[]uint32{0o2751, 0o751}, 0o751, darwinLegacyClientLauncherLink, "Darwin client launcher",
		); err != nil {
			return err
		}
		return detachDarwinPublicFile(
			bin, darwinClientFrontendName, 0, identity.ArtifactSHA256, maxDarwinClientFrontendBytes,
			[]uint32{0o755}, 0, "", "Darwin client frontend",
		)
	case "provisioner":
		return detachDarwinPublicFile(
			bin, darwinProvisionerFrontendName, 0, identity.ArtifactSHA256, maxDarwinProvisionerFrontendBytes,
			[]uint32{0o755}, 0, darwinLegacyProvisionerFrontendLink, "Darwin provisioner frontend",
		)
	default:
		return errors.New("Darwin package detach supports only client or provisioner")
	}
}

// detachDarwinPublicFile is idempotent. An absent public name is already
// detached. The client launcher additionally accepts its authenticated 0751
// crash residue and removes setgid through the opened inode before unlinking
// the canonical name, which deactivates every retained hard-link alias.
func detachDarwinPublicFile(
	directory *os.File,
	name string,
	expectedGID uint32,
	expectedDigest string,
	limit int64,
	allowedModes []uint32,
	deactivatedMode uint32,
	legacyLink string,
	label string,
) error {
	directoryFD := int(directory.Fd())
	var selected unix.Stat_t
	err := unix.Fstatat(directoryFD, name, &selected, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		// A previous invocation may have unlinked the name and stopped before
		// syncing the directory.  Sync even the already-absent state so retry
		// converges durably after every interruption point.
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync already-detached %s directory: %w", label, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if selected.Mode&unix.S_IFMT == unix.S_IFLNK {
		if legacyLink == "" || selected.Uid != 0 || selected.Gid != 0 || selected.Nlink != 1 {
			return fmt.Errorf("%s is an unauthorized symlink", label)
		}
		buffer := make([]byte, len(legacyLink)+1)
		length, readErr := unix.Readlinkat(directoryFD, name, buffer)
		if readErr != nil || length != len(legacyLink) || string(buffer[:length]) != legacyLink || selected.Size != int64(length) {
			return fmt.Errorf("%s is not the exact legacy selector symlink", label)
		}
		var after unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameDarwinStat(selected, after) {
			return fmt.Errorf("%s changed during legacy-symlink validation", label)
		}
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
			return fmt.Errorf("detach %s: %w", label, err)
		}
		return syncDetachedDarwinName(directory, name, label)
	}
	if selected.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not regular", label)
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("retain %s descriptor", label)
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || !sameDarwinStat(selected, before) || before.Uid != 0 || before.Gid != expectedGID ||
		before.Nlink < 1 || before.Size <= 0 || before.Size > limit || !allowedDarwinDetachMode(uint32(before.Mode)&0o7777, allowedModes) {
		return fmt.Errorf("%s metadata is invalid", label)
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("%s ACL: %w", label, err)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil || written != before.Size || hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return fmt.Errorf("%s digest or size differs from the authenticated runtime", label)
	}
	var afterRead unix.Stat_t
	if err := unix.Fstat(fd, &afterRead); err != nil || !sameDarwinStat(before, afterRead) {
		return fmt.Errorf("%s changed while it was authenticated", label)
	}
	if deactivatedMode != 0 && uint32(afterRead.Mode)&0o7777 != deactivatedMode {
		if err := unix.Fchmod(fd, deactivatedMode); err != nil {
			return fmt.Errorf("deactivate %s: %w", label, err)
		}
		if err := unix.Fsync(fd); err != nil {
			return fmt.Errorf("sync deactivated %s: %w", label, err)
		}
		if err := unix.Fstat(fd, &afterRead); err != nil || afterRead.Uid != 0 || afterRead.Gid != expectedGID ||
			uint32(afterRead.Mode)&0o7777 != deactivatedMode || afterRead.Nlink < 1 || afterRead.Size != before.Size {
			return fmt.Errorf("%s deactivation metadata is invalid", label)
		}
	}
	var named unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameDarwinStat(afterRead, named) {
		return fmt.Errorf("%s canonical name changed before detach", label)
	}
	if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
		return fmt.Errorf("detach %s: %w", label, err)
	}
	return syncDetachedDarwinName(directory, name, label)
}

func allowedDarwinDetachMode(mode uint32, allowed []uint32) bool {
	for _, candidate := range allowed {
		if mode == candidate {
			return true
		}
	}
	return false
}

func syncDetachedDarwinName(directory *os.File, name, label string) error {
	var residue unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &residue, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%s canonical name remains after detach", label)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync detached %s directory: %w", label, err)
	}
	return nil
}
