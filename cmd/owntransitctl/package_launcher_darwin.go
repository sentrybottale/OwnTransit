//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const (
	darwinClientLauncherName       = "owntransit"
	darwinClientLauncherStageRoot  = "/Library/OwnTransit/launcher-stage"
	darwinClientLauncherStageName  = "client-launcher.v1.stage"
	darwinLegacyClientLauncherLink = "../roles/client/current/owntransit"
	maxDarwinClientLauncherBytes   = 16 << 20
)

// publishDarwinClientLauncher publishes a distinct setgid inode in the public
// bin directory. The authenticated release launcher remains inside the
// protected release tree and is never hard-linked into the public namespace.
func publishDarwinClientLauncher(receipt []byte, runtimeIdentity packagetxn.RuntimeIdentity) error {
	identity, err := parseDarwinReaderIdentity(receipt)
	if err != nil || runtimeIdentity.Role != "client" || runtimeIdentity.OS != "darwin" || runtimeIdentity.Arch != "arm64" ||
		!validPackageReleaseID(runtimeIdentity.ReleaseID) || !validPackageDigest(runtimeIdentity.LauncherSHA256) {
		return errors.New("Darwin public launcher requires an authenticated client launcher and identity")
	}
	source := filepath.Join("/Library/OwnTransit/roles/client/releases", runtimeIdentity.ReleaseID, darwinClientLauncherName)
	contents, sourceInfo, err := readDarwinInstalledExecutable(
		source, identity.readerGID, 0o2751, runtimeIdentity.LauncherSHA256, maxDarwinClientLauncherBytes,
		"authenticated Darwin release launcher",
	)
	if err != nil {
		return err
	}

	bin, err := openDarwinOwnedDirectory(darwinClientFrontendDirectory, 0, 0, 0o755)
	if err != nil {
		return err
	}
	defer bin.Close()
	stage, err := openDarwinOwnedDirectory(darwinClientLauncherStageRoot, 0, 0, 0o700)
	if err != nil {
		return err
	}
	defer stage.Close()
	if err := validateExistingDarwinPublicLauncher(int(bin.Fd()), identity.readerGID); err != nil {
		return err
	}
	if err := removeRecoverableDarwinLauncherStage(int(stage.Fd()), identity.readerGID); err != nil {
		return err
	}

	fd, err := unix.Openat(int(stage.Fd()), darwinClientLauncherStageName,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create private Darwin launcher stage: %w", err)
	}
	staged := true
	defer func() {
		_ = unix.Close(fd)
		if staged {
			_ = unix.Unlinkat(int(stage.Fd()), darwinClientLauncherStageName, 0)
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return fmt.Errorf("own private Darwin launcher stage: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("protect private Darwin launcher stage: %w", err)
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("private Darwin launcher stage ACL: %w", err)
	}
	if err := writeAllDarwinFD(fd, contents); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync private Darwin launcher bytes: %w", err)
	}
	// chown must precede chmod: changing ownership clears setgid on macOS.
	if err := unix.Fchown(fd, 0, int(identity.readerGID)); err != nil {
		return fmt.Errorf("own staged Darwin launcher: %w", err)
	}
	if err := unix.Fchmod(fd, 0o2751); err != nil {
		return fmt.Errorf("activate staged Darwin launcher mode: %w", err)
	}
	if err := verifyDarwinExecutableFD(fd, identity.readerGID, 0o2751, int64(len(contents)), runtimeIdentity.LauncherSHA256, "staged Darwin launcher"); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync staged Darwin launcher metadata: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("close staged Darwin launcher: %w", err)
	}
	fd = -1
	if err := unix.Renameat(int(stage.Fd()), darwinClientLauncherStageName, int(bin.Fd()), darwinClientLauncherName); err != nil {
		return fmt.Errorf("publish Darwin launcher: %w", err)
	}
	staged = false
	if err := bin.Sync(); err != nil {
		return fmt.Errorf("sync Darwin public bin directory: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync Darwin launcher stage directory: %w", err)
	}
	target := filepath.Join(darwinClientFrontendDirectory, darwinClientLauncherName)
	_, targetInfo, err := readDarwinInstalledExecutable(
		target, identity.readerGID, 0o2751, runtimeIdentity.LauncherSHA256, maxDarwinClientLauncherBytes,
		"published Darwin launcher",
	)
	if err != nil {
		return err
	}
	if os.SameFile(sourceInfo, targetInfo) {
		return errors.New("published Darwin launcher is a hard link to the protected release launcher")
	}
	return nil
}

func openDarwinOwnedDirectory(path string, uid, gid uint32, mode uint32) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open protected Darwin directory %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("retain protected Darwin directory descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Gid != gid || uint32(stat.Mode)&0o7777 != mode {
		_ = file.Close()
		return nil, fmt.Errorf("protected Darwin directory %s has invalid metadata", path)
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, true); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protected Darwin directory %s ACL: %w", path, err)
	}
	return file, nil
}

func validateExistingDarwinPublicLauncher(directory int, readerGID uint32) error {
	var selected unix.Stat_t
	err := unix.Fstatat(directory, darwinClientLauncherName, &selected, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing Darwin public launcher: %w", err)
	}
	switch selected.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		if selected.Uid != 0 || selected.Gid != 0 || selected.Nlink != 1 {
			return errors.New("legacy Darwin public launcher symlink metadata is invalid")
		}
		buffer := make([]byte, len(darwinLegacyClientLauncherLink)+1)
		length, err := unix.Readlinkat(directory, darwinClientLauncherName, buffer)
		if err != nil || length != len(darwinLegacyClientLauncherLink) || string(buffer[:length]) != darwinLegacyClientLauncherLink || selected.Size != int64(length) {
			return errors.New("existing Darwin public launcher is not the exact legacy symlink")
		}
		var after unix.Stat_t
		if err := unix.Fstatat(directory, darwinClientLauncherName, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			selected.Dev != after.Dev || selected.Ino != after.Ino || selected.Mode != after.Mode || selected.Uid != after.Uid ||
			selected.Gid != after.Gid || selected.Nlink != after.Nlink || selected.Size != after.Size {
			return errors.New("legacy Darwin public launcher changed during validation")
		}
		return nil
	case unix.S_IFREG:
		fd, err := unix.Openat(directory, darwinClientLauncherName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open existing Darwin public launcher: %w", err)
		}
		defer unix.Close(fd)
		var opened unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != selected.Dev || opened.Ino != selected.Ino ||
			opened.Uid != 0 || opened.Gid != readerGID || !recoverableDarwinPublicLauncherMode(uint32(opened.Mode)&0o7777) || opened.Nlink < 1 ||
			opened.Size <= 0 || opened.Size > maxDarwinClientLauncherBytes {
			return errors.New("existing Darwin public launcher metadata is invalid")
		}
		if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
			return fmt.Errorf("existing Darwin public launcher ACL: %w", err)
		}
		return nil
	default:
		return errors.New("existing Darwin public launcher is neither a regular launcher nor the exact legacy symlink")
	}
}

func recoverableDarwinPublicLauncherMode(mode uint32) bool {
	return mode == 0o2751 || mode == 0o751
}

func removeRecoverableDarwinLauncherStage(directory int, readerGID uint32) error {
	fd, err := unix.Openat(directory, darwinClientLauncherStageName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open interrupted Darwin launcher stage: %w", err)
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	aclErr := securefs.VerifyNoExtendedACLFD(fd, false)
	closeErr := unix.Close(fd)
	if statErr != nil || aclErr != nil || closeErr != nil || !recoverableDarwinLauncherStage(stat, readerGID) {
		return errors.New("interrupted Darwin launcher stage is not safely recoverable")
	}
	if err := unix.Unlinkat(directory, darwinClientLauncherStageName, 0); err != nil {
		return fmt.Errorf("remove interrupted Darwin launcher stage: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("sync recovered Darwin launcher stage directory: %w", err)
	}
	return nil
}

func recoverableDarwinLauncherStage(stat unix.Stat_t, readerGID uint32) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 ||
		stat.Size < 0 || stat.Size > maxDarwinClientLauncherBytes {
		return false
	}
	permissions := uint32(stat.Mode) & 0o7777
	if stat.Gid == 0 && permissions == 0o600 {
		// Creation and byte-copy state, before ownership transfer.
		return true
	}
	if readerGID != 0 && stat.Gid == readerGID && permissions == 0o600 && stat.Size > 0 {
		// Ownership has moved but setgid activation has not yet happened.
		return true
	}
	return readerGID != 0 && stat.Gid == readerGID && permissions == 0o2751 && stat.Size > 0
}

func readDarwinInstalledExecutable(path string, gid, mode uint32, expectedDigest string, limit int64, label string) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is absent", label)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("retain %s descriptor", label)
	}
	defer file.Close()
	afterOpen, err := file.Stat()
	if err != nil || !os.SameFile(before, afterOpen) {
		return nil, nil, fmt.Errorf("%s selection changed", label)
	}
	stat, ok := afterOpen.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != gid || uint32(stat.Mode)&0o7777 != mode || stat.Nlink != 1 || afterOpen.Size() <= 0 || afterOpen.Size() > limit {
		return nil, nil, fmt.Errorf("%s metadata is invalid", label)
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return nil, nil, fmt.Errorf("%s ACL: %w", label, err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(contents) == 0 || int64(len(contents)) > limit || int64(len(contents)) != afterOpen.Size() {
		return nil, nil, fmt.Errorf("%s could not be measured exactly", label)
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return nil, nil, fmt.Errorf("%s digest changed", label)
	}
	afterRead, err := file.Stat()
	if err != nil || !os.SameFile(afterOpen, afterRead) {
		return nil, nil, fmt.Errorf("%s changed while it was measured", label)
	}
	afterStat, ok := afterRead.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev != afterStat.Dev || stat.Ino != afterStat.Ino || stat.Mode != afterStat.Mode ||
		stat.Uid != afterStat.Uid || stat.Gid != afterStat.Gid || stat.Nlink != afterStat.Nlink || stat.Size != afterStat.Size {
		return nil, nil, fmt.Errorf("%s changed while it was measured", label)
	}
	return contents, afterRead, nil
}

func writeAllDarwinFD(fd int, contents []byte) error {
	for len(contents) > 0 {
		written, err := unix.Write(fd, contents)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("write private Darwin launcher stage: %w", err)
		}
		if written <= 0 {
			return errors.New("write private Darwin launcher stage made no progress")
		}
		contents = contents[written:]
	}
	return nil
}

func verifyDarwinExecutableFD(fd int, gid, mode uint32, size int64, expectedDigest, label string) error {
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != gid ||
		uint32(before.Mode)&0o7777 != mode || before.Nlink != 1 || before.Size != size {
		return fmt.Errorf("%s metadata is invalid", label)
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("%s ACL: %w", label, err)
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return fmt.Errorf("seek %s: %w", label, err)
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	remaining := size
	for remaining > 0 {
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		read, err := unix.Read(fd, buffer[:want])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || read <= 0 {
			return fmt.Errorf("measure %s: %w", label, err)
		}
		_, _ = hash.Write(buffer[:read])
		remaining -= int64(read)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return fmt.Errorf("%s digest is invalid", label)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameDarwinStat(before, after) {
		return fmt.Errorf("%s changed while it was measured", label)
	}
	return nil
}

func sameDarwinStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid &&
		left.Gid == right.Gid && left.Nlink == right.Nlink && left.Size == right.Size
}
