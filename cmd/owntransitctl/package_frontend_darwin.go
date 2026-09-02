//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const (
	darwinClientFrontendDirectory = "/Library/OwnTransit/bin"
	darwinClientFrontendName      = "owntransit-cli"
	darwinClientFrontendStageName = "client-frontend.v1.stage"
	maxDarwinClientFrontendBytes  = 64 << 20
)

func publishDarwinClientFrontend(receipt []byte, runtimeIdentity packagetxn.RuntimeIdentity) error {
	identity, err := parseDarwinReaderIdentity(receipt)
	if err != nil || runtimeIdentity.Role != "client" || runtimeIdentity.OS != "darwin" ||
		!validPackageReleaseID(runtimeIdentity.ReleaseID) || !validPackageDigest(runtimeIdentity.ArtifactSHA256) {
		return errors.New("Darwin client frontend requires an authenticated client release and identity")
	}
	source := filepath.Join("/Library/OwnTransit/roles/client/releases", runtimeIdentity.ReleaseID, "owntransit-real")
	contents, sourceInfo, err := readDarwinInstalledExecutable(
		source, identity.readerGID, 0o750, runtimeIdentity.ArtifactSHA256, maxDarwinClientFrontendBytes,
		"authenticated Darwin client frontend source",
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
	if err := validateExistingDarwinClientFrontend(int(bin.Fd())); err != nil {
		return err
	}
	if err := removeRecoverableDarwinFrontendStage(int(stage.Fd())); err != nil {
		return err
	}

	fd, err := unix.Openat(int(stage.Fd()), darwinClientFrontendStageName,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create private Darwin frontend stage: %w", err)
	}
	staged := true
	defer func() {
		_ = unix.Close(fd)
		if staged {
			_ = unix.Unlinkat(int(stage.Fd()), darwinClientFrontendStageName, 0)
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return fmt.Errorf("own private Darwin frontend stage: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("protect private Darwin frontend stage: %w", err)
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("private Darwin frontend stage ACL: %w", err)
	}
	if err := writeAllDarwinFD(fd, contents); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync private Darwin frontend bytes: %w", err)
	}
	if err := unix.Fchmod(fd, 0o755); err != nil {
		return fmt.Errorf("activate staged Darwin frontend mode: %w", err)
	}
	if err := verifyDarwinExecutableFD(fd, 0, 0o755, int64(len(contents)), runtimeIdentity.ArtifactSHA256, "staged Darwin frontend"); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync staged Darwin frontend metadata: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("close staged Darwin frontend: %w", err)
	}
	fd = -1
	if err := unix.Renameat(int(stage.Fd()), darwinClientFrontendStageName, int(bin.Fd()), darwinClientFrontendName); err != nil {
		return fmt.Errorf("publish Darwin frontend: %w", err)
	}
	staged = false
	if err := bin.Sync(); err != nil {
		return fmt.Errorf("sync Darwin public bin directory: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync Darwin frontend stage directory: %w", err)
	}
	target := filepath.Join(darwinClientFrontendDirectory, darwinClientFrontendName)
	_, targetInfo, err := readDarwinInstalledExecutable(
		target, 0, 0o755, runtimeIdentity.ArtifactSHA256, maxDarwinClientFrontendBytes,
		"published Darwin frontend",
	)
	if err != nil {
		return err
	}
	if os.SameFile(sourceInfo, targetInfo) {
		return errors.New("published Darwin frontend is a hard link to the protected release client")
	}
	return nil
}

func validateExistingDarwinClientFrontend(directory int) error {
	var selected unix.Stat_t
	err := unix.Fstatat(directory, darwinClientFrontendName, &selected, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing Darwin client frontend: %w", err)
	}
	if selected.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("existing Darwin client frontend is not regular")
	}
	fd, err := unix.Openat(directory, darwinClientFrontendName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open existing Darwin client frontend: %w", err)
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameDarwinStat(selected, opened) || opened.Uid != 0 || opened.Gid != 0 ||
		uint32(opened.Mode)&0o7777 != 0o755 || opened.Nlink < 1 || opened.Size <= 0 || opened.Size > maxDarwinClientFrontendBytes {
		return errors.New("existing Darwin client frontend metadata is invalid")
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("existing Darwin client frontend ACL: %w", err)
	}
	return nil
}

func removeRecoverableDarwinFrontendStage(directory int) error {
	fd, err := unix.Openat(directory, darwinClientFrontendStageName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open interrupted Darwin frontend stage: %w", err)
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	aclErr := securefs.VerifyNoExtendedACLFD(fd, false)
	closeErr := unix.Close(fd)
	if statErr != nil || aclErr != nil || closeErr != nil || !recoverableDarwinFrontendStage(stat) {
		return errors.New("interrupted Darwin frontend stage is not safely recoverable")
	}
	if err := unix.Unlinkat(directory, darwinClientFrontendStageName, 0); err != nil {
		return fmt.Errorf("remove interrupted Darwin frontend stage: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("sync recovered Darwin frontend stage directory: %w", err)
	}
	return nil
}

func recoverableDarwinFrontendStage(stat unix.Stat_t) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 ||
		stat.Size < 0 || stat.Size > maxDarwinClientFrontendBytes {
		return false
	}
	permissions := uint32(stat.Mode) & 0o7777
	return permissions == 0o600 || (permissions == 0o755 && stat.Size > 0)
}

func readDarwinFrontendSource(path string, readerGID uint32, expectedDigest string) ([]byte, error) {
	contents, _, err := readDarwinInstalledExecutable(
		path, readerGID, 0o750, expectedDigest, maxDarwinClientFrontendBytes,
		"authenticated Darwin client frontend source",
	)
	return contents, err
}
