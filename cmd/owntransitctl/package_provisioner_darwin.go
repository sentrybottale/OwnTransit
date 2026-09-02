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
	darwinProvisionerFrontendName       = "owntransit-provision"
	darwinProvisionerFrontendStageName  = "provisioner-frontend.v1.stage"
	darwinLegacyProvisionerFrontendLink = "../roles/provisioner/current/owntransit-provision"
	maxDarwinProvisionerFrontendBytes   = 64 << 20
)

// publishDarwinProvisionerFrontend keeps the authenticated package tree
// non-traversable and publishes a distinct ordinary executable. This avoids
// making manager-authenticated release inodes hard-linkable by local users on
// Darwin, where link(2) does not provide Linux protected-hardlink semantics.
func publishDarwinProvisionerFrontend(runtimeIdentity packagetxn.RuntimeIdentity) error {
	if runtimeIdentity.Role != "provisioner" || runtimeIdentity.OS != "darwin" || runtimeIdentity.Arch != "arm64" ||
		!validPackageReleaseID(runtimeIdentity.ReleaseID) || !validPackageDigest(runtimeIdentity.ArtifactSHA256) {
		return errors.New("Darwin provisioner frontend requires an authenticated current provisioner release")
	}
	source := filepath.Join("/Library/OwnTransit/roles/provisioner/releases", runtimeIdentity.ReleaseID, darwinProvisionerFrontendName)
	contents, sourceInfo, err := readDarwinInstalledExecutable(
		source, 0, 0o755, runtimeIdentity.ArtifactSHA256, maxDarwinProvisionerFrontendBytes,
		"authenticated Darwin provisioner source",
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
	if err := validateExistingDarwinProvisionerFrontend(int(bin.Fd())); err != nil {
		return err
	}
	if err := removeRecoverableDarwinProvisionerStage(int(stage.Fd())); err != nil {
		return err
	}

	fd, err := unix.Openat(int(stage.Fd()), darwinProvisionerFrontendStageName,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create private Darwin provisioner stage: %w", err)
	}
	staged := true
	defer func() {
		_ = unix.Close(fd)
		if staged {
			_ = unix.Unlinkat(int(stage.Fd()), darwinProvisionerFrontendStageName, 0)
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return fmt.Errorf("own private Darwin provisioner stage: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("protect private Darwin provisioner stage: %w", err)
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("private Darwin provisioner stage ACL: %w", err)
	}
	if err := writeAllDarwinFD(fd, contents); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync private Darwin provisioner bytes: %w", err)
	}
	if err := unix.Fchmod(fd, 0o755); err != nil {
		return fmt.Errorf("activate staged Darwin provisioner mode: %w", err)
	}
	if err := verifyDarwinExecutableFD(fd, 0, 0o755, int64(len(contents)), runtimeIdentity.ArtifactSHA256, "staged Darwin provisioner"); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync staged Darwin provisioner metadata: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("close staged Darwin provisioner: %w", err)
	}
	fd = -1
	if err := unix.Renameat(int(stage.Fd()), darwinProvisionerFrontendStageName, int(bin.Fd()), darwinProvisionerFrontendName); err != nil {
		return fmt.Errorf("publish Darwin provisioner frontend: %w", err)
	}
	staged = false
	if err := bin.Sync(); err != nil {
		return fmt.Errorf("sync Darwin public bin directory: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync Darwin provisioner stage directory: %w", err)
	}
	target := filepath.Join(darwinClientFrontendDirectory, darwinProvisionerFrontendName)
	_, targetInfo, err := readDarwinInstalledExecutable(
		target, 0, 0o755, runtimeIdentity.ArtifactSHA256, maxDarwinProvisionerFrontendBytes,
		"published Darwin provisioner frontend",
	)
	if err != nil {
		return err
	}
	if os.SameFile(sourceInfo, targetInfo) {
		return errors.New("published Darwin provisioner is a hard link to the protected release artifact")
	}
	return nil
}

func validateExistingDarwinProvisionerFrontend(directory int) error {
	var selected unix.Stat_t
	err := unix.Fstatat(directory, darwinProvisionerFrontendName, &selected, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing Darwin provisioner frontend: %w", err)
	}
	if selected.Mode&unix.S_IFMT == unix.S_IFLNK {
		if selected.Uid != 0 || selected.Gid != 0 || selected.Nlink != 1 {
			return errors.New("legacy Darwin provisioner symlink metadata is invalid")
		}
		buffer := make([]byte, len(darwinLegacyProvisionerFrontendLink)+1)
		length, err := unix.Readlinkat(directory, darwinProvisionerFrontendName, buffer)
		if err != nil || length != len(darwinLegacyProvisionerFrontendLink) ||
			string(buffer[:length]) != darwinLegacyProvisionerFrontendLink || selected.Size != int64(length) {
			return errors.New("existing Darwin provisioner frontend is not the exact legacy symlink")
		}
		var after unix.Stat_t
		if err := unix.Fstatat(directory, darwinProvisionerFrontendName, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameDarwinStat(selected, after) {
			return errors.New("legacy Darwin provisioner symlink changed during validation")
		}
		return nil
	}
	if selected.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("existing Darwin provisioner frontend is not regular")
	}
	fd, err := unix.Openat(directory, darwinProvisionerFrontendName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open existing Darwin provisioner frontend: %w", err)
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameDarwinStat(selected, opened) || opened.Uid != 0 || opened.Gid != 0 ||
		uint32(opened.Mode)&0o7777 != 0o755 || opened.Nlink < 1 || opened.Size <= 0 || opened.Size > maxDarwinProvisionerFrontendBytes {
		return errors.New("existing Darwin provisioner frontend metadata is invalid")
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("existing Darwin provisioner frontend ACL: %w", err)
	}
	return nil
}

func removeRecoverableDarwinProvisionerStage(directory int) error {
	fd, err := unix.Openat(directory, darwinProvisionerFrontendStageName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open interrupted Darwin provisioner stage: %w", err)
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	aclErr := securefs.VerifyNoExtendedACLFD(fd, false)
	closeErr := unix.Close(fd)
	if statErr != nil || aclErr != nil || closeErr != nil || !recoverableDarwinProvisionerStage(stat) {
		return errors.New("interrupted Darwin provisioner stage is not safely recoverable")
	}
	if err := unix.Unlinkat(directory, darwinProvisionerFrontendStageName, 0); err != nil {
		return fmt.Errorf("remove interrupted Darwin provisioner stage: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("sync recovered Darwin provisioner stage directory: %w", err)
	}
	return nil
}

func recoverableDarwinProvisionerStage(stat unix.Stat_t) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 ||
		stat.Size < 0 || stat.Size > maxDarwinProvisionerFrontendBytes {
		return false
	}
	permissions := uint32(stat.Mode) & 0o7777
	return permissions == 0o600 || (permissions == 0o755 && stat.Size > 0)
}
