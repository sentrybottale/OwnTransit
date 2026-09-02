//go:build darwin || linux

package packagetxn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"golang.org/x/sys/unix"
)

func openProtectedBundleRoot(path string, aclCheck func(int, bool) error) (int, error) {
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("packagetxn: open filesystem root for bundle: %w", err)
	}
	for index, component := range components {
		if !validFilesystemComponent(component) {
			_ = unix.Close(fd)
			return -1, errors.New("packagetxn: bundle root is not canonical")
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("packagetxn: open bundle directory: %w", openErr)
		}
		if index == len(components)-1 {
			if err := requireProtectedSourceDirectory(next, aclCheck); err != nil {
				_ = unix.Close(next)
				return -1, err
			}
		}
		fd = next
	}
	return fd, nil
}

func validFilesystemComponent(component string) bool {
	return component != "" && component != "." && component != ".." && len(component) <= 255 && !strings.ContainsRune(component, 0)
}

func requireProtectedSourceDirectory(fd int, aclCheck func(int, bool) error) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("packagetxn: inspect bundle directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
		return errors.New("packagetxn: bundle directory is not protected")
	}
	if err := aclCheck(fd, true); err != nil {
		return fmt.Errorf("packagetxn: bundle directory ACL: %w", err)
	}
	return nil
}

func stageReleaseDirectory(
	releasesFD, bundleFD int,
	decision decision,
	receipt receiptRecord,
	receiptBytes []byte,
	receiptDigest string,
	manager *Manager,
) error {
	releaseFD, err := ensurePackageDirectory(releasesFD, decision.releaseID, manager)
	if err != nil {
		return err
	}
	defer unix.Close(releaseFD)

	allowed := map[string]struct{}{receiptFileName: {}, receiptStageName: {}}
	for _, file := range decision.files {
		allowed[file.InstallName] = struct{}{}
		allowed[payloadStageName(file.InstallName)] = struct{}{}
	}
	if err := requireAllowedDirectoryEntries(releaseFD, allowed, "interrupted release"); err != nil {
		return err
	}

	receiptReady, err := recoverPayloadStage(releaseFD, decisionFile{
		InstallName: receiptFileName,
		SHA256:      receiptDigest,
		Size:        int64(len(receiptBytes)),
		Mode:        0o600,
		GID:         manager.ownerGID,
	}, receiptStageName, manager)
	if err != nil {
		return err
	}
	if receiptReady {
		return verifyOpenReleaseDirectory(releaseFD, &receipt, receiptBytes, receiptDigest, manager)
	}

	for _, file := range decision.files {
		if err := stageAuthenticatedFile(releaseFD, bundleFD, file, manager); err != nil {
			return err
		}
	}
	if err := publishExactBytes(releaseFD, receiptFileName, receiptStageName, receiptBytes, 0o600, receiptDigest, manager); err != nil {
		return err
	}
	if err := unix.Fsync(releaseFD); err != nil {
		return fmt.Errorf("packagetxn: sync complete release directory: %w", err)
	}
	if err := unix.Fsync(releasesFD); err != nil {
		return fmt.Errorf("packagetxn: sync releases directory: %w", err)
	}
	return verifyOpenReleaseDirectory(releaseFD, &receipt, receiptBytes, receiptDigest, manager)
}

func verifyReleaseDirectory(releasesFD int, releaseID string, expected *receiptRecord, expectedDigest string, manager *Manager) error {
	_, receiptBytes, digest, err := loadAndVerifyRelease(releasesFD, releaseID, manager)
	if err != nil {
		return err
	}
	if expected != nil {
		expectedBytes, encodeErr := encodeReceipt(*expected)
		if encodeErr != nil {
			return encodeErr
		}
		if !bytes.Equal(receiptBytes, expectedBytes) {
			return fmt.Errorf("%w: installed receipt differs from authenticated decision", ErrResidue)
		}
	}
	if expectedDigest != "" && digest != expectedDigest {
		return fmt.Errorf("%w: installed receipt digest differs from authenticated decision", ErrResidue)
	}
	return nil
}

func loadAndVerifyRelease(releasesFD int, releaseID string, manager *Manager) (receiptRecord, []byte, string, error) {
	if !validReleaseID(releaseID) {
		return receiptRecord{}, nil, "", fmt.Errorf("%w: release directory name is invalid", ErrResidue)
	}
	releaseFD, err := unix.Openat(releasesFD, releaseID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return receiptRecord{}, nil, "", fmt.Errorf("%w: open release directory: %v", ErrResidue, err)
	}
	defer unix.Close(releaseFD)
	if err := requirePackageDirectory(releaseFD, manager); err != nil {
		return receiptRecord{}, nil, "", err
	}
	receiptBytes, exists, err := readOptionalExactFile(releaseFD, receiptFileName, 0o600, maximumMetadataSize, manager)
	if err != nil {
		return receiptRecord{}, nil, "", err
	}
	if !exists {
		return receiptRecord{}, nil, "", fmt.Errorf("%w: release has no durable receipt", ErrResidue)
	}
	var receipt receiptRecord
	if err := decodeCanonical(receiptBytes, &receipt, encodeReceipt); err != nil {
		return receiptRecord{}, nil, "", fmt.Errorf("%w: receipt: %v", ErrResidue, err)
	}
	if receipt.ReleaseID != releaseID || receipt.Role != manager.role {
		return receiptRecord{}, nil, "", fmt.Errorf("%w: receipt identity differs from its namespace", ErrResidue)
	}
	digest := digestBytes(receiptBytes)
	if err := verifyOpenReleaseDirectory(releaseFD, &receipt, receiptBytes, digest, manager); err != nil {
		return receiptRecord{}, nil, "", err
	}
	return receipt, receiptBytes, digest, nil
}

func verifyOpenReleaseDirectory(releaseFD int, expected *receiptRecord, expectedBytes []byte, expectedDigest string, manager *Manager) error {
	if expected == nil {
		return errors.New("packagetxn: internal receipt expectation is nil")
	}
	if err := validateReceipt(*expected); err != nil {
		return err
	}
	canonical, err := encodeReceipt(*expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, expectedBytes) || digestBytes(expectedBytes) != expectedDigest {
		return errors.New("packagetxn: internal receipt encoding mismatch")
	}
	allowed := map[string]struct{}{receiptFileName: {}}
	for _, file := range expected.Files {
		allowed[file.Name] = struct{}{}
	}
	if err := requireAllowedDirectoryEntries(releaseFD, allowed, "complete release"); err != nil {
		return err
	}
	contents, exists, err := readOptionalExactFile(releaseFD, receiptFileName, 0o600, maximumMetadataSize, manager)
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(contents, expectedBytes) {
		return fmt.Errorf("%w: receipt contents differ", ErrResidue)
	}
	for _, file := range expected.Files {
		if err := verifyInstalledFile(releaseFD, file.Name, decodeInstallMode(file.Mode), file.GID, file.Size, file.SHA256, manager); err != nil {
			return err
		}
	}
	return nil
}

func stageAuthenticatedFile(releaseFD, bundleFD int, record decisionFile, manager *Manager) error {
	stage := payloadStageName(record.InstallName)
	ready, err := recoverPayloadStage(releaseFD, record, stage, manager)
	if err != nil {
		return err
	}
	if ready {
		return nil
	}

	sourceFD, err := openProtectedSourceFile(bundleFD, record.SourcePath, record.Size, manager.checkACL)
	if err != nil {
		return err
	}
	defer unix.Close(sourceFD)

	destinationFD, err := unix.Openat(releaseFD, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("packagetxn: create payload stage: %w", err)
	}
	stageExists := true
	defer func() {
		_ = unix.Close(destinationFD)
		if stageExists {
			_ = unix.Unlinkat(releaseFD, stage, 0)
		}
	}()
	if err := unix.Fchown(destinationFD, int(manager.ownerUID), int(record.GID)); err != nil {
		return fmt.Errorf("packagetxn: own payload stage: %w", err)
	}
	if err := unix.Fchmod(destinationFD, 0o600); err != nil {
		return fmt.Errorf("packagetxn: protect payload stage: %w", err)
	}
	if _, err := requireRegularFile(destinationFD, manager.ownerUID, record.GID, 0o600, 0, manager.checkACL); err != nil {
		return err
	}
	digest, err := copyAuthenticatedFile(sourceFD, destinationFD, record.Size)
	if err != nil {
		return err
	}
	if digest != record.SHA256 {
		return errors.New("packagetxn: authenticated source digest changed before staging")
	}
	if err := unix.Fchmod(destinationFD, unixInstallMode(record.Mode)); err != nil {
		return fmt.Errorf("packagetxn: set installed payload mode: %w", err)
	}
	if err := unix.Fsync(destinationFD); err != nil {
		return fmt.Errorf("packagetxn: sync payload stage: %w", err)
	}
	if _, err := requireRegularFile(destinationFD, manager.ownerUID, record.GID, unixInstallMode(record.Mode), record.Size, manager.checkACL); err != nil {
		return err
	}
	if err := unix.Close(destinationFD); err != nil {
		destinationFD = -1
		return fmt.Errorf("packagetxn: close payload stage: %w", err)
	}
	destinationFD = -1
	if err := unix.Linkat(releaseFD, stage, releaseFD, record.InstallName, 0); err != nil {
		return fmt.Errorf("packagetxn: publish installed payload without overwrite: %w", err)
	}
	if err := unix.Fsync(releaseFD); err != nil {
		return fmt.Errorf("packagetxn: sync payload publication: %w", err)
	}
	if err := unix.Unlinkat(releaseFD, stage, 0); err != nil {
		return fmt.Errorf("packagetxn: unlink published payload stage: %w", err)
	}
	stageExists = false
	if err := unix.Fsync(releaseFD); err != nil {
		return fmt.Errorf("packagetxn: sync payload stage removal: %w", err)
	}
	return verifyInstalledFile(releaseFD, record.InstallName, record.Mode, record.GID, record.Size, record.SHA256, manager)
}

func openProtectedSourceFile(bundleFD int, path string, expectedSize int64, aclCheck func(int, bool) error) (int, error) {
	if !validRelativePath(path) || expectedSize <= 0 || expectedSize > 1<<40 {
		return -1, errors.New("packagetxn: authenticated source record is invalid")
	}
	components := strings.Split(path, "/")
	directoryFD, err := unix.Dup(bundleFD)
	if err != nil {
		return -1, fmt.Errorf("packagetxn: duplicate bundle descriptor: %w", err)
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(directoryFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(directoryFD)
		if openErr != nil {
			return -1, fmt.Errorf("packagetxn: open bundle component: %w", openErr)
		}
		if err := requireProtectedSourceDirectory(next, aclCheck); err != nil {
			_ = unix.Close(next)
			return -1, err
		}
		directoryFD = next
	}
	defer unix.Close(directoryFD)
	fd, err := unix.Openat(directoryFD, components[len(components)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("packagetxn: open authenticated source file: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("packagetxn: inspect authenticated source file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 || stat.Size != expectedSize || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("packagetxn: authenticated source is not a protected single-link file of the declared size")
	}
	if err := aclCheck(fd, false); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("packagetxn: authenticated source ACL: %w", err)
	}
	return fd, nil
}

func copyAuthenticatedFile(sourceFD, destinationFD int, expectedSize int64) (string, error) {
	var before unix.Stat_t
	if err := unix.Fstat(sourceFD, &before); err != nil {
		return "", fmt.Errorf("packagetxn: inspect source before copy: %w", err)
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var copied int64
	for {
		n, readErr := unix.Read(sourceFD, buffer)
		if n > 0 {
			copied += int64(n)
			if copied > expectedSize {
				return "", errors.New("packagetxn: authenticated source grew during copy")
			}
			_, _ = hash.Write(buffer[:n])
			if err := writeAll(destinationFD, buffer[:n]); err != nil {
				return "", fmt.Errorf("packagetxn: copy authenticated source: %w", err)
			}
		}
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			return "", fmt.Errorf("packagetxn: read authenticated source: %w", readErr)
		}
		if n == 0 {
			break
		}
	}
	if copied != expectedSize {
		return "", errors.New("packagetxn: authenticated source changed size during copy")
	}
	var after unix.Stat_t
	if err := unix.Fstat(sourceFD, &after); err != nil {
		return "", fmt.Errorf("packagetxn: inspect source after copy: %w", err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mode != after.Mode || before.Nlink != after.Nlink || uint64(after.Nlink) != 1 {
		return "", errors.New("packagetxn: authenticated source metadata changed during copy")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func recoverPayloadStage(releaseFD int, record decisionFile, stageName string, manager *Manager) (bool, error) {
	stageFD, stageExists, err := openOptionalFile(releaseFD, stageName)
	if err != nil {
		return false, err
	}
	if stageExists {
		defer unix.Close(stageFD)
	}
	finalFD, finalExists, err := openOptionalFile(releaseFD, record.InstallName)
	if err != nil {
		return false, err
	}
	if finalExists {
		defer unix.Close(finalFD)
	}

	if finalExists && stageExists {
		var stageStat, finalStat unix.Stat_t
		if err := unix.Fstat(stageFD, &stageStat); err != nil {
			return false, fmt.Errorf("packagetxn: inspect payload stage: %w", err)
		}
		if err := unix.Fstat(finalFD, &finalStat); err != nil {
			return false, fmt.Errorf("packagetxn: inspect published payload: %w", err)
		}
		if stageStat.Dev != finalStat.Dev || stageStat.Ino != finalStat.Ino || uint64(stageStat.Nlink) != 2 || uint64(finalStat.Nlink) != 2 {
			return false, fmt.Errorf("%w: payload stage and final name are not one interrupted publication", ErrResidue)
		}
		if err := verifyOpenInstalledFile(finalFD, record.Mode, record.GID, record.Size, record.SHA256, manager, 2); err != nil {
			return false, err
		}
		if err := unix.Unlinkat(releaseFD, stageName, 0); err != nil {
			return false, fmt.Errorf("packagetxn: finish interrupted payload publication: %w", err)
		}
		if err := unix.Fsync(releaseFD); err != nil {
			return false, fmt.Errorf("packagetxn: sync interrupted payload recovery: %w", err)
		}
		return true, verifyInstalledFile(releaseFD, record.InstallName, record.Mode, record.GID, record.Size, record.SHA256, manager)
	}
	if finalExists {
		if err := verifyOpenInstalledFile(finalFD, record.Mode, record.GID, record.Size, record.SHA256, manager, 1); err != nil {
			return false, err
		}
		return true, nil
	}
	if stageExists {
		if err := requireAuthorizedPartialStage(stageFD, record, manager); err != nil {
			return false, err
		}
		if err := unix.Unlinkat(releaseFD, stageName, 0); err != nil {
			return false, fmt.Errorf("packagetxn: remove interrupted payload stage: %w", err)
		}
		if err := unix.Fsync(releaseFD); err != nil {
			return false, fmt.Errorf("packagetxn: sync interrupted payload stage removal: %w", err)
		}
	}
	return false, nil
}

func requireAuthorizedPartialStage(fd int, record decisionFile, manager *Manager) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("packagetxn: inspect interrupted payload stage: %w", err)
	}
	mode := uint32(stat.Mode) & 0o7777
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 || stat.Uid != manager.ownerUID || stat.Gid != record.GID ||
		(mode != 0o600 && mode != unixInstallMode(record.Mode)) || stat.Size < 0 || stat.Size > record.Size {
		return fmt.Errorf("%w: interrupted payload stage is not attributable to this transaction", ErrResidue)
	}
	if err := manager.checkACL(fd, false); err != nil {
		return fmt.Errorf("packagetxn: interrupted payload stage ACL: %w", err)
	}
	return nil
}

func publishExactBytes(directory int, target, stage string, contents []byte, mode fs.FileMode, expectedDigest string, manager *Manager) error {
	record := decisionFile{InstallName: target, Size: int64(len(contents)), SHA256: expectedDigest, Mode: mode, GID: manager.ownerGID}
	ready, err := recoverPayloadStage(directory, record, stage, manager)
	if err != nil || ready {
		return err
	}
	fd, err := unix.Openat(directory, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("packagetxn: create receipt stage: %w", err)
	}
	stageExists := true
	defer func() {
		_ = unix.Close(fd)
		if stageExists {
			_ = unix.Unlinkat(directory, stage, 0)
		}
	}()
	if err := unix.Fchown(fd, int(manager.ownerUID), int(manager.ownerGID)); err != nil {
		return fmt.Errorf("packagetxn: own receipt stage: %w", err)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("packagetxn: protect receipt stage: %w", err)
	}
	if err := writeAll(fd, contents); err != nil {
		return fmt.Errorf("packagetxn: write receipt stage: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("packagetxn: sync receipt stage: %w", err)
	}
	if _, err := requireRegularFile(fd, manager.ownerUID, manager.ownerGID, uint32(mode.Perm()), int64(len(contents)), manager.checkACL); err != nil {
		return err
	}
	if digestBytes(contents) != expectedDigest {
		return errors.New("packagetxn: internal receipt digest mismatch")
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("packagetxn: close receipt stage: %w", err)
	}
	fd = -1
	if err := unix.Linkat(directory, stage, directory, target, 0); err != nil {
		return fmt.Errorf("packagetxn: publish receipt without overwrite: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("packagetxn: sync receipt publication: %w", err)
	}
	if err := unix.Unlinkat(directory, stage, 0); err != nil {
		return fmt.Errorf("packagetxn: remove receipt stage: %w", err)
	}
	stageExists = false
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("packagetxn: sync receipt stage removal: %w", err)
	}
	return nil
}

func payloadStageName(name string) string {
	return "." + name + ".stage"
}

func openOptionalFile(directory int, name string) (int, bool, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, false, nil
	}
	if err != nil {
		return -1, false, fmt.Errorf("%w: open %s: %v", ErrResidue, name, err)
	}
	return fd, true, nil
}

func verifyInstalledFile(directory int, name string, mode fs.FileMode, gid uint32, size int64, digest string, manager *Manager) error {
	fd, exists, err := openOptionalFile(directory, name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: installed file %s is absent", ErrResidue, name)
	}
	defer unix.Close(fd)
	return verifyOpenInstalledFile(fd, mode, gid, size, digest, manager, 1)
}

func verifyOpenInstalledFile(fd int, mode fs.FileMode, gid uint32, size int64, digest string, manager *Manager, links uint64) error {
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return fmt.Errorf("packagetxn: inspect installed file: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || uint64(before.Nlink) != links || before.Uid != manager.ownerUID || before.Gid != gid ||
		uint32(before.Mode)&0o7777 != unixInstallMode(mode) || before.Size != size {
		return fmt.Errorf("%w: installed file ownership, type, links, size, or mode is not exact", ErrResidue)
	}
	if err := manager.checkACL(fd, false); err != nil {
		return fmt.Errorf("packagetxn: installed file ACL: %w", err)
	}
	digestValue, err := hashExactFD(fd, size)
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return fmt.Errorf("packagetxn: reinspect installed file: %w", err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Size != after.Size || before.Nlink != after.Nlink {
		return fmt.Errorf("%w: installed file changed while verified", ErrResidue)
	}
	if digestValue != digest {
		return fmt.Errorf("%w: installed file digest differs from its receipt", ErrResidue)
	}
	return nil
}

func hashExactFD(fd int, expectedSize int64) (string, error) {
	if expectedSize <= 0 || expectedSize > 1<<40 {
		return "", errors.New("packagetxn: installed file size is outside the supported bound")
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return "", fmt.Errorf("packagetxn: seek installed file: %w", err)
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var readTotal int64
	for {
		n, readErr := unix.Read(fd, buffer)
		if n > 0 {
			readTotal += int64(n)
			if readTotal > expectedSize {
				return "", errors.New("packagetxn: installed file grew while hashed")
			}
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			return "", fmt.Errorf("packagetxn: hash installed file: %w", readErr)
		}
		if n == 0 {
			break
		}
	}
	if readTotal != expectedSize {
		return "", errors.New("packagetxn: installed file changed size while hashed")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// retireReleaseDirectory removes only the exact files named by the retained
// authenticated receipt. The receipt is removed last, so an interruption is
// resumable without guessing which names belong to the transaction.
func retireReleaseDirectory(releasesFD int, releaseID, expectedReceiptDigest string, manager *Manager) error {
	if !validReleaseID(releaseID) || !validDigest(expectedReceiptDigest) {
		return errors.New("packagetxn: retirement binding is invalid")
	}
	releaseFD, err := unix.Openat(releasesFD, releaseID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: open retired release directory: %v", ErrResidue, err)
	}
	defer unix.Close(releaseFD)
	if err := requirePackageDirectory(releaseFD, manager); err != nil {
		return err
	}
	receiptBytes, exists, err := readOptionalExactFile(releaseFD, receiptFileName, 0o600, maximumMetadataSize, manager)
	if err != nil {
		return err
	}
	if !exists {
		if err := requireAllowedDirectoryEntries(releaseFD, map[string]struct{}{}, "retired release"); err != nil {
			return err
		}
		if err := unix.Unlinkat(releasesFD, releaseID, unix.AT_REMOVEDIR); err != nil {
			return fmt.Errorf("packagetxn: finish retired release directory removal: %w", err)
		}
		return unix.Fsync(releasesFD)
	}
	if digestBytes(receiptBytes) != expectedReceiptDigest {
		return fmt.Errorf("%w: retired release receipt differs from the journal", ErrResidue)
	}
	var receipt receiptRecord
	if err := decodeCanonical(receiptBytes, &receipt, encodeReceipt); err != nil {
		return fmt.Errorf("%w: retired release receipt: %v", ErrResidue, err)
	}
	if receipt.ReleaseID != releaseID || receipt.Role != manager.role {
		return fmt.Errorf("%w: retired release receipt identity is invalid", ErrResidue)
	}
	allowed := map[string]struct{}{receiptFileName: {}}
	for _, file := range receipt.Files {
		allowed[file.Name] = struct{}{}
	}
	if err := requireAllowedDirectoryEntries(releaseFD, allowed, "retired release"); err != nil {
		return err
	}
	for _, file := range receipt.Files {
		fd, present, err := openOptionalFile(releaseFD, file.Name)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		if err := verifyOpenInstalledFile(fd, decodeInstallMode(file.Mode), file.GID, file.Size, file.SHA256, manager, 1); err != nil {
			_ = unix.Close(fd)
			return err
		}
		_ = unix.Close(fd)
		if err := unix.Unlinkat(releaseFD, file.Name, 0); err != nil {
			return fmt.Errorf("packagetxn: retire authenticated payload: %w", err)
		}
		if err := unix.Fsync(releaseFD); err != nil {
			return fmt.Errorf("packagetxn: sync retired payload removal: %w", err)
		}
	}
	if err := unix.Unlinkat(releaseFD, receiptFileName, 0); err != nil {
		return fmt.Errorf("packagetxn: retire authenticated receipt: %w", err)
	}
	if err := unix.Fsync(releaseFD); err != nil {
		return fmt.Errorf("packagetxn: sync retired receipt removal: %w", err)
	}
	if err := requireAllowedDirectoryEntries(releaseFD, map[string]struct{}{}, "retired release"); err != nil {
		return err
	}
	if err := unix.Unlinkat(releasesFD, releaseID, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("packagetxn: remove retired release directory: %w", err)
	}
	if err := unix.Fsync(releasesFD); err != nil {
		return fmt.Errorf("packagetxn: sync release retirement: %w", err)
	}
	return nil
}
