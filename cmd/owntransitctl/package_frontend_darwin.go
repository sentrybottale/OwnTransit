//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
	"golang.org/x/sys/unix"
)

const (
	darwinClientFrontendDirectory = "/Library/OwnTransit/bin"
	darwinClientFrontendName      = "owntransit-cli"
	maxDarwinClientFrontendBytes  = 64 << 20
)

func publishDarwinClientFrontend(receipt []byte, runtimeIdentity packagetxn.RuntimeIdentity) error {
	identity, err := parseDarwinReaderIdentity(receipt)
	if err != nil || runtimeIdentity.Role != "client" || runtimeIdentity.OS != "darwin" ||
		!validPackageReleaseID(runtimeIdentity.ReleaseID) || !validPackageDigest(runtimeIdentity.ArtifactSHA256) {
		return errors.New("Darwin client frontend requires an authenticated client release and identity")
	}
	source := filepath.Join("/Library/OwnTransit/roles/client/releases", runtimeIdentity.ReleaseID, "owntransit-real")
	contents, err := readDarwinFrontendSource(source, identity.readerGID, runtimeIdentity.ArtifactSHA256)
	if err != nil {
		return err
	}
	directoryInfo, err := os.Lstat(darwinClientFrontendDirectory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o755 {
		return errors.New("Darwin client frontend directory is invalid")
	}
	if stat, ok := directoryInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 || stat.Gid != 0 {
		return errors.New("Darwin client frontend directory is not root:wheel")
	}
	target := filepath.Join(darwinClientFrontendDirectory, darwinClientFrontendName)
	if info, err := os.Lstat(target); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
			return errors.New("existing Darwin client frontend boundary is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(darwinClientFrontendDirectory, ".owntransit-cli.*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	// Keep the staging inode root-only until its complete bytes are durable.
	if err := temporary.Chmod(0o755); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return err
	}
	committed = true
	directory, err := os.Open(darwinClientFrontendDirectory)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func readDarwinFrontendSource(path string, readerGID uint32, expectedDigest string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("authenticated Darwin client frontend source is absent")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(before, after) || after.Mode().Perm() != 0o750 || stat.Uid != 0 || stat.Gid != readerGID || stat.Nlink != 1 || after.Size() <= 0 || after.Size() > maxDarwinClientFrontendBytes {
		return nil, errors.New("authenticated Darwin client frontend source metadata is invalid")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxDarwinClientFrontendBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maxDarwinClientFrontendBytes {
		return nil, errors.New("authenticated Darwin client frontend source exceeds its bound")
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return nil, errors.New("authenticated Darwin client frontend source digest changed")
	}
	if err := unix.Access(path, unix.X_OK); err != nil {
		return nil, errors.New("authenticated Darwin client frontend source is not executable by root")
	}
	return contents, nil
}
