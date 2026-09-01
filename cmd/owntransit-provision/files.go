package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const maxOfflineKeyFileSize int64 = 64 << 10

func createOutputRoot(path string) (*securefs.Root, error) {
	if path == "" {
		return nil, errors.New("output directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) {
		return nil, errors.New("output directory cannot be the filesystem root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("resolve output parent: %w", err)
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	root, err := securefs.CreateRoot(resolved)
	if err != nil {
		return nil, err
	}
	return root, nil
}

// readRegularFile opens one bounded regular file without following its final
// path component. Private input additionally requires 0600-style permissions.
func readRegularFile(path string, limit int64, private bool) ([]byte, error) {
	if path == "" || limit <= 0 || limit > securefs.MaxReadBytes {
		return nil, errors.New("input path and bounded read limit are required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open input %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open input %q: invalid file descriptor", path)
	}
	defer file.Close()

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, fmt.Errorf("inspect input %q: %w", path, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 1 || before.Size > limit {
		return nil, fmt.Errorf("input %q must be a bounded single-link regular file", path)
	}
	if private && (before.Uid != uint32(unix.Geteuid()) || os.FileMode(before.Mode).Perm()&0o077 != 0) {
		return nil, fmt.Errorf("private input %q must be owned by the effective user without group/world permissions", path)
	}

	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read input %q: %w", path, err)
	}
	if len(contents) < 1 || int64(len(contents)) > limit {
		return nil, fmt.Errorf("input %q changed size while being read", path)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, fmt.Errorf("reinspect input %q: %w", path, err)
	}
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Nlink != 1 || after.Size != int64(len(contents)) || before.Size != after.Size {
		return nil, fmt.Errorf("input %q changed while being read", path)
	}
	return contents, nil
}

// writeAtomicPublicFile publishes complete signed bytes under a previously
// absent name. linkat is the atomic no-replace commit: a competing target
// creation fails closed and a partial temporary file is never authoritative.
func writeAtomicPublicFile(path string, contents []byte) error {
	if path == "" || len(contents) == 0 || int64(len(contents)) > securefs.MaxReadBytes {
		return errors.New("bounded public output path and contents are required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve public output: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) {
		return errors.New("public output cannot be the filesystem root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return fmt.Errorf("resolve public output parent: %w", err)
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open public output parent: %w", err)
	}
	defer unix.Close(parentFD)
	target := filepath.Base(absolute)
	var targetStat unix.Stat_t
	if err := unix.Fstatat(parentFD, target, &targetStat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return fmt.Errorf("public output %q already exists", path)
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect public output %q: %w", path, err)
	}

	var temporary string
	fd := -1
	for attempt := 0; attempt < 32; attempt++ {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("generate output staging name: %w", err)
		}
		temporary = ".owntransit-output-" + hex.EncodeToString(nonce)
		fd, err = unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create public output staging file: %w", err)
		}
		break
	}
	if fd < 0 {
		return errors.New("could not allocate a unique public output staging file")
	}
	temporaryExists := true
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if temporaryExists {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o644); err != nil {
		return fmt.Errorf("set public output mode: %w", err)
	}
	for remaining := contents; len(remaining) != 0; {
		written, writeErr := unix.Write(fd, remaining)
		if written > 0 {
			remaining = remaining[written:]
		}
		if writeErr != nil {
			if errors.Is(writeErr, unix.EINTR) {
				continue
			}
			return fmt.Errorf("write public output: %w", writeErr)
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync public output: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("close public output: %w", err)
	}
	fd = -1
	if err := unix.Linkat(parentFD, temporary, parentFD, target, 0); err != nil {
		return fmt.Errorf("commit public output without replacement: %w", err)
	}
	if err := unix.Unlinkat(parentFD, temporary, 0); err != nil {
		_ = unix.Unlinkat(parentFD, target, 0)
		return fmt.Errorf("remove public output staging link: %w", err)
	}
	temporaryExists = false
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync public output parent: %w", err)
	}
	return nil
}
