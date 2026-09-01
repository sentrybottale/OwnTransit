package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maxPublicBootstrapFile int64 = 256 << 10

type publicOutput struct {
	parentFD int
	name     string
	open     bool
}

func resolveStateRoot(path string) (string, error) {
	if path == "" {
		return "", errors.New("state root is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve state root: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) {
		return "", errors.New("state root cannot be the filesystem root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("resolve state parent: %w", err)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func preparePublicOutput(path string) (*publicOutput, error) {
	if path == "" {
		return nil, errors.New("public output path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve public output: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) {
		return nil, errors.New("public output cannot be the filesystem root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("resolve public output parent: %w", err)
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open public output parent: %w", err)
	}
	name := filepath.Base(absolute)
	var stat unix.Stat_t
	err = unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("public output %q already exists", path)
	}
	if !errors.Is(err, unix.ENOENT) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect public output %q: %w", path, err)
	}
	return &publicOutput{parentFD: fd, name: name, open: true}, nil
}

func (output *publicOutput) Close() error {
	if output == nil || !output.open {
		return nil
	}
	output.open = false
	if err := unix.Close(output.parentFD); err != nil {
		return fmt.Errorf("close public output parent: %w", err)
	}
	return nil
}

func (output *publicOutput) Write(data []byte) error {
	if output == nil || !output.open || len(data) == 0 {
		return errors.New("public output and non-empty data are required")
	}
	fd, err := unix.Openat(
		output.parentFD,
		output.name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o644,
	)
	if err != nil {
		return fmt.Errorf("create public output: %w", err)
	}
	created := true
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if created {
			_ = unix.Unlinkat(output.parentFD, output.name, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o644); err != nil {
		return fmt.Errorf("set public output permissions: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect public output: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return errors.New("public output is not a single-link regular file")
	}
	for len(data) > 0 {
		written, writeErr := unix.Write(fd, data)
		if written > 0 {
			data = data[written:]
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
	if err := unix.Fsync(output.parentFD); err != nil {
		return fmt.Errorf("sync public output parent: %w", err)
	}
	created = false
	return nil
}

func readPublicFile(path string) ([]byte, error) {
	return readBoundedPublicFile(path, maxPublicBootstrapFile)
}

func readBoundedPublicFile(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("public input path is required")
	}
	if limit <= 0 {
		return nil, errors.New("public input size limit must be positive")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open public input %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open public input %q: invalid file descriptor", path)
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, fmt.Errorf("inspect public input %q: %w", path, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 1 || before.Size > limit {
		return nil, fmt.Errorf("public input %q must be a bounded single-link regular file", path)
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read public input %q: %w", path, err)
	}
	if len(contents) < 1 || int64(len(contents)) > limit {
		return nil, fmt.Errorf("public input %q changed size while being read", path)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, fmt.Errorf("reinspect public input %q: %w", path, err)
	}
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Nlink != 1 || after.Size != int64(len(contents)) || before.Size != after.Size {
		return nil, fmt.Errorf("public input %q changed while being read", path)
	}
	return contents, nil
}
