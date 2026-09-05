//go:build darwin || linux

// Package securefs provides a deliberately small dirfd-relative filesystem
// surface for OwnTransit target-local state. Paths below an opened root are
// always one validated component; callers cannot pass traversal paths.
package securefs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// MaxReadBytes is a defense-in-depth ceiling in addition to the smaller
	// per-call limit required by ReadFile.
	MaxReadBytes       int64 = 8 << 20
	maxComponentLength       = 128
	temporaryAttempts        = 32
)

var (
	// ErrClosed means the root dirfd has already been closed.
	ErrClosed = errors.New("securefs: root is closed")
	// ErrLocked means another process holds the requested advisory lock.
	ErrLocked = errors.New("securefs: lock is already held")
)

// Root owns a directory descriptor. Root methods never resolve paths outside
// that descriptor and are safe to use concurrently with Close.
type Root struct {
	mu   sync.RWMutex
	fd   int
	open bool
}

// Lock is an advisory exclusive flock held until Close.
type Lock struct {
	mu   sync.Mutex
	fd   int
	open bool
}

// OpenRoot opens an existing absolute directory without following a symlink in
// any path component. The path must be canonical so visually different paths
// cannot select the same state root.
func OpenRoot(path string) (*Root, error) {
	components, err := absoluteComponents(path)
	if err != nil {
		return nil, err
	}
	fd, err := openDirectoryChain(components)
	if err != nil {
		return nil, err
	}
	if err := requirePrivateRoot(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &Root{fd: fd, open: true}, nil
}

// CreateRoot exclusively creates a new canonical absolute root with fixed mode
// 0700. Existing parent directories are opened component-by-component without
// following symlinks. The new directory and its parent are both fsynced.
func CreateRoot(path string) (*Root, error) {
	components, err := absoluteComponents(path)
	if err != nil {
		return nil, err
	}
	parent, err := openDirectoryChain(components[:len(components)-1])
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	name := components[len(components)-1]
	if err := unix.Mkdirat(parent, name, 0o700); err != nil {
		return nil, fmt.Errorf("securefs: create root: %w", err)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open new root: %w", err)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: set new root permissions: %w", err)
	}
	if err := requirePrivateRoot(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: sync new root: %w", err)
	}
	if err := unix.Fsync(parent); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: sync new root parent: %w", err)
	}
	return &Root{fd: fd, open: true}, nil
}

// Close closes the root descriptor. It does not remove any state.
func (root *Root) Close() error {
	if root == nil {
		return nil
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if !root.open {
		return nil
	}
	fd := root.fd
	root.open = false
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("securefs: close root: %w", err)
	}
	return nil
}

// Sync durably orders completed changes to the root directory.
func (root *Root) Sync() error {
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync root directory: %w", err)
	}
	return nil
}

// MkdirExclusive creates exactly one child directory and syncs the parent.
func (root *Root) MkdirExclusive(name string, mode fs.FileMode) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	permissions, err := directoryPermissions(mode)
	if err != nil {
		return err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	if err := unix.Mkdirat(root.fd, name, permissions); err != nil {
		return fmt.Errorf("securefs: create directory %q: %w", name, err)
	}
	child, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("securefs: verify directory %q: %w", name, err)
	}
	if err := requireDirectory(child); err != nil {
		_ = unix.Close(child)
		return err
	}
	if err := unix.Fchmod(child, permissions); err != nil {
		_ = unix.Close(child)
		return fmt.Errorf("securefs: set directory %q permissions: %w", name, err)
	}
	if err := unix.Fsync(child); err != nil {
		_ = unix.Close(child)
		return fmt.Errorf("securefs: sync directory %q: %w", name, err)
	}
	if err := unix.Close(child); err != nil {
		return fmt.Errorf("securefs: close directory %q: %w", name, err)
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync parent after creating %q: %w", name, err)
	}
	return nil
}

// OpenDir opens exactly one existing child directory without following a
// symlink. The returned Root has an independent descriptor.
func (root *Root) OpenDir(name string) (*Root, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open directory %q: %w", name, err)
	}
	if err := requirePrivateRoot(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &Root{fd: fd, open: true}, nil
}

// CreateExclusive creates, writes, fsyncs and closes one new regular file,
// then syncs its parent. It never replaces an existing name.
func (root *Root) CreateExclusive(name string, data []byte, mode fs.FileMode) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	permissions, err := filePermissions(mode)
	if err != nil {
		return err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, permissions)
	if err != nil {
		return fmt.Errorf("securefs: create file %q: %w", name, err)
	}
	created := true
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if created {
			_ = unix.Unlinkat(root.fd, name, 0)
		}
	}()
	if err := prepareRegularFile(fd, permissions); err != nil {
		return err
	}
	if err := writeAll(fd, data); err != nil {
		return fmt.Errorf("securefs: write file %q: %w", name, err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securefs: sync file %q: %w", name, err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("securefs: close file %q: %w", name, err)
	}
	fd = -1
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync parent after creating %q: %w", name, err)
	}
	created = false
	return nil
}

// EnsureFile makes an interrupted create step idempotent. It creates and
// durably syncs a missing file, or succeeds for an existing non-writable-by-
// others, single-link regular file only when mode and contents are exact.
func (root *Root) EnsureFile(name string, data []byte, mode fs.FileMode) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if int64(len(data)) > MaxReadBytes {
		return fmt.Errorf("securefs: ensured file exceeds %d bytes", MaxReadBytes)
	}
	permissions, err := filePermissions(mode)
	if err != nil {
		return err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	for attempt := 0; attempt < 4; attempt++ {
		fd, stat, openErr := openRegularAt(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK)
		if openErr == nil {
			if uint32(stat.Mode)&0o7777 != permissions || stat.Size != int64(len(data)) {
				_ = unix.Close(fd)
				return fmt.Errorf("securefs: existing file %q differs in mode or size", name)
			}
			contents, readErr := readAllBounded(fd, int64(len(data)))
			var finalStat unix.Stat_t
			statErr := unix.Fstat(fd, &finalStat)
			closeErr := unix.Close(fd)
			if readErr != nil {
				return fmt.Errorf("securefs: verify existing file %q: %w", name, readErr)
			}
			if statErr != nil {
				return fmt.Errorf("securefs: reinspect existing file %q: %w", name, statErr)
			}
			if closeErr != nil {
				return fmt.Errorf("securefs: close existing file %q: %w", name, closeErr)
			}
			if finalStat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(finalStat.Nlink) != 1 ||
				uint32(finalStat.Mode)&0o7777 != permissions || finalStat.Size != int64(len(data)) ||
				!bytes.Equal(contents, data) {
				return fmt.Errorf("securefs: existing file %q changed or differs in contents", name)
			}
			return nil
		}
		if !errors.Is(openErr, unix.ENOENT) {
			return openErr
		}

		fd, createErr := unix.Openat(root.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, permissions)
		if errors.Is(createErr, unix.EEXIST) {
			continue
		}
		if createErr != nil {
			return fmt.Errorf("securefs: create ensured file %q: %w", name, createErr)
		}
		if prepareErr := prepareRegularFile(fd, permissions); prepareErr != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(root.fd, name, 0)
			return prepareErr
		}
		if writeErr := writeAll(fd, data); writeErr != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(root.fd, name, 0)
			return fmt.Errorf("securefs: write ensured file %q: %w", name, writeErr)
		}
		if syncErr := unix.Fsync(fd); syncErr != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(root.fd, name, 0)
			return fmt.Errorf("securefs: sync ensured file %q: %w", name, syncErr)
		}
		if closeErr := unix.Close(fd); closeErr != nil {
			_ = unix.Unlinkat(root.fd, name, 0)
			return fmt.Errorf("securefs: close ensured file %q: %w", name, closeErr)
		}
		if syncErr := unix.Fsync(root.fd); syncErr != nil {
			_ = unix.Unlinkat(root.fd, name, 0)
			return fmt.Errorf("securefs: sync parent after ensuring %q: %w", name, syncErr)
		}
		return nil
	}
	return fmt.Errorf("securefs: ensured file %q changed repeatedly", name)
}

// ReadFile reads one regular, single-link file through the root descriptor. A
// caller-supplied limit and the package ceiling are both enforced even if the
// file changes while it is read.
func (root *Root) ReadFile(name string, limit int64) ([]byte, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxReadBytes {
		return nil, fmt.Errorf("securefs: read limit must be within 1..%d bytes", MaxReadBytes)
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	fd, stat, err := openRegularAt(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if stat.Size < 0 || stat.Size > limit {
		return nil, fmt.Errorf("securefs: file %q exceeds the read limit", name)
	}

	contents := make([]byte, 0, int(stat.Size))
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := unix.Read(fd, buffer)
		if n > 0 {
			if int64(len(contents))+int64(n) > limit {
				return nil, fmt.Errorf("securefs: file %q exceeds the read limit", name)
			}
			contents = append(contents, buffer[:n]...)
		}
		if readErr != nil {
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			return nil, fmt.Errorf("securefs: read file %q: %w", name, readErr)
		}
		if n == 0 {
			return contents, nil
		}
	}
}

// ReplaceFile atomically replaces or creates one regular file in the root.
// Existing symlinks, non-regular files and multiply linked files are rejected.
// The temporary file is created exclusively in the same directory, fsynced,
// renamed with renameat, and followed by a directory fsync.
func (root *Root) ReplaceFile(name string, data []byte, mode fs.FileMode) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	permissions, err := filePermissions(mode)
	if err != nil {
		return err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	if err := inspectReplaceTarget(root.fd, name); err != nil {
		return err
	}

	temporary, fd, err := createTemporary(root.fd, permissions)
	if err != nil {
		return err
	}
	temporaryExists := true
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if temporaryExists {
			_ = unix.Unlinkat(root.fd, temporary, 0)
		}
	}()
	if err := prepareRegularFile(fd, permissions); err != nil {
		return err
	}
	if err := writeAll(fd, data); err != nil {
		return fmt.Errorf("securefs: write replacement for %q: %w", name, err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securefs: sync replacement for %q: %w", name, err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("securefs: close replacement for %q: %w", name, err)
	}
	fd = -1
	if err := unix.Renameat(root.fd, temporary, root.fd, name); err != nil {
		return fmt.Errorf("securefs: replace file %q: %w", name, err)
	}
	temporaryExists = false
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync parent after replacing %q: %w", name, err)
	}
	return nil
}

// UnlinkFile removes exactly one validated regular, single-link file and
// syncs its parent. It never follows a symlink and performs no recursive work.
func (root *Root) UnlinkFile(name string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	fd, _, err := openRegularAt(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return err
	}
	if err := unix.Unlinkat(root.fd, name, 0); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("securefs: unlink file %q: %w", name, err)
	}
	closeErr := unix.Close(fd)
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync parent after unlinking %q: %w", name, err)
	}
	if closeErr != nil {
		return fmt.Errorf("securefs: close unlinked file %q: %w", name, closeErr)
	}
	return nil
}

// RemoveDir removes exactly one empty, private child directory and syncs its
// parent. Non-empty directories and symlinks are rejected; removal is never
// recursive.
func (root *Root) RemoveDir(name string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("securefs: open directory %q for removal: %w", name, err)
	}
	if err := requirePrivateRoot(fd); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := unix.Unlinkat(root.fd, name, unix.AT_REMOVEDIR); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("securefs: remove empty directory %q: %w", name, err)
	}
	closeErr := unix.Close(fd)
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync parent after removing %q: %w", name, err)
	}
	if closeErr != nil {
		return fmt.Errorf("securefs: close removed directory %q: %w", name, closeErr)
	}
	return nil
}

// TryLock obtains a non-blocking exclusive advisory lock on one regular,
// single-link lock file. The file is created with mode 0600 if absent.
func (root *Root) TryLock(name string) (*Lock, error) {
	return root.tryFlock(name, unix.LOCK_EX)
}

// TrySharedLock holds a process-lifetime admission gate. A kill operation first
// persists denial, then obtains the exclusive lock to acknowledge that every
// previously admitted worker has stopped. Lock files must never be replaced.
func (root *Root) TrySharedLock(name string) (*Lock, error) {
	return root.tryFlock(name, unix.LOCK_SH)
}

func (root *Root) tryFlock(name string, operation int) (*Lock, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	fd, created, err := openLockFile(root.fd, name)
	if err != nil {
		return nil, err
	}
	if created {
		if err := unix.Fsync(root.fd); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("securefs: sync new lock file %q: %w", name, err)
		}
	}
	if err := unix.Flock(fd, operation|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("securefs: lock file %q: %w", name, err)
	}
	return &Lock{fd: fd, open: true}, nil
}

// Close releases the advisory lock and closes its descriptor.
func (lock *Lock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if !lock.open {
		return nil
	}
	fd := lock.fd
	lock.open = false
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	closeErr := unix.Close(fd)
	if unlockErr != nil {
		return fmt.Errorf("securefs: unlock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("securefs: close lock: %w", closeErr)
	}
	return nil
}

func validateComponent(name string) error {
	if name == "" || len(name) > maxComponentLength || name == "." || name == ".." {
		return errors.New("securefs: name must be one bounded fixed component")
	}
	for index := range name {
		character := name[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return errors.New("securefs: name contains a non-portable character")
		}
	}
	return nil
}

func absoluteComponents(path string) ([]string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errors.New("securefs: root must be a canonical absolute non-root path")
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.IndexByte(component, 0) >= 0 {
			return nil, errors.New("securefs: root contains an invalid path component")
		}
	}
	return components, nil
}

func openDirectoryChain(components []string) (int, error) {
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("securefs: open filesystem root: %w", err)
	}
	for _, component := range components {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("securefs: open root component: %w", openErr)
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return -1, fmt.Errorf("securefs: close root ancestor: %w", closeErr)
		}
		fd = next
	}
	return fd, nil
}

func filePermissions(mode fs.FileMode) (uint32, error) {
	// Roots are always private 0700 directories. Public certificates and
	// summaries may nevertheless be emitted 0644 for later copying; child
	// files may never be group/world writable or executable.
	if mode != mode.Perm() || mode.Perm() == 0 || mode.Perm()&0o111 != 0 || mode.Perm()&0o022 != 0 {
		return 0, errors.New("securefs: file mode must be nonzero, non-writable by others and non-executable")
	}
	return uint32(mode.Perm()), nil
}

func directoryPermissions(mode fs.FileMode) (uint32, error) {
	if mode != mode.Perm() || mode.Perm() == 0 || mode.Perm()&0o077 != 0 {
		return 0, errors.New("securefs: directory mode must be private and contain only permission bits")
	}
	return uint32(mode.Perm()), nil
}

func requireDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("securefs: inspect directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("securefs: descriptor is not a directory")
	}
	return nil
}

func requirePrivateRoot(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("securefs: inspect root directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("securefs: root descriptor is not a directory")
	}
	if stat.Uid != uint32(unix.Geteuid()) {
		return errors.New("securefs: root directory is not owned by the effective user")
	}
	if stat.Mode&0o077 != 0 {
		return errors.New("securefs: root directory has group or other permissions")
	}
	return nil
}

func prepareRegularFile(fd int, permissions uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("securefs: inspect new file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 {
		return errors.New("securefs: new file is not a single-link regular file")
	}
	if err := unix.Fchmod(fd, permissions); err != nil {
		return fmt.Errorf("securefs: set new file permissions: %w", err)
	}
	return nil
}

func openRegularAt(directory int, name string, flags int) (int, unix.Stat_t, error) {
	fd, err := unix.Openat(directory, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, fmt.Errorf("securefs: open file %q: %w", name, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, fmt.Errorf("securefs: inspect file %q: %w", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, fmt.Errorf("securefs: file %q must be a single-link regular file", name)
	}
	return fd, stat, nil
}

func inspectReplaceTarget(directory int, name string) error {
	fd, _, err := openRegularAt(directory, name, unix.O_RDONLY|unix.O_NONBLOCK)
	if err == nil {
		return unix.Close(fd)
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return fmt.Errorf("securefs: replacement target: %w", err)
}

func createTemporary(directory int, permissions uint32) (string, int, error) {
	var random [12]byte
	for attempt := 0; attempt < temporaryAttempts; attempt++ {
		if _, err := rand.Read(random[:]); err != nil {
			return "", -1, fmt.Errorf("securefs: generate temporary name: %w", err)
		}
		name := ".owntransit-tmp-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, permissions)
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, fmt.Errorf("securefs: create replacement file: %w", err)
		}
	}
	return "", -1, errors.New("securefs: could not allocate a unique replacement file")
}

func writeAll(fd int, data []byte) error {
	for len(data) > 0 {
		written, err := unix.Write(fd, data)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if written == 0 {
			return errors.New("zero-length write")
		}
		data = data[written:]
	}
	return nil
}

func readAllBounded(fd int, limit int64) ([]byte, error) {
	if limit < 0 || limit > MaxReadBytes {
		return nil, errors.New("invalid read bound")
	}
	contents := make([]byte, 0, int(limit))
	buffer := make([]byte, 32<<10)
	for {
		n, err := unix.Read(fd, buffer)
		if n > 0 {
			if int64(len(contents))+int64(n) > limit {
				return nil, errors.New("file exceeds expected size")
			}
			contents = append(contents, buffer[:n]...)
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			return contents, nil
		}
	}
}

func openLockFile(directory int, name string) (int, bool, error) {
	for attempt := 0; attempt < 4; attempt++ {
		fd, err := unix.Openat(directory, name, unix.O_RDWR|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		created := false
		if errors.Is(err, unix.ENOENT) {
			fd, err = unix.Openat(directory, name, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
			created = err == nil
			if errors.Is(err, unix.EEXIST) {
				continue
			}
		}
		if err != nil {
			return -1, false, fmt.Errorf("securefs: open lock file %q: %w", name, err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return -1, false, fmt.Errorf("securefs: inspect lock file %q: %w", name, err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 || stat.Mode&0o077 != 0 {
			_ = unix.Close(fd)
			return -1, false, fmt.Errorf("securefs: lock file %q must be a private single-link regular file", name)
		}
		if created {
			if err := unix.Fchmod(fd, 0o600); err != nil {
				_ = unix.Close(fd)
				return -1, false, fmt.Errorf("securefs: set lock file %q permissions: %w", name, err)
			}
			if err := unix.Fsync(fd); err != nil {
				_ = unix.Close(fd)
				return -1, false, fmt.Errorf("securefs: sync lock file %q: %w", name, err)
			}
		}
		return fd, created, nil
	}
	return -1, false, fmt.Errorf("securefs: lock file %q changed repeatedly", name)
}
