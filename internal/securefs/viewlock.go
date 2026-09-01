//go:build darwin || linux

package securefs

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// ViewLock is a descriptor-bound advisory lock on one exact file inside a
// validated publication root. It never exposes its descriptor.
type ViewLock struct {
	mu   sync.Mutex
	fd   int
	open bool
}

// TrySharedLock obtains the runtime lifetime side of an activation gate. The
// selected inode, exact contents, ownership, mode and ACL are checked after
// flock, and the root name must still select that same inode.
func (root *ReadOnlyRoot) TrySharedLock(name string, exactContents []byte) (*ViewLock, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if len(exactContents) == 0 || int64(len(exactContents)) > MaxReadBytes {
		return nil, errors.New("securefs: shared lock contents are invalid")
	}
	if root == nil {
		return nil, ErrReadOnlyClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrReadOnlyClosed
	}
	if err := requireReadOnlyCallerGroup(root.readerGID); err != nil {
		return nil, err
	}
	return lockViewFile(root.fd, name, 0, root.readerGID, exactContents, unix.LOCK_SH)
}

// TryExclusiveLock obtains the root lifecycle side of an activation gate
// through the already descriptor-pinned publication root.
func (root *ViewWriter) TryExclusiveLock(name string, exactContents []byte) (*ViewLock, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if len(exactContents) == 0 || int64(len(exactContents)) > MaxReadBytes {
		return nil, errors.New("securefs: exclusive lock contents are invalid")
	}
	if root == nil {
		return nil, ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	return lockViewFile(root.fd, name, 0, root.readerGID, exactContents, unix.LOCK_EX)
}

func lockViewFile(directory int, name string, ownerUID, readerGID uint32, exactContents []byte, operation int) (*ViewLock, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open publication lock %q: %w", name, err)
	}
	return lockOpenedViewFile(directory, name, fd, ownerUID, readerGID, exactContents, operation)
}

// lockOpenedViewFile takes ownership of fd. Keeping selection verification in
// this helper lets tests replace the directory name after open and prove that
// the old descriptor cannot become a parallel activation gate.
func lockOpenedViewFile(directory int, name string, fd int, ownerUID, readerGID uint32, exactContents []byte, operation int) (*ViewLock, error) {
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(fd)
		}
	}()
	before, err := inspectReadOnlyFile(fd, ownerUID, readerGID)
	if err != nil {
		return nil, fmt.Errorf("securefs: validate publication lock %q: %w", name, err)
	}
	if err := unix.Flock(fd, operation|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("securefs: lock publication file %q: %w", name, err)
	}
	locked := true
	defer func() {
		if locked {
			_ = unix.Flock(fd, unix.LOCK_UN)
		}
	}()
	var selected unix.Stat_t
	if err := unix.Fstatat(directory, name, &selected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fmt.Errorf("securefs: reselect publication lock %q: %w", name, err)
	}
	if selected.Dev != before.Dev || selected.Ino != before.Ino || selected.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("securefs: publication lock name changed before acquisition")
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, fmt.Errorf("securefs: seek publication lock %q: %w", name, err)
	}
	contents, err := readAllBounded(fd, int64(len(exactContents)))
	if err != nil {
		return nil, fmt.Errorf("securefs: read publication lock %q: %w", name, err)
	}
	after, err := inspectReadOnlyFile(fd, ownerUID, readerGID)
	if err != nil {
		return nil, fmt.Errorf("securefs: revalidate publication lock %q: %w", name, err)
	}
	if !sameReadOnlyFile(before, after) || !bytes.Equal(contents, exactContents) {
		return nil, errors.New("securefs: publication lock changed or has invalid contents")
	}
	closeOnError = false
	locked = false
	return &ViewLock{fd: fd, open: true}, nil
}

func (lock *ViewLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if !lock.open {
		return nil
	}
	lock.open = false
	unlockErr := unix.Flock(lock.fd, unix.LOCK_UN)
	closeErr := unix.Close(lock.fd)
	if unlockErr != nil {
		return fmt.Errorf("securefs: unlock publication file: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("securefs: close publication lock: %w", closeErr)
	}
	return nil
}
