//go:build darwin || linux

package securefs

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// ReadOnlyDirectoryMode is the only accepted runtime-view directory mode.
	// Root retains mutation authority; the dedicated runtime group may only
	// traverse and read the directory.
	ReadOnlyDirectoryMode fs.FileMode = 0o750
	// ReadOnlyFileMode is the only accepted runtime-view regular-file mode.
	// Runtime processes receive read access through their primary group and no
	// write access to the material they consume.
	ReadOnlyFileMode fs.FileMode = 0o640
)

var (
	// ErrReadOnlyClosed means a read-only root descriptor has been closed.
	ErrReadOnlyClosed = errors.New("securefs: read-only root is closed")
	// ErrReadOnlyACLVerificationUnavailable is returned when the platform
	// cannot prove, without CGO, that an extended ACL does not grant authority
	// beyond the validated Unix mode. It is a fail-closed qualification and
	// activation residual, not permission to continue with a weaker check.
	ErrReadOnlyACLVerificationUnavailable = errors.New("securefs: CGO-free extended ACL verification is unavailable on this platform")
)

// VerifyNoExtendedACLFD authoritatively proves that an already-open file or
// directory descriptor has no platform extended ACL. It is exported only so
// other internal privileged filesystem boundaries can share the same
// descriptor-based Darwin/Linux verifier instead of duplicating platform ABI
// code or falling back to path-based inspection.
func VerifyNoExtendedACLFD(fd int, directory bool) error {
	return verifyNoExtendedACL(fd, directory)
}

// ReadOnlyMetadata is descriptor-derived immutable identity and ownership
// information for an opened runtime-view directory.
type ReadOnlyMetadata struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   fs.FileMode
}

// ReadOnlyRoot is a non-mutating descriptor-relative view of root-owned
// runtime material. Its method set intentionally contains no create, replace,
// rename, unlink, chmod, chown, sync, or lock operation.
//
// Every opened directory remains pinned by descriptor. Child names are one
// bounded portable component, and files are opened without following symlinks.
type ReadOnlyRoot struct {
	mu        sync.RWMutex
	fd        int
	open      bool
	ownerUID  uint32
	readerGID uint32
	metadata  ReadOnlyMetadata
}

// OpenReadOnlyRoot opens a canonical absolute runtime-view directory one
// component at a time without following symlinks.
//
// All ancestors, including the filesystem root, must be root-owned directories
// with no group or world write bit and no extended access-control list. The
// final directory must be exactly root:readerGID mode 0750. readerGID must be a
// non-root dedicated group and the caller's effective primary GID must match it
// exactly; supplementary-group membership is not accepted as the authority.
func OpenReadOnlyRoot(path string, readerGID int) (*ReadOnlyRoot, error) {
	components, err := absoluteComponents(path)
	if err != nil {
		return nil, err
	}
	for _, component := range components {
		if err := validateComponent(component); err != nil {
			return nil, err
		}
	}
	validatedGID, err := validateReadOnlyReaderGID(readerGID, unix.Getegid())
	if err != nil {
		return nil, err
	}

	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open filesystem root for read-only view: %w", err)
	}
	return openReadOnlyDirectoryChain(fd, components, readOnlyPolicy{
		ownerUID:  0,
		readerGID: validatedGID,
	})
}

// Close releases the held directory descriptor. It never changes filesystem
// state and is idempotent.
func (root *ReadOnlyRoot) Close() error {
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
		return fmt.Errorf("securefs: close read-only root: %w", err)
	}
	return nil
}

// Metadata returns descriptor-derived metadata captured when the directory was
// opened. The returned value contains no mutable reference or file descriptor.
func (root *ReadOnlyRoot) Metadata() (ReadOnlyMetadata, error) {
	if root == nil {
		return ReadOnlyMetadata{}, ErrReadOnlyClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ReadOnlyMetadata{}, ErrReadOnlyClosed
	}
	return root.metadata, nil
}

// Recheck revalidates the held directory immediately before a security-
// sensitive use such as opening a network connection. It checks the caller's
// current effective primary GID, descriptor identity, exact ownership/mode,
// and absence of an extended ACL. It resolves no pathname and mutates nothing.
func (root *ReadOnlyRoot) Recheck() error {
	if root == nil {
		return ErrReadOnlyClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrReadOnlyClosed
	}
	if err := requireReadOnlyCallerGroup(root.readerGID); err != nil {
		return err
	}
	stat, err := inspectReadOnlyDirectory(root.fd, root.ownerUID, root.readerGID)
	if err != nil {
		return fmt.Errorf("securefs: revalidate read-only root: %w", err)
	}
	if uint64(stat.Dev) != root.metadata.Device || uint64(stat.Ino) != root.metadata.Inode {
		return errors.New("securefs: held read-only root identity changed")
	}
	return nil
}

// OpenDir opens one exact child runtime-view directory. The returned handle is
// independent of its parent and applies the same root:reader-group 0750 and
// no-ACL policy.
func (root *ReadOnlyRoot) OpenDir(name string) (*ReadOnlyRoot, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
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

	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open read-only directory %q: %w", name, err)
	}
	stat, err := inspectReadOnlyDirectory(fd, root.ownerUID, root.readerGID)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: validate read-only directory %q: %w", name, err)
	}
	return newReadOnlyRoot(fd, stat, root.ownerUID, root.readerGID), nil
}

// ReadFile reads one exact root:reader-group mode-0640, single-link regular
// file through the held directory descriptor. Both the caller limit and the
// package-wide MaxReadBytes ceiling are enforced before and during the read.
func (root *ReadOnlyRoot) ReadFile(name string, limit int64) ([]byte, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxReadBytes {
		return nil, fmt.Errorf("securefs: read-only limit must be within 1..%d bytes", MaxReadBytes)
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

	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open read-only file %q: %w", name, err)
	}
	defer unix.Close(fd)

	before, err := inspectReadOnlyFile(fd, root.ownerUID, root.readerGID)
	if err != nil {
		return nil, fmt.Errorf("securefs: validate read-only file %q: %w", name, err)
	}
	if before.Size < 0 || before.Size > limit {
		return nil, fmt.Errorf("securefs: read-only file %q exceeds the read limit", name)
	}
	contents, err := readAllBounded(fd, limit)
	if err != nil {
		return nil, fmt.Errorf("securefs: read read-only file %q: %w", name, err)
	}

	after, err := inspectReadOnlyFile(fd, root.ownerUID, root.readerGID)
	if err != nil {
		return nil, fmt.Errorf("securefs: revalidate read-only file %q: %w", name, err)
	}
	if !sameReadOnlyFile(before, after) || int64(len(contents)) != after.Size {
		return nil, fmt.Errorf("securefs: read-only file %q changed while being read", name)
	}
	return contents, nil
}

type readOnlyPolicy struct {
	ownerUID  uint32
	readerGID uint32
}

func validateReadOnlyReaderGID(expected, effective int) (uint32, error) {
	if expected <= 0 || uint64(expected) >= math.MaxUint32 {
		return 0, errors.New("securefs: read-only reader GID must identify a non-root dedicated group")
	}
	if effective != expected {
		return 0, fmt.Errorf("securefs: effective primary GID %d does not match dedicated reader GID %d", effective, expected)
	}
	return uint32(expected), nil
}

func requireReadOnlyCallerGroup(readerGID uint32) error {
	if uint32(unix.Getegid()) != readerGID {
		return fmt.Errorf("securefs: effective primary GID no longer matches dedicated reader GID %d", readerGID)
	}
	return nil
}

// openReadOnlyDirectoryChain takes ownership of startFD whether it succeeds or
// fails. Production passes the filesystem-root descriptor; tests use the same
// chain logic below an already validated disposable fixture.
func openReadOnlyDirectoryChain(startFD int, components []string, policy readOnlyPolicy) (*ReadOnlyRoot, error) {
	if startFD < 0 || len(components) == 0 {
		if startFD >= 0 {
			_ = unix.Close(startFD)
		}
		return nil, errors.New("securefs: read-only directory chain is empty")
	}
	fd := startFD
	for index, component := range components {
		if err := inspectReadOnlyAncestor(fd, policy.ownerUID); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("securefs: validate read-only ancestor: %w", err)
		}
		if err := validateComponent(component); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("securefs: open read-only root component: %w", err)
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return nil, fmt.Errorf("securefs: close read-only root ancestor: %w", closeErr)
		}
		fd = next
		if index == len(components)-1 {
			stat, err := inspectReadOnlyDirectory(fd, policy.ownerUID, policy.readerGID)
			if err != nil {
				_ = unix.Close(fd)
				return nil, fmt.Errorf("securefs: validate read-only root: %w", err)
			}
			return newReadOnlyRoot(fd, stat, policy.ownerUID, policy.readerGID), nil
		}
	}
	_ = unix.Close(fd)
	return nil, errors.New("securefs: read-only directory chain did not select a root")
}

func newReadOnlyRoot(fd int, stat unix.Stat_t, ownerUID, readerGID uint32) *ReadOnlyRoot {
	return &ReadOnlyRoot{
		fd:        fd,
		open:      true,
		ownerUID:  ownerUID,
		readerGID: readerGID,
		metadata: ReadOnlyMetadata{
			Device: uint64(stat.Dev),
			Inode:  uint64(stat.Ino),
			UID:    stat.Uid,
			GID:    stat.Gid,
			Mode:   fs.FileMode(stat.Mode & 0o7777),
		},
	}
}

func inspectReadOnlyAncestor(fd int, ownerUID uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect ancestor: %w", err)
	}
	if err := validateReadOnlyAncestorStat(stat, ownerUID); err != nil {
		return err
	}
	if err := verifyNoExtendedACL(fd, true); err != nil {
		return err
	}
	return nil
}

func inspectReadOnlyDirectory(fd int, ownerUID, readerGID uint32) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("inspect directory: %w", err)
	}
	if err := validateReadOnlyDirectoryStat(stat, ownerUID, readerGID); err != nil {
		return unix.Stat_t{}, err
	}
	if err := verifyNoExtendedACL(fd, true); err != nil {
		return unix.Stat_t{}, err
	}
	return stat, nil
}

func inspectReadOnlyFile(fd int, ownerUID, readerGID uint32) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("inspect file: %w", err)
	}
	if err := validateReadOnlyFileStat(stat, ownerUID, readerGID); err != nil {
		return unix.Stat_t{}, err
	}
	if err := verifyNoExtendedACL(fd, false); err != nil {
		return unix.Stat_t{}, err
	}
	return stat, nil
}

func validateReadOnlyAncestorStat(stat unix.Stat_t, ownerUID uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("securefs: read-only ancestor is not a directory")
	}
	if stat.Uid != ownerUID {
		return errors.New("securefs: read-only ancestor is not root-owned")
	}
	if stat.Mode&0o022 != 0 {
		return errors.New("securefs: read-only ancestor is writable by group or other")
	}
	return nil
}

func validateReadOnlyDirectoryStat(stat unix.Stat_t, ownerUID, readerGID uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("securefs: read-only tree entry is not a directory")
	}
	if stat.Uid != ownerUID || stat.Gid != readerGID {
		return errors.New("securefs: read-only directory ownership does not match root:reader-group")
	}
	if uint32(stat.Mode)&0o7777 != uint32(ReadOnlyDirectoryMode) {
		return fmt.Errorf("securefs: read-only directory mode must be exactly %04o", ReadOnlyDirectoryMode)
	}
	return nil
}

func validateReadOnlyFileStat(stat unix.Stat_t, ownerUID, readerGID uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("securefs: read-only entry is not a regular file")
	}
	if uint64(stat.Nlink) != 1 {
		return errors.New("securefs: read-only file must have exactly one link")
	}
	if stat.Uid != ownerUID || stat.Gid != readerGID {
		return errors.New("securefs: read-only file ownership does not match root:reader-group")
	}
	if uint32(stat.Mode)&0o7777 != uint32(ReadOnlyFileMode) {
		return fmt.Errorf("securefs: read-only file mode must be exactly %04o", ReadOnlyFileMode)
	}
	return nil
}

func sameReadOnlyFile(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino &&
		first.Mode == second.Mode && first.Nlink == second.Nlink &&
		first.Uid == second.Uid && first.Gid == second.Gid &&
		first.Size == second.Size
}
