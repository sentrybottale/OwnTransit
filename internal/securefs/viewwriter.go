//go:build darwin || linux

package securefs

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"

	"golang.org/x/sys/unix"
)

// ViewWriter is the privileged, deliberately separate counterpart to
// ReadOnlyRoot. It may mutate only one root-owned, dedicated-reader-group
// publication tree. Runtime processes never receive this type.
type ViewWriter struct {
	mu        sync.RWMutex
	fd        int
	open      bool
	readerGID uint32
}

// CreateViewRoot exclusively creates a root:readerGID mode-0750 publication
// root. Every existing ancestor is root-owned, non-writable by group/other and
// free of an extended ACL. The caller must be root.
func CreateViewRoot(path string, readerGID int) (*ViewWriter, error) {
	validated, err := validateViewWriterCaller(readerGID)
	if err != nil {
		return nil, err
	}
	components, err := absoluteComponents(path)
	if err != nil {
		return nil, err
	}
	parent, err := openViewWriterChain(components[:len(components)-1], 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	name := components[len(components)-1]
	if err := unix.Mkdirat(parent, name, 0o700); err != nil {
		return nil, fmt.Errorf("securefs: create publication root: %w", err)
	}
	created := true
	defer func() {
		if created {
			_ = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		}
	}()
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open publication root: %w", err)
	}
	if err := prepareViewDirectory(fd, validated); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: sync publication root: %w", err)
	}
	if err := unix.Fsync(parent); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: sync publication-root parent: %w", err)
	}
	created = false
	return &ViewWriter{fd: fd, open: true, readerGID: validated}, nil
}

// OpenViewRoot opens an existing publication root for a root lifecycle
// transaction. It applies the same complete ancestor and final-root policy as
// CreateViewRoot.
func OpenViewRoot(path string, readerGID int) (*ViewWriter, error) {
	validated, err := validateViewWriterCaller(readerGID)
	if err != nil {
		return nil, err
	}
	components, err := absoluteComponents(path)
	if err != nil {
		return nil, err
	}
	fd, err := openViewWriterChain(components, validated)
	if err != nil {
		return nil, err
	}
	return &ViewWriter{fd: fd, open: true, readerGID: validated}, nil
}

func validateViewWriterCaller(readerGID int) (uint32, error) {
	if unix.Geteuid() != 0 {
		return 0, errors.New("securefs: publication mutation requires root")
	}
	if readerGID <= 0 || uint64(readerGID) >= math.MaxUint32 {
		return 0, errors.New("securefs: publication reader GID must identify a non-root dedicated group")
	}
	return uint32(readerGID), nil
}

// openViewWriterChain opens a canonical component list from the filesystem
// root. A zero finalGID means every selected component is an ancestor; a
// nonzero finalGID applies the exact publication-root policy to the final one.
func openViewWriterChain(components []string, finalGID uint32) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("securefs: open filesystem root for publication: %w", err)
	}
	if len(components) == 0 {
		if err := inspectReadOnlyAncestor(fd, 0); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		return fd, nil
	}
	for index, component := range components {
		if err := inspectReadOnlyAncestor(fd, 0); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("securefs: validate publication ancestor: %w", err)
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("securefs: open publication component: %w", openErr)
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return -1, fmt.Errorf("securefs: close publication ancestor: %w", closeErr)
		}
		fd = next
		if finalGID != 0 && index == len(components)-1 {
			if _, err := inspectReadOnlyDirectory(fd, 0, finalGID); err != nil {
				_ = unix.Close(fd)
				return -1, fmt.Errorf("securefs: validate publication root: %w", err)
			}
		}
	}
	if finalGID == 0 {
		if err := inspectReadOnlyAncestor(fd, 0); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("securefs: validate publication parent: %w", err)
		}
	}
	return fd, nil
}

func prepareViewDirectory(fd int, readerGID uint32) error {
	if err := unix.Fchown(fd, 0, int(readerGID)); err != nil {
		return fmt.Errorf("securefs: set publication directory ownership: %w", err)
	}
	if err := unix.Fchmod(fd, uint32(ReadOnlyDirectoryMode)); err != nil {
		return fmt.Errorf("securefs: set publication directory mode: %w", err)
	}
	if _, err := inspectReadOnlyDirectory(fd, 0, readerGID); err != nil {
		return err
	}
	return nil
}

func prepareViewFile(fd int, readerGID uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("securefs: inspect publication file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 {
		return errors.New("securefs: publication file is not a single-link regular file")
	}
	if err := unix.Fchown(fd, 0, int(readerGID)); err != nil {
		return fmt.Errorf("securefs: set publication file ownership: %w", err)
	}
	if err := unix.Fchmod(fd, uint32(ReadOnlyFileMode)); err != nil {
		return fmt.Errorf("securefs: set publication file mode: %w", err)
	}
	if _, err := inspectReadOnlyFile(fd, 0, readerGID); err != nil {
		return err
	}
	return nil
}

func preparePrivatePublicationFile(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("securefs: inspect private publication file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 {
		return errors.New("securefs: private publication file is not a single-link regular file")
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return fmt.Errorf("securefs: own private publication file: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("securefs: protect private publication file: %w", err)
	}
	if err := verifyNoExtendedACL(fd, false); err != nil {
		return err
	}
	return nil
}

func (root *ViewWriter) Close() error {
	if root == nil {
		return nil
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if !root.open {
		return nil
	}
	root.open = false
	if err := unix.Close(root.fd); err != nil {
		return fmt.Errorf("securefs: close publication root: %w", err)
	}
	return nil
}

func (root *ViewWriter) Sync() error {
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync publication root: %w", err)
	}
	return nil
}

func (root *ViewWriter) MkdirExclusive(name string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	if err := unix.Mkdirat(root.fd, name, 0o700); err != nil {
		return fmt.Errorf("securefs: create publication directory %q: %w", name, err)
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("securefs: open publication directory %q: %w", name, err)
	}
	defer unix.Close(fd)
	if err := prepareViewDirectory(fd, root.readerGID); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securefs: sync publication directory %q: %w", name, err)
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync publication parent: %w", err)
	}
	return nil
}

// MkdirPrivateExclusive creates a root:root mode-0700 staging directory below
// the view. The reader group cannot traverse or observe its contents. The
// returned ordinary private Root may prepare exact bytes before ExposeDir makes
// the complete directory visible in one final chmod step.
func (root *ViewWriter) MkdirPrivateExclusive(name string) (*Root, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	if err := unix.Mkdirat(root.fd, name, 0o700); err != nil {
		return nil, fmt.Errorf("securefs: create private publication stage %q: %w", name, err)
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open private publication stage %q: %w", name, err)
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: own private publication stage: %w", err)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: protect private publication stage: %w", err)
	}
	if err := requirePrivateRoot(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := verifyNoExtendedACL(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: sync private publication stage: %w", err)
	}
	if err := unix.Fsync(root.fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("securefs: sync publication parent: %w", err)
	}
	return &Root{fd: fd, open: true}, nil
}

// OpenPrivateDir reopens an interrupted, still-unexposed root:root 0700 stage.
func (root *ViewWriter) OpenPrivateDir(name string) (*Root, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open private publication stage %q: %w", name, err)
	}
	if err := requirePrivateRoot(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := verifyNoExtendedACL(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &Root{fd: fd, open: true}, nil
}

// ExposeDir proves that a private stage contains exactly the named private
// files, converts every file to root:readerGID 0640, syncs them, and changes the
// directory to root:readerGID 0750 last. No partial file set is traversable by
// the runtime group.
func (root *ViewWriter) ExposeDir(name string, fileNames []string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if len(fileNames) == 0 {
		return errors.New("securefs: publication stage file set is empty")
	}
	want := append([]string(nil), fileNames...)
	sort.Strings(want)
	for index, fileName := range want {
		if err := validateComponent(fileName); err != nil {
			return err
		}
		if index > 0 && want[index-1] == fileName {
			return errors.New("securefs: publication stage file set contains a duplicate")
		}
	}
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	directory, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("securefs: open publication stage for exposure: %w", err)
	}
	defer unix.Close(directory)
	if err := requirePrivateRoot(directory); err != nil {
		return err
	}
	if err := verifyNoExtendedACL(directory, true); err != nil {
		return err
	}
	actual, err := directoryNames(directory)
	if err != nil {
		return err
	}
	if len(actual) != len(want) {
		return errors.New("securefs: publication stage does not contain the exact file set")
	}
	for index := range actual {
		if actual[index] != want[index] {
			return errors.New("securefs: publication stage does not contain the exact file set")
		}
	}
	for _, fileName := range want {
		fd, err := unix.Openat(directory, fileName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("securefs: open staged publication file %q: %w", fileName, err)
		}
		if err := prepareViewFile(fd, root.readerGID); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := unix.Fsync(fd); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("securefs: sync exposed publication file %q: %w", fileName, err)
		}
		if err := unix.Close(fd); err != nil {
			return fmt.Errorf("securefs: close exposed publication file %q: %w", fileName, err)
		}
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("securefs: sync publication stage files: %w", err)
	}
	if err := prepareViewDirectory(directory, root.readerGID); err != nil {
		return err
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("securefs: sync exposed publication directory: %w", err)
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync publication parent: %w", err)
	}
	return nil
}

// RetireDir removes an exposed generation containing only a subset of the
// caller's exact allowed names. Accepting a subset makes interrupted retirement
// resumable; any unexpected entry fails closed. The caller must hold the
// exclusive activation gate, so no compliant runtime retains this generation.
func (root *ViewWriter) RetireDir(name string, allowedNames []string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	allowed := make(map[string]struct{}, len(allowedNames))
	for _, fileName := range allowedNames {
		if err := validateComponent(fileName); err != nil {
			return err
		}
		if _, duplicate := allowed[fileName]; duplicate {
			return errors.New("securefs: retired publication file set contains a duplicate")
		}
		allowed[fileName] = struct{}{}
	}
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	directory, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("securefs: open retired publication directory: %w", err)
	}
	if _, err := inspectReadOnlyDirectory(directory, 0, root.readerGID); err != nil {
		_ = unix.Close(directory)
		return err
	}
	actual, err := directoryNames(directory)
	if err != nil {
		_ = unix.Close(directory)
		return err
	}
	for _, fileName := range actual {
		if _, ok := allowed[fileName]; !ok {
			_ = unix.Close(directory)
			return fmt.Errorf("securefs: retired publication directory contains unexpected file %q", fileName)
		}
		fd, err := unix.Openat(directory, fileName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = unix.Close(directory)
			return fmt.Errorf("securefs: open retired publication file %q: %w", fileName, err)
		}
		if _, err := inspectReadOnlyFile(fd, 0, root.readerGID); err != nil {
			_ = unix.Close(fd)
			_ = unix.Close(directory)
			return err
		}
		if err := unix.Unlinkat(directory, fileName, 0); err != nil {
			_ = unix.Close(fd)
			_ = unix.Close(directory)
			return fmt.Errorf("securefs: remove retired publication file %q: %w", fileName, err)
		}
		if err := unix.Close(fd); err != nil {
			_ = unix.Close(directory)
			return fmt.Errorf("securefs: close retired publication file %q: %w", fileName, err)
		}
	}
	if err := unix.Fsync(directory); err != nil {
		_ = unix.Close(directory)
		return fmt.Errorf("securefs: sync retired publication directory: %w", err)
	}
	if err := unix.Close(directory); err != nil {
		return fmt.Errorf("securefs: close retired publication directory: %w", err)
	}
	if err := unix.Unlinkat(root.fd, name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("securefs: remove retired publication directory: %w", err)
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync publication parent after retirement: %w", err)
	}
	return nil
}

func directoryNames(fd int) ([]string, error) {
	// dup(2) shares a directory offset with the held descriptor. Repeated exact
	// checks would therefore see EOF and fail even though the directory is
	// unchanged. Reopen the already-held directory itself to obtain an
	// independent open-file description without resolving an external path.
	duplicate, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: reopen publication stage descriptor: %w", err)
	}
	file := os.NewFile(uintptr(duplicate), "publication-stage")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, errors.New("securefs: invalid publication stage descriptor")
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("securefs: enumerate publication stage: %w", err)
	}
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.Name()
	}
	sort.Strings(result)
	return result, nil
}

func (root *ViewWriter) OpenDir(name string) (*ViewWriter, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open publication directory %q: %w", name, err)
	}
	if _, err := inspectReadOnlyDirectory(fd, 0, root.readerGID); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &ViewWriter{fd: fd, open: true, readerGID: root.readerGID}, nil
}

func (root *ViewWriter) CreateExclusive(name string, data []byte) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if len(data) == 0 || int64(len(data)) > MaxReadBytes {
		return errors.New("securefs: publication file size is invalid")
	}
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("securefs: create publication file %q: %w", name, err)
	}
	created := true
	defer func() {
		_ = unix.Close(fd)
		if created {
			_ = unix.Unlinkat(root.fd, name, 0)
		}
	}()
	if err := preparePrivatePublicationFile(fd); err != nil {
		return err
	}
	if err := writeAll(fd, data); err != nil {
		return fmt.Errorf("securefs: write publication file %q: %w", name, err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securefs: sync publication file %q: %w", name, err)
	}
	// The final name exists as root:root 0600 while bytes are written and
	// synced. Only complete bytes become group-readable.
	if err := prepareViewFile(fd, root.readerGID); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securefs: sync publication file permissions %q: %w", name, err)
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync publication parent: %w", err)
	}
	created = false
	return nil
}

func (root *ViewWriter) ReplaceFile(name string, data []byte) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if len(data) == 0 || int64(len(data)) > MaxReadBytes {
		return errors.New("securefs: publication file size is invalid")
	}
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	if err := inspectViewReplaceTarget(root.fd, name, root.readerGID); err != nil {
		return err
	}
	temporary, fd, err := createTemporary(root.fd, 0o600)
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
	if err := preparePrivatePublicationFile(fd); err != nil {
		return err
	}
	if err := writeAll(fd, data); err != nil {
		return fmt.Errorf("securefs: write publication replacement: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securefs: sync publication replacement: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("securefs: close publication replacement: %w", err)
	}
	fd = -1
	if err := unix.Renameat(root.fd, temporary, root.fd, name); err != nil {
		return fmt.Errorf("securefs: replace publication file %q: %w", name, err)
	}
	temporaryExists = false
	// The temporary name and replacement target remain root:root 0600 until
	// after complete bytes have been fsynced and atomically selected. A reader
	// can observe a transient permission denial, never partial or future bytes.
	fd, err = unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("securefs: open selected publication replacement: %w", err)
	}
	if err := prepareViewFile(fd, root.readerGID); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securefs: sync selected publication permissions: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("securefs: close selected publication replacement: %w", err)
	}
	fd = -1
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync publication parent: %w", err)
	}
	return nil
}

func inspectViewReplaceTarget(directory int, name string, readerGID uint32) error {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("securefs: inspect publication replacement target: %w", err)
	}
	defer unix.Close(fd)
	if _, err := inspectRecoverablePublicationFile(fd, readerGID); err != nil {
		return fmt.Errorf("securefs: publication replacement target: %w", err)
	}
	return nil
}

// ReadRecoverableFile reads either an ordinary published root:reader-GID 0640
// file or the exact root:root 0600 final-name residue that ReplaceFile can
// leave if power is lost after its atomic rename but before permission
// exposure. Runtime readers never receive ViewWriter and therefore cannot use
// this recovery-only exception.
func (root *ViewWriter) ReadRecoverableFile(name string, limit int64) ([]byte, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxReadBytes {
		return nil, errors.New("securefs: recoverable publication read limit is invalid")
	}
	if root == nil {
		return nil, ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open recoverable publication file %q: %w", name, err)
	}
	defer unix.Close(fd)
	before, err := inspectRecoverablePublicationFile(fd, root.readerGID)
	if err != nil {
		return nil, err
	}
	if before.Size < 0 || before.Size > limit {
		return nil, errors.New("securefs: recoverable publication file exceeds read limit")
	}
	contents, err := readAllBounded(fd, limit)
	if err != nil {
		return nil, err
	}
	after, err := inspectRecoverablePublicationFile(fd, root.readerGID)
	if err != nil {
		return nil, err
	}
	if !sameReadOnlyFile(before, after) || int64(len(contents)) != after.Size {
		return nil, errors.New("securefs: recoverable publication file changed while being read")
	}
	return contents, nil
}

func inspectRecoverablePublicationFile(fd int, readerGID uint32) (unix.Stat_t, error) {
	if stat, err := inspectReadOnlyFile(fd, 0, readerGID); err == nil {
		return stat, nil
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("securefs: inspect interrupted publication file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 || stat.Uid != 0 || stat.Gid != 0 || uint32(stat.Mode)&0o7777 != 0o600 {
		return unix.Stat_t{}, errors.New("securefs: interrupted publication file is not exact root:root 0600")
	}
	if err := verifyNoExtendedACL(fd, false); err != nil {
		return unix.Stat_t{}, err
	}
	return stat, nil
}

func (root *ViewWriter) ReadFile(name string, limit int64) ([]byte, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxReadBytes {
		return nil, errors.New("securefs: publication read limit is invalid")
	}
	if root == nil {
		return nil, ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return nil, ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securefs: open publication file %q: %w", name, err)
	}
	defer unix.Close(fd)
	stat, err := inspectReadOnlyFile(fd, 0, root.readerGID)
	if err != nil {
		return nil, err
	}
	if stat.Size < 0 || stat.Size > limit {
		return nil, errors.New("securefs: publication file exceeds read limit")
	}
	return readAllBounded(fd, limit)
}

// ValidateExactFiles rejects every directory entry except the sorted unique
// regular-file set named by the caller. It does not return directory contents
// or a descriptor and performs no mutation.
func (root *ViewWriter) ValidateExactFiles(names []string) error {
	want := append([]string(nil), names...)
	sort.Strings(want)
	for index, name := range want {
		if err := validateComponent(name); err != nil {
			return err
		}
		if index > 0 && want[index-1] == name {
			return errors.New("securefs: publication file set contains a duplicate")
		}
	}
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	actual, err := directoryNames(root.fd)
	if err != nil {
		return err
	}
	if len(actual) != len(want) {
		return errors.New("securefs: publication directory does not contain the exact file set")
	}
	for index, name := range actual {
		if name != want[index] {
			return errors.New("securefs: publication directory does not contain the exact file set")
		}
		fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("securefs: open publication member %q: %w", name, err)
		}
		if _, err := inspectReadOnlyFile(fd, 0, root.readerGID); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := unix.Close(fd); err != nil {
			return fmt.Errorf("securefs: close publication member %q: %w", name, err)
		}
	}
	return nil
}

func (root *ViewWriter) UnlinkFile(name string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if root == nil {
		return ErrClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrClosed
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("securefs: open publication file for removal: %w", err)
	}
	if _, err := inspectReadOnlyFile(fd, 0, root.readerGID); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := unix.Unlinkat(root.fd, name, 0); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("securefs: unlink publication file: %w", err)
	}
	closeErr := unix.Close(fd)
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("securefs: sync publication parent: %w", err)
	}
	return closeErr
}
