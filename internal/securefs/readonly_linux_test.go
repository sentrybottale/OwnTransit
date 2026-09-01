//go:build linux

package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadOnlyRootReadsExactTree(t *testing.T) {
	root, path := newReadOnlyTestRoot(t)
	defer root.Close()

	if err := writeReadOnlyTestFile(filepath.Join(path, "config.json"), []byte("configuration")); err != nil {
		t.Fatal(err)
	}
	contents, err := root.ReadFile("config.json", 64)
	if err != nil || string(contents) != "configuration" {
		t.Fatalf("ReadFile = %q, %v", contents, err)
	}
	if _, err := root.ReadFile("config.json", 4); err == nil {
		t.Fatal("ReadFile ignored the caller bound")
	}
	if _, err := root.ReadFile("config.json", MaxReadBytes+1); err == nil {
		t.Fatal("ReadFile ignored the package bound")
	}

	metadata, err := root.Metadata()
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if metadata.UID != uint32(unix.Geteuid()) || metadata.GID != uint32(unix.Getegid()) || metadata.Mode != ReadOnlyDirectoryMode {
		t.Fatalf("Metadata = %+v", metadata)
	}
	if err := root.Recheck(); err != nil {
		t.Fatalf("Recheck: %v", err)
	}

	childPath := filepath.Join(path, "records")
	if err := os.Mkdir(childPath, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(childPath, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	child, err := root.OpenDir("records")
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	if err := child.Close(); err != nil {
		t.Fatalf("close child: %v", err)
	}

	if err := root.Close(); err != nil {
		t.Fatalf("close root: %v", err)
	}
	if _, err := root.Metadata(); !errors.Is(err, ErrReadOnlyClosed) {
		t.Fatalf("Metadata after close = %v, want ErrReadOnlyClosed", err)
	}
	if err := root.Recheck(); !errors.Is(err, ErrReadOnlyClosed) {
		t.Fatalf("Recheck after close = %v, want ErrReadOnlyClosed", err)
	}
}

func TestReadOnlyRootRecheckRejectsChangedMode(t *testing.T) {
	root, path := newReadOnlyTestRoot(t)
	defer root.Close()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.Recheck(); err == nil {
		t.Fatal("Recheck accepted a held directory whose mode changed")
	}
}

func TestReadOnlyRootRejectsWritableAncestorAndSymlinkComponents(t *testing.T) {
	base, ownerUID, readerGID := newReadOnlyTestBase(t)

	writable := filepath.Join(base, "writable")
	if err := os.Mkdir(writable, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o770); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(writable, "runtime")
	if err := os.Mkdir(runtime, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtime, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if _, err := openReadOnlyTestChain(base, []string{"writable", "runtime"}, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a group-writable ancestor")
	}

	realPath := filepath.Join(base, "real")
	if err := os.Mkdir(realPath, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(realPath, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := openReadOnlyTestChain(base, []string{"alias"}, ownerUID, readerGID); err == nil {
		t.Fatal("followed a final symlink")
	}
	if _, err := openReadOnlyTestChain(base, []string{"alias", "child"}, ownerUID, readerGID); err == nil {
		t.Fatal("followed an ancestor symlink")
	}
}

func TestReadOnlyRootRejectsWrongTreeAndFileMode(t *testing.T) {
	base, ownerUID, readerGID := newReadOnlyTestBase(t)
	path := filepath.Join(base, "runtime")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openReadOnlyTestChain(base, []string{"runtime"}, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a runtime tree whose mode was not exactly 0750")
	}

	if err := os.Chmod(path, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	root, err := openReadOnlyTestChain(base, []string{"runtime"}, ownerUID, readerGID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	filePath := filepath.Join(path, "config.json")
	if err := os.WriteFile(filePath, []byte("configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("config.json", 64); err == nil {
		t.Fatal("accepted a runtime file whose mode was not exactly 0640")
	}
}

func TestReadOnlyRootRejectsSymlinkHardlinkAndSpecialFile(t *testing.T) {
	root, path := newReadOnlyTestRoot(t)
	defer root.Close()

	outside := filepath.Join(canonicalTempDir(t), "outside")
	if err := writeReadOnlyTestFile(outside, []byte("outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("linked", 64); err == nil {
		t.Fatal("followed a file symlink")
	}

	original := filepath.Join(path, "original")
	if err := writeReadOnlyTestFile(original, []byte("material")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, filepath.Join(path, "duplicate")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("original", 64); err == nil {
		t.Fatal("accepted a multiply linked regular file")
	}

	fifo := filepath.Join(path, "pipe")
	if err := unix.Mkfifo(fifo, uint32(ReadOnlyFileMode)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fifo, ReadOnlyFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("pipe", 64); err == nil {
		t.Fatal("accepted a FIFO")
	}

	directory := filepath.Join(path, "directory")
	if err := os.Mkdir(directory, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("directory", 64); err == nil {
		t.Fatal("accepted a directory as a regular file")
	}
}

func TestReadOnlyRootRejectsExtendedACLAttribute(t *testing.T) {
	base, ownerUID, readerGID := newReadOnlyTestBase(t)
	path := filepath.Join(base, "runtime")
	if err := os.Mkdir(path, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(path, "user.owntransit_acl_probe", []byte("present"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skipf("filesystem cannot create a test ACL-named xattr: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := openReadOnlyTestChain(base, []string{"runtime"}, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a directory carrying an ACL-named extended attribute")
	}
}

func TestOpenReadOnlyRootRejectsWorldWritableAbsoluteAncestor(t *testing.T) {
	if unix.Getegid() == 0 {
		t.Skip("the exported API requires a non-root dedicated reader group")
	}
	path := filepath.Join(canonicalTempDir(t), "runtime")
	if err := os.Mkdir(path, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnlyRoot(path, unix.Getegid()); err == nil {
		t.Fatal("accepted an absolute path below a world-writable temporary ancestor")
	}
}

func TestViewLockUsesOneSelectedInodeAndBlocksExclusiveMutation(t *testing.T) {
	root, path := newReadOnlyTestRoot(t)
	defer root.Close()
	const contents = "activation-gate\n"
	lockPath := filepath.Join(path, "activation.lock")
	if err := writeReadOnlyTestFile(lockPath, []byte(contents)); err != nil {
		t.Fatal(err)
	}
	ownerUID, readerGID := uint32(unix.Geteuid()), uint32(unix.Getegid())
	shared, err := lockViewFile(root.fd, "activation.lock", ownerUID, readerGID, []byte(contents), unix.LOCK_SH)
	if err != nil {
		t.Fatalf("shared lock: %v", err)
	}
	if _, err := lockViewFile(root.fd, "activation.lock", ownerUID, readerGID, []byte(contents), unix.LOCK_EX); !errors.Is(err, ErrLocked) {
		t.Fatalf("exclusive lock while shared is held = %v, want ErrLocked", err)
	}
	if err := shared.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := lockViewFile(root.fd, "activation.lock", ownerUID, readerGID, []byte(contents), unix.LOCK_EX)
	if err != nil {
		t.Fatalf("exclusive lock after release: %v", err)
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestViewLockRejectsNameSwapBetweenOpenAndFlock(t *testing.T) {
	root, path := newReadOnlyTestRoot(t)
	defer root.Close()
	const contents = "activation-gate\n"
	lockPath := filepath.Join(path, "activation.lock")
	if err := writeReadOnlyTestFile(lockPath, []byte(contents)); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat(root.fd, "activation.lock", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(lockPath, filepath.Join(path, "old-activation.lock")); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := writeReadOnlyTestFile(lockPath, []byte(contents)); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	_, err = lockOpenedViewFile(
		root.fd, "activation.lock", fd,
		uint32(unix.Geteuid()), uint32(unix.Getegid()), []byte(contents), unix.LOCK_SH,
	)
	if err == nil {
		t.Fatal("descriptor-bound lock accepted a replaced activation-lock name")
	}
}

func newReadOnlyTestRoot(t *testing.T) (*ReadOnlyRoot, string) {
	t.Helper()
	base, ownerUID, readerGID := newReadOnlyTestBase(t)
	path := filepath.Join(base, "runtime")
	if err := os.Mkdir(path, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	root, err := openReadOnlyTestChain(base, []string{"runtime"}, ownerUID, readerGID)
	if err != nil {
		t.Fatalf("open read-only test root: %v", err)
	}
	return root, path
}

func newReadOnlyTestBase(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	base := canonicalTempDir(t)
	if err := os.Chmod(base, ReadOnlyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	return base, uint32(unix.Geteuid()), uint32(unix.Getegid())
}

func openReadOnlyTestChain(base string, components []string, ownerUID, readerGID uint32) (*ReadOnlyRoot, error) {
	fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return openReadOnlyDirectoryChain(fd, components, readOnlyPolicy{ownerUID: ownerUID, readerGID: readerGID})
}

func writeReadOnlyTestFile(path string, contents []byte) error {
	if err := os.WriteFile(path, contents, ReadOnlyFileMode); err != nil {
		return err
	}
	return os.Chmod(path, ReadOnlyFileMode)
}
