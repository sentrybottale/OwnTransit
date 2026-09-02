//go:build darwin || linux

package securefs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

const testCurrentTarget = "releases/aeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func openRootOwnedSymlinkFixture(t *testing.T, target string) (*ReadOnlyRoot, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned selector fixture requires root")
	}
	readerGID := os.Getegid()
	directory := filepath.Join(t.TempDir(), "role")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, 0, readerGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	selector := filepath.Join(directory, "current")
	if err := os.Symlink(target, selector); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(selector, 0, 0); err != nil {
		t.Fatal(err)
	}

	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := inspectReadOnlyDirectory(fd, 0, uint32(readerGID))
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	root := newReadOnlyRoot(fd, stat, 0, uint32(readerGID))
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("close fixture root: %v", err)
		}
	})
	return root, directory
}

func TestReadRootSymlinkAcceptsOnlyExactBoundedRootOwnedSelector(t *testing.T) {
	root, directory := openRootOwnedSymlinkFixture(t, testCurrentTarget)
	got, err := root.ReadRootSymlink("current", len(testCurrentTarget))
	if err != nil {
		t.Fatal(err)
	}
	if got != testCurrentTarget {
		t.Fatalf("selector=%q, want %q", got, testCurrentTarget)
	}

	if _, err := root.ReadRootSymlink("current", len(testCurrentTarget)-1); err == nil {
		t.Fatal("selector exceeding the authenticated target limit was accepted")
	}
	for _, name := range []string{"", ".", "../current", "nested/current", "current/"} {
		if _, err := root.ReadRootSymlink(name, len(testCurrentTarget)); err == nil {
			t.Errorf("non-component selector name %q accepted", name)
		}
	}
	if _, err := root.ReadRootSymlink("current", 0); err == nil {
		t.Fatal("zero selector read limit accepted")
	}

	selector := filepath.Join(directory, "current")
	if err := os.Lchown(selector, 0, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadRootSymlink("current", len(testCurrentTarget)); err == nil {
		t.Fatal("selector owned by a non-root group accepted")
	}
	if err := os.Lchown(selector, 0, 0); err != nil {
		t.Fatal(err)
	}

	alias := filepath.Join(directory, "selector-alias")
	if err := os.Link(selector, alias); err != nil {
		t.Logf("filesystem cannot hard-link a symlink fixture: %v", err)
	} else {
		if _, err := root.ReadRootSymlink("current", len(testCurrentTarget)); err == nil {
			t.Fatal("multiply linked selector accepted")
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Remove(selector); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selector, []byte(testCurrentTarget), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadRootSymlink("current", len(testCurrentTarget)); err == nil {
		t.Fatal("regular file selector accepted")
	}
}

func TestReadRootSymlinkUsesHeldDirectoryAndRechecksItsPolicy(t *testing.T) {
	root, directory := openRootOwnedSymlinkFixture(t, testCurrentTarget)
	parent := filepath.Dir(directory)
	heldPath := filepath.Join(parent, "held-role")
	if err := os.Rename(directory, heldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, 0, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	attackerTarget := "releases/aqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.Symlink(attackerTarget, filepath.Join(directory, "current")); err != nil {
		t.Fatal(err)
	}

	got, err := root.ReadRootSymlink("current", len(testCurrentTarget))
	if err != nil {
		t.Fatal(err)
	}
	if got != testCurrentTarget {
		t.Fatalf("held selector read %q after path replacement, want %q", got, testCurrentTarget)
	}

	if err := os.Chmod(heldPath, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadRootSymlink("current", len(testCurrentTarget)); err == nil {
		t.Fatal("selector accepted after held publication directory became writable")
	}
}
