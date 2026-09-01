//go:build darwin || linux

package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateOpenReadReplaceAndSync(t *testing.T) {
	parent := canonicalTempDir(t)
	path := filepath.Join(parent, "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	defer root.Close()

	if err := root.CreateExclusive("state.json", []byte("first"), 0o600); err != nil {
		t.Fatalf("CreateExclusive: %v", err)
	}
	if err := root.CreateExclusive("state.json", []byte("duplicate"), 0o600); err == nil {
		t.Fatal("CreateExclusive accepted an existing file")
	}
	contents, err := root.ReadFile("state.json", 5)
	if err != nil || string(contents) != "first" {
		t.Fatalf("ReadFile = %q, %v", contents, err)
	}
	if _, err := root.ReadFile("state.json", 4); err == nil {
		t.Fatal("ReadFile ignored its bound")
	}
	if err := root.ReplaceFile("state.json", []byte("second"), 0o600); err != nil {
		t.Fatalf("ReplaceFile: %v", err)
	}
	contents, err = root.ReadFile("state.json", 64)
	if err != nil || string(contents) != "second" {
		t.Fatalf("ReadFile after replacement = %q, %v", contents, err)
	}
	if err := root.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if err := root.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := root.ReadFile("state.json", 64); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadFile after close = %v, want ErrClosed", err)
	}
	reopened, err := OpenRoot(path)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer reopened.Close()
}

func TestNamesCannotTraverseRoot(t *testing.T) {
	root, _ := newRoot(t)
	defer root.Close()
	for _, name := range []string{"", ".", "..", "../state", "child/state", "/absolute", "bad name", strings.Repeat("a", maxComponentLength+1)} {
		if err := root.CreateExclusive(name, []byte("x"), 0o600); err == nil {
			t.Errorf("CreateExclusive accepted %q", name)
		}
		if _, err := root.ReadFile(name, 10); err == nil {
			t.Errorf("ReadFile accepted %q", name)
		}
	}
}

func TestEnsureFileIsExactAndIdempotent(t *testing.T) {
	root, path := newRoot(t)
	defer root.Close()
	if err := root.EnsureFile("request.json", []byte("request"), 0o600); err != nil {
		t.Fatalf("first EnsureFile: %v", err)
	}
	if err := root.EnsureFile("request.json", []byte("request"), 0o600); err != nil {
		t.Fatalf("idempotent EnsureFile: %v", err)
	}
	if err := root.EnsureFile("request.json", []byte("changed"), 0o600); err == nil {
		t.Fatal("EnsureFile accepted different contents")
	}
	if err := os.Chmod(filepath.Join(path, "request.json"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureFile("request.json", []byte("request"), 0o600); err == nil {
		t.Fatal("EnsureFile accepted different permissions")
	}
	oversized := make([]byte, MaxReadBytes+1)
	if err := root.EnsureFile("large", oversized, 0o600); err == nil {
		t.Fatal("EnsureFile accepted oversized contents")
	}
}

func TestOpenRootRejectsSymlinkAndSharedMode(t *testing.T) {
	parent := canonicalTempDir(t)
	realPath := filepath.Join(parent, "real")
	if err := os.Mkdir(realPath, 0o700); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(parent, "link")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(linkPath); err == nil {
		t.Fatal("OpenRoot followed a final symlink")
	}
	childPath := filepath.Join(realPath, "child")
	if err := os.Mkdir(childPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(filepath.Join(linkPath, "child")); err == nil {
		t.Fatal("OpenRoot followed an intermediate symlink")
	}
	if err := os.Chmod(realPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(realPath); err == nil {
		t.Fatal("OpenRoot accepted a group-accessible root")
	}
}

func TestReadAndReplaceRejectLinksAndSpecialFiles(t *testing.T) {
	root, path := newRoot(t)
	defer root.Close()
	if err := root.CreateExclusive("first", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(path, "first"), filepath.Join(path, "second")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("first", 64); err == nil {
		t.Fatal("ReadFile accepted a multiply linked file")
	}
	if err := root.ReplaceFile("first", []byte("replacement"), 0o600); err == nil {
		t.Fatal("ReplaceFile accepted a multiply linked target")
	}

	outside := filepath.Join(canonicalTempDir(t), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("linked", 64); err == nil {
		t.Fatal("ReadFile followed a symlink")
	}
	if err := root.ReplaceFile("linked", []byte("replacement"), 0o600); err == nil {
		t.Fatal("ReplaceFile replaced a symlink")
	}
	contents, err := os.ReadFile(outside)
	if err != nil || string(contents) != "outside" {
		t.Fatalf("outside file changed: %q, %v", contents, err)
	}

	if err := os.Mkdir(filepath.Join(path, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile("directory", 64); err == nil {
		t.Fatal("ReadFile accepted a directory")
	}
}

func TestPrivateChildDirectoryAndAdvisoryLock(t *testing.T) {
	root, _ := newRoot(t)
	defer root.Close()
	if err := root.MkdirExclusive("records", 0o700); err != nil {
		t.Fatalf("MkdirExclusive: %v", err)
	}
	child, err := root.OpenDir("records")
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	defer child.Close()
	if err := child.CreateExclusive("record.json", []byte("record"), 0o600); err != nil {
		t.Fatalf("child CreateExclusive: %v", err)
	}

	first, err := root.TryLock("state.lock")
	if err != nil {
		t.Fatalf("first TryLock: %v", err)
	}
	if _, err := root.TryLock("state.lock"); !errors.Is(err, ErrLocked) {
		t.Fatalf("second TryLock = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close lock: %v", err)
	}
	second, err := root.TryLock("state.lock")
	if err != nil {
		t.Fatalf("TryLock after release: %v", err)
	}
	defer second.Close()
}

func TestOpenDirRejectsSymlinkAndHardlinkedLock(t *testing.T) {
	root, path := newRoot(t)
	defer root.Close()
	if err := os.Mkdir(filepath.Join(path, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(path, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.OpenDir("alias"); err == nil {
		t.Fatal("OpenDir followed a symlink")
	}

	lock, err := root.TryLock("state.lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(path, "state.lock"), filepath.Join(path, "other.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.TryLock("state.lock"); err == nil {
		t.Fatal("TryLock accepted a multiply linked lock file")
	}
}

func TestUnlinkAndRemoveDirAreNonRecursive(t *testing.T) {
	root, path := newRoot(t)
	defer root.Close()
	if err := root.CreateExclusive("record", []byte("record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.UnlinkFile("record"); err != nil {
		t.Fatalf("UnlinkFile: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(path, "record")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unlinked file still exists: %v", err)
	}

	if err := root.MkdirExclusive("empty", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.RemoveDir("empty"); err != nil {
		t.Fatalf("RemoveDir empty: %v", err)
	}
	if err := root.MkdirExclusive("nonempty", 0o700); err != nil {
		t.Fatal(err)
	}
	child, err := root.OpenDir("nonempty")
	if err != nil {
		t.Fatal(err)
	}
	if err := child.CreateExclusive("kept", []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.RemoveDir("nonempty"); err == nil {
		t.Fatal("RemoveDir recursively removed a nonempty directory")
	}
	if _, err := os.Stat(filepath.Join(path, "nonempty", "kept")); err != nil {
		t.Fatalf("nonempty directory contents changed: %v", err)
	}
}

func newRoot(t *testing.T) (*Root, string) {
	t.Helper()
	path := filepath.Join(canonicalTempDir(t), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	return root, path
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	return path
}
