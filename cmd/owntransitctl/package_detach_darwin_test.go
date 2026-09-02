//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const testDarwinDetachReaderGID = 4242

func TestDetachDarwinPublicFileExactAndRetry(t *testing.T) {
	requireDarwinDetachRoot(t)
	directory, path := newDarwinDetachDirectory(t)
	contents := []byte("authenticated launcher fixture\n")
	writeDarwinDetachFile(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, contents)

	if err := detachDarwinTestLauncher(directory, darwinClientLauncherName, digestDarwinDetach(contents)); err != nil {
		t.Fatalf("detach exact launcher: %v", err)
	}
	assertDarwinDetachNameAbsent(t, path, darwinClientLauncherName)

	// Absence is an authenticated terminal state. Repeating the operation also
	// exercises the directory-sync path used after a crash following unlink.
	if err := detachDarwinTestLauncher(directory, darwinClientLauncherName, digestDarwinDetach(contents)); err != nil {
		t.Fatalf("retry already-detached launcher: %v", err)
	}
}

func TestDetachDarwinPublicFileAlreadyAbsent(t *testing.T) {
	directory, _ := newDarwinDetachDirectory(t)
	if err := detachDarwinTestLauncher(directory, darwinClientLauncherName, strings.Repeat("0", 64)); err != nil {
		t.Fatalf("sync already-detached launcher state: %v", err)
	}
}

func TestDetachDarwinPublicFileAcceptsDeactivatedRetry(t *testing.T) {
	requireDarwinDetachRoot(t)
	directory, path := newDarwinDetachDirectory(t)
	contents := []byte("authenticated deactivated launcher fixture\n")
	writeDarwinDetachFile(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o751, contents)

	if err := detachDarwinTestLauncher(directory, darwinClientLauncherName, digestDarwinDetach(contents)); err != nil {
		t.Fatalf("detach 0751 launcher residue: %v", err)
	}
	assertDarwinDetachNameAbsent(t, path, darwinClientLauncherName)
}

func TestDetachDarwinClientNamesResumeAfterPartialDetach(t *testing.T) {
	requireDarwinDetachRoot(t)
	directory, path := newDarwinDetachDirectory(t)
	launcherContents := []byte("authenticated launcher fixture\n")
	frontendContents := []byte("authenticated frontend fixture\n")
	writeDarwinDetachFile(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, launcherContents)
	writeDarwinDetachFile(t, path, darwinClientFrontendName, 0, 0o755, frontendContents)

	if err := detachDarwinTestLauncher(directory, darwinClientLauncherName, digestDarwinDetach(launcherContents)); err != nil {
		t.Fatalf("detach launcher before simulated interruption: %v", err)
	}
	assertDarwinDetachNameAbsent(t, path, darwinClientLauncherName)
	if _, err := os.Lstat(filepath.Join(path, darwinClientFrontendName)); err != nil {
		t.Fatalf("frontend unexpectedly changed before retry: %v", err)
	}

	// A retry first observes the already-absent launcher, then completes the
	// second public-name detach.
	if err := detachDarwinTestLauncher(directory, darwinClientLauncherName, digestDarwinDetach(launcherContents)); err != nil {
		t.Fatalf("retry detached launcher: %v", err)
	}
	if err := detachDarwinPublicFile(
		directory, darwinClientFrontendName, 0, digestDarwinDetach(frontendContents), maxDarwinClientFrontendBytes,
		[]uint32{0o755}, 0, "", "test Darwin client frontend",
	); err != nil {
		t.Fatalf("detach frontend on retry: %v", err)
	}
	assertDarwinDetachNameAbsent(t, path, darwinClientFrontendName)
}

func TestDetachDarwinPublicFileRemovesExactLegacySymlink(t *testing.T) {
	requireDarwinDetachRoot(t)
	directory, path := newDarwinDetachDirectory(t)
	name := darwinClientLauncherName
	linkPath := filepath.Join(path, name)
	if err := os.Symlink(darwinLegacyClientLauncherLink, linkPath); err != nil {
		t.Fatalf("create legacy selector: %v", err)
	}
	if err := os.Lchown(linkPath, 0, 0); err != nil {
		t.Fatalf("own legacy selector: %v", err)
	}

	if err := detachDarwinTestLauncher(directory, name, strings.Repeat("0", 64)); err != nil {
		t.Fatalf("detach exact legacy selector: %v", err)
	}
	assertDarwinDetachNameAbsent(t, path, name)
}

func TestDetachDarwinPublicFileRejectsWrongDigestAndType(t *testing.T) {
	t.Run("digest", func(t *testing.T) {
		requireDarwinDetachRoot(t)
		directory, path := newDarwinDetachDirectory(t)
		contents := []byte("authenticated launcher fixture\n")
		writeDarwinDetachFile(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, contents)
		wrongDigest := strings.Repeat("0", 64)
		if wrongDigest == digestDarwinDetach(contents) {
			t.Fatal("test digest unexpectedly matched fixture")
		}

		err := detachDarwinTestLauncher(directory, darwinClientLauncherName, wrongDigest)
		if err == nil || !strings.Contains(err.Error(), "digest or size") {
			t.Fatalf("wrong digest error = %v, want digest rejection", err)
		}
		statDarwinDetachName(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, 1)
	})

	t.Run("non-regular", func(t *testing.T) {
		directory, path := newDarwinDetachDirectory(t)
		name := darwinClientLauncherName
		if err := os.Mkdir(filepath.Join(path, name), 0o755); err != nil {
			t.Fatalf("create non-regular selector: %v", err)
		}

		err := detachDarwinTestLauncher(directory, name, strings.Repeat("0", 64))
		if err == nil || !strings.Contains(err.Error(), "not regular") {
			t.Fatalf("non-regular error = %v, want type rejection", err)
		}
		if info, err := os.Lstat(filepath.Join(path, name)); err != nil || !info.IsDir() {
			t.Fatalf("rejected non-regular selector was changed: info=%v err=%v", info, err)
		}
	})

	t.Run("unauthorized-symlink", func(t *testing.T) {
		requireDarwinDetachRoot(t)
		directory, path := newDarwinDetachDirectory(t)
		name := darwinClientLauncherName
		linkPath := filepath.Join(path, name)
		if err := os.Symlink("../attacker-controlled", linkPath); err != nil {
			t.Fatalf("create unauthorized selector: %v", err)
		}
		if err := os.Lchown(linkPath, 0, 0); err != nil {
			t.Fatalf("own unauthorized selector: %v", err)
		}

		err := detachDarwinTestLauncher(directory, name, strings.Repeat("0", 64))
		if err == nil || !strings.Contains(err.Error(), "exact legacy selector") {
			t.Fatalf("unauthorized symlink error = %v, want exact-target rejection", err)
		}
		if target, err := os.Readlink(linkPath); err != nil || target != "../attacker-controlled" {
			t.Fatalf("rejected unauthorized selector was changed: target=%q err=%v", target, err)
		}
	})
}

func TestAllowedDarwinDetachMode(t *testing.T) {
	allowed := []uint32{0o2751, 0o751}
	for _, mode := range allowed {
		if !allowedDarwinDetachMode(mode, allowed) {
			t.Fatalf("allowed mode %04o rejected", mode)
		}
	}
	for _, mode := range []uint32{0, 0o750, 0o755, 0o4751, 0o2771} {
		if allowedDarwinDetachMode(mode, allowed) {
			t.Fatalf("unlisted mode %04o accepted", mode)
		}
	}
}

func TestDetachDarwinPublicFileRejectsExtendedACL(t *testing.T) {
	requireDarwinDetachRoot(t)
	directory, path := newDarwinDetachDirectory(t)
	contents := []byte("authenticated ACL-bearing launcher fixture\n")
	writeDarwinDetachFile(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, contents)
	target := filepath.Join(path, darwinClientLauncherName)
	if output, err := exec.Command("/bin/chmod", "+a", "everyone allow read", target).CombinedOutput(); err != nil {
		t.Skipf("temporary filesystem cannot create a Darwin extended ACL: %v (%s)", err, strings.TrimSpace(string(output)))
	}

	err := detachDarwinTestLauncher(directory, darwinClientLauncherName, digestDarwinDetach(contents))
	if err == nil || !strings.Contains(err.Error(), "ACL") {
		t.Fatalf("extended-ACL error = %v, want ACL rejection", err)
	}
	statDarwinDetachName(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, 1)
}

func TestDetachDarwinPublicFileDeactivatesRetainedHardlink(t *testing.T) {
	requireDarwinDetachRoot(t)
	directory, path := newDarwinDetachDirectory(t)
	contents := []byte("authenticated launcher fixture\n")
	writeDarwinDetachFile(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, contents)
	alias := "retained-launcher-alias"
	if err := os.Link(filepath.Join(path, darwinClientLauncherName), filepath.Join(path, alias)); err != nil {
		t.Fatalf("retain launcher hard link: %v", err)
	}
	statDarwinDetachName(t, path, darwinClientLauncherName, testDarwinDetachReaderGID, 0o2751, 2)

	if err := detachDarwinTestLauncher(directory, darwinClientLauncherName, digestDarwinDetach(contents)); err != nil {
		t.Fatalf("detach hard-linked launcher: %v", err)
	}
	assertDarwinDetachNameAbsent(t, path, darwinClientLauncherName)
	statDarwinDetachName(t, path, alias, testDarwinDetachReaderGID, 0o751, 1)
}

func requireDarwinDetachRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned Darwin detach fixtures require a root test process")
	}
}

func newDarwinDetachDirectory(t *testing.T) (*os.File, string) {
	t.Helper()
	path := mustCanonicalTempDir(t)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("protect detach directory: %v", err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatalf("open detach directory: %v", err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close detach directory: %v", err)
		}
	})
	return directory, path
}

func writeDarwinDetachFile(t *testing.T, directory, name string, gid uint32, mode os.FileMode, contents []byte) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	// Ownership changes clear setgid on Darwin, so ownership must precede the
	// final activation mode just as it does in the production publisher.
	if err := os.Chown(path, 0, int(gid)); err != nil {
		t.Fatalf("own %s: %v", name, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("activate %s: %v", name, err)
	}
}

func detachDarwinTestLauncher(directory *os.File, name, digest string) error {
	return detachDarwinPublicFile(
		directory, name, testDarwinDetachReaderGID, digest, maxDarwinClientLauncherBytes,
		[]uint32{0o2751, 0o751}, 0o751, darwinLegacyClientLauncherLink, "test Darwin client launcher",
	)
}

func digestDarwinDetach(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func assertDarwinDetachNameAbsent(t *testing.T, directory, name string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s remains after detach: %v", name, err)
	}
}

func statDarwinDetachName(t *testing.T, directory, name string, gid, mode uint32, nlink uint16) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(filepath.Join(directory, name), &stat); err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != gid ||
		uint32(stat.Mode)&0o7777 != mode || stat.Nlink != nlink {
		t.Fatalf("%s metadata = uid:%d gid:%d mode:%04o nlink:%d, want uid:0 gid:%d mode:%04o nlink:%d",
			name, stat.Uid, stat.Gid, uint32(stat.Mode)&0o7777, stat.Nlink, gid, mode, nlink)
	}
}
