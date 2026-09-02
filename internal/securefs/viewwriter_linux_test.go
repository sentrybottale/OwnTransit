//go:build linux

package securefs

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const viewWriterReaderHelperEnvironment = "OWNTRANSIT_VIEW_WRITER_READER_HELPER"

func copyTestExecutableForUnprivilegedReader(t *testing.T) string {
	t.Helper()
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	directory, err := os.MkdirTemp("/tmp", "owntransit-viewwriter-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(directory, 0o700)
		_ = os.RemoveAll(directory)
	})
	destinationPath := filepath.Join(directory, "securefs.test")
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if _, err := io.Copy(destination, source); err != nil {
		t.Fatal(err)
	}
	if err := destination.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := destination.Chmod(0o555); err != nil {
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	return destinationPath
}

// TestViewWriterReaderHelper is selected explicitly in a child process whose
// credentials are reduced to the dedicated runtime reader. It continuously
// enumerates the public tree while the root parent creates and replaces a
// large file. A staging name may be enumerable, but it must never be openable;
// the final name may yield only one complete old or new value.
func TestViewWriterReaderHelper(t *testing.T) {
	rootPath := os.Getenv(viewWriterReaderHelperEnvironment)
	if rootPath == "" {
		return
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stopped)
	}()
	for {
		select {
		case <-stopped:
			return
		default:
		}
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			value, readErr := os.ReadFile(filepath.Join(rootPath, entry.Name()))
			if entry.Name() != "active.json" {
				if readErr == nil {
					t.Fatalf("runtime reader opened private publication name %q", entry.Name())
				}
				continue
			}
			if readErr != nil {
				continue // A transient root:root 0600 final name is fail closed.
			}
			if len(value) != 2<<20 || !allPublicationBytesEqual(value, 'a') && !allPublicationBytesEqual(value, 'b') {
				t.Fatalf("runtime reader observed partial or unexpected active bytes: length=%d", len(value))
			}
		}
	}
}

func TestViewWriterNeverExposesPartialOrTemporaryMaterial(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("root is required to exercise the cross-principal publication boundary")
	}
	base, err := os.MkdirTemp("/var/lib", "owntransit-viewwriter-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	readerGID := 65532
	rootPath := filepath.Join(base, "runtime")
	root, err := CreateViewRoot(rootPath, readerGID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	command := exec.Command(copyTestExecutableForUnprivilegedReader(t), "-test.run=^TestViewWriterReaderHelper$")
	command.Env = append(os.Environ(), viewWriterReaderHelperEnvironment+"="+rootPath)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: 65534, Gid: uint32(readerGID), Groups: []uint32{uint32(readerGID)},
	}}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("reader helper did not start: line=%q err=%v stderr=%q", line, err, stderr.String())
	}

	first := bytes.Repeat([]byte{'a'}, 2<<20)
	second := bytes.Repeat([]byte{'b'}, 2<<20)
	if err := root.CreateExclusive("active.json", first); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 16; iteration++ {
		value := first
		if iteration%2 == 0 {
			value = second
		}
		if err := root.ReplaceFile("active.json", value); err != nil {
			t.Fatal(err)
		}
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	remainder, _ := io.ReadAll(reader)
	waitErr := command.Wait()
	if waitErr != nil {
		t.Fatalf("reader helper: %v stdout=%q stderr=%q gid=%s", waitErr, remainder, stderr.String(), strconv.Itoa(readerGID))
	}
	information, err := os.Stat(filepath.Join(rootPath, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := information.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != uint32(readerGID) || information.Mode().Perm() != ReadOnlyFileMode {
		t.Fatalf("published file metadata = uid/gid/mode %#v/%v", stat, information.Mode())
	}
}

func allPublicationBytesEqual(value []byte, expected byte) bool {
	for _, current := range value {
		if current != expected {
			return false
		}
	}
	return true
}
