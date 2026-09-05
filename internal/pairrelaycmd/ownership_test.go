//go:build linux || darwin

package pairrelaycmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnprivilegedStateStillRequiresPrivateOwnedFiles(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "relay")
	if _, err := Init(state, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := StateInfo(state); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(state, tokenKeyFile)
	if err := os.Chmod(key, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := StateInfo(state); err == nil {
		t.Fatal("unprivileged mode accepted publicly writable private state")
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "alias")
	if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	if _, err := StateInfo(link); err == nil {
		t.Fatal("unprivileged mode followed symlinked state")
	}
}
