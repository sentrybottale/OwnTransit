//go:build darwin || linux

package securefs

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSharedAdmissionGateBlocksExclusiveAcknowledgement(t *testing.T) {
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	r, e := CreateRoot(filepath.Join(base, "gate"))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	a, e := r.TrySharedLock("active.lock")
	if e != nil {
		t.Fatal(e)
	}
	b, e := r.TrySharedLock("active.lock")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := r.TryLock("active.lock"); !errors.Is(e, ErrLocked) {
		t.Fatal("exclusive gate bypassed active users")
	}
	a.Close()
	if _, e := r.TryLock("active.lock"); !errors.Is(e, ErrLocked) {
		t.Fatal("exclusive gate bypassed remaining user")
	}
	b.Close()
	c, e := r.TryLock("active.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e := r.TrySharedLock("active.lock"); !errors.Is(e, ErrLocked) {
		t.Fatal("shared gate bypassed acknowledgement")
	}
}
