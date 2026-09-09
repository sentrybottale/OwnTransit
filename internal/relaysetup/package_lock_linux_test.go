//go:build linux

package relaysetup

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func requirePackageLockFixture(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root fixture")
	}
	if _, err := os.Stat("/owntransit-relay-setup-fixture"); err != nil {
		t.Skip("requires explicit disposable relay fixture")
	}
	exe, err := os.Executable()
	if err != nil || filepath.Dir(exe) != "/usr/local/libexec/owntransit-relay-setup-check" {
		t.Fatal("unexpected fixture executable path")
	}
}

func TestManagedPackageLockHandoffChild(t *testing.T) {
	if os.Getenv("OWNTRANSIT_LOCK_HANDOFF_TEST") == "" {
		t.Skip("subprocess fixture only")
	}
	requirePackageLockFixture(t)
	lock, err := LockPackage(9)
	if os.Getenv("OWNTRANSIT_LOCK_HANDOFF_TEST") == "reject" {
		if err == nil {
			lock.Close()
			t.Fatal("accepted an unrelated inherited descriptor")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/sh", "-c", "test ! -e /proc/self/fd/9").CombinedOutput(); err != nil {
		t.Fatalf("lock reference escaped to helper subprocess: %v %s", err, out)
	}
}

func TestManagedPackageLockSerializesAndRetainsInheritedOwnership(t *testing.T) {
	requirePackageLockFixture(t)
	first, err := LockPackage(0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LockPackage(0)
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	file, err := os.OpenFile(packageManagerRoot+"/package.lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("package mutation was allowed during management")
	}
	first.Close()
	second.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if lock, err := LockPackage(0); err == nil {
		lock.Close()
		t.Fatal("management was allowed during package mutation")
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	exe, _ := os.Executable()
	for _, valid := range []bool{true, false} {
		fd := file
		mode := "accept"
		if !valid {
			fd, mode = devnull, "reject"
		}
		child := exec.Command(exe, "-test.run=^TestManagedPackageLockHandoffChild$", "-test.v")
		child.Env = append(os.Environ(), "OWNTRANSIT_LOCK_HANDOFF_TEST="+mode)
		child.ExtraFiles = []*os.File{devnull, devnull, devnull, devnull, devnull, devnull, fd}
		if out, err := child.CombinedOutput(); err != nil {
			t.Fatalf("handoff child: %v %s", err, out)
		}
	}
	if lock, err := LockPackage(0); err == nil {
		lock.Close()
		t.Fatal("helper released its parent installer's exclusive lock")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	last, err := LockPackage(0)
	if err != nil {
		t.Fatal(err)
	}
	last.Close()
}
