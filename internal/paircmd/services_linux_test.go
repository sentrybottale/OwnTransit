//go:build linux

package paircmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

// Real root paths are exercised only in the explicitly marked disposable
// container. Ordinary go test cannot modify an operator's systemd setup.
func TestNamedReceiverServicesAreScopedAndPreserveDefault(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root fixture")
	}
	if _, err := os.Stat("/owntransit-pair-service-fixture"); err != nil {
		t.Skip("requires explicit fixture marker")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(executable) != "/usr/local/libexec/owntransit-pair-service-check" {
		t.Fatal("unexpected root fixture executable")
	}
	if err = os.MkdirAll(receiverUnits, 0755); err != nil {
		t.Fatal(err)
	}
	template := []byte("[Unit]\nConditionPathIsDirectory=" + originalReceiverState + "\n[Service]\nType=notify\nExecStart=" + executable + " pair serve --state " + originalReceiverState + "\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL\nReadWritePaths=" + originalReceiverState + "\n")
	for _, path := range []string{filepath.Join(filepath.Dir(executable), "service.template"), filepath.Join(receiverUnits, "owntransit-connector-pair.service")} {
		if err = os.WriteFile(path, template, 0644); err != nil {
			t.Fatal(err)
		}
	}
	guard, err := receiverMaintenanceGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	control, err := securefs.OpenRoot(receiverMaintenanceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if _, err := control.TryLock("package.lock"); !errors.Is(err, securefs.ErrLocked) {
		t.Fatal("setup did not block exclusive package mutation")
	}
	for _, name := range []string{"alpha", "bravo"} {
		if err = prepareInstalledReceiver(context.Background(), name); err != nil {
			t.Fatal(err)
		}
		if err = prepareInstalledReceiver(context.Background(), name); err != nil {
			t.Fatal("rerun failed", err)
		}
		unit, _ := receiverUnit(name)
		data, err := protectedUnit(filepath.Join(receiverUnits, unit))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := namedReceiverUnit(template, name)
		if !bytes.Equal(data, want) {
			t.Fatal("named service selected wrong state or lost confinement")
		}
	}
	data, err := protectedUnit(filepath.Join(receiverUnits, "owntransit-connector-pair.service"))
	if err != nil || !bytes.Equal(data, template) {
		t.Fatal("named setup changed default service")
	}
	if err := startInstalledReceiver(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile("/tmp/owntransit-named-service.calls")
	if err != nil || string(calls) != "enable owntransit-connector-pair@alpha.service\nrestart owntransit-connector-pair@alpha.service\n" {
		t.Fatal("restart did not target only selected tunnel")
	}
	unit, _ := receiverUnit("alpha")
	if err = os.WriteFile(filepath.Join(receiverUnits, unit), []byte("unmanaged unit"), 0644); err != nil {
		t.Fatal(err)
	}
	if err = prepareInstalledReceiver(context.Background(), "alpha"); err == nil {
		t.Fatal("changed unit accepted")
	}
	guard.Close()
	lock, err := control.TryLock("package.lock")
	if err != nil {
		t.Fatal("maintenance lock not released", err)
	}
	lock.Close()
}
