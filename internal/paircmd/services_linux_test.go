//go:build linux

package paircmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
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
	template := []byte("[Unit]\nConditionPathIsDirectory=" + originalReceiverState + "\n[Service]\nType=notify\nExecStart=" + executable + " serve --state " + originalReceiverState + "\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL\nReadWritePaths=" + originalReceiverState + "\n")
	for _, path := range []string{filepath.Join(filepath.Dir(executable), "service.template"), filepath.Join(receiverUnits, "owntransit-target.service")} {
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
	data, err := protectedUnit(filepath.Join(receiverUnits, "owntransit-target.service"))
	if err != nil || !bytes.Equal(data, template) {
		t.Fatal("named setup changed default service")
	}
	if err := startInstalledReceiver(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile("/tmp/owntransit-named-service.calls")
	if err != nil || string(calls) != "enable owntransit-target@alpha.service\nrestart owntransit-target@alpha.service\n" {
		t.Fatal("restart did not target only selected tunnel")
	}
	exerciseReceiverRecoveryCommands(t)
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

// Called only after the containing test's disposable-root/marker/path guards.
// Exercise the real CLI dispatch and authority store; systemd is the existing
// isolated service fixture, and discovery is a private test dependency.
func exerciseReceiverRecoveryCommands(t *testing.T) {
	t.Helper()
	base := originalReceiverState
	if err := ensureTunnelRoot(base); err != nil {
		t.Fatal(err)
	}
	path, _ := tunnelState(base, "alpha")
	info := recoveryRelayInfo(t, base)
	attempt, err := pairruntime.InitializeReceiverWithOffer(path, "wss://relay.example/connects", info)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(attempt.Code)
	oldDiscover := discoverReceiverOffer
	t.Cleanup(func() { discoverReceiverOffer = oldDiscover })
	discoveries := 0
	discoverReceiverOffer = func(context.Context, string) (pairrelay.ServerInfo, error) { discoveries++; return info, nil }
	var out, diag bytes.Buffer
	defer func() { clear(out.Bytes()); clear(diag.Bytes()) }()
	run := func(args []string, input string, want int) {
		t.Helper()
		clear(out.Bytes())
		out.Reset()
		clear(diag.Bytes())
		diag.Reset()
		if got := Run(true, args, strings.NewReader(input), &out, &diag); got != want {
			t.Fatalf("recovery CLI exit=%d want=%d", got, want)
		}
	}
	for i := 0; i < 2; i++ {
		run([]string{"setup", "--tunnel", "alpha"}, "", 0)
		if bytes.Count(out.Bytes(), attempt.Code) != 1 || discoveries != 0 || strings.Contains(out.String(), "TUNNEL READY") {
			t.Fatal("setup retry changed code, contacted discovery or invented readiness")
		}
	}
	run([]string{"code", "--target-id", attempt.ReceiverID}, "", 0)
	if bytes.Count(out.Bytes(), attempt.Code) != 1 || bytes.Contains(diag.Bytes(), attempt.Code) {
		t.Fatal("ID-specific code retrieval failed or leaked diagnostics")
	}
	run([]string{"setup", "--tunnel", "alpha", "--legacy-codes"}, "", 1)
	if discoveries != 0 || !strings.Contains(diag.String(), "--replace --legacy-codes") {
		t.Fatal("profile flag silently replaced a pending target")
	}
	r, err := receiverpairing.Open(filepath.Join(path, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := r.PendingCode(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pending.Code)
	request, err := receiverpairing.CreateRequest(receiverpairing.CreateRequestOptions{Advertisement: pending.Advertisement, Code: pending.Code, RelayOrigin: "wss://relay.example/connects", Now: time.Now(), Validity: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Claim(request.Encrypted, time.Now(), func(receiverpairing.PeerRequest) ([]byte, error) { return []byte("public fixture authorization"), nil }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, "authority", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	run([]string{"setup", "--tunnel", "alpha"}, "", 0)
	if discoveries != 0 || bytes.Contains(out.Bytes(), attempt.Code) || !strings.Contains(out.String(), "Existing pairing retained") {
		t.Fatal("paired setup did not preserve the existing tunnel")
	}
	run([]string{"setup", "--tunnel", "alpha", "--replace"}, "no\n", 0)
	after, err := os.ReadFile(filepath.Join(path, "authority", "state.json"))
	if err != nil || !bytes.Equal(before, after) || discoveries != 0 {
		t.Fatal("declined replacement changed authority")
	}
	run([]string{"setup", "--tunnel", "alpha", "--replace"}, "yes\n", 0)
	fresh, err := pairruntime.ReceiverCode(path, time.Now())
	defer clear(fresh.Code)
	if err != nil || fresh.ReceiverID == attempt.ReceiverID || bytes.Equal(fresh.Code, attempt.Code) || discoveries != 1 {
		t.Fatal("explicit replacement did not create fresh identities")
	}
	if !strings.Contains(out.String(), "New tunnel with a new local name") || !strings.Contains(out.String(), "Continue that new draft") || !strings.Contains(out.String(), "public Target ID in the new draft:\n  "+fresh.ReceiverID) {
		t.Fatal("replacement omitted exact new-ID approval command")
	}
	unit, _ := receiverUnit("alpha")
	unitPath := filepath.Join(receiverUnits, unit)
	unitBefore, err := protectedUnit(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	otherUnit, _ := receiverUnit("bravo")
	otherBefore, err := protectedUnit(filepath.Join(receiverUnits, otherUnit))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("unmanaged unit"), 0644); err != nil {
		t.Fatal(err)
	}
	run([]string{"remove", "--tunnel", "alpha"}, "", 1)
	if removed, err := pairruntime.IsRemoved(path); err != nil || removed {
		t.Fatal("unmanaged service removal changed pairing")
	}
	if err := os.WriteFile(unitPath, unitBefore, 0644); err != nil {
		t.Fatal(err)
	}
	before, err = os.ReadFile(filepath.Join(path, "authority", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	run([]string{"remove", "--tunnel", "alpha"}, "", 0)
	if removed, err := pairruntime.IsRemoved(path); err != nil || !removed {
		t.Fatal("selected tunnel was not detached")
	}
	run([]string{"setup", "--tunnel", "alpha"}, "", 1)
	run([]string{"restore", "--tunnel", "alpha"}, "", 0)
	after, err = os.ReadFile(filepath.Join(path, "authority", "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("removal or restore changed target authority")
	}
	otherAfter, err := protectedUnit(filepath.Join(receiverUnits, otherUnit))
	if err != nil || !bytes.Equal(otherBefore, otherAfter) {
		t.Fatal("selected removal changed another target service")
	}
	run([]string{"remove", "--tunnel", "alpha"}, "", 0)
	run([]string{"killswitch", "--tunnel", "alpha"}, "", 0)
	run([]string{"restore", "--tunnel", "alpha"}, "", 1)
}
