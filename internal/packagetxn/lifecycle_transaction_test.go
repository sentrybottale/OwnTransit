//go:build darwin || linux

package packagetxn

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/release"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

type signedPackageFixture struct {
	input     ApplyInput
	releaseID string
	lifecycle packageMeasurement
	manifest  release.Manifest
}

func TestLifecycleRejectsNestedPackageAndRollbackRoots(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packageRoot := filepath.Join(base, "package")
	anchorInside := filepath.Join(packageRoot, "anchor")
	for index, path := range []string{packageRoot, anchorInside} {
		mode := os.FileMode(0o755)
		if index == 1 {
			mode = 0o700
		}
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := openLifecycleManager(packageRoot, anchorInside, "client", uint32(os.Geteuid()), uint32(os.Getegid()), false, func(int, bool) error { return nil }); err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("nested anchor error = %v", err)
	}
	if _, err := openLifecycleManager(anchorInside, packageRoot, "client", uint32(os.Geteuid()), uint32(os.Getegid()), false, func(int, bool) error { return nil }); err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("nested package error = %v", err)
	}
}

func TestLifecycleApplyMeasuresExecutableRejectsStaleAndRollsBack(t *testing.T) {
	manager, base := newLifecycleManagerHarness(t, "client")
	releaseKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
	a := newSignedPackageFixture(t, base, "a", 1, releaseKeys, policyBytes, policySignature, policyKeys)
	b := newSignedPackageFixture(t, base, "b", 2, releaseKeys, policyBytes, policySignature, policyKeys)

	manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
	bad := a.input
	bad.ManifestSignature = append([]byte(nil), a.input.ManifestSignature...)
	bad.ManifestSignature[len(bad.ManifestSignature)-1] ^= 1
	if err := manager.PreflightApply(bad); err == nil {
		t.Fatal("preflight accepted an invalid release signature")
	}
	if err := manager.PreflightApply(a.input); err != nil {
		t.Fatalf("valid apply preflight: %v", err)
	}
	for _, path := range []string{filepath.Join(base, "package", "client", "current"), filepath.Join(base, "anchor", "client", packageAnchorFileName)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("preflight published package state at %s: %v", path, err)
		}
	}
	first, err := manager.Apply(a.input)
	if err != nil || first.Current != a.releaseID || first.Generation != 1 || !first.Installed {
		t.Fatalf("apply A = %+v, %v", first, err)
	}
	if first.Runtime.ReleaseID != first.Current || first.Runtime.ReleaseSequence != 1 || first.Runtime.Role != "client" ||
		first.Runtime.OS != "linux" || first.Runtime.Arch != "amd64" || !validDigest(first.Runtime.ArtifactSHA256) {
		t.Fatalf("apply A authenticated runtime = %+v", first.Runtime)
	}
	assertActiveRelease(t, base, "client", a.releaseID)
	assertLinuxClientInodes(t, manager, base, a.releaseID, a.input.BundleRoot)
	idempotent, err := manager.Apply(a.input)
	if err != nil || !idempotent.Idempotent || idempotent.Installed {
		t.Fatalf("reinstall A = %+v, %v", idempotent, err)
	}
	if idempotent.Runtime != first.Runtime {
		t.Fatalf("idempotent runtime = %+v, want %+v", idempotent.Runtime, first.Runtime)
	}

	manager.runningMeasurement = func() (packageMeasurement, error) {
		return packageMeasurement{SHA256: strings.Repeat("f", 64), Size: a.lifecycle.Size}, nil
	}
	if _, err := manager.Apply(b.input); err == nil || !strings.Contains(err.Error(), "running lifecycle executable differs") {
		t.Fatalf("wrong running executable error = %v", err)
	}

	manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
	second, err := manager.Apply(b.input)
	if err != nil || second.Current != b.releaseID || second.Previous != a.releaseID || second.Generation != 2 {
		t.Fatalf("apply B = %+v, %v", second, err)
	}
	assertActiveRelease(t, base, "client", b.releaseID)
	manager.runningMeasurement = func() (packageMeasurement, error) { return b.lifecycle, nil }
	if _, err := manager.Apply(a.input); err == nil || !strings.Contains(err.Error(), "replay or downgrade") {
		t.Fatalf("stale release A error = %v", err)
	}
	if _, err := manager.Rollback(RollbackInput{ToReleaseID: testReleaseID("wrong")}); err == nil {
		t.Fatal("rollback accepted a non-retained target")
	}
	rolledBack, err := manager.Rollback(RollbackInput{ToReleaseID: a.releaseID})
	if err != nil || rolledBack.Current != a.releaseID || rolledBack.Previous != b.releaseID || rolledBack.Generation != 3 {
		t.Fatalf("rollback to A = %+v, %v", rolledBack, err)
	}
	assertActiveRelease(t, base, "client", a.releaseID)
	manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
	rolledForward, err := manager.Rollback(RollbackInput{ToReleaseID: b.releaseID})
	if err != nil || rolledForward.Current != b.releaseID || rolledForward.Previous != a.releaseID || rolledForward.Generation != 4 {
		t.Fatalf("rollback swap to B = %+v, %v", rolledForward, err)
	}
	assertActiveRelease(t, base, "client", b.releaseID)
}

func TestCurrentRuntimeGuardPreventsEverySelectorMutation(t *testing.T) {
	manager, base := newLifecycleManagerHarness(t, "client")
	releaseKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
	a := newSignedPackageFixture(t, base, "guard-a", 1, releaseKeys, policyBytes, policySignature, policyKeys)
	b := newSignedPackageFixture(t, base, "guard-b", 2, releaseKeys, policyBytes, policySignature, policyKeys)
	c := newSignedPackageFixture(t, base, "guard-c", 3, releaseKeys, policyBytes, policySignature, policyKeys)
	manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
	if _, err := manager.Apply(a.input); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(b.input); err != nil {
		t.Fatal(err)
	}
	manager.runningMeasurement = func() (packageMeasurement, error) { return b.lifecycle, nil }

	started := make(chan RuntimeIdentity, 1)
	releaseGuard := make(chan struct{})
	guardDone := make(chan error, 1)
	go func() {
		guardDone <- manager.WithCurrentRuntimeIdentity(func(identity RuntimeIdentity) error {
			started <- identity
			<-releaseGuard
			return nil
		})
	}()
	identity := <-started
	if identity.ReleaseID != b.releaseID || identity.ReleaseSequence != 2 {
		close(releaseGuard)
		t.Fatalf("guarded identity = %+v, want release B", identity)
	}

	if _, err := manager.Apply(c.input); !errors.Is(err, ErrLocked) {
		close(releaseGuard)
		t.Fatalf("Apply during guarded setup = %v, want %v", err, ErrLocked)
	}
	if _, err := manager.Rollback(RollbackInput{ToReleaseID: a.releaseID}); !errors.Is(err, ErrLocked) {
		close(releaseGuard)
		t.Fatalf("Rollback during guarded setup = %v, want %v", err, ErrLocked)
	}
	if _, err := manager.Recover(); !errors.Is(err, ErrLocked) {
		close(releaseGuard)
		t.Fatalf("Recover during guarded setup = %v, want %v", err, ErrLocked)
	}
	selector := readSelectorFromDisk(t, &transactionHarness{root: filepath.Join(base, "package")}, "client")
	if selector.Current != b.releaseID || selector.Generation != 2 {
		close(releaseGuard)
		t.Fatalf("selector changed while setup guard was held: %+v", selector)
	}
	close(releaseGuard)
	if err := <-guardDone; err != nil {
		t.Fatalf("guarded setup operation: %v", err)
	}

	result, err := manager.Apply(c.input)
	if err != nil || result.Current != c.releaseID || result.Generation != 3 {
		t.Fatalf("Apply after guarded setup = %+v, %v", result, err)
	}
}

func TestCurrentRuntimeGuardFailsClosedWithoutEnteringCallbackDuringMutation(t *testing.T) {
	manager, base := newLifecycleManagerHarness(t, "client")
	releaseKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
	a := newSignedPackageFixture(t, base, "mutator-a", 1, releaseKeys, policyBytes, policySignature, policyKeys)
	b := newSignedPackageFixture(t, base, "mutator-b", 2, releaseKeys, policyBytes, policySignature, policyKeys)
	manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
	if _, err := manager.Apply(a.input); err != nil {
		t.Fatal(err)
	}

	mutationStarted := make(chan struct{})
	releaseMutation := make(chan struct{})
	mutationDone := make(chan error, 1)
	manager.failureHook = func(point failurePoint) error {
		if point == pointJournalPlanned {
			close(mutationStarted)
			<-releaseMutation
		}
		return nil
	}
	go func() {
		_, err := manager.Apply(b.input)
		mutationDone <- err
	}()
	<-mutationStarted
	callbackEntered := false
	err = manager.WithCurrentRuntimeIdentity(func(RuntimeIdentity) error {
		callbackEntered = true
		return nil
	})
	if !errors.Is(err, ErrLocked) || callbackEntered {
		close(releaseMutation)
		t.Fatalf("guard during mutation = %v, callback entered=%v", err, callbackEntered)
	}
	close(releaseMutation)
	if err := <-mutationDone; err != nil {
		t.Fatalf("concurrent mutation: %v", err)
	}
	manager.failureHook = nil
}

func assertLinuxClientInodes(t *testing.T, manager *Manager, base, releaseID, bundleRoot string) {
	t.Helper()
	releaseRoot := filepath.Join(base, "package", "client", releasesDirectory, releaseID)
	ux, err := os.Stat(filepath.Join(releaseRoot, "owntransit"))
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := os.Stat(filepath.Join(releaseRoot, "owntransit-proxy"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(ux, proxy) {
		t.Fatal("normal UX and setgid proxy are the same inode")
	}
	if ux.Mode().Perm() != 0o755 || ux.Mode()&os.ModeSetgid != 0 {
		t.Fatalf("normal UX mode = %v", ux.Mode())
	}
	if proxy.Mode().Perm() != 0o750 || proxy.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("proxy mode = %v", proxy.Mode())
	}
	proxyStat, ok := proxy.Sys().(*syscall.Stat_t)
	if !ok || proxyStat.Gid != manager.readerGID || proxyStat.Nlink != 1 {
		t.Fatalf("proxy metadata = %#v; reader GID=%d", proxy.Sys(), manager.readerGID)
	}
	for installName, sourceName := range map[string]string{
		"LICENSE":                  "LICENSE",
		"THIRD_PARTY_LICENSES.txt": "evidence/THIRD_PARTY_LICENSES.txt",
	} {
		installedPath := filepath.Join(releaseRoot, installName)
		installed, err := os.Stat(installedPath)
		if err != nil {
			t.Fatal(err)
		}
		installedStat, ok := installed.Sys().(*syscall.Stat_t)
		if !ok || installed.Mode().Perm() != 0o644 || installed.Mode()&(os.ModeSetgid|os.ModeSetuid) != 0 || installedStat.Gid != manager.ownerGID || installedStat.Nlink != 1 {
			t.Fatalf("installed notice %s metadata = mode %v, stat %#v", installName, installed.Mode(), installed.Sys())
		}
		actual, err := os.ReadFile(installedPath)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := os.ReadFile(filepath.Join(bundleRoot, filepath.FromSlash(sourceName)))
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(expected) {
			t.Fatalf("installed notice %s differs from authenticated bundle", installName)
		}
	}
}

func TestLifecycleRejectsSameBytesInvokedFromAnotherRolePath(t *testing.T) {
	manager, base := newLifecycleManagerHarness(t, "client")
	releaseKeys, _ := signing.Generate()
	policyKeys, _ := signing.Generate()
	policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
	fixture := newSignedPackageFixture(t, base, "fixed-path", 1, releaseKeys, policyBytes, policySignature, policyKeys)
	manager.enforceExecutablePath = true
	wrong := fixture.lifecycle
	wrong.Path = filepath.Join(base, "package", "connector", releasesDirectory, fixture.releaseID, "owntransitctl")
	manager.runningMeasurement = func() (packageMeasurement, error) { return wrong, nil }
	if _, err := manager.Apply(fixture.input); err == nil || !strings.Contains(err.Error(), "this role's authenticated fixed path") {
		t.Fatalf("cross-role lifecycle path error = %v", err)
	}
	manager.runningMeasurement = func() (packageMeasurement, error) { return fixture.lifecycle, nil }
	if _, err := manager.Apply(fixture.input); err != nil {
		t.Fatalf("apply from authenticated candidate path: %v", err)
	}
}

func TestLifecycleRequiresDistinctReleaseAndPolicySigners(t *testing.T) {
	manager, base := newLifecycleManagerHarness(t, "client")
	shared, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, policySignature := signedTestPolicy(t, shared, shared, 1, 1)
	fixture := newSignedPackageFixture(t, base, "shared-signer", 1, shared, policyBytes, policySignature, shared)
	manager.runningMeasurement = func() (packageMeasurement, error) { return fixture.lifecycle, nil }
	if err := manager.PreflightApply(fixture.input); err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("shared release/policy signer error = %v", err)
	}
}

func TestLifecycleRolesCoexistAndExactReinstallIsIdempotent(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packageRoot, anchorRoot := filepath.Join(base, "package"), filepath.Join(base, "anchor")
	if err := os.Mkdir(packageRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(anchorRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	releaseKeys, _ := signing.Generate()
	policyKeys, _ := signing.Generate()
	policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
	fixture := newSignedPackageFixture(t, base, "coexisting-roles", 1, releaseKeys, policyBytes, policySignature, policyKeys)

	managers := make(map[string]*Manager)
	for _, role := range []string{"client", "connector", "relay"} {
		manager, err := openLifecycleManager(packageRoot, anchorRoot, role, uint32(os.Geteuid()), uint32(os.Getegid()), false, func(int, bool) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		manager.platformOS, manager.platformArch = "linux", "amd64"
		if os.Getegid() == 0 {
			manager.readerGID = 4242
		}
		manager.runningMeasurement = func() (packageMeasurement, error) { return fixture.lifecycle, nil }
		managers[role] = manager
		t.Cleanup(func() { _ = manager.Close() })
		result, err := manager.Apply(fixture.input)
		if err != nil || result.Role != role || result.Current != fixture.releaseID || !result.Installed {
			t.Fatalf("apply %s = %+v, %v", role, result, err)
		}
		assertActiveRelease(t, base, role, fixture.releaseID)
		for _, notice := range []string{"LICENSE", "THIRD_PARTY_LICENSES.txt"} {
			if _, err := os.Stat(filepath.Join(packageRoot, role, releasesDirectory, fixture.releaseID, notice)); err != nil {
				t.Fatalf("%s notice %s: %v", role, notice, err)
			}
		}
	}

	reinstalled, err := managers["client"].Apply(fixture.input)
	if err != nil || !reinstalled.Idempotent || reinstalled.Installed || reinstalled.Current != fixture.releaseID {
		t.Fatalf("exact client reinstall = %+v, %v", reinstalled, err)
	}
	for _, role := range []string{"client", "connector", "relay"} {
		assertActiveRelease(t, base, role, fixture.releaseID)
	}
}

func TestLifecycleRollbackObeysAdvancedAuthenticatedFloor(t *testing.T) {
	manager, base := newLifecycleManagerHarness(t, "client")
	releaseKeys, _ := signing.Generate()
	policyKeys, _ := signing.Generate()
	policyOne, signatureOne := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
	a := newSignedPackageFixture(t, base, "floor-a", 1, releaseKeys, policyOne, signatureOne, policyKeys)
	policyTwo, signatureTwo := signedTestPolicy(t, policyKeys, releaseKeys, 2, 2)
	b := newSignedPackageFixture(t, base, "floor-b", 2, releaseKeys, policyTwo, signatureTwo, policyKeys)
	manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
	if _, err := manager.Apply(a.input); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(b.input); err != nil {
		t.Fatal(err)
	}
	manager.runningMeasurement = func() (packageMeasurement, error) { return b.lifecycle, nil }
	if _, err := manager.Rollback(RollbackInput{ToReleaseID: a.releaseID}); err == nil || !strings.Contains(err.Error(), "rollback floor") {
		t.Fatalf("rollback below authenticated floor error = %v", err)
	}
}

func TestLifecycleInterruptionRequiresSignedInputBeforeAnchorAndRecoversAfterAnchor(t *testing.T) {
	t.Run("before-anchor", func(t *testing.T) {
		manager, base := newLifecycleManagerHarness(t, "client")
		releaseKeys, _ := signing.Generate()
		policyKeys, _ := signing.Generate()
		policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
		a := newSignedPackageFixture(t, base, "pre-anchor-a", 1, releaseKeys, policyBytes, policySignature, policyKeys)
		b := newSignedPackageFixture(t, base, "pre-anchor-b", 2, releaseKeys, policyBytes, policySignature, policyKeys)
		manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
		if _, err := manager.Apply(a.input); err != nil {
			t.Fatal(err)
		}
		manager.failureHook = interruptAt(pointJournalStaged)
		if _, err := manager.Apply(b.input); !errorsIsInterrupted(err) {
			t.Fatalf("pre-anchor interruption = %v", err)
		}
		manager.failureHook = nil
		if _, err := manager.Recover(); err == nil || !strings.Contains(err.Error(), "original signed input") {
			t.Fatalf("pre-anchor recovery error = %v", err)
		}
		resumed, err := manager.Apply(b.input)
		if err != nil || !resumed.Resumed || resumed.Current != b.releaseID {
			t.Fatalf("signed resume = %+v, %v", resumed, err)
		}
	})

	t.Run("after-anchor", func(t *testing.T) {
		manager, base := newLifecycleManagerHarness(t, "client")
		releaseKeys, _ := signing.Generate()
		policyKeys, _ := signing.Generate()
		policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
		a := newSignedPackageFixture(t, base, "post-anchor-a", 1, releaseKeys, policyBytes, policySignature, policyKeys)
		b := newSignedPackageFixture(t, base, "post-anchor-b", 2, releaseKeys, policyBytes, policySignature, policyKeys)
		manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
		if _, err := manager.Apply(a.input); err != nil {
			t.Fatal(err)
		}
		manager.failureHook = interruptAt(pointSelectorCommit)
		if _, err := manager.Apply(b.input); !errorsIsInterrupted(err) {
			t.Fatalf("post-anchor interruption = %v", err)
		}
		manager.failureHook = nil
		// Selector publication precedes the stable per-role active link. The old
		// authenticated lifecycle remains the only executable reachable at the
		// fixed path until recovery finishes that exact journal transition.
		manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
		recovered, err := manager.Recover()
		if err != nil || !recovered.Resumed || recovered.Current != b.releaseID {
			t.Fatalf("durable recovery = %+v, %v", recovered, err)
		}
	})

	t.Run("after-active-link", func(t *testing.T) {
		manager, base := newLifecycleManagerHarness(t, "client")
		releaseKeys, _ := signing.Generate()
		policyKeys, _ := signing.Generate()
		policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
		a := newSignedPackageFixture(t, base, "post-link-a", 1, releaseKeys, policyBytes, policySignature, policyKeys)
		b := newSignedPackageFixture(t, base, "post-link-b", 2, releaseKeys, policyBytes, policySignature, policyKeys)
		manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
		if _, err := manager.Apply(a.input); err != nil {
			t.Fatal(err)
		}
		manager.failureHook = interruptAt(pointActiveCommit)
		if _, err := manager.Apply(b.input); !errorsIsInterrupted(err) {
			t.Fatalf("post-link interruption = %v", err)
		}
		assertActiveRelease(t, base, "client", b.releaseID)
		manager.failureHook = nil
		manager.runningMeasurement = func() (packageMeasurement, error) { return b.lifecycle, nil }
		recovered, err := manager.Recover()
		if err != nil || !recovered.Resumed || recovered.Current != b.releaseID {
			t.Fatalf("post-link recovery = %+v, %v", recovered, err)
		}
	})
}

func TestLifecycleThirdReleaseRetirementResumesWithoutGuessing(t *testing.T) {
	manager, base := newLifecycleManagerHarness(t, "client")
	releaseKeys, _ := signing.Generate()
	policyKeys, _ := signing.Generate()
	policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
	a := newSignedPackageFixture(t, base, "retire-a", 1, releaseKeys, policyBytes, policySignature, policyKeys)
	b := newSignedPackageFixture(t, base, "retire-b", 2, releaseKeys, policyBytes, policySignature, policyKeys)
	c := newSignedPackageFixture(t, base, "retire-c", 3, releaseKeys, policyBytes, policySignature, policyKeys)
	manager.runningMeasurement = func() (packageMeasurement, error) { return a.lifecycle, nil }
	if _, err := manager.Apply(a.input); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(b.input); err != nil {
		t.Fatal(err)
	}
	manager.runningMeasurement = func() (packageMeasurement, error) { return b.lifecycle, nil }
	manager.failureHook = interruptAt(pointReleaseRetired)
	if _, err := manager.Apply(c.input); !errorsIsInterrupted(err) {
		t.Fatalf("retirement interruption = %v", err)
	}
	manager.failureHook = nil
	manager.runningMeasurement = func() (packageMeasurement, error) { return c.lifecycle, nil }
	recovered, err := manager.Recover()
	if err != nil || recovered.Current != c.releaseID || recovered.Previous != b.releaseID {
		t.Fatalf("retirement recovery = %+v, %v", recovered, err)
	}
	if _, err := os.Stat(filepath.Join(base, "package", "client", releasesDirectory, a.releaseID)); !os.IsNotExist(err) {
		t.Fatalf("retired A remains: %v", err)
	}
}

func newLifecycleManagerHarness(t *testing.T, role string) (*Manager, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packageRoot, anchorRoot := filepath.Join(base, "package"), filepath.Join(base, "anchor")
	for index, path := range []string{packageRoot, anchorRoot} {
		mode := os.FileMode(0o755)
		if index == 1 {
			mode = 0o700
		}
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := openLifecycleManager(packageRoot, anchorRoot, role, uint32(os.Geteuid()), uint32(os.Getegid()), false, func(int, bool) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if os.Getegid() == 0 {
		manager.readerGID = 4242
	}
	manager.platformOS, manager.platformArch = "linux", "amd64"
	t.Cleanup(func() { _ = manager.Close() })
	return manager, base
}

func signedTestPolicy(t *testing.T, policyKeys, releaseKeys signing.KeyPair, sequence, floor uint64) ([]byte, []byte) {
	t.Helper()
	policy := release.Policy{
		Schema: release.PolicySchema, Product: "owntransit", Sequence: sequence, CreatedUnix: 1700000000,
		ReleaseKeyID: signing.KeyID(releaseKeys.Public), MinimumReleaseSequence: floor, MinimumLifecycle: 1,
	}
	encoded, signature, err := release.SignPolicy(policy, policyKeys.Private)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, signature
}

func newSignedPackageFixture(t *testing.T, base, label string, sequence uint64, releaseKeys signing.KeyPair, policyBytes, policySignature []byte, policyKeys signing.KeyPair) signedPackageFixture {
	t.Helper()
	root := filepath.Join(base, "bundle-"+label)
	for _, directory := range []string{root, filepath.Join(root, "artifacts"), filepath.Join(root, "evidence")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	releaseIDBytes := sha256.Sum256([]byte("release-" + label))
	releaseID := protocol.ID(releaseIDBytes).String()
	manifest := release.Manifest{
		Schema: release.ManifestSchema, Product: "owntransit", Version: "1.0." + string(rune('0'+sequence)),
		ReleaseID: releaseID, Sequence: sequence, CreatedUnix: 1700000000 + int64(sequence),
		Protocol: wireprofile.LegacyV1Protocol, License: "Apache-2.0", MinimumLifecycle: 1,
		Source:    release.Source{Repository: "https://github.com/sentrybottale/owntransit", Commit: strings.Repeat("b", 40), ManifestSHA256: strings.Repeat("a", 64)},
		Toolchain: release.Toolchain{GoVersion: "go1.26.7", BuilderImage: "registry.example/build/go@sha256:" + strings.Repeat("c", 64)},
		Artifacts: release.ArtifactMatrix(),
	}
	var lifecycle packageMeasurement
	for index := range manifest.Artifacts {
		contents := []byte("artifact-" + label + "-" + manifest.Artifacts[index].Name + "\n")
		writeProtectedFixture(t, filepath.Join(root, filepath.FromSlash(manifest.Artifacts[index].File)), contents)
		digest := sha256.Sum256(contents)
		manifest.Artifacts[index].SHA256 = hex.EncodeToString(digest[:])
		manifest.Artifacts[index].Size = int64(len(contents))
		if manifest.Artifacts[index].Name == "lifecycle-linux-amd64" {
			lifecycle = packageMeasurement{Path: filepath.Join(root, filepath.FromSlash(manifest.Artifacts[index].File)), SHA256: manifest.Artifacts[index].SHA256, Size: manifest.Artifacts[index].Size}
		}
	}
	licenseBytes, err := os.ReadFile("../../LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	writeProtectedFixture(t, filepath.Join(root, "LICENSE"), licenseBytes)
	thirdParty := []byte(release.LicenseEvidenceHeader + "\nComponent: fixture v1\nFile: LICENSE\n---\nfixture\n---\n")
	writeProtectedFixture(t, filepath.Join(root, "evidence/THIRD_PARTY_LICENSES.txt"), thirdParty)

	packages := []release.SPDXPackage{{Name: "Go standard library", SPDXID: "SPDXRef-Package-0000", VersionInfo: "go1.26.7", DownloadLocation: "https://go.dev/", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "BSD-3-Clause", CopyrightText: "NOASSERTION", ExternalRefs: []release.SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/std@go1.26.7"}}}}
	for _, artifact := range manifest.Artifacts {
		document := release.SPDXDocument{
			SPDXVersion: release.SPDXVersion, DataLicense: release.SPDXDataLicense, SPDXID: release.SPDXDocumentID,
			Name: "owntransit-" + artifact.Name, DocumentNamespace: "https://spdx.org/spdxdocs/owntransit-" + manifest.ReleaseID + "-" + artifact.Name,
			CreationInfo: release.SPDXCreationInfo{Created: time.Unix(manifest.CreatedUnix, 0).UTC().Format(time.RFC3339), Creators: []string{release.EvidenceToolCreator}},
			Files:        []release.SPDXFile{{FileName: artifact.File, SPDXID: release.SPDXArtifactID, Checksums: []release.SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: artifact.SHA256}}, LicenseConcluded: "NOASSERTION", CopyrightText: "NOASSERTION"}},
			Packages:     packages,
			Relationships: []release.SPDXRelationship{
				{SPDXElementID: release.SPDXDocumentID, RelationshipType: "DESCRIBES", RelatedSPDXElement: release.SPDXArtifactID},
				{SPDXElementID: packages[0].SPDXID, RelationshipType: "BUILD_DEPENDENCY_OF", RelatedSPDXElement: release.SPDXArtifactID},
			},
		}
		encoded, err := release.EncodeSPDX(document, manifest, artifact)
		if err != nil {
			t.Fatal(err)
		}
		writeProtectedFixture(t, filepath.Join(root, "evidence", filepath.Base(artifact.File)+".spdx.json"), encoded)
	}
	provenance := release.Provenance{
		Schema: release.ProvenanceSchema, Product: manifest.Product, Version: manifest.Version, ReleaseID: manifest.ReleaseID,
		Sequence: manifest.Sequence, CreatedUnix: manifest.CreatedUnix, Protocol: manifest.Protocol, License: manifest.License,
		Source: manifest.Source, Toolchain: manifest.Toolchain, BuildProfile: release.BuildProfile,
		SourceDateEpoch: manifest.CreatedUnix, Trimpath: true,
	}
	for _, artifact := range manifest.Artifacts {
		provenance.Subjects = append(provenance.Subjects, release.ProvenanceSubject{Name: artifact.Name, File: artifact.File, SHA256: artifact.SHA256, Size: artifact.Size})
	}
	provenanceBytes, err := release.EncodeProvenance(provenance, manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeProtectedFixture(t, filepath.Join(root, "evidence/PROVENANCE.json"), provenanceBytes)

	records := []release.Evidence{{Name: "project-license", File: "LICENSE", Kind: "project-license"}, {Name: "provenance", File: "evidence/PROVENANCE.json", Kind: "provenance"}, {Name: "third-party-licenses", File: "evidence/THIRD_PARTY_LICENSES.txt", Kind: "licenses"}}
	for _, artifact := range manifest.Artifacts {
		records = append(records, release.Evidence{Name: artifact.SBOM, File: "evidence/" + filepath.Base(artifact.File) + ".spdx.json", Kind: "sbom"})
	}
	sort.Slice(records, func(left, right int) bool { return records[left].Name < records[right].Name })
	for index := range records {
		contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(records[index].File)))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		records[index].SHA256, records[index].Size = hex.EncodeToString(digest[:]), int64(len(contents))
	}
	manifest.Evidence = records
	manifestBytes, manifestSignature, err := release.Sign(manifest, releaseKeys.Private)
	if err != nil {
		t.Fatal(err)
	}
	return signedPackageFixture{
		input:     ApplyInput{BundleRoot: root, ManifestBytes: manifestBytes, ManifestSignature: manifestSignature, ReleaseKey: releaseKeys.Public, PolicyBytes: policyBytes, PolicySignature: policySignature, PolicyKey: policyKeys.Public},
		releaseID: releaseID, lifecycle: lifecycle, manifest: manifest,
	}
}

func writeProtectedFixture(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func errorsIsInterrupted(err error) bool {
	return err != nil && strings.Contains(err.Error(), errInterrupted.Error())
}

func assertActiveRelease(t *testing.T, base, role, releaseID string) {
	t.Helper()
	target, err := os.Readlink(filepath.Join(base, "package", role, activeLinkName))
	if err != nil {
		t.Fatal(err)
	}
	if target != activeLinkTarget(releaseID) {
		t.Fatalf("active release target = %q, want %q", target, activeLinkTarget(releaseID))
	}
}
