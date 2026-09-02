//go:build darwin || linux

package packagetxn

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestDarwinClientRuntimeIdentityRequiresExactLauncherReceipt(t *testing.T) {
	const (
		clientDigest   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		launcherDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	validReceipt := receiptRecord{
		Schema:    receiptSchema,
		Role:      "client",
		OS:        "darwin",
		Arch:      "arm64",
		ReleaseID: testReleaseID("darwin-runtime-identity"),
		Sequence:  7,
		Files: []receiptFile{
			{ArtifactName: "client-darwin-arm64", Name: "owntransit-real", SHA256: clientDigest, Size: 11, Mode: 0o750, GID: 704},
			{ArtifactName: "launcher-darwin-arm64", Name: "owntransit", SHA256: launcherDigest, Size: 13, Mode: 0o2751, GID: 704},
		},
	}

	identity, err := runtimeIdentityFromReceipt(validReceipt)
	if err != nil {
		t.Fatalf("derive Darwin client runtime identity: %v", err)
	}
	if identity.ArtifactSHA256 != clientDigest || identity.LauncherSHA256 != launcherDigest ||
		identity.Role != "client" || identity.OS != "darwin" || identity.Arch != "arm64" ||
		identity.ReleaseID != validReceipt.ReleaseID || identity.ReleaseSequence != validReceipt.Sequence {
		t.Fatalf("Darwin client runtime identity = %+v", identity)
	}

	tests := map[string]func(*receiptRecord){
		"missing": func(receipt *receiptRecord) {
			receipt.Files = receipt.Files[:1]
		},
		"wrong-install-name": func(receipt *receiptRecord) {
			receipt.Files[1].Name = "owntransit-launcher"
		},
		"wrong-mode": func(receipt *receiptRecord) {
			receipt.Files[1].Mode = 0o751
		},
		"owner-group": func(receipt *receiptRecord) {
			receipt.Files[1].GID = 0
		},
		"invalid-digest": func(receipt *receiptRecord) {
			receipt.Files[1].SHA256 = "not-a-digest"
		},
		"duplicate": func(receipt *receiptRecord) {
			receipt.Files = append(receipt.Files, receipt.Files[1])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := validReceipt
			receipt.Files = append([]receiptFile(nil), validReceipt.Files...)
			mutate(&receipt)
			if identity, err := runtimeIdentityFromReceipt(receipt); err == nil {
				t.Fatalf("invalid launcher receipt produced identity %+v", identity)
			}
		})
	}

	linuxReceipt := validReceipt
	linuxReceipt.OS = "linux"
	linuxReceipt.Arch = "amd64"
	linuxReceipt.Files = []receiptFile{{ArtifactName: "client-linux-amd64", Name: "owntransit", SHA256: clientDigest, Size: 11, Mode: 0o755, GID: 0}}
	linuxIdentity, err := runtimeIdentityFromReceipt(linuxReceipt)
	if err != nil {
		t.Fatalf("derive Linux client runtime identity: %v", err)
	}
	if linuxIdentity.LauncherSHA256 != "" {
		t.Fatalf("Linux runtime unexpectedly carries a Darwin launcher digest: %+v", linuxIdentity)
	}
}

func TestCompleteLifecycleRecoverAuthenticatesRunningExecutable(t *testing.T) {
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
	fixture := newSignedPackageFixture(t, base, "complete-recover-authentication", 1, releaseKeys, policyBytes, policySignature, policyKeys)
	manager.runningMeasurement = func() (packageMeasurement, error) { return fixture.lifecycle, nil }
	if _, err := manager.Apply(fixture.input); err != nil {
		t.Fatalf("install complete lifecycle fixture: %v", err)
	}

	wrongBytes := fixture.lifecycle
	wrongBytes.SHA256 = strings.Repeat("f", 64)
	manager.runningMeasurement = func() (packageMeasurement, error) { return wrongBytes, nil }
	if _, err := manager.Recover(); err == nil || !strings.Contains(err.Error(), "running lifecycle executable differs") {
		t.Fatalf("complete recovery with wrong lifecycle bytes error = %v", err)
	}

	manager.enforceExecutablePath = true
	wrongPath := fixture.lifecycle
	wrongPath.Path = filepath.Join(base, "package", "connector", releasesDirectory, fixture.releaseID, "owntransitctl")
	manager.runningMeasurement = func() (packageMeasurement, error) { return wrongPath, nil }
	if _, err := manager.Recover(); err == nil || !strings.Contains(err.Error(), "authenticated fixed path") {
		t.Fatalf("complete recovery with wrong lifecycle path error = %v", err)
	}

	exact := fixture.lifecycle
	exact.Path = filepath.Join(base, "package", "client", releasesDirectory, fixture.releaseID, "owntransitctl")
	manager.runningMeasurement = func() (packageMeasurement, error) { return exact, nil }
	recovered, err := manager.Recover()
	if err != nil {
		t.Fatalf("recover exact complete lifecycle: %v", err)
	}
	if !recovered.Idempotent || recovered.Installed || recovered.Resumed || recovered.Current != fixture.releaseID {
		t.Fatalf("exact complete recovery result = %+v", recovered)
	}
}

func TestPackageDirectoryProfilesSeparateProvisionerFromRuntimeReaders(t *testing.T) {
	for _, test := range []struct {
		role     string
		goos     string
		wantGID  uint32
		wantMode uint32
	}{
		{role: "client", goos: "darwin", wantGID: 704, wantMode: 0o750},
		{role: "connector", goos: "linux", wantGID: 704, wantMode: 0o750},
		{role: "relay", goos: "linux", wantGID: 704, wantMode: 0o750},
		{role: "provisioner", goos: "linux", wantGID: 0, wantMode: 0o755},
		{role: "provisioner", goos: "darwin", wantGID: 0, wantMode: 0o750},
	} {
		readerGID := uint32(704)
		if test.role == "provisioner" {
			readerGID = 0
		}
		manager := &Manager{role: test.role, ownerGID: 0, readerGID: readerGID, platformOS: test.goos}
		gotGID, gotMode := packageDirectoryProfile(manager)
		if gotGID != test.wantGID || gotMode != test.wantMode {
			t.Fatalf("%s package directory profile = gid %d mode %04o, want gid %d mode %04o", test.role, gotGID, gotMode, test.wantGID, test.wantMode)
		}
	}
}

func TestInstalledPackageDirectoriesEnforceRoleProfile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to verify exact root-owned package directory metadata; the pinned root build gate runs this test")
	}

	for _, role := range []string{"client", "connector", "relay", "provisioner"} {
		t.Run(role, func(t *testing.T) {
			manager, base := newLifecycleManagerHarness(t, role)
			if role == "provisioner" {
				manager.readerGID = 0
			}
			releaseKeys, err := signing.Generate()
			if err != nil {
				t.Fatal(err)
			}
			policyKeys, err := signing.Generate()
			if err != nil {
				t.Fatal(err)
			}
			policyBytes, policySignature := signedTestPolicy(t, policyKeys, releaseKeys, 1, 1)
			fixture := newSignedPackageFixture(t, base, "directory-profile-"+role, 1, releaseKeys, policyBytes, policySignature, policyKeys)
			manager.runningMeasurement = func() (packageMeasurement, error) { return fixture.lifecycle, nil }
			if _, err := manager.Apply(fixture.input); err != nil {
				t.Fatalf("apply %s fixture: %v", role, err)
			}

			wantGID, wantMode := packageDirectoryProfile(manager)
			for _, path := range []string{
				filepath.Join(base, "package", role),
				filepath.Join(base, "package", role, releasesDirectory),
				filepath.Join(base, "package", role, releasesDirectory, fixture.releaseID),
			} {
				assertExactPackageDirectory(t, path, manager.ownerUID, wantGID, os.FileMode(wantMode))
			}
		})
	}
}

func assertExactPackageDirectory(t *testing.T, path string, wantUID, wantGID uint32, wantMode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat package directory %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("package directory %s has unexpected stat type %T", path, info.Sys())
	}
	if !info.IsDir() || info.Mode().Perm() != wantMode || stat.Uid != wantUID || stat.Gid != wantGID {
		t.Fatalf("package directory %s = directory %v mode %04o owner %d:%d, want directory true mode %04o owner %d:%d", path, info.IsDir(), info.Mode().Perm(), stat.Uid, stat.Gid, wantMode, wantUID, wantGID)
	}
}
