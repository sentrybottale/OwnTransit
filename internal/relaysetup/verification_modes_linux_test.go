//go:build linux

package relaysetup

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
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
)

type verificationFixtureSnapshot struct {
	legacyKeys, defaultKeys, defaultContainer string
	defaultEnabled                            bool
	defaultUnit, legacyUnit, website          []byte
}

func TestManagedLocalVerificationMissingRouteRefusesRerunAndUpgrade(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "same-version"
		if upgrade {
			name = "new-image"
		}
		t.Run(name, func(t *testing.T) {
			f := newMigrationFixture(t)
			before := snapshotVerificationFixture(t, f)
			probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
				return pairrelay.ServerInfo{}, errProbeForbidden
			}
			plan, err := PrepareSetup(context.Background(), "", f.old.url)
			if err != nil {
				t.Fatal(err)
			}
			var initialOutput bytes.Buffer
			result, err := ApplySetupWithResult(context.Background(), plan, true, &initialOutput)
			if err != nil {
				t.Fatal("initial local migration failed", err)
			}
			assertLocalVerificationReport(t, initialOutput.String(), result)
			containerBefore := planDigest(f.containers[f.target.container])
			unitBefore, err := os.ReadFile(f.target.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			missing := []byte("server { listen 443 ssl; server_name work.example; location / { proxy_pass http://127.0.0.1:8080; } }\n")
			if err := os.WriteFile("/etc/nginx/sites-enabled/migration.conf", missing, 0644); err != nil {
				t.Fatal(err)
			}
			if upgrade {
				f.newImage = "sha256:" + strings.Repeat("e", 64)
			}
			callStart := len(f.calls)
			plan, err = PrepareSetup(context.Background(), "", f.old.url)
			var output bytes.Buffer
			if err == nil {
				_, err = ApplySetupWithResult(context.Background(), plan, false, &output)
			}
			if err == nil {
				t.Fatal("HTTP403 accepted a missing managed route")
			}
			if planDigest(f.containers[f.target.container]) != containerBefore || !f.enabled[f.target.unitName] {
				t.Fatal("missing route changed the running managed source")
			}
			for _, call := range f.calls[callStart:] {
				for _, mutation := range []string{"systemctl stop ", "systemctl start ", "systemctl restart ", "systemctl disable ", "systemctl enable "} {
					if strings.Contains(call, mutation) {
						t.Fatal("missing route reached service mutation")
					}
				}
			}
			if _, err := os.Lstat(filepath.Join(f.target.root, "upgrade.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing route created an upgrade journal", err)
			}
			unitAfter, err := os.ReadFile(f.target.unitPath)
			if err != nil || !bytes.Equal(unitAfter, unitBefore) {
				t.Fatal("missing route changed the managed unit", err)
			}
			siteAfter, err := os.ReadFile("/etc/nginx/sites-enabled/migration.conf")
			if err != nil || !bytes.Equal(siteAfter, missing) {
				t.Fatal("failed upgrade rewrote the missing website route", err)
			}
			assertNoPublicVerificationClaim(t, output.String())
			if strings.Contains(output.String(), "Local relay service and exact website route verified") {
				t.Fatal("missing managed route produced local verification success")
			}
			assertVerificationFixtureRetained(t, f, before, false)
		})
	}
}

func TestManagedFreshLocalVerificationRequiresApplyingMissingRoute(t *testing.T) {
	f := newMigrationFixture(t)
	before := snapshotVerificationFixture(t, f)
	for _, path := range []string{f.target.unitPath, filepath.Join(f.target.root, "pending-setup.json")} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	// Model a fresh target on the reserved port. Retain the unrelated old keys
	// and default relay so the test also detects unintended identity changes.
	delete(f.containers, f.old.container)
	const sitePath = "/etc/nginx/sites-enabled/migration.conf"
	missing := []byte("server { listen 443 ssl; server_name work.example; location / { proxy_pass http://127.0.0.1:8080; } }\n")
	if err := os.WriteFile(sitePath, missing, 0644); err != nil {
		t.Fatal(err)
	}
	reloaded, initialized := false, false
	beforeReloadProbes, afterReloadProbes := 0, 0
	var output bytes.Buffer
	probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
		if f.containers[f.target.container].State.Running {
			if reloaded {
				afterReloadProbes++
			} else {
				beforeReloadProbes++
			}
		}
		return pairrelay.ServerInfo{}, errProbeForbidden
	}
	command = func(ctx context.Context, program string, args ...string) ([]byte, error) {
		if program == "/usr/bin/podman" && len(args) > 0 && args[0] == "run" {
			joined := " " + strings.Join(args, " ") + " "
			if !strings.Contains(joined, " pair init ") || !strings.Contains(joined, " --volume="+f.target.dataRoot()+":/state:rw ") || initialized {
				return nil, errors.New("unexpected fresh identity initialization")
			}
			f.calls = append(f.calls, program+" "+strings.Join(args, " "))
			if _, err := pairrelaycmd.Init(f.target.dataRoot()+"/relay", time.Now()); err != nil {
				return nil, err
			}
			if err := filepath.Walk(f.target.dataRoot(), func(path string, _ os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				return os.Chown(path, 65532, 65532)
			}); err != nil {
				return nil, err
			}
			var err error
			f.local, err = readPublicIdentity(f.target)
			if err != nil {
				return nil, err
			}
			initialized = true
			return nil, nil
		}
		if program == "/usr/bin/systemctl" && len(args) > 1 && args[len(args)-1] == f.target.unitName && (args[0] == "enable" || args[0] == "start") {
			f.calls = append(f.calls, program+" "+strings.Join(args, " "))
			if !initialized {
				return nil, errors.New("fresh service started before initialization")
			}
			if args[0] == "enable" {
				f.enabled[f.target.unitName] = true
			}
			if args[0] == "start" || strings.Contains(strings.Join(args, " "), "--now") {
				f.containers[f.target.container] = f.container(f.target, f.newImage, "f")
			}
			return nil, nil
		}
		if program == "/usr/sbin/nginx" && (len(args) == 1 && args[0] == "-t" || len(args) == 2 && args[0] == "-s" && args[1] == "reload") {
			f.calls = append(f.calls, program+" "+strings.Join(args, " "))
			current, err := os.ReadFile(sitePath)
			if err != nil {
				return nil, err
			}
			route, err := NginxRouteForPort(current, "work.example", f.target.port)
			if err != nil || !route.Reused {
				return nil, errors.New("website verification ran before exact route publication")
			}
			if strings.Contains(output.String(), "Local relay service and exact website route verified") {
				t.Fatal("local verification was reported before website reload")
			}
			if len(args) == 2 {
				reloaded = true
			}
			return nil, nil
		}
		return f.command(ctx, program, args...)
	}
	plan, err := PrepareSetup(context.Background(), "", f.target.url)
	if err != nil || plan.Kind != "reserved" || plan.Port != 9089 {
		t.Fatal("fresh reserved target did not prepare", err)
	}
	result, err := ApplySetupWithResult(context.Background(), plan, false, &output)
	if err != nil {
		t.Fatal("fresh HTTP403 route setup failed", err)
	}
	assertLocalVerificationReport(t, output.String(), result)
	if !initialized || !reloaded || beforeReloadProbes == 0 || afterReloadProbes == 0 {
		t.Fatal("fresh local verification skipped initialization, route reload or post-reload proof")
	}
	current, err := os.ReadFile(sitePath)
	if err != nil {
		t.Fatal(err)
	}
	route, err := NginxRouteForPort(current, "work.example", 9089)
	if err != nil || !route.Reused || !bytes.Contains(current, []byte("proxy_pass http://127.0.0.1:8080")) {
		t.Fatal("fresh setup did not retain the website and publish its exact route", err)
	}
	if !f.containers[f.target.container].State.Running || !f.target.ownsContainer(f.containers[f.target.container], f.newImage) || !f.enabled[f.target.unitName] {
		t.Fatal("fresh setup activated the wrong container, port or state mount")
	}
	if _, err := os.Lstat(filepath.Join(f.target.root, "setup.json")); err != nil {
		t.Fatal("fresh verified setup did not persist its selected configuration", err)
	}
	assertVerificationFixtureRetained(t, f, before, false)
}

func snapshotVerificationFixture(t *testing.T, f *migrationFixture) verificationFixtureSnapshot {
	t.Helper()
	legacy, err := identityDigests(f.old)
	if err != nil {
		t.Fatal(err)
	}
	d := defaultInstance()
	defaultKeys, err := identityDigests(d)
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return verificationFixtureSnapshot{
		legacyKeys: planDigest(legacy), defaultKeys: planDigest(defaultKeys),
		defaultContainer: planDigest(f.containers[d.container]), defaultEnabled: f.enabled[d.unitName],
		defaultUnit: read(d.unitPath), legacyUnit: read(f.old.unitPath),
		website: read("/etc/nginx/sites-enabled/migration.conf"),
	}
}

func assertVerificationFixtureRetained(t *testing.T, f *migrationFixture, before verificationFixtureSnapshot, websiteUnchanged bool) {
	t.Helper()
	legacy, err := identityDigests(f.old)
	if err != nil || planDigest(legacy) != before.legacyKeys {
		t.Fatal("verification mode changed retained relay keys", err)
	}
	d := defaultInstance()
	defaultKeys, err := identityDigests(d)
	if err != nil || planDigest(defaultKeys) != before.defaultKeys {
		t.Fatal("verification mode changed default relay keys", err)
	}
	if planDigest(f.containers[d.container]) != before.defaultContainer || f.enabled[d.unitName] != before.defaultEnabled {
		t.Fatal("verification mode changed the default relay service")
	}
	unit, err := os.ReadFile(d.unitPath)
	if err != nil || !bytes.Equal(unit, before.defaultUnit) {
		t.Fatal("verification mode changed the default relay unit", err)
	}
	if websiteUnchanged {
		site, err := os.ReadFile("/etc/nginx/sites-enabled/migration.conf")
		if err != nil || !bytes.Equal(site, before.website) {
			t.Fatal("verification mode changed the website configuration", err)
		}
	}
}

func assertLocalVerificationReport(t *testing.T, output string, result SetupResult) {
	t.Helper()
	if result.Verification != VerificationLocal403 {
		t.Fatalf("actual verification=%q, want local HTTP403 result", result.Verification)
	}
	for _, text := range []string{"Local relay service and exact website route verified", "HTTP 403", "public reachability was not proved here", "allowed network"} {
		if !strings.Contains(output, text) {
			t.Fatalf("local-only report omitted %q", text)
		}
	}
	assertNoPublicVerificationClaim(t, output)
}

func assertNoPublicVerificationClaim(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{"Relay public WebSocket route", "Relay ready", "Relay is ready", "public READY", "THIS VPS is finished"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("limited or failed verification claimed %q", forbidden)
		}
	}
}

func TestManagedMigrationVerificationModesAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name, initial, final string
		success              bool
	}{
		{"local-to-local", VerificationLocal403, "forbidden", true},
		{"local-to-public", VerificationLocal403, "public", true},
		{"public-to-forbidden", VerificationPublic, "forbidden", false},
		{"local-to-generic-error", VerificationLocal403, "generic", false},
		{"local-to-tls-error", VerificationLocal403, "tls", false},
		{"local-to-fake-forbidden-text", VerificationLocal403, "fake-forbidden", false},
		{"local-to-wrong-identity", VerificationLocal403, "identity", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMigrationFixture(t)
			before := snapshotVerificationFixture(t, f)
			probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
				if c, ok := f.containers[f.target.container]; ok && c.State.Running {
					switch tc.final {
					case "public":
						return f.local, nil
					case "forbidden":
						return pairrelay.ServerInfo{}, errProbeForbidden
					case "generic":
						return pairrelay.ServerInfo{}, errors.New("fixture route unavailable")
					case "tls":
						return pairrelay.ServerInfo{}, errors.New("tls: failed to verify certificate")
					case "fake-forbidden":
						return pairrelay.ServerInfo{}, errors.New("HTTP 403 Forbidden")
					case "identity":
						wrong := f.local
						wrong.ServerName = "other.example"
						return wrong, nil
					}
				}
				if tc.initial == VerificationLocal403 {
					return pairrelay.ServerInfo{}, errProbeForbidden
				}
				return f.local, nil
			}
			plan, err := PrepareSetup(context.Background(), "", f.old.url)
			if err != nil {
				t.Fatal("migration preparation failed", err)
			}
			if plan.Kind != "migration" || plan.Verification != tc.initial {
				t.Fatalf("wrong prepared verification: kind=%q level=%q", plan.Kind, plan.Verification)
			}
			var output bytes.Buffer
			result, err := ApplySetupWithResult(context.Background(), plan, true, &output)
			if (err == nil) != tc.success {
				t.Fatalf("unexpected migration outcome: success=%v err=%v", tc.success, err)
			}
			if tc.success {
				if !f.containers[f.target.container].State.Running || !f.enabled[f.target.unitName] {
					t.Fatal("successful verified migration did not activate its exact target")
				}
				if _, exists := f.containers[f.old.container]; exists {
					t.Fatal("successful migration retained the old container")
				}
				if _, err := os.Lstat(f.old.unitPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("successful migration retained the old service", err)
				}
				if tc.final == "forbidden" {
					assertLocalVerificationReport(t, output.String(), result)
				} else {
					if result.Verification != VerificationPublic || !strings.Contains(output.String(), "Relay public WebSocket route and retained identity verified") {
						t.Fatal("public improvement did not reach the actual result and report")
					}
					if strings.Contains(output.String(), "public reachability was not proved here") {
						t.Fatal("successful public verification retained the old limited report")
					}
				}
			} else {
				if !f.containers[f.old.container].State.Running || !f.enabled[f.old.unitName] {
					t.Fatal("failed verification did not restore the previous service")
				}
				if f.containers[f.target.container].State.Running {
					t.Fatal("failed verification left its replacement running")
				}
				oldUnit, readErr := os.ReadFile(f.old.unitPath)
				if readErr != nil || !bytes.Equal(oldUnit, before.legacyUnit) {
					t.Fatal("failed verification did not restore the exact old unit", readErr)
				}
				assertNoPublicVerificationClaim(t, output.String())
				if strings.Contains(output.String(), "Local relay service and exact website route verified") || strings.Contains(output.String(), "Local relay migration completed") {
					t.Fatal("failed migration printed a successful local-only outcome")
				}
			}
			assertVerificationFixtureRetained(t, f, before, true)
		})
	}
}

func TestManagedMigratedRelayLocalVerificationRerunAndUpgrade(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "same-version-rerun"
		if upgrade {
			name = "new-image-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			f := newMigrationFixture(t)
			before := snapshotVerificationFixture(t, f)
			probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
				return pairrelay.ServerInfo{}, errProbeForbidden
			}
			plan, err := PrepareSetup(context.Background(), "", f.old.url)
			if err != nil {
				t.Fatal(err)
			}
			var firstOutput bytes.Buffer
			firstResult, err := ApplySetupWithResult(context.Background(), plan, true, &firstOutput)
			if err != nil {
				t.Fatal("initial limited migration failed", err)
			}
			assertLocalVerificationReport(t, firstOutput.String(), firstResult)
			containerBefore := planDigest(f.containers[f.target.container])
			if upgrade {
				f.newImage = "sha256:" + strings.Repeat("e", 64)
			}
			plan, err = PrepareSetup(context.Background(), "", f.old.url)
			if err != nil || plan.Kind != "managed" {
				t.Fatal("migrated URL did not select the retained managed relay", err)
			}
			callStart := len(f.calls)
			var output bytes.Buffer
			result, err := ApplySetupWithResult(context.Background(), plan, false, &output)
			if err != nil {
				t.Fatal("managed local verification failed", err)
			}
			assertLocalVerificationReport(t, output.String(), result)
			if upgrade {
				if f.containers[f.target.container].Image != f.newImage || !f.containers[f.target.container].State.Running {
					t.Fatal("upgrade did not verify the newly selected image")
				}
			} else {
				if planDigest(f.containers[f.target.container]) != containerBefore {
					t.Fatal("same-version verification replaced the running container")
				}
				for _, call := range f.calls[callStart:] {
					for _, mutation := range []string{"systemctl stop ", "systemctl start ", "systemctl restart ", "systemctl disable "} {
						if strings.Contains(call, mutation) {
							t.Fatal("same-version local verification restarted the relay")
						}
					}
				}
			}
			assertVerificationFixtureRetained(t, f, before, true)
		})
	}
}

func TestManagedLocalVerificationRejectsChangedSelectedRouteAfterPreparation(t *testing.T) {
	f := newMigrationFixture(t)
	before := snapshotVerificationFixture(t, f)
	probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
		return pairrelay.ServerInfo{}, errProbeForbidden
	}
	plan, err := PrepareSetup(context.Background(), "", f.old.url)
	if err != nil || plan.Verification != VerificationLocal403 {
		t.Fatal("limited migration did not prepare", err)
	}
	changed := append(append([]byte(nil), before.website...), []byte("# selected route changed after verification\n")...)
	if err := os.WriteFile("/etc/nginx/sites-enabled/migration.conf", changed, 0644); err != nil {
		t.Fatal(err)
	}
	callStart := len(f.calls)
	var output bytes.Buffer
	if _, err := ApplySetupWithResult(context.Background(), plan, true, &output); err == nil {
		t.Fatal("stale selected-site evidence authorized limited verification")
	}
	for _, call := range f.calls[callStart:] {
		for _, mutation := range []string{"systemctl stop ", "systemctl start ", "systemctl disable ", "systemctl enable "} {
			if strings.Contains(call, mutation) {
				t.Fatal("changed site evidence reached service mutation")
			}
		}
	}
	if !f.containers[f.old.container].State.Running || !f.enabled[f.old.unitName] {
		t.Fatal("changed site evidence stopped the old relay")
	}
	if strings.Contains(output.String(), "Local relay service and exact website route verified") || strings.Contains(output.String(), "Local relay migration completed") {
		t.Fatal("changed route produced a limited-success report")
	}
	assertNoPublicVerificationClaim(t, output.String())
	assertVerificationFixtureRetained(t, f, before, false)
	after, err := os.ReadFile("/etc/nginx/sites-enabled/migration.conf")
	if err != nil || !bytes.Equal(after, changed) {
		t.Fatal("stale migration overwrote the changed website", err)
	}
}
