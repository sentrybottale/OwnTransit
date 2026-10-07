//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
)

const ingressFixtureSite = "/etc/nginx/sites-enabled/migration.conf"
const untouchedIngressSite = "server { listen 443 ssl; server_name other.example; location / { return 200 untouched; } }\n"

func oldIngressFixtureRoute(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(ingressFixtureSite)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(" "+nginxPeerHeader), nil, 1)
	if bytes.Contains(b, []byte(proxyPeerHeader)) {
		t.Fatal("fixture still contains a peer header")
	}
	b = append([]byte(untouchedIngressSite), b...)
	if err := os.WriteFile(ingressFixtureSite, b, 0644); err != nil {
		t.Fatal(err)
	}
	return b
}

func assertIngressRoute(t *testing.T, before []byte, hardened bool) {
	t.Helper()
	want := before
	if hardened {
		edit, err := NginxRouteForPort(before, "work.example", 9088)
		if err != nil || !edit.Exists || edit.Reused {
			t.Fatal("invalid old-route fixture", err)
		}
		want = edit.After
	}
	got, err := os.ReadFile(ingressFixtureSite)
	if err != nil || !bytes.Equal(got, want) || !bytes.HasPrefix(got, []byte(untouchedIngressSite)) {
		t.Fatal("selected route or unrelated website bytes were not retained", err)
	}
}

func TestManagedPeerHeaderMigrationAndRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "failed-probe", "validation-failure", "reload-failure", "route", "started"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMigrationFixture(t)
			before := oldIngressFixtureRoute(t)
			plan, err := PrepareSetup(context.Background(), "", f.old.url)
			if err != nil || plan.Kind != "migration" {
				t.Fatal("recognized old route was not offered for migration", err)
			}
			f.failNewProbe = scenario == "failed-probe"
			if scenario == "route" || scenario == "started" {
				f.crash = scenario
			}
			failed := false
			command = func(ctx context.Context, program string, args ...string) ([]byte, error) {
				if program == "/usr/sbin/nginx" && !failed && (scenario == "validation-failure" && len(args) == 1 && args[0] == "-t" || scenario == "reload-failure" && len(args) == 2 && args[1] == "reload") {
					failed = true
					return nil, errors.New("fixture route publication failure")
				}
				return f.command(ctx, program, args...)
			}
			func() {
				defer func() {
					if value := recover(); value != nil && !f.crashed {
						panic(value)
					}
				}()
				err = ApplySetup(context.Background(), plan, true, io.Discard)
			}()
			if f.crashed {
				manager, lock, openErr := managerRoot(true)
				if openErr != nil {
					t.Fatal(openErr)
				}
				journal, readErr := readMigration(manager)
				if readErr != nil || journal.Route == nil || journal.Schema != "owntransit.relay-migration.v3" {
					t.Fatal("route change was not bound in the interrupted migration", readErr)
				}
				err = restoreMigration(context.Background(), manager, journal)
				_ = lock.Close()
				_ = manager.Close()
				if err != nil {
					t.Fatal("migration route recovery failed", err)
				}
				assertIngressRoute(t, before, false)
				plan, err = PrepareSetup(context.Background(), "", f.old.url)
				if err != nil {
					t.Fatal(err)
				}
				err = ApplySetup(context.Background(), plan, true, io.Discard)
			}
			success := scenario == "success" || f.crashed
			if success && err != nil || !success && err == nil {
				t.Fatalf("unexpected migration result: %v", err)
			}
			assertIngressRoute(t, before, success)
		})
	}
}

func TestManagedPeerHeaderUpgradeAndRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "same-version", "failed-probe", "validation-failure", "reload-failure", "route", "started", "changed-site", "changed-backup"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMigrationFixture(t)
			plan, err := PrepareSetup(context.Background(), "", f.old.url)
			if err != nil {
				t.Fatal(err)
			}
			if err := ApplySetup(context.Background(), plan, true, io.Discard); err != nil {
				t.Fatal(err)
			}
			s := f.target
			s.port, s.legacyDataLabel = f.old.port, f.old.name
			previous, err := s.loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			next := previous
			if scenario != "same-version" {
				next.Image = "sha256:" + strings.Repeat("7", 64)
			}
			f.newImage = next.Image
			before := oldIngressFixtureRoute(t)
			root, err := s.openRoot()
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if scenario == "route" || scenario == "started" {
				f.crash = scenario
			} else if scenario == "changed-site" || scenario == "changed-backup" {
				f.crash = "route"
			}
			failed := false
			command = func(ctx context.Context, program string, args ...string) ([]byte, error) {
				if program == "/usr/sbin/nginx" && !failed && (scenario == "validation-failure" && len(args) == 1 && args[0] == "-t" || scenario == "reload-failure" && len(args) == 2 && args[1] == "reload") {
					failed = true
					return nil, errors.New("fixture route publication failure")
				}
				// The same service fixture must honor both recorded images when
				// rollback starts the previous unit after a failed upgrade.
				if program == "/usr/bin/systemctl" && len(args) > 1 && args[len(args)-1] == s.unitName && (args[0] == "start" || args[0] == "enable") {
					unit, _ := os.ReadFile(s.unitPath)
					savedImage := f.newImage
					if bytes.Contains(unit, []byte(previous.Image+" serve --state")) {
						f.newImage = previous.Image
					}
					defer func() { f.newImage = savedImage }()
				}
				return f.command(ctx, program, args...)
			}
			probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
				if scenario == "failed-probe" && f.containers[s.container].Image == next.Image {
					return pairrelay.ServerInfo{}, errors.New("fixture new image probe failed")
				}
				return f.local, nil
			}
			func() {
				defer func() {
					if value := recover(); value != nil && !f.crashed {
						panic(value)
					}
				}()
				err = s.upgradeManaged(context.Background(), root, previous, next, io.Discard)
			}()
			if f.crashed {
				journalBytes, readErr := root.ReadPrivateFile("upgrade.json", upgradeJournalLimit)
				var journal upgradeIntent
				if readErr != nil || json.Unmarshal(journalBytes, &journal) != nil || journal.Schema != "owntransit.relay-upgrade.v5" || journal.Route == nil {
					t.Fatal("interrupted upgrade omitted route recovery evidence", readErr)
				}
				if scenario == "changed-site" {
					current, _ := os.ReadFile(ingressFixtureSite)
					if err := os.WriteFile(ingressFixtureSite, append(current, []byte("# external edit\n")...), 0644); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "changed-backup" {
					if err := root.ReplaceFile(journal.Route.Backup, []byte("changed backup"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				count := len(f.calls)
				err = s.recoverManaged(context.Background(), root, io.Discard)
				if scenario == "changed-site" || scenario == "changed-backup" {
					if err == nil || len(f.calls) != count {
						t.Fatal("changed recovery evidence reached host operations")
					}
					return
				}
				if err != nil {
					t.Fatal("interrupted upgrade recovery failed", err)
				}
				assertIngressRoute(t, before, false)
				if f.containers[s.container].Image != previous.Image {
					t.Fatal("route recovery did not restore the previous relay")
				}
				err = s.upgradeManaged(context.Background(), root, previous, next, io.Discard)
			}
			success := scenario == "success" || scenario == "same-version" || f.crashed
			if success && err != nil || !success && err == nil {
				t.Fatalf("unexpected upgrade result: %v", err)
			}
			assertIngressRoute(t, before, success)
			if success {
				count := len(f.calls)
				if err := s.upgradeManaged(context.Background(), root, next, next, io.Discard); err != nil {
					t.Fatal("idempotent route reapply failed", err)
				}
				for _, call := range f.calls[count:] {
					if strings.Contains(call, "systemctl stop") || strings.Contains(call, "systemctl start") || call == "/usr/sbin/nginx -t" || call == "/usr/sbin/nginx -s reload" {
						t.Fatal("idempotent upgrade changed a service or route")
					}
				}
			}
		})
	}
}
