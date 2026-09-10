//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedPackageHookMigration(t *testing.T) {
	requireNamedRelayFixture(t)
	for _, scenario := range []string{"all-instances", "modified-unit", "unknown-reference", "pending-upgrade", "reload-retry"} {
		t.Run(scenario, func(t *testing.T) {
			if err := os.RemoveAll(managedRoot); err != nil {
				t.Fatal(err)
			}
			specs := []instanceSpec{fixtureSpec(t, "default", 9087), fixtureSpec(t, "alpha", 9088), fixtureSpec(t, "beta", 9089)}
			for _, s := range specs {
				_ = os.Remove(s.unitPath)
			}
			foreign := "/etc/systemd/system/package-hook-foreign-fixture.service"
			_ = os.Remove(foreign)
			t.Cleanup(func() { _ = os.Remove(foreign) })
			if err := os.MkdirAll("/etc/systemd/system", 0755); err != nil {
				t.Fatal(err)
			}
			root, lock, err := managerRoot(true)
			if err != nil {
				t.Fatal(err)
			}
			lock.Close()
			root.Close()
			// An unused reservation has no service or relay identity to migrate.
			unused := fixtureSpec(t, "gamma", 9090)
			_ = os.Remove(unused.unitPath)
			if err := os.MkdirAll(unused.root, 0700); err != nil {
				t.Fatal(err)
			}
			binding, _ := json.Marshal(instanceBinding{Schema: "owntransit.relay-instance.v1", Name: unused.name, URL: unused.url, Port: unused.port})
			if err := os.WriteFile(unused.root+"/instance.json", binding, 0600); err != nil {
				t.Fatal(err)
			}
			image := "sha256:" + strings.Repeat("a", 64)
			original := make(map[string][]byte)
			containers := make(map[string]containerInfo)
			for _, s := range specs {
				if err := os.MkdirAll(s.root, 0700); err != nil {
					t.Fatal(err)
				}
				binding, _ := json.Marshal(instanceBinding{Schema: "owntransit.relay-instance.v1", Name: s.name, URL: s.url, Port: s.port})
				if err := os.WriteFile(s.root+"/instance.json", binding, 0600); err != nil {
					t.Fatal(err)
				}
				config, _ := json.Marshal(s.config(s.url, "/usr/bin/podman", image))
				if err := os.WriteFile(s.root+"/setup.json", config, 0600); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{s.dataRoot(), s.dataRoot() + "/relay"} {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Chown(path, 65532, 65532); err != nil {
						t.Fatal(err)
					}
				}
				unit := bytes.ReplaceAll(s.unit(image, "/usr/bin/podman"), currentPackageHelper, previousPackageHelper)
				unit = bytes.ReplaceAll(unit, []byte(image+" serve --state"), []byte(image+" pair serve --state"))
				if scenario == "modified-unit" && s.name == "beta" {
					unit = append(unit, []byte("Environment=UNMANAGED=yes\n")...)
				}
				if err := writeAtomic(s.unitPath, unit, 0644); err != nil {
					t.Fatal(err)
				}
				original[s.name] = unit
				c := ownedFixtureContainer(s, image)
				c.ID = strings.Repeat(string('c'+rune(s.port-9087)), 64)
				c.State.Running = true
				containers[s.container] = c
			}
			if scenario == "unknown-reference" {
				if err := os.WriteFile(foreign, []byte("[Service]\nExecStart=/usr/local/bin/owntransit-relay-preview cleanup-container\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "pending-upgrade" {
				if err := os.WriteFile(specs[2].root+"/upgrade.json", []byte("pending fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			saved := command
			t.Cleanup(func() { command = saved })
			reloads := 0
			command = func(_ context.Context, program string, args ...string) ([]byte, error) {
				if program == "/usr/bin/systemctl" {
					if args[0] == "show" {
						return nil, nil
					}
					if len(args) == 1 && args[0] == "daemon-reload" {
						reloads++
						if scenario == "reload-retry" && reloads == 1 {
							return nil, errors.New("reload fixture failure")
						}
						return nil, nil
					}
					t.Fatalf("package hook migration changed service state: %v", args)
				}
				if program == "/usr/bin/podman" && args[0] == "ps" {
					c := containers[strings.TrimPrefix(args[len(args)-1], "name=")]
					return []byte(c.ID), nil
				}
				if program == "/usr/bin/podman" && args[0] == "container" {
					for _, c := range containers {
						if c.ID == args[len(args)-1] {
							return json.Marshal([]containerInfo{c})
						}
					}
				}
				t.Fatalf("unexpected package integration operation: %s %v", filepath.Base(program), args)
				return nil, errors.New("unexpected fixture operation")
			}
			err = MigratePackageHooks(context.Background())
			failure := scenario != "all-instances"
			if (err != nil) != failure {
				t.Fatalf("migration error=%v, expected failure=%t", err, failure)
			}
			if scenario == "reload-retry" {
				if err := MigratePackageHooks(context.Background()); err != nil {
					t.Fatalf("retry: %v", err)
				}
				if reloads != 2 {
					t.Fatal("retry failed to reload published units")
				}
			}
			for _, s := range specs {
				got, err := os.ReadFile(s.unitPath)
				if err != nil {
					t.Fatal(err)
				}
				want := original[s.name]
				if scenario == "all-instances" || scenario == "reload-retry" {
					want = bytes.ReplaceAll(want, previousPackageHelper, currentPackageHelper)
				}
				if !bytes.Equal(got, want) {
					t.Fatal("migration changed fields beyond the validated helper path")
				}
				if !containers[s.container].State.Running {
					t.Fatal("running relay changed during helper migration")
				}
			}
		})
	}
}
