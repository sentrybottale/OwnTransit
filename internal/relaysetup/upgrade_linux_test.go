//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedUpgradeLifecycle(t *testing.T) {
	exe, _ := os.Executable()
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root fixture")
	}
	if _, err := os.Stat("/owntransit-relay-setup-fixture"); err != nil {
		t.Skip("requires explicit disposable fixture")
	}
	if filepath.Dir(exe) != "/usr/local/libexec/owntransit-relay-setup-check" {
		t.Fatal("unexpected fixture path")
	}
	for _, scenario := range []string{"success", "uninstall-reinstall", "failed-public-probe", "stale-running-image", "edited-unit", "interrupted", "stopped-disabled"} {
		t.Run(scenario, func(t *testing.T) {
			_ = os.RemoveAll(managedRoot)
			_ = os.Remove(unitPath)
			if err := os.MkdirAll("/etc/systemd/system", 0755); err != nil {
				t.Fatal(err)
			}
			root, err := stateRoot()
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := os.MkdirAll(managedRoot+"/data", 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := pairrelaycmd.Init(managedRoot+"/data/relay", time.Now()); err != nil {
				t.Fatal(err)
			}
			keyPath := managedRoot + "/data/relay/relay-key.pem"
			beforeKey, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			prev := savedConfig{Schema: "owntransit.relay-setup.v1", URL: "wss://relay.example/connects", Engine: "/usr/bin/podman", Image: "sha256:" + strings.Repeat("a", 64)}
			next := prev
			next.Image = "sha256:" + strings.Repeat("b", 64)
			b, _ := json.Marshal(prev)
			if err := root.CreateExclusive("setup.json", b, 0600); err != nil {
				t.Fatal(err)
			}
			if err := writeAtomic(unitPath, unit(prev.Image, prev.Engine), 0644); err != nil {
				t.Fatal(err)
			}
			currentImage := prev.Image
			present := true
			running, enabled := true, true
			if scenario == "stopped-disabled" {
				running, enabled = false, false
			}
			var calls []string
			savedCommand, savedProbe, savedTimeout := command, probeServer, routeProbeTimeout
			defer func() { command, probeServer, routeProbeTimeout = savedCommand, savedProbe, savedTimeout }()
			routeProbeTimeout = 30 * time.Millisecond
			local := pairrelay.ServerInfo{ServerName: "relay.example", CAPEM: []byte("public test CA"), LeafSPKISHA256: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
			command = func(_ context.Context, program string, args ...string) ([]byte, error) {
				calls = append(calls, program+" "+strings.Join(args, " "))
				if filepath.Base(program) == "systemctl" {
					switch args[0] {
					case "show", "daemon-reload":
						return nil, nil
					case "is-active":
						if running {
							return nil, nil
						}
						return nil, errors.New("inactive")
					case "is-enabled":
						if enabled {
							return nil, nil
						}
						return nil, errors.New("disabled")
					case "enable":
						enabled = true
					case "disable":
						enabled = false
						if len(args) > 1 && args[1] == "--now" {
							running = false
						}
					case "stop":
						running = false
					case "start":
						if present {
							return nil, errors.New("orphan container name blocks start")
						}
						present = true
						running = true
						selected, _, _ := protectedFile(unitPath)
						if bytes.Equal(selected, unit(next.Image, next.Engine)) && scenario != "stale-running-image" {
							currentImage = next.Image
						} else {
							currentImage = prev.Image
						}
					default:
						return nil, errors.New("unexpected systemd command")
					}
					return nil, nil
				}
				if args[0] == "image" {
					return []byte(prev.Image), nil
				}
				if args[0] == "ps" {
					if present {
						return []byte(strings.Repeat("c", 64)), nil
					}
					return nil, nil
				}
				if args[0] == "rm" {
					if running {
						return nil, errors.New("refusing to remove running container")
					}
					present = false
					return nil, nil
				}
				if args[0] == "container" {
					if !present {
						return nil, errors.New("container absent")
					}
					c := containerInfo{ID: strings.Repeat("c", 64), Name: "/" + managedContainer, Image: currentImage}
					c.Config.Entrypoint = []string{"/owntransit-relay"}
					c.Mounts = []struct{ Type, Source, Destination string }{{"bind", managedRoot + "/data", "/state"}}
					c.State.Running = running
					return json.Marshal([]containerInfo{c})
				}
				if args[0] == "exec" {
					return json.Marshal(local)
				}
				return nil, errors.New("unexpected engine command")
			}
			probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
				if scenario == "failed-public-probe" || scenario == "stopped-disabled" {
					return pairrelay.ServerInfo{}, errors.New("probe unavailable")
				}
				return local, nil
			}
			var output bytes.Buffer
			if scenario == "edited-unit" {
				if err := os.WriteFile(unitPath, append(unit(prev.Image, prev.Engine), []byte("# local override\n")...), 0644); err != nil {
					t.Fatal(err)
				}
				if err := UninstallManaged(context.Background()); err == nil || len(calls) != 0 {
					t.Fatal("uninstall accepted an edited unit or mutated the host")
				}
			}
			if scenario == "uninstall-reinstall" {
				if err := UninstallManaged(context.Background()); err != nil {
					t.Fatal(err)
				}
				if running || enabled || present {
					t.Fatal("uninstall left active service/container")
				}
				retained, _, err := protectedFile(unitPath)
				if err != nil || !bytes.Equal(retained, unit(prev.Image, prev.Engine)) {
					t.Fatal("uninstall changed retained configuration")
				}
				if err := UninstallManaged(context.Background()); err != nil {
					t.Fatal("uninstall rerun failed", err)
				}
			}
			if scenario == "interrupted" {
				journal, _ := json.Marshal(upgradeIntent{"owntransit.relay-upgrade.v1", prev, next, true, true, nil})
				if err := root.CreateExclusive("upgrade.json", journal, 0600); err != nil {
					t.Fatal(err)
				}
				if err := writeAtomic(unitPath, unit(next.Image, next.Engine), 0644); err != nil {
					t.Fatal(err)
				}
				currentImage = next.Image
				if err := recoverManaged(context.Background(), root, &output); err != nil {
					t.Fatal(err)
				}
				if currentImage != prev.Image || !running || !enabled {
					t.Fatal("interrupted upgrade did not restore old state")
				}
			} else {
				err := upgradeManaged(context.Background(), root, prev, next, &output)
				if scenario == "success" || scenario == "uninstall-reinstall" {
					if err != nil || currentImage != next.Image || !running || !enabled {
						t.Fatalf("upgrade failed: %v", err)
					}
					callCount := len(calls)
					if err := upgradeManaged(context.Background(), root, next, next, &output); err != nil {
						t.Fatal(err)
					}
					for _, call := range calls[callCount:] {
						if strings.Contains(call, "systemctl stop") || strings.Contains(call, "systemctl start") {
							t.Fatal("rerun restarted unchanged relay")
						}
					}
				} else if err == nil {
					t.Fatal("negative upgrade accepted")
				} else if scenario == "edited-unit" {
					if len(calls) != 0 {
						t.Fatal("edited unit triggered host operations")
					}
				} else if (running && currentImage != prev.Image) || running != (scenario != "stopped-disabled") || enabled != (scenario != "stopped-disabled") {
					t.Fatal("rollback changed previous service state")
				}
			}
			afterKey, err := os.ReadFile(keyPath)
			if err != nil || !bytes.Equal(beforeKey, afterKey) {
				t.Fatal("upgrade changed relay key")
			}
			if scenario != "edited-unit" {
				selected, err := loadConfig()
				expected := prev
				if scenario == "success" || scenario == "uninstall-reinstall" {
					expected = next
				}
				if err != nil || selected != expected {
					t.Fatal("wrong persisted image/config after cutover")
				}
			}
			if _, err := root.ReadFile("upgrade.json", 8192); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("completed rollback/upgrade retained active journal")
			}
			for _, call := range calls {
				if strings.Contains(call, "nginx") || strings.Contains(call, "apache") || strings.Contains(call, "caddy") {
					t.Fatal("managed upgrade touched website routing")
				}
			}
		})
	}
}
