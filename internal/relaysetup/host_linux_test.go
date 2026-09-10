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
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
)

// This test intentionally uses the real root paths, only in a marked,
// disposable container. Normal native test runs cannot mutate an operator host.
func TestManagedSetupAndFailedRouteRollback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires disposable root container")
	}
	if _, err := os.Stat("/owntransit-relay-setup-fixture"); err != nil {
		t.Skip("requires explicit disposable setup fixture")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(exe) != "/usr/local/libexec/owntransit-relay-setup-check" {
		t.Fatal("fixture executable is not protected")
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(exe), "owntransit-relay.oci.tar"), []byte("test image archive"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/run/systemd/system", "/etc/systemd/system", "/etc/nginx/sites-enabled"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, program := range []string{"/usr/bin/podman", "/usr/sbin/nginx"} {
		if err := os.WriteFile(program, []byte("fixture executable"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	originalCommand, originalProbe := command, probeServer
	originalFirst, originalLater := firstProbeTimeout, routeProbeTimeout
	defer func() {
		command, probeServer = originalCommand, originalProbe
		firstProbeTimeout, routeProbeTimeout = originalFirst, originalLater
	}()
	// These cases test ownership/rollback, not elapsed-time limits. Leave room
	// for real certificate and file-digest verification on instrumented CI.
	firstProbeTimeout, routeProbeTimeout = 100*time.Millisecond, 100*time.Millisecond
	const sitePath = "/etc/nginx/sites-enabled/selected.conf"
	const other = `server { listen 443 ssl; server_name other.example; location / { proxy_pass http://127.0.0.1:8080; } }`
	const original = other + "\n" + `server { listen 443 ssl; server_name relay.example; location / { try_files $uri /index.php; } }` + "\n"
	for _, failRoute := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[failRoute], func(t *testing.T) {
			if err := os.RemoveAll(managedRoot); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(unitPath)
			if err := os.WriteFile(sitePath, []byte(original), 0644); err != nil {
				t.Fatal(err)
			}
			var calls []string
			var local pairrelay.ServerInfo
			oldRunning, managedRunning, managedEnabled := true, false, false
			oldID, newID := strings.Repeat("a", 64), strings.Repeat("d", 64)
			newImage := "sha256:" + strings.Repeat("b", 64)
			managedInfo := func() containerInfo {
				c := containerInfo{ID: newID, Image: newImage, Name: managedContainer}
				c.Config.User = "65532:65532"
				c.Config.Entrypoint = []string{"/owntransit-relay"}
				c.Config.Cmd = []string{"serve", "--state", "/state/relay"}
				c.State.Running = managedRunning
				c.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{"9087/tcp": {{"127.0.0.1", "9087"}}}
				c.HostConfig.ReadonlyRootfs, c.HostConfig.AutoRemove = true, true
				c.HostConfig.CapDrop = []string{"ALL"}
				c.HostConfig.SecurityOpt = []string{"no-new-privileges"}
				c.HostConfig.Memory, c.HostConfig.PidsLimit = 268435456, 128
				c.HostConfig.CpuPeriod, c.HostConfig.CpuQuota = 100000, 100000
				c.Mounts = []inspectionMount{{"bind", managedRoot + "/data", "/state", true}}
				return c
			}
			command = func(_ context.Context, program string, args ...string) ([]byte, error) {
				call := filepath.Base(program) + " " + strings.Join(args, " ")
				calls = append(calls, call)
				if filepath.Base(program) == "nginx" {
					if len(args) == 1 && args[0] == "-T" {
						contents, err := os.ReadFile(sitePath)
						return append([]byte("# configuration file "+sitePath+":\n"), contents...), err
					}
					return nil, nil
				}
				if filepath.Base(program) == "systemctl" {
					unit := args[len(args)-1]
					if args[0] == "is-active" || args[0] == "is-enabled" {
						if unit == managedUnit && ((args[0] == "is-active" && managedRunning) || (args[0] == "is-enabled" && managedEnabled)) {
							return nil, nil
						}
						return nil, errors.New("legacy unit absent")
					}
					if unit == managedUnit {
						switch args[0] {
						case "enable":
							if oldRunning {
								return nil, errors.New("old relay still owns the port")
							}
							managedEnabled, managedRunning = true, true
						case "disable":
							managedEnabled, managedRunning = false, false
						}
					}
					return nil, nil
				}
				if filepath.Base(program) != "podman" {
					return nil, errors.New("unknown engine")
				}
				switch args[0] {
				case "ps":
					if oldRunning {
						return []byte(oldID), nil
					}
					if managedRunning {
						return []byte(newID), nil
					}
					return nil, nil
				case "container":
					if args[len(args)-1] == managedContainer || args[len(args)-1] == newID {
						if !managedRunning {
							return nil, errors.New("managed relay absent")
						}
						return json.Marshal([]containerInfo{managedInfo()})
					}
					c := containerInfo{ID: oldID, Image: "sha256:" + strings.Repeat("c", 64), Name: "/owntransit-relay"}
					c.Config.Entrypoint = []string{"/owntransit-relay"}
					c.Config.Cmd = []string{"run"}
					c.State.Running = oldRunning
					c.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{"9087/tcp": {{"127.0.0.1", "9087"}}}
					return json.Marshal([]containerInfo{c})
				case "info":
					return []byte("arm64"), nil
				case "image":
					if args[len(args)-2] == "{{.Config.User}}" {
						return []byte("65532:65532"), nil
					}
					return []byte(newImage), nil
				case "exec":
					if !managedRunning {
						return nil, errors.New("managed relay absent")
					}
					if !fixtureIdentityCommand(managedInfo(), args) {
						return nil, errors.New("unexpected relay identity command")
					}
					return json.Marshal(local)
				case "run":
					if !strings.HasSuffix(call, newImage+" init --state /state/relay") {
						return nil, errors.New("unexpected container run")
					}
					data := managedRoot + "/data"
					if err := os.Chown(data, 0, 0); err != nil {
						return nil, err
					}
					if _, err := pairrelaycmd.Init(data+"/relay", time.Now()); err != nil {
						return nil, err
					}
					if err := filepath.Walk(data, func(path string, _ os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						return os.Chown(path, 65532, 65532)
					}); err != nil {
						return nil, err
					}
					var err error
					local, err = readPublicIdentity(defaultInstance())
					return nil, err
				case "stop":
					if args[len(args)-1] == oldID {
						oldRunning = false
					}
					return nil, nil
				case "start":
					if args[len(args)-1] == oldID {
						if managedRunning {
							return nil, errors.New("new relay still owns the port")
						}
						oldRunning = true
					}
					return nil, nil
				case "load":
					return nil, nil
				}
				return nil, errors.New("unexpected setup command")
			}
			probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
				b, _ := os.ReadFile(sitePath)
				if !failRoute && bytes.Contains(b, []byte("location = /connects")) {
					return local, nil
				}
				return pairrelay.ServerInfo{}, errors.New("route absent")
			}
			var output bytes.Buffer
			err := Setup(context.Background(), "https://relay.example/connects", &output)
			written, _ := os.ReadFile(sitePath)
			if failRoute {
				if err == nil || !bytes.Equal(written, []byte(original)) {
					t.Fatal("failed route was not restored")
				}
				if !strings.Contains(strings.Join(calls, "\n"), "podman start "+strings.Repeat("a", 64)) {
					t.Fatal("previous relay was not restored")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasPrefix(written, []byte(other+"\n")) {
					t.Fatal("another site changed")
				}
				if !strings.Contains(output.String(), "Local relay setup completed for wss://relay.example/connects") {
					t.Fatal("missing verified URL")
				}
			}
		})
	}
	t.Run("adopt exact keys and reject symlinks", func(t *testing.T) {
		parent := t.TempDir()
		source := filepath.Join(parent, "relay")
		if _, err := pairrelaycmd.Init(source, time.Now()); err != nil {
			t.Fatal(err)
		}
		c := containerInfo{}
		c.Mounts = []inspectionMount{{"bind", parent, "/state", true}}
		dataDir := filepath.Join(managedRoot, "adoption-data")
		if err := os.Mkdir(dataDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := adoptState(c, dataDir); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"token-hmac.key", "relay-ca-cert.pem", "relay-ca-key.pem", "relay-cert.pem", "relay-key.pem"} {
			before, e := os.ReadFile(filepath.Join(source, name))
			if e != nil {
				t.Fatal(e)
			}
			after, e := os.ReadFile(filepath.Join(dataDir, "relay", name))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("adoption changed a relay identity")
			}
		}
		badDir := filepath.Join(managedRoot, "bad-adoption-data")
		if err := os.Mkdir(badDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(source, "relay-key.pem")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/passwd", filepath.Join(source, "relay-key.pem")); err != nil {
			t.Fatal(err)
		}
		if err := adoptState(c, badDir); err == nil {
			t.Fatal("adoption followed a relay-controlled symlink")
		}
		if _, err := os.Stat(filepath.Join(badDir, "relay")); !os.IsNotExist(err) {
			t.Fatal("failed adoption published partial state")
		}
	})
}
