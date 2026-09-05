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
	firstProbeTimeout, routeProbeTimeout = time.Millisecond, time.Millisecond
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
			local := pairrelay.ServerInfo{ServerName: "relay.pairrelay.v2.owntransit.invalid", CAPEM: []byte("public test CA"), LeafSPKISHA256: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
			command = func(_ context.Context, program string, args ...string) ([]byte, error) {
				call := filepath.Base(program) + " " + strings.Join(args, " ")
				calls = append(calls, call)
				if filepath.Base(program) == "nginx" {
					if len(args) == 1 && args[0] == "-T" {
						return []byte("# configuration file " + sitePath + ":\n" + original), nil
					}
					return nil, nil
				}
				if filepath.Base(program) == "systemctl" {
					if args[0] == "is-active" || args[0] == "is-enabled" {
						return nil, errors.New("legacy unit absent")
					}
					return nil, nil
				}
				if filepath.Base(program) != "podman" {
					return nil, errors.New("unknown engine")
				}
				switch args[0] {
				case "ps":
					return []byte(strings.Repeat("a", 64)), nil
				case "container":
					c := containerInfo{ID: strings.Repeat("a", 64), Name: "/owntransit-relay"}
					c.Config.Entrypoint = []string{"/owntransit-relay"}
					c.Config.Cmd = []string{"run"}
					c.State.Running = true
					c.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{"9087/tcp": {{"127.0.0.1", "9087"}}}
					return json.Marshal([]containerInfo{c})
				case "info":
					return []byte("arm64"), nil
				case "image":
					if args[len(args)-2] == "{{.Config.User}}" {
						return []byte("65532:65532"), nil
					}
					return []byte("sha256:" + strings.Repeat("b", 64)), nil
				case "exec":
					return json.Marshal(local)
				case "load", "run", "start", "stop":
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
				if !strings.Contains(output.String(), "ready at wss://relay.example/connects") {
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
		c.Mounts = []struct{ Type, Source, Destination string }{{"bind", parent, "/state"}}
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
