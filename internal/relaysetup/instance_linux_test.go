//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func fixtureSpec(t *testing.T, name string, port int) instanceSpec {
	t.Helper()
	s, err := instanceFromBinding(instanceBinding{"owntransit.relay-instance.v1", name, "wss://" + name + ".example/connects", port})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ownedFixtureContainer(s instanceSpec, image string) containerInfo {
	c := containerInfo{ID: strings.Repeat("c", 64), Image: image, Name: "/" + s.container}
	c.Config.Entrypoint = []string{"/owntransit-relay"}
	c.Config.Cmd = []string{"pair", "serve", "--state", "/state/relay"}
	c.Mounts = []struct{ Type, Source, Destination string }{{"bind", s.root + "/data", "/state"}}
	c.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{"9087/tcp": {{"127.0.0.1", strconv.Itoa(s.port)}}}
	return c
}

func TestInstanceBindingUnitsAndOwnership(t *testing.T) {
	a, b := fixtureSpec(t, "alpha", 9088), fixtureSpec(t, "beta", 9089)
	image := "sha256:" + strings.Repeat("a", 64)
	ac := a.config(a.url, "/usr/bin/podman", image)
	if !a.validSaved(ac) || b.validSaved(ac) || defaultInstance().validSaved(ac) {
		t.Fatal("setup config escaped its instance")
	}
	for _, mutate := range []func(*savedConfig){func(c *savedConfig) { c.Port++ }, func(c *savedConfig) { c.Instance = "beta" }, func(c *savedConfig) { c.URL = b.url }, func(c *savedConfig) { c.Schema = "owntransit.relay-setup.v1" }} {
		bad := ac
		mutate(&bad)
		if a.validSaved(bad) {
			t.Fatal("altered config accepted")
		}
	}
	if !a.knownUnit(a.unit(image, ac.Engine), ac) || a.knownUnit(b.unit(image, ac.Engine), ac) || a.knownUnit(a.legacyUnit(image, ac.Engine), ac) {
		t.Fatal("unit ownership widened")
	}
	if !bytes.Contains(a.unit(image, ac.Engine), []byte("cleanup-container --instance alpha ")) || !bytes.Contains(a.unit(image, ac.Engine), []byte("--publish=127.0.0.1:9088:9087/tcp")) {
		t.Fatal("missing instance unit confinement")
	}
	for _, scenario := range []string{"owned", "name", "image", "entry", "cmd", "mount", "extra-mount", "port", "wildcard", "extra-port"} {
		c := ownedFixtureContainer(a, image)
		switch scenario {
		case "name":
			c.Name = b.container
		case "image":
			c.Image = "sha256:" + strings.Repeat("b", 64)
		case "entry":
			c.Config.Entrypoint = []string{"/bin/owntransit-relay"}
		case "cmd":
			c.Config.Cmd = []string{"pair", "serve", "--state", "/state/other"}
		case "mount":
			c.Mounts[0].Source = b.root + "/data"
		case "extra-mount":
			c.Mounts = append(c.Mounts, c.Mounts[0])
		case "port":
			c.HostConfig.PortBindings["9087/tcp"][0].HostPort = "9089"
		case "wildcard":
			c.HostConfig.PortBindings["9087/tcp"][0].HostIP = "0.0.0.0"
		case "extra-port":
			c.HostConfig.PortBindings["9088/tcp"] = c.HostConfig.PortBindings["9087/tcp"]
		}
		if a.ownsContainer(c, image) != (scenario == "owned") {
			t.Fatalf("ownership scenario %s", scenario)
		}
	}
	for _, schema := range []string{"owntransit.relay-upgrade.v1", "owntransit.relay-upgrade.v2"} {
		if a.validJournalSchema(schema) || !defaultInstance().validJournalSchema(schema) {
			t.Fatal("legacy journal selected a named instance")
		}
	}
	if !a.validJournalSchema("owntransit.relay-upgrade.v3") || defaultInstance().validJournalSchema("owntransit.relay-upgrade.v3") {
		t.Fatal("named journal accepted by legacy default")
	}
	misplaced := ownedFixtureContainer(a, image)
	misplaced.Config.Labels = map[string]string{"org.opencontainers.image.title": "OwnTransit Relay"}
	misplaced.HostConfig.PortBindings["9087/tcp"][0].HostPort = "9087"
	if !ownsPort(misplaced) || ownRelay(misplaced) {
		t.Fatal("default legacy discovery adopted a misplaced named instance")
	}
	old := command
	defer func() { command = old }()
	command = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("cross-instance journal reached host operation")
		return nil, nil
	}
	if a.restoreManaged(context.Background(), nil, upgradeIntent{Schema: "owntransit.relay-upgrade.v3", Previous: ac, Next: b.config(b.url, ac.Engine, image)}) == nil {
		t.Fatal("cross-instance recovery accepted")
	}
}

func requireNamedRelayFixture(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root fixture")
	}
	if _, err := os.Stat("/owntransit-relay-setup-fixture"); err != nil {
		t.Skip("requires explicit disposable fixture")
	}
	exe, err := os.Executable()
	if err != nil || filepath.Dir(exe) != "/usr/local/libexec/owntransit-relay-setup-check" {
		t.Fatal("unexpected fixture executable path")
	}
}

func TestNamedRelayLifecycleIsolation(t *testing.T) {
	requireNamedRelayFixture(t)
	if err := os.RemoveAll(managedRoot); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{managedUnit, managedContainer + "-alpha.service", managedContainer + "-beta.service"} {
		_ = os.Remove("/etc/systemd/system/" + name)
	}
	for _, dir := range []string{"/run/systemd/system", "/etc/systemd/system", "/etc/nginx/sites-enabled"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	exe, _ := os.Executable()
	for _, file := range []string{"/usr/bin/podman", "/usr/sbin/nginx", filepath.Join(filepath.Dir(exe), "owntransit-relay.oci.tar")} {
		if err := os.WriteFile(file, []byte("disposable fixture"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	const site = "/etc/nginx/sites-enabled/named-relays.conf"
	var initial strings.Builder
	for _, name := range []string{"default", "alpha", "beta"} {
		fmt.Fprintf(&initial, "server { listen 443 ssl; server_name %s.example; location / { try_files $uri /index.html; } }\n", name)
	}
	if err := os.WriteFile(site, []byte(initial.String()), 0644); err != nil {
		t.Fatal(err)
	}
	a, b, d := fixtureSpec(t, "alpha", 9088), fixtureSpec(t, "beta", 9089), fixtureSpec(t, "default", 9087)
	specs := []instanceSpec{d, a, b}
	containers := map[string]*containerInfo{}
	enabled := map[string]bool{}
	oldImage := "sha256:" + strings.Repeat("a", 64)
	newImage := "sha256:" + strings.Repeat("b", 64)
	selectedImage := oldImage
	failedURL := ""
	registrationUnavailable := false
	var calls []string
	find := func(name string) (instanceSpec, bool) {
		for _, s := range specs {
			if name == s.container || name == s.unitName || name == s.url {
				return s, true
			}
		}
		return instanceSpec{}, false
	}
	info := func(s instanceSpec) pairrelay.ServerInfo {
		return pairrelay.ServerInfo{ServerName: "relay.pairrelay.v2.owntransit.invalid", CAPEM: []byte("public fixture " + s.name), LeafSPKISHA256: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	}
	oldCommand, oldProbe, oldFirst, oldLater := command, probeServer, firstProbeTimeout, routeProbeTimeout
	defer func() {
		command, probeServer, firstProbeTimeout, routeProbeTimeout = oldCommand, oldProbe, oldFirst, oldLater
	}()
	firstProbeTimeout, routeProbeTimeout = time.Millisecond, 5*time.Millisecond
	command = func(ctx context.Context, program string, args ...string) ([]byte, error) {
		calls = append(calls, program+" "+strings.Join(args, " "))
		if filepath.Base(program) == "nginx" {
			if len(args) == 1 && args[0] == "-T" {
				return []byte("# configuration file " + site + ":\n"), nil
			}
			return nil, nil
		}
		if filepath.Base(program) == "systemctl" {
			if args[0] == "daemon-reload" {
				return nil, nil
			}
			s, ok := find(args[len(args)-1])
			if args[0] == "show" {
				s, ok = find(args[1])
			}
			if !ok {
				return nil, errors.New("unknown fixture unit")
			}
			switch args[0] {
			case "show":
				return nil, nil
			case "is-active":
				if c := containers[s.container]; c != nil && c.State.Running {
					return nil, nil
				}
				return nil, errors.New("inactive")
			case "is-enabled":
				if enabled[s.unitName] {
					return nil, nil
				}
				return nil, errors.New("disabled")
			case "disable", "stop":
				if args[0] == "disable" {
					enabled[s.unitName] = false
				}
				if args[0] == "stop" || (len(args) > 1 && args[1] == "--now") {
					if c := containers[s.container]; c != nil {
						c.State.Running = false
						return nil, CleanupInstance(ctx, s.name, "/usr/bin/podman", c.Image)
					}
				}
				return nil, nil
			case "enable":
				enabled[s.unitName] = true
				if len(args) < 2 || args[1] != "--now" {
					return nil, nil
				}
			case "start":
			default:
				return nil, errors.New("unexpected fixture service action")
			}
			data, err := os.ReadFile(s.unitPath)
			if err != nil {
				return nil, err
			}
			image := oldImage
			if bytes.Contains(data, []byte(newImage)) {
				image = newImage
			}
			if err := CleanupInstance(ctx, s.name, "/usr/bin/podman", image); err != nil {
				return nil, err
			}
			c := ownedFixtureContainer(s, image)
			c.ID = strings.Repeat(string('c'+rune(s.port-9087)), 64)
			c.State.Running = true
			containers[s.container] = &c
			return nil, nil
		}
		if filepath.Base(program) != "podman" {
			return nil, errors.New("unknown fixture engine")
		}
		switch args[0] {
		case "info":
			return []byte("amd64"), nil
		case "load":
			return nil, nil
		case "image":
			if args[len(args)-2] == "{{.Config.User}}" {
				return []byte("65532:65532"), nil
			}
			return []byte(selectedImage), nil
		case "ps":
			var ids []string
			filter := ""
			all := false
			for _, arg := range args {
				if strings.HasPrefix(arg, "name=") {
					filter = strings.TrimPrefix(arg, "name=")
				}
				if arg == "--all" {
					all = true
				}
			}
			for _, c := range containers {
				if (all || c.State.Running) && (filter == "" || strings.Contains(c.Name, filter)) {
					ids = append(ids, c.ID)
				}
			}
			return []byte(strings.Join(ids, "\n")), nil
		case "container":
			for _, c := range containers {
				if args[2] == c.ID || args[2] == strings.TrimPrefix(c.Name, "/") {
					return json.Marshal([]containerInfo{*c})
				}
			}
			return nil, errors.New("absent")
		case "rm":
			for name, c := range containers {
				if args[1] == c.ID {
					if len(args) != 2 || c.State.Running {
						t.Fatal("unsafe cleanup")
					}
					delete(containers, name)
					return nil, nil
				}
			}
			return nil, errors.New("absent")
		case "run":
			path := ""
			for _, arg := range args {
				if strings.HasPrefix(arg, "--volume=") {
					path = strings.TrimSuffix(strings.TrimPrefix(arg, "--volume="), ":/state:rw") + "/relay"
				}
			}
			if path == "" {
				return nil, errors.New("missing state bind")
			}
			_, err := pairrelaycmd.Init(path, time.Now())
			if err != nil {
				return nil, err
			}
			return nil, filepath.Walk(path, func(path string, _ os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				return os.Chown(path, 65532, 65532)
			})
		case "exec":
			s, ok := find(args[1])
			if !ok {
				t.Fatal("registration escaped selected instance")
			}
			if len(args) > 4 && args[4] == "register" {
				if registrationUnavailable && s.name == a.name {
					return nil, errors.New("fixture receiver is not advertising on alpha")
				}
				return []byte("fixture registration for " + s.name), nil
			}
			return json.Marshal(info(s))
		}
		return nil, errors.New("unexpected fixture engine action")
	}
	probeServer = func(_ context.Context, url string) (pairrelay.ServerInfo, error) {
		s, ok := find(url)
		if !ok || url == failedURL {
			return pairrelay.ServerInfo{}, errors.New("fixture public route unavailable")
		}
		data, _ := os.ReadFile(site)
		edit, err := NginxRouteForPort(data, strings.TrimPrefix(strings.TrimSuffix(url, "/connects"), "wss://"), s.port)
		if err != nil || !edit.Reused {
			return pairrelay.ServerInfo{}, errors.New("fixture route absent")
		}
		return info(s), nil
	}
	if err := SetupInstance(context.Background(), d.name, d.url, io.Discard); err != nil {
		t.Fatal(err)
	}
	failedURL = a.url
	if err := SetupInstance(context.Background(), a.name, a.url, io.Discard); err == nil {
		t.Fatal("initial failed route accepted")
	}
	failedAKey, err := os.ReadFile(a.root + "/data/relay/relay-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	failedURL = ""
	if err := SetupInstance(context.Background(), b.name, b.url, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := SetupInstance(context.Background(), a.name, a.url, io.Discard); err != nil {
		t.Fatal("A retry after B changed the shared site", err)
	}
	retriedAKey, _ := os.ReadFile(a.root + "/data/relay/relay-key.pem")
	if !bytes.Equal(failedAKey, retriedAKey) {
		t.Fatal("failed first setup replaced A's keys")
	}
	keys := map[string][]byte{}
	for _, s := range specs {
		key, err := os.ReadFile(s.root + "/data/relay/relay-key.pem")
		if err != nil {
			t.Fatal(err)
		}
		keys[s.name] = key
	}
	if bytes.Equal(keys[a.name], keys[b.name]) || bytes.Equal(keys[a.name], keys[d.name]) {
		t.Fatal("relay keys reused across instances")
	}
	beforeB, _ := os.ReadFile(b.unitPath)
	beforeD, _ := os.ReadFile(d.unitPath)
	beforeSite, _ := os.ReadFile(site)
	start := len(calls)
	selectedImage = newImage
	if err := SetupInstance(context.Background(), a.name, a.url, io.Discard); err != nil {
		t.Fatal("named upgrade", err)
	}
	if containers[a.container].Image != newImage {
		t.Fatal("wrong upgraded image")
	}
	publicID := (protocol.ID{1}).String()
	registration, err := RegisterInstance(context.Background(), a.name, publicID)
	if err != nil || registration != "fixture registration for alpha" {
		t.Fatal("scoped registration", err)
	}
	assertOnlyAlphaCalls := func(from int) {
		t.Helper()
		for _, call := range calls[from:] {
			if !strings.Contains(call, " "+a.container+" ") && !strings.HasSuffix(call, " "+a.container) {
				t.Fatal("URL registration touched another instance", call)
			}
		}
	}
	urlStart := len(calls)
	registration, err = RegisterURL(context.Background(), "https://ALPHA.example:443/", publicID)
	if err != nil || registration != "fixture registration for alpha" {
		t.Fatal("canonical URL registration did not select alpha", err)
	}
	assertOnlyAlphaCalls(urlStart)
	for _, request := range []struct{ url, id string }{
		{"wss://unknown.example/connects", publicID},
		{a.url, "otpair1.invalid-fixture"},
		{"http://alpha.example/connects", publicID},
	} {
		urlStart = len(calls)
		if _, err := RegisterURL(context.Background(), request.url, request.id); err == nil {
			t.Fatal("invalid or unknown URL registration accepted")
		}
		if len(calls) != urlStart {
			t.Fatal("invalid or unknown URL registration reached a host command")
		}
	}
	containers[a.container].State.Running = false
	urlStart = len(calls)
	if _, err := RegisterURL(context.Background(), a.url, publicID); err == nil {
		t.Fatal("unavailable alpha fell back to another relay")
	}
	assertOnlyAlphaCalls(urlStart)
	containers[a.container].State.Running = true
	registrationUnavailable = true
	urlStart = len(calls)
	if _, err := RegisterURL(context.Background(), a.url, publicID); err == nil {
		t.Fatal("unavailable alpha registration fell back to another relay")
	}
	assertOnlyAlphaCalls(urlStart)
	registrationUnavailable = false
	br, err := b.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	conflict, _ := json.Marshal(instanceBinding{"owntransit.relay-instance.v1", b.name, a.url, b.port})
	if err := br.ReplaceFile("instance.json", conflict, 0600); err != nil {
		t.Fatal(err)
	}
	urlStart = len(calls)
	if _, err := RegisterURL(context.Background(), a.url, publicID); err == nil {
		t.Fatal("conflicting URL registration selected a relay")
	}
	if len(calls) != urlStart {
		t.Fatal("conflicting URL registration reached a host command")
	}
	bound, _ := json.Marshal(instanceBinding{"owntransit.relay-instance.v1", b.name, b.url, b.port})
	if err := br.ReplaceFile("instance.json", bound, 0600); err != nil {
		t.Fatal(err)
	}
	br.Close()
	selectedImage = oldImage
	failedURL = a.url
	if err := SetupInstance(context.Background(), a.name, a.url, io.Discard); err == nil {
		t.Fatal("failed public verification accepted")
	}
	if containers[a.container].Image != newImage || !containers[a.container].State.Running {
		t.Fatal("failed upgrade did not restore A")
	}
	failedURL = ""
	if err := UninstallInstance(context.Background(), a.name); err != nil {
		t.Fatal(err)
	}
	if containers[a.container] != nil || enabled[a.unitName] {
		t.Fatal("uninstall left A running")
	}
	for _, s := range []instanceSpec{b, d} {
		if containers[s.container] == nil || !containers[s.container].State.Running || !enabled[s.unitName] {
			t.Fatal("A changed another instance")
		}
	}
	afterB, _ := os.ReadFile(b.unitPath)
	afterD, _ := os.ReadFile(d.unitPath)
	afterSite, _ := os.ReadFile(site)
	if !bytes.Equal(beforeB, afterB) || !bytes.Equal(beforeD, afterD) || !bytes.Equal(beforeSite, afterSite) {
		t.Fatal("scoped lifecycle changed another unit or website")
	}
	for _, s := range specs {
		after, _ := os.ReadFile(s.root + "/data/relay/relay-key.pem")
		if !bytes.Equal(keys[s.name], after) {
			t.Fatal("lifecycle changed relay keys")
		}
	}
	for _, call := range calls[start:] {
		if strings.Contains(call, "systemctl") && (strings.Contains(call, b.unitName) || strings.Contains(call, d.unitName)) {
			t.Fatal("scoped lifecycle touched another unit", call)
		}
	}
	var list bytes.Buffer
	if err := ListInstances(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list.String(), "alpha\twss://alpha.example/connects\t127.0.0.1:9088\tstopped") {
		t.Fatal("list lost retained instance", list.String())
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserveInstance(root, "gamma", a.url); err == nil {
		t.Fatal("removed instance URL was reused")
	}
	if _, err := reserveInstance(root, a.name, b.url); err == nil {
		t.Fatal("existing instance URL was changed")
	}
	lock.Close()
	root.Close()
	if err := os.Remove(b.unitPath); err != nil {
		t.Fatal(err)
	}
	start = len(calls)
	if err := UninstallAllManaged(context.Background()); err == nil {
		t.Fatal("all removal accepted B running without its unit")
	}
	for _, call := range calls[start:] {
		if strings.Contains(call, "systemctl disable") || strings.Contains(call, "systemctl stop") || strings.Contains(call, "podman rm") {
			t.Fatal("all removal mutated before missing-unit prevalidation")
		}
	}
	if err := os.WriteFile(b.unitPath, beforeB, 0644); err != nil {
		t.Fatal(err)
	}
	// The all-instance operation must not stop default/A before noticing B's
	// modified unit, regardless of its position in the bounded registry.
	if err := os.WriteFile(b.unitPath, append(beforeB, []byte("# local modification\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	start = len(calls)
	if err := UninstallAllManaged(context.Background()); err == nil {
		t.Fatal("all removal accepted modified B")
	}
	for _, call := range calls[start:] {
		if strings.Contains(call, "systemctl disable") || strings.Contains(call, "systemctl stop") || strings.Contains(call, "podman rm") {
			t.Fatal("all removal mutated before full prevalidation")
		}
	}
	if err := os.WriteFile(b.unitPath, beforeB, 0644); err != nil {
		t.Fatal(err)
	}
	if err := UninstallAllManaged(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(containers) != 0 {
		t.Fatal("all removal left managed containers")
	}
}

func TestNamedRelayPendingSetupRecoveryAndReservations(t *testing.T) {
	requireNamedRelayFixture(t)
	if err := os.RemoveAll(managedRoot); err != nil {
		t.Fatal(err)
	}
	a := fixtureSpec(t, "alpha", 9088)
	_ = os.Remove(a.unitPath)
	_ = os.Remove(unitPath)
	_ = os.Remove("/etc/systemd/system/" + managedContainer + "-beta.service")
	root, lock, err := managerRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer lock.Close()
	a, err = reserveInstance(root, a.name, a.url)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a.root + "/data", a.root + "/data/relay"} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65532, 65532); err != nil {
			t.Fatal(err)
		}
	}
	r, err := a.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	oldImage, newImage := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	previous, next := a.config(a.url, "/usr/bin/podman", oldImage), a.config(a.url, "/usr/bin/podman", newImage)
	oldCommand := command
	defer func() { command = oldCommand }()
	var mutations int
	command = func(_ context.Context, program string, args ...string) ([]byte, error) {
		if filepath.Base(program) == "systemctl" {
			if args[0] == "show" {
				if args[1] != a.unitName {
					t.Fatal("wrong recovery unit")
				}
				return nil, nil
			}
			if len(args) != 3 || args[0] != "disable" || args[1] != "--now" || args[2] != a.unitName {
				t.Fatal("unexpected recovery mutation")
			}
			mutations++
			return nil, nil
		}
		if args[0] == "ps" {
			return nil, nil
		}
		t.Fatal("unexpected recovery command")
		return nil, nil
	}
	for _, scenario := range []string{"old-unit", "new-pending-no-unit", "new-unit", "cross-instance", "wrong-mode"} {
		t.Run(scenario, func(t *testing.T) {
			_ = os.Remove(a.unitPath)
			c := previous
			if scenario == "new-pending-no-unit" || scenario == "new-unit" {
				c = next
			}
			if scenario == "cross-instance" {
				c.Instance = "beta"
			}
			encoded, _ := json.Marshal(c)
			if err := r.ReplaceFile("pending-setup.json", encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if scenario != "new-pending-no-unit" {
				if err := writeAtomic(a.unitPath, a.unit(c.Image, c.Engine), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "wrong-mode" {
				if err := os.Chmod(a.root+"/pending-setup.json", 0644); err != nil {
					t.Fatal(err)
				}
			}
			before := mutations
			err := a.recoverFresh(context.Background(), r)
			if scenario == "cross-instance" || scenario == "wrong-mode" {
				if err == nil || mutations != before {
					t.Fatal("unsafe pending record reached service mutation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(a.unitPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("incomplete unit not removed before pending image change")
			}
			if _, err := r.ReadFile("pending-setup.json", 8192); err != nil {
				t.Fatal("recovery lost durable pending record")
			}
			// Simulate interruption immediately after changing pending image but
			// before publishing its unit, then recover again.
			encoded, _ = json.Marshal(next)
			if err := r.ReplaceFile("pending-setup.json", encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.recoverFresh(context.Background(), r); err != nil {
				t.Fatal("interrupted pending replacement cannot recover", err)
			}
		})
	}
	if err := os.Chmod(a.root+"/pending-setup.json", 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.UnlinkFile("pending-setup.json"); err != nil {
		t.Fatal(err)
	}
	b, err := reserveInstance(root, "beta", "wss://beta.example/connects")
	if err != nil {
		t.Fatal(err)
	}
	if b.port != a.port+1 {
		t.Fatal("reserved pending port was reused")
	}
	br, err := b.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	good, _ := json.Marshal(instanceBinding{"owntransit.relay-instance.v1", b.name, b.url, b.port})
	for _, bad := range []instanceBinding{
		{"owntransit.relay-instance.v1", b.name, b.url, a.port},
		{"owntransit.relay-instance.v1", b.name, a.url, b.port},
		{"owntransit.relay-instance.v1", a.name, b.url, b.port},
	} {
		data, _ := json.Marshal(bad)
		if err := br.ReplaceFile("instance.json", data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := scanInstances(root); err == nil {
			t.Fatal("conflicting or cross-instance binding accepted")
		}
	}
	if err := br.ReplaceFile("instance.json", good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(b.root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := scanInstances(root); err == nil {
		t.Fatal("public instance root accepted")
	}
	if err := os.Chmod(b.root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b.root, managedRoot+"/instances/gamma"); err != nil {
		t.Fatal(err)
	}
	if _, err := scanInstances(root); err == nil {
		t.Fatal("symlink instance accepted")
	}
	if err := os.Remove(managedRoot + "/instances/gamma"); err != nil {
		t.Fatal(err)
	}
}
