//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

type migrationFixture struct {
	t                  *testing.T
	old, target        instanceSpec
	oldImage, newImage string
	containers         map[string]containerInfo
	enabled            map[string]bool
	local              pairrelay.ServerInfo
	calls              []string
	failNewProbe       bool
	crash              string
	crashed            bool
	extraNginxDump     string
}

func newMigrationFixture(t *testing.T) *migrationFixture {
	t.Helper()
	requireNamedRelayFixture(t)
	for _, path := range []string{managedRoot, legacyRoot("alpha")} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{managedUnit, "owntransit-relay-alpha.service", managedContainer + "-work.service"} {
		_ = os.Remove("/etc/systemd/system/" + name)
		_ = os.RemoveAll("/etc/systemd/system/" + name + ".d")
	}
	for _, dir := range []string{"/run/systemd/system", "/etc/systemd/system", "/etc/nginx/sites-enabled"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	exe, _ := os.Executable()
	for _, file := range []string{"/usr/bin/podman", "/usr/sbin/nginx", filepath.Join(filepath.Dir(exe), "owntransit-relay.oci.tar")} {
		if err := os.WriteFile(file, []byte("disposable migration fixture"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	f := &migrationFixture{t: t, old: legacySpec("alpha", "wss://work.example/connects", 9088), target: fixtureSpec(t, "work", 9089), oldImage: "sha256:" + strings.Repeat("a", 64), newImage: "sha256:" + strings.Repeat("b", 64), containers: map[string]containerInfo{}, enabled: map[string]bool{}}
	root, lock, err := managerRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer lock.Close()
	if _, err := reserveInstance(root, "default", "wss://default.example/connects"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.target.root, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := f.target.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, _ := json.Marshal(f.target.binding())
	if err := r.CreateExclusive("instance.json", b, 0600); err != nil {
		t.Fatal(err)
	}
	pending := f.target.config(f.target.url, "/usr/bin/podman", f.oldImage)
	b, _ = json.Marshal(pending)
	if err := r.CreateExclusive("pending-setup.json", b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(f.target.unitPath, f.target.unit(f.oldImage, pending.Engine), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.old.dataRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := pairrelaycmd.Init(f.old.dataRoot()+"/relay", time.Now()); err != nil {
		t.Fatal(err)
	}
	info, err := pairrelaycmd.StateInfo(f.old.dataRoot() + "/relay")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(info, &f.local); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(f.old.dataRoot(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, 65532, 65532)
	}); err != nil {
		t.Fatal(err)
	}
	manual := bytes.Replace(f.old.legacyUnit(f.oldImage, pending.Engine), []byte("Description=OwnTransit managed relay"), []byte("Description=OwnTransit independent relay"), 1)
	manual = bytes.Replace(manual, []byte("Restart=on-failure\n"), []byte("ExecStopPost=-/usr/bin/podman rm --ignore "+f.old.container+"\nRestart=on-failure\n"), 1)
	if err := writeAtomic(f.old.unitPath, manual, 0644); err != nil {
		t.Fatal(err)
	}
	site := []byte("server { listen 443 ssl; server_name work.example; location = /connects { proxy_pass http://127.0.0.1:9088/connects; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"upgrade\"; } }\n")
	if err := os.WriteFile("/etc/nginx/sites-enabled/migration.conf", site, 0644); err != nil {
		t.Fatal(err)
	}
	f.containers[f.old.container] = f.container(f.old, f.oldImage, "c")
	f.enabled[f.old.unitName] = true
	// A second, untouched default container is included in every inventory.
	d := defaultInstance()
	f.containers[d.container] = f.container(d, f.oldImage, "d")
	f.enabled[d.unitName] = true
	if err := os.MkdirAll(d.dataRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := pairrelaycmd.Init(d.dataRoot()+"/relay", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(d.dataRoot(), func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, 65532, 65532)
	}); err != nil {
		t.Fatal(err)
	}
	defaultConfig, _ := json.Marshal(d.config("wss://default.example/connects", "/usr/bin/podman", f.oldImage))
	if err := root.CreateExclusive("setup.json", defaultConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(d.unitPath, d.unit(f.oldImage, "/usr/bin/podman"), 0644); err != nil {
		t.Fatal(err)
	}
	previousCommand, previousProbe, previousTimeout, previousFirst := command, probeServer, routeProbeTimeout, firstProbeTimeout
	t.Cleanup(func() {
		command, probeServer, routeProbeTimeout, firstProbeTimeout = previousCommand, previousProbe, previousTimeout, previousFirst
	})
	routeProbeTimeout, firstProbeTimeout = 10*time.Millisecond, 10*time.Millisecond
	command = f.command
	probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
		if f.failNewProbe {
			if c, ok := f.containers[f.target.container]; ok && c.State.Running {
				return pairrelay.ServerInfo{}, errors.New("fixture new route unavailable")
			}
		}
		return f.local, nil
	}
	return f
}
func (f *migrationFixture) container(s instanceSpec, image, id string) containerInfo {
	c := ownedFixtureContainer(s, image)
	c.Mounts[0].Source = s.dataRoot()
	c.ID = strings.Repeat(id, 64)
	c.State.Running = true
	c.Config.User = "65532:65532"
	c.HostConfig.ReadonlyRootfs = true
	c.HostConfig.AutoRemove = true
	c.HostConfig.CapDrop = []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT"}
	c.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	c.HostConfig.Memory = 268435456
	c.HostConfig.PidsLimit = 128
	c.HostConfig.NanoCpus = 1000000000
	c.HostConfig.CpuPeriod = 100000
	c.HostConfig.CpuQuota = 100000
	return c
}
func (f *migrationFixture) interrupt(point string) {
	if f.crash == point && !f.crashed {
		f.crashed = true
		panic("disposable process interruption")
	}
}
func (f *migrationFixture) command(_ context.Context, program string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, program+" "+strings.Join(args, " "))
	if program == "/usr/sbin/nginx" {
		if len(args) == 1 && args[0] == "-T" {
			return []byte(f.extraNginxDump + "# configuration file /etc/nginx/sites-enabled/migration.conf:\n"), nil
		}
		return nil, errors.New("website mutation forbidden")
	}
	if program == "/usr/bin/systemctl" {
		op := args[0]
		name := args[len(args)-1]
		if op == "show" {
			if strings.Contains(strings.Join(args, " "), "FragmentPath") {
				return []byte("/etc/systemd/system/" + args[1]), nil
			}
			return nil, nil
		}
		if op == "daemon-reload" {
			if b, _ := os.ReadFile(f.old.unitPath); bytes.Contains(b, []byte("ConditionPathExists=")) {
				f.interrupt("guard")
			}
			if _, err := os.Stat(f.old.unitPath); errors.Is(err, os.ErrNotExist) {
				f.interrupt("retired")
			}
			return nil, nil
		}
		container := strings.TrimSuffix(name, ".service")
		if name == managedUnit {
			return nil, errors.New("default mutation forbidden")
		}
		if op == "is-active" {
			if c, ok := f.containers[container]; ok && c.State.Running {
				return nil, nil
			}
			return nil, errors.New("inactive")
		}
		if op == "is-enabled" {
			if f.enabled[name] {
				return nil, nil
			}
			return nil, errors.New("disabled")
		}
		if op == "disable" || op == "stop" {
			if op == "disable" {
				f.enabled[name] = false
			}
			if op == "stop" || strings.Contains(strings.Join(args, " "), "--now") {
				if c, ok := f.containers[container]; ok {
					c.State.Running = false
					f.containers[container] = c
				}
			}
			if name == f.old.unitName {
				f.interrupt("stopped")
			}
			return nil, nil
		}
		if op == "enable" || op == "start" {
			if op == "enable" {
				f.enabled[name] = true
			}
			if op == "start" || strings.Contains(strings.Join(args, " "), "--now") {
				if c, ok := f.containers[container]; ok && c.State.Running {
					return nil, nil
				}
				unit, _ := os.ReadFile("/etc/systemd/system/" + name)
				if bytes.Contains(unit, []byte("ConditionPathExists=")) {
					return nil, errors.New("guarded legacy unit")
				}
				if _, ok := f.containers[container]; ok {
					return nil, errors.New("orphan container blocks start")
				}
				s, image, id := f.old, f.oldImage, "e"
				if name == f.target.unitName {
					s = f.target
					s.legacyDataLabel = f.old.name
					s.port = f.old.port
					image = f.newImage
					id = "f"
				}
				f.containers[container] = f.container(s, image, id)
				if name == f.target.unitName {
					f.interrupt("started")
				}
			}
			return nil, nil
		}
		return nil, errors.New("unexpected systemctl operation")
	}
	if program != "/usr/bin/podman" {
		return nil, errors.New("unavailable fixture engine")
	}
	if args[0] == "info" {
		return []byte("amd64"), nil
	}
	if args[0] == "load" {
		return nil, nil
	}
	if args[0] == "image" {
		if args[3] == "{{.Config.User}}" {
			return []byte("65532:65532"), nil
		}
		if validImage(args[len(args)-1]) {
			return []byte(args[len(args)-1]), nil
		}
		return []byte(f.newImage), nil
	}
	if args[0] == "ps" {
		var ids []string
		filter := ""
		for _, arg := range args {
			if strings.HasPrefix(arg, "name=") {
				filter = strings.TrimPrefix(arg, "name=")
			}
		}
		for name, c := range f.containers {
			if filter == "" || name == filter {
				ids = append(ids, c.ID)
			}
		}
		return []byte(strings.Join(ids, "\n")), nil
	}
	if args[0] == "container" {
		for name, c := range f.containers {
			if args[2] == name || args[2] == c.ID {
				return json.Marshal([]containerInfo{c})
			}
		}
		return nil, errors.New("absent")
	}
	if args[0] == "exec" {
		if len(args) > 4 && args[4] == "register" {
			return []byte("public-fixture-registration"), nil
		}
		return json.Marshal(f.local)
	}
	if args[0] == "rm" {
		for name, c := range f.containers {
			if c.ID == args[1] {
				if c.State.Running {
					return nil, errors.New("refuse running removal")
				}
				delete(f.containers, name)
				return nil, nil
			}
		}
		return nil, errors.New("absent")
	}
	return nil, errors.New("unexpected fixture command")
}
func TestManagedMigrationLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "unrelated-large-fragment", "other-manual-port", "failed-probe", "changed-unit", "unconfirmed", "reservation-data", "reservation-active", "reservation-stopped", "reservation-dropin", "unknown-state", "shared-state", "guard", "stopped", "started", "retired", "commit-before-publication", "commit-after-publication", "tampered-journal"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMigrationFixture(t)
			if scenario == "other-manual-port" {
				other := legacySpec("beta", "wss://other.example/connects", 9091)
				f.containers[other.container] = f.container(other, f.oldImage, "7")
			}
			if scenario == "unrelated-large-fragment" {
				const path = "/etc/nginx/sites-enabled/migration-geo.conf"
				contents := "geo $fixture_country { default 0;\n" + strings.Repeat("192.0.2.0/24 1;\n", 66000) + "}\n"
				if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
					t.Fatal(err)
				}
				f.extraNginxDump = "# configuration file " + path + ":\n"
				const empty = "/etc/nginx/sites-enabled/migration-empty.conf"
				if err := os.WriteFile(empty, nil, 0644); err != nil {
					t.Fatal(err)
				}
				f.extraNginxDump += "# configuration file " + empty + ":\n"
			}
			commitFault := strings.HasPrefix(scenario, "commit-")
			if commitFault {
				original := publishMigration
				fired := false
				t.Cleanup(func() { publishMigration = original })
				publishMigration = func(root *securefs.Root, j migrationIntent, create bool) error {
					if j.Phase == "committed" && !fired {
						fired = true
						if scenario == "commit-after-publication" {
							if err := saveMigration(root, j, create); err != nil {
								return err
							}
						}
						return errors.New("fixture commit publication failure")
					}
					return saveMigration(root, j, create)
				}
			}
			before, _ := identityDigests(f.old)
			defaultBefore := planDigest(f.containers[managedContainer])
			defaultKeys, e := identityDigests(defaultInstance())
			if e != nil {
				t.Fatal(e)
			}
			defaultUnit, _ := os.ReadFile(unitPath)
			siteBefore, _ := os.ReadFile("/etc/nginx/sites-enabled/migration.conf")
			if scenario == "reservation-data" {
				if err := os.Mkdir(f.target.root+"/data", 0700); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "reservation-active" {
				f.enabled[f.target.unitName] = true
			}
			if scenario == "reservation-stopped" {
				c := f.container(f.target, f.oldImage, "8")
				c.State.Running = false
				f.containers[f.target.container] = c
			}
			if scenario == "reservation-dropin" {
				if err := os.Remove(f.target.unitPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(f.target.unitPath+".d", 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.target.unitPath+".d/override.conf", []byte("[Service]\nExecStartPost=/bin/true\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "unknown-state" {
				if err := os.WriteFile(f.old.dataRoot()+"/relay/unexpected", nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "shared-state" {
				c := f.containers[managedContainer]
				c.ID, c.Name = strings.Repeat("9", 64), "unrelated"
				c.Mounts[0].Source = f.old.dataRoot()
				f.containers["unrelated"] = c
			}
			plan, err := PrepareSetup(context.Background(), "", f.old.url)
			if scenario == "reservation-data" || scenario == "reservation-active" || scenario == "reservation-stopped" || scenario == "reservation-dropin" || scenario == "unknown-state" || scenario == "shared-state" {
				if err == nil {
					t.Fatal("unsafe migration prepared")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.Kind != "migration" || plan.Instance != "work" || plan.Port != 9088 || plan.LegacyState != f.old.dataRoot() {
				t.Fatalf("wrong migration plan: %+v", plan)
			}
			if scenario == "changed-unit" {
				b, _ := os.ReadFile(f.old.unitPath)
				if err := os.WriteFile(f.old.unitPath, append(b, []byte("# changed\n")...), 0644); err != nil {
					t.Fatal(err)
				}
			}
			f.failNewProbe = scenario == "failed-probe"
			if scenario == "guard" || scenario == "stopped" || scenario == "started" || scenario == "retired" {
				f.crash = scenario
			}
			if scenario == "tampered-journal" {
				f.crash = "guard"
			}
			func() {
				defer func() {
					if r := recover(); r != nil && !f.crashed {
						panic(r)
					}
				}()
				err = ApplySetup(context.Background(), plan, scenario != "unconfirmed", io.Discard)
			}()
			if f.crashed {
				if err := UninstallAllManaged(context.Background()); err == nil {
					t.Fatal("package removal bypassed pending migration")
				}
				if scenario == "tampered-journal" {
					path := managedRoot + "/" + migrationFile
					original, e := os.ReadFile(path)
					if e != nil {
						t.Fatal(e)
					}
					bad := bytes.Replace(original, []byte(`"Phase":"prepared"`), []byte(`"Phase":"unknown"`), 1)
					if bytes.Equal(original, bad) {
						t.Fatal("fixture did not change journal")
					}
					if e := os.WriteFile(path, bad, 0600); e != nil {
						t.Fatal(e)
					}
					count := len(f.calls)
					if _, e := PrepareSetup(context.Background(), "", f.old.url); e == nil {
						t.Fatal("tampered journal accepted")
					}
					if len(f.calls) != count {
						t.Fatal("tampered journal reached host command")
					}
					if e := os.WriteFile(path, original, 0600); e != nil {
						t.Fatal(e)
					}
				}
				plan, e := PrepareSetup(context.Background(), "", f.old.url)
				if e != nil {
					t.Fatal(e)
				}
				err = ApplySetup(context.Background(), plan, true, io.Discard)
				if err != nil {
					t.Fatal("one retry did not recover and complete migration", err)
				}
			}
			if commitFault {
				if err == nil {
					t.Fatal("commit fault did not interrupt migration")
				}
				if !f.containers[f.target.container].State.Running {
					t.Fatal("uncertain commit rolled back verified service")
				}
				p, e := PrepareSetup(context.Background(), "", f.old.url)
				if e != nil {
					t.Fatal(e)
				}
				if e := ApplySetup(context.Background(), p, true, io.Discard); e != nil {
					t.Fatal("commit recovery", e)
				}
				err = nil
			}
			if scenario == "success" || scenario == "unrelated-large-fragment" || scenario == "other-manual-port" || f.crashed || commitFault {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(f.old.unitPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("old unit remains")
				}
				if _, ok := f.containers[f.old.container]; ok {
					t.Fatal("orphan legacy container remains")
				}
				p, e := PrepareSetup(context.Background(), "", f.old.url)
				if e != nil || p.Kind != "managed" {
					t.Fatal("migrated URL not managed", e)
				}
				calls := len(f.calls)
				if err := ApplySetup(context.Background(), p, false, io.Discard); err != nil {
					t.Fatal("rerun", err)
				}
				for _, call := range f.calls[calls:] {
					if strings.Contains(call, "systemctl stop") || strings.Contains(call, "systemctl start") {
						t.Fatal("rerun restarted relay")
					}
				}
				if _, err := RegisterURL(context.Background(), f.old.url, (protocol.ID{1}).String()); err != nil {
					t.Fatal("ordinary URL approval selection failed", err)
				}
				if err := UninstallInstance(context.Background(), "work"); err != nil {
					t.Fatal("selected removal", err)
				}
			} else {
				if err == nil {
					t.Fatal("unsafe migration applied")
				}
				if !f.containers[f.old.container].State.Running || !f.enabled[f.old.unitName] {
					t.Fatal("old service not retained/restored")
				}
			}
			after, e := identityDigests(f.old)
			if e != nil || planDigest(before) != planDigest(after) {
				t.Fatal("migration changed relay keys", e)
			}
			if planDigest(f.containers[managedContainer]) != defaultBefore || !f.enabled[managedUnit] {
				t.Fatal("migration changed default")
			}
			defaultAfter, e := identityDigests(defaultInstance())
			if e != nil || planDigest(defaultAfter) != planDigest(defaultKeys) {
				t.Fatal("migration changed default keys", e)
			}
			defaultUnitAfter, _ := os.ReadFile(unitPath)
			if !bytes.Equal(defaultUnit, defaultUnitAfter) {
				t.Fatal("migration changed default unit")
			}
			siteAfter, _ := os.ReadFile("/etc/nginx/sites-enabled/migration.conf")
			if !bytes.Equal(siteBefore, siteAfter) {
				t.Fatal("migration changed website")
			}
		})
	}
}

func TestManagedMigrationIdentitySpecialFiles(t *testing.T) {
	f := newMigrationFixture(t)
	fd, err := unix.Open(f.old.dataRoot()+"/relay", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	path := f.old.dataRoot() + "/relay/relay-key.pem"
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() { _, err := hashIdentityMember(fd, "relay-key.pem"); completed <- err }()
	select {
	case err := <-completed:
		if err == nil {
			t.Fatal("FIFO identity accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("identity FIFO blocked the privileged manager")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("relay-ca-key.pem", path); err != nil {
		t.Fatal(err)
	}
	if _, err := hashIdentityMember(fd, "relay-key.pem"); err == nil {
		t.Fatal("symlink identity accepted")
	}
}

func TestManagedMigrationUnknownRouteDoesNotCreateIdentity(t *testing.T) {
	for _, scenario := range []string{"duplicate-https", "unsupported-location"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMigrationFixture(t)
			const site = "/etc/nginx/sites-enabled/migration.conf"
			contents, err := os.ReadFile(site)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "duplicate-https" {
				contents = append(contents, contents...)
			} else {
				contents = bytes.Replace(contents, []byte("location = /connects"), []byte("location ~ /connects"), 1)
			}
			if err := os.WriteFile(site, contents, 0644); err != nil {
				t.Fatal(err)
			}
			beforeKeys, err := identityDigests(f.old)
			if err != nil {
				t.Fatal(err)
			}
			unitBefore, err := os.ReadFile(f.target.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			pendingBefore, err := os.ReadFile(f.target.root + "/pending-setup.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := PrepareSetup(context.Background(), "", f.old.url); err == nil {
				t.Fatal("unknown existing route became a fresh setup plan")
			}
			unitAfter, _ := os.ReadFile(f.target.unitPath)
			pendingAfter, _ := os.ReadFile(f.target.root + "/pending-setup.json")
			if !bytes.Equal(unitBefore, unitAfter) || !bytes.Equal(pendingBefore, pendingAfter) {
				t.Fatal("failed preparation changed the reservation")
			}
			// The low-level setup entry must enforce the same boundary even when
			// an unused reservation contains only its binding and no pending unit.
			if err := os.Remove(f.target.unitPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(f.target.root + "/pending-setup.json"); err != nil {
				t.Fatal(err)
			}
			callStart := len(f.calls)
			if err := SetupInstance(context.Background(), f.target.name, f.old.url, io.Discard); err == nil {
				t.Fatal("ambiguous site initialized a relay")
			}
			if _, err := os.Lstat(f.target.dataRoot()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed route preflight created an identity directory")
			}
			if _, err := os.Lstat(f.target.unitPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed route preflight created a managed unit")
			}
			for _, call := range f.calls[callStart:] {
				if strings.Contains(call, " pair init ") || strings.Contains(call, "systemctl enable") || strings.Contains(call, "systemctl disable") || strings.Contains(call, "systemctl start") || strings.Contains(call, "systemctl stop") {
					t.Fatal("failed route preflight mutated relay state")
				}
			}
			afterKeys, err := identityDigests(f.old)
			if err != nil || planDigest(beforeKeys) != planDigest(afterKeys) {
				t.Fatal("route failure changed legacy identity", err)
			}
			if !f.containers[f.old.container].State.Running || !f.enabled[f.old.unitName] {
				t.Fatal("route failure stopped the existing relay")
			}
		})
	}
}

func TestManagedFreshOccupiedPortDoesNotCreateIdentity(t *testing.T) {
	f := newMigrationFixture(t)
	if err := os.Remove(f.target.unitPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.target.root + "/pending-setup.json"); err != nil {
		t.Fatal(err)
	}
	const site = "/etc/nginx/sites-enabled/migration.conf"
	contents, err := os.ReadFile(site)
	if err != nil {
		t.Fatal(err)
	}
	contents = bytes.ReplaceAll(contents, []byte("127.0.0.1:9088"), []byte("127.0.0.1:9089"))
	if err := os.WriteFile(site, contents, 0644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:9089")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := SetupInstance(context.Background(), f.target.name, f.old.url, io.Discard); err == nil {
		t.Fatal("occupied port accepted")
	}
	if _, err := os.Lstat(f.target.dataRoot()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("occupied port created relay identity state")
	}
	if _, err := os.Lstat(f.target.unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("occupied port created relay unit")
	}
	for _, call := range f.calls {
		if strings.Contains(call, " pair init ") {
			t.Fatal("occupied port reached identity initialization")
		}
	}
}
