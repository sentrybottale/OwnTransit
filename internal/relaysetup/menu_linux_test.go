//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

func TestManagedMenuPlanStorageRejectsMalformedAndCrossInstanceFiles(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := securefs.CreateRoot(filepath.Join(base, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	const url = "wss://relay.example/connects"
	missing, err := loadMenuPlans(root, url)
	if err != nil || !missing.valid(url) || len(missing.Items) != 0 {
		t.Fatal("missing file was not a fresh empty plan", err)
	}
	id, route := menuPublicIDs(t)
	p := tunnelPlans{Schema: "owntransit.relay-menu.v1", URL: url, Items: []tunnelPlan{{Name: "office", ReceiverID: id, RouteID: route}}}
	if err := saveMenuPlans(root, p); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadMenuPlans(root, url)
	if err != nil || !reflect.DeepEqual(loaded, p) {
		t.Fatal("saved exact binding changed", err)
	}
	if _, err := loadMenuPlans(root, "wss://other.example/connects"); err == nil {
		t.Fatal("plan moved to another relay URL")
	}
	for _, raw := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"url":"wss://relay.example/connects","items":[]}`),
		[]byte(`{"schema":"owntransit.relay-menu.v1","items":[]}`),
		[]byte(`{"schema":"owntransit.relay-menu.v1","url":"wss://relay.example/connects","items":null}`),
		[]byte(`{"schema":"owntransit.relay-menu.v1","url":"wss://relay.example/connects","items":[],"unknown":true}`),
		bytes.Repeat([]byte("x"), 64<<10+1),
	} {
		if err := root.ReplaceFile(menuPlanFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadMenuPlans(root, url); err == nil {
			t.Fatal("malformed existing plan accepted")
		}
	}
	if err := root.UnlinkFile(menuPlanFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "foreign"), filepath.Join(base, "plans", menuPlanFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMenuPlans(root, url); err == nil {
		t.Fatal("symlink plan accepted")
	}
	if err := saveMenuPlans(root, p); err == nil {
		t.Fatal("symlink plan replaced")
	}
}

type menuFixture struct {
	specs                []instanceSpec
	items                map[string][]pairrelay.AdmissionInfo
	registrations        map[string]string
	calls                []string
	beforeApprovalResult func()
}

// Every host path below is used only inside the repository's explicitly
// marked disposable root fixture; commands are fully mocked before any API run.
func newMenuFixture(t *testing.T) *menuFixture {
	t.Helper()
	requireNamedRelayFixture(t)
	if err := os.RemoveAll(managedRoot); err != nil {
		t.Fatal(err)
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer lock.Close()
	f := &menuFixture{items: map[string][]pairrelay.AdmissionInfo{}, registrations: map[string]string{}}
	const image = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, name := range []string{"menu-alpha", "menu-beta"} {
		s, err := reserveInstance(root, name, "wss://"+name+".example/connects")
		if err != nil {
			t.Fatal(err)
		}
		selected, err := s.openRoot()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(s.config(s.url, "/usr/bin/podman", image))
		err = selected.CreateExclusive("setup.json", data, 0600)
		selected.Close()
		if err != nil {
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
		if err := os.WriteFile(s.dataRoot()+"/relay/admissions.v1.json", []byte("retained admission-history fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(s.dataRoot()+"/relay/admissions.v1.json", 65532, 65532); err != nil {
			t.Fatal(err)
		}
		f.specs = append(f.specs, s)
	}
	ca, err := pki.NewCA("OwnTransit local menu public fixture", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := identity.SPKIPin(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	info := pairrelay.ServerInfo{ServerName: "relay.example", CAPEM: ca.CertPEM, LeafSPKISHA256: pin}
	for _, s := range f.specs {
		id, route := menuPublicIDs(t)
		receiver, _ := protocol.ParseID(id)
		routeID, _ := protocol.ParseRouteID(route)
		code, err := pairrelaycmd.EncodeRegistration(pairrelay.Registration{ReceiverID: receiver, RouteID: routeID, Token: []byte("public admission fixture"), ServerInfo: info})
		if err != nil {
			t.Fatal(err)
		}
		f.registrations[id] = code
		f.items[s.name] = []pairrelay.AdmissionInfo{{ReceiverID: id, RouteID: route, Status: "approved"}}
	}
	previous := command
	t.Cleanup(func() { command = previous })
	command = func(ctx context.Context, program string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if program != "/usr/bin/podman" {
			t.Fatalf("menu touched unexpected host program %q", program)
		}
		var selected instanceSpec
		if len(args) == 3 && args[0] == "container" && args[1] == "inspect" {
			for _, s := range f.specs {
				if s.container == args[2] {
					selected = s
				}
			}
			if selected.name == "" {
				t.Fatal("inspected another relay")
			}
			c := ownedFixtureContainer(selected, image)
			c.Config.Cmd = []string{"serve", "--state", "/state/relay"}
			c.State.Running = true
			return json.Marshal([]containerInfo{c})
		}
		if len(args) < 6 || args[0] != "exec" || args[2] != "/owntransit-relay" || args[4] != "--state" || args[5] != "/state/relay" {
			t.Fatal("unscoped menu control command")
		}
		for _, s := range f.specs {
			if s.container == args[1] {
				selected = s
			}
		}
		if selected.name == "" {
			t.Fatal("controlled another relay")
		}
		switch args[3] {
		case "state-info":
			return json.Marshal(info)
		case "admissions":
			return json.Marshal(f.items[selected.name])
		case "approve-admission":
			if len(args) != 7 || f.registrations[args[6]] == "" {
				t.Fatal("unexpected approval identity")
			}
			f.calls = append(f.calls, selected.name+":approve:"+args[6])
			if f.beforeApprovalResult != nil {
				f.beforeApprovalResult()
			}
			return []byte(f.registrations[args[6]]), nil
		case "remove-admission":
			if len(args) != 10 || args[6] != "--receiver" || args[8] != "--route" {
				t.Fatal("incomplete removal scope")
			}
			f.calls = append(f.calls, selected.name+":remove:"+args[7]+":"+args[9])
			for i, item := range f.items[selected.name] {
				if item.ReceiverID == args[7] && item.RouteID == args[9] {
					f.items[selected.name][i].Status = "removed"
					return nil, nil
				}
			}
			t.Fatal("removed another admission")
		default:
			t.Fatal("menu invoked an unintended control operation")
		}
		return nil, errors.New("unhandled fixture operation")
	}
	return f
}

func fixtureMenuPlans(t *testing.T, s instanceSpec) tunnelPlans {
	t.Helper()
	root, err := s.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, err := loadMenuPlans(root, s.url)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagedMenuPlansScopeApprovalAndRemovalToExactInstance(t *testing.T) {
	f := newMenuFixture(t)
	a, b := f.specs[0], f.specs[1]
	ctx := context.Background()
	for _, s := range f.specs {
		if err := NewMenuTunnel(ctx, s.url, "office"); err != nil {
			t.Fatal(err)
		}
	}
	if NewMenuTunnel(ctx, a.url, "office") == nil {
		t.Fatal("duplicate name replaced plan")
	}
	first, second := f.items[a.name][0], f.items[b.name][0]
	if err := ApproveMenuTunnel(ctx, a.url, "office", first.ReceiverID); err != nil {
		t.Fatal(err)
	}
	if err := NewMenuTunnel(ctx, a.url, "other"); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	for _, args := range [][2]string{{"office", first.ReceiverID}, {"office", second.ReceiverID}, {"other", first.ReceiverID}} {
		if ApproveMenuTunnel(ctx, a.url, args[0], args[1]) == nil {
			t.Fatal("reapproval or duplicate binding accepted")
		}
	}
	if len(f.calls) != before {
		t.Fatal("rejected binding mutated admission")
	}
	if got := fixtureMenuPlans(t, b); len(got.Items) != 1 || got.Items[0].ReceiverID != "" {
		t.Fatal("approval changed another instance plan")
	}
	selected := MenuTunnel{Name: "office", ReceiverID: first.ReceiverID, RouteID: first.RouteID, Status: "approved"}
	wrong := selected
	wrong.RouteID = second.RouteID
	if RemoveMenuTunnel(ctx, a.url, wrong) == nil {
		t.Fatal("stale route selection removed admission")
	}
	if len(f.calls) != before {
		t.Fatal("stale removal reached relay mutation")
	}
	if err := RemoveMenuTunnel(ctx, a.url, selected); err != nil {
		t.Fatal(err)
	}
	if f.items[a.name][0].Status != "removed" || f.items[b.name][0].Status != "approved" {
		t.Fatal("removal escaped selected admission")
	}
	if got := fixtureMenuPlans(t, a); len(got.Items) != 1 || got.Items[0].Name != "other" {
		t.Fatal("removal erased another display mapping")
	}
	for _, s := range f.specs {
		data, err := os.ReadFile(s.dataRoot() + "/relay/admissions.v1.json")
		if err != nil || string(data) != "retained admission-history fixture" {
			t.Fatal("menu erased relay admission history")
		}
	}
	items, err := MenuTunnels(ctx, a.url)
	if err != nil || len(items) != 2 {
		t.Fatal("removed admission disappeared from inventory", err)
	}
}

func TestManagedMenuMissingAdmissionRemovalIsOnlyDisplayMetadata(t *testing.T) {
	f := newMenuFixture(t)
	a := f.specs[0]
	id := f.items[a.name][0]
	if err := NewMenuTunnel(context.Background(), a.url, "office"); err != nil {
		t.Fatal(err)
	}
	if err := ApproveMenuTunnel(context.Background(), a.url, "office", id.ReceiverID); err != nil {
		t.Fatal(err)
	}
	f.items[a.name] = []pairrelay.AdmissionInfo{}
	before := len(f.calls)
	err := RemoveMenuTunnel(context.Background(), a.url, MenuTunnel{Name: "office", ReceiverID: id.ReceiverID, RouteID: id.RouteID, Status: "unavailable"})
	if !errors.Is(err, ErrMenuPlanRemoved) {
		t.Fatal("metadata removal claimed admission revocation", err)
	}
	if len(f.calls) != before || len(fixtureMenuPlans(t, a).Items) != 0 {
		t.Fatal("metadata removal mutated relay or retained stale display name")
	}
}

func TestManagedMenuPendingOperationsAndPackageLockBlockMutations(t *testing.T) {
	f := newMenuFixture(t)
	a := f.specs[0]
	ctx := context.Background()
	if err := NewMenuTunnel(ctx, a.url, "draft"); err != nil {
		t.Fatal(err)
	}
	root, err := a.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	draft := MenuTunnel{Name: "draft", Status: "under construction"}
	blocked := func() {
		t.Helper()
		if NewMenuTunnel(ctx, a.url, "next") == nil {
			t.Fatal("blocked new plan succeeded")
		}
		if ApproveMenuTunnel(ctx, a.url, "draft", f.items[a.name][0].ReceiverID) == nil {
			t.Fatal("blocked approval succeeded")
		}
		if RemoveMenuTunnel(ctx, a.url, draft) == nil {
			t.Fatal("blocked draft removal succeeded")
		}
		if len(f.calls) != 0 || len(fixtureMenuPlans(t, a).Items) != 1 {
			t.Fatal("blocked operation changed state")
		}
	}
	for _, pending := range []string{"upgrade.json", "pending-setup.json", "migration.json"} {
		if err := root.CreateExclusive(pending, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		blocked()
		if err := root.UnlinkFile(pending); err != nil {
			t.Fatal(err)
		}
	}
	packageFile, err := os.OpenFile(packageManagerRoot+"/package.lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer packageFile.Close()
	if err := unix.Flock(int(packageFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	blocked()
	if err := unix.Flock(int(packageFile.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	manager, guard, err := managerRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	blocked()
	guard.Close()
	manager.Close()
	if err := RemoveMenuTunnel(ctx, a.url, draft); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatal("draft deletion touched runtime admission")
	}
}

func TestManagedMenuApprovalReportsDurablePartialSuccess(t *testing.T) {
	f := newMenuFixture(t)
	a := f.specs[0]
	if err := NewMenuTunnel(context.Background(), a.url, "office"); err != nil {
		t.Fatal(err)
	}
	id := f.items[a.name][0].ReceiverID
	f.beforeApprovalResult = func() {
		if err := os.Remove(filepath.Join(a.root, menuPlanFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(a.root, menuPlanFile), 0700); err != nil {
			t.Fatal(err)
		}
	}
	err := ApproveMenuTunnel(context.Background(), a.url, "office", id)
	if !errors.Is(err, ErrMenuApprovalSaved) || len(f.calls) != 1 || !strings.Contains(f.calls[0], ":approve:"+id) {
		t.Fatal("durable approval hidden by local metadata failure", err)
	}
}
