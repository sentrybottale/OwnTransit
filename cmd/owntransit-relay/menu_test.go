package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/relaysetup"
)

const menuTestURL = "wss://relay.example/connects"

func menuTestOperations(t *testing.T) relayMenuOperations {
	t.Helper()
	return relayMenuOperations{
		instances: func(context.Context) ([]relaysetup.InstanceSummary, error) {
			return []relaysetup.InstanceSummary{{Name: "default", URL: menuTestURL, Configured: true}}, nil
		},
		tunnels: func(context.Context, string) ([]relaysetup.MenuTunnel, error) { return nil, nil },
		configure: func(context.Context, string, string, *bufio.Reader, io.Writer) error {
			t.Fatal("unexpected relay configuration")
			return nil
		},
		newTunnel: func(context.Context, string, string) error { t.Fatal("unexpected creation"); return nil },
		approve:   func(context.Context, string, string, string) error { t.Fatal("unexpected approval"); return nil },
		remove:    func(context.Context, string, relaysetup.MenuTunnel) error { t.Fatal("unexpected removal"); return nil },
	}
}

func TestRelayMenuExitDoesNotReconfigure(t *testing.T) {
	ops := menuTestOperations(t)
	var out bytes.Buffer
	if got := relayMenu(context.Background(), nil, strings.NewReader("0\n"), &out, &out, ops); got != 0 {
		t.Fatalf("exit=%d: %s", got, &out)
	}
	if strings.Contains(out.String(), "TUNNEL READY") {
		t.Fatal("relay claimed endpoint readiness")
	}
}

func TestRelayMenuNewDraftShowsOnlyTargetStep(t *testing.T) {
	ops := menuTestOperations(t)
	created := false
	ops.newTunnel = func(_ context.Context, url, name string) error {
		if url != menuTestURL || name != "office" {
			t.Fatalf("wrong selection: %q %q", url, name)
		}
		created = true
		return nil
	}
	var out bytes.Buffer
	if got := relayMenu(context.Background(), nil, strings.NewReader("1\noffice\n"), &out, &out, ops); got != 0 || !created {
		t.Fatalf("exit=%d created=%t: %s", got, created, &out)
	}
	if !strings.Contains(out.String(), "sudo owntransit-target setup") || !strings.Contains(out.String(), "UNDER CONSTRUCTION") {
		t.Fatal("missing next target step")
	}
	if strings.Contains(out.String(), "owntransit-client setup") || strings.Contains(out.String(), "curl ") {
		t.Fatal("new draft dumped unrelated later steps")
	}
}

func TestRelayMenuApprovalHandlesTerminalNewline(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n"} {
		for _, partial := range []bool{false, true} {
			ops := menuTestOperations(t)
			id := (protocol.ID{1}).String()
			ops.tunnels = func(context.Context, string) ([]relaysetup.MenuTunnel, error) {
				return []relaysetup.MenuTunnel{{Name: "office", Status: "under construction"}}, nil
			}
			approved := false
			ops.approve = func(_ context.Context, url, name, gotID string) error {
				if url != menuTestURL || name != "office" || gotID != id {
					t.Fatal("wrong approval selection")
				}
				approved = true
				if partial {
					return errors.Join(relaysetup.ErrMenuApprovalSaved, errors.New("fixture persistence failure"))
				}
				return nil
			}
			var out bytes.Buffer
			input := "2" + ending + "1" + ending + id + ending
			if got := relayMenu(context.Background(), nil, strings.NewReader(input), &out, &out, ops); got != 0 || !approved {
				t.Fatalf("exit=%d approved=%t: %s", got, approved, &out)
			}
			for _, want := range []string{"owntransit-client setup", "sudo owntransit-target code --target-id " + id, "UNDER CONSTRUCTION"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q", want)
				}
			}
			if partial && !strings.Contains(out.String(), "Approval is saved") {
				t.Fatal("lost partial success")
			}
		}
	}
}

func TestRelayMenuRejectsPrivateCodeAtPublicIDPrompt(t *testing.T) {
	ops := menuTestOperations(t)
	ops.tunnels = func(context.Context, string) ([]relaysetup.MenuTunnel, error) {
		return []relaysetup.MenuTunnel{{Name: "office", Status: "under construction"}}, nil
	}
	var out bytes.Buffer
	input := "2\n1\notpair2.NOT-A-PUBLIC-ID\n0\n"
	if got := relayMenu(context.Background(), nil, strings.NewReader(input), &out, &out, ops); got != 0 {
		t.Fatal(got)
	}
	if !strings.Contains(out.String(), "not a public Target ID") || strings.Contains(out.String(), "NOT-A-PUBLIC-ID") {
		t.Fatal("private-looking input accepted or reflected")
	}
}

func TestRelayMenuConfirmedScopedRemoveAndMetadataRecovery(t *testing.T) {
	for _, metadataOnly := range []bool{false, true} {
		ops := menuTestOperations(t)
		item := relaysetup.MenuTunnel{Name: "office", ReceiverID: (protocol.ID{1}).String(), RouteID: (protocol.RouteID{2}).String(), Status: "approved"}
		ops.tunnels = func(context.Context, string) ([]relaysetup.MenuTunnel, error) {
			return []relaysetup.MenuTunnel{item}, nil
		}
		removed := false
		ops.remove = func(_ context.Context, url string, selected relaysetup.MenuTunnel) error {
			if url != menuTestURL || selected != item {
				t.Fatal("wrong removal target")
			}
			removed = true
			if metadataOnly {
				return relaysetup.ErrMenuPlanRemoved
			}
			return nil
		}
		var out bytes.Buffer
		if got := relayMenu(context.Background(), nil, strings.NewReader("4\n1\nremove\n0\n"), &out, &out, ops); got != 0 || !removed {
			t.Fatalf("exit=%d removed=%t: %s", got, removed, &out)
		}
		if metadataOnly && !strings.Contains(out.String(), "does not revoke old tokens") {
			t.Fatal("metadata cleanup claimed revocation")
		}
	}
}

func TestRelayMenuStartRequiresExplicitConfirmation(t *testing.T) {
	for _, confirmation := range []string{"yes\n", "no\n", "yes\r\n"} {
		ops := menuTestOperations(t)
		configured := false
		ops.configure = func(_ context.Context, name, url string, _ *bufio.Reader, _ io.Writer) error {
			if name != "default" || url != menuTestURL {
				t.Fatal("wrong relay configured")
			}
			configured = true
			return nil
		}
		var out bytes.Buffer
		if got := relayMenu(context.Background(), nil, strings.NewReader("5\n"+confirmation+"0\n"), &out, &out, ops); got != 0 {
			t.Fatal(got)
		}
		if configured != strings.HasPrefix(confirmation, "yes") {
			t.Fatalf("bad confirmation %q", confirmation)
		}
	}
}

func TestRelayMenuUnavailablePlanDoesNotPretendApproved(t *testing.T) {
	ops := menuTestOperations(t)
	ops.tunnels = func(context.Context, string) ([]relaysetup.MenuTunnel, error) {
		return []relaysetup.MenuTunnel{{Name: "office", ReceiverID: (protocol.ID{1}).String(), RouteID: (protocol.RouteID{2}).String(), Status: "unavailable"}}, nil
	}
	var out bytes.Buffer
	if got := relayMenu(context.Background(), nil, strings.NewReader("2\n1\n0\n"), &out, &out, ops); got != 0 {
		t.Fatal(got)
	}
	if !strings.Contains(out.String(), "No admission record") || strings.Contains(out.String(), "Next on the CLIENT") {
		t.Fatal("unavailable state invented progress")
	}
}

func TestRelayMenuSelectsExactNamedInstance(t *testing.T) {
	ops := menuTestOperations(t)
	ops.instances = func(context.Context) ([]relaysetup.InstanceSummary, error) {
		return []relaysetup.InstanceSummary{{Name: "alpha", URL: menuTestURL, Configured: true}, {Name: "beta", URL: "wss://other.example/connects", Configured: true}}, nil
	}
	selected := ""
	ops.tunnels = func(_ context.Context, url string) ([]relaysetup.MenuTunnel, error) { selected = url; return nil, nil }
	var out bytes.Buffer
	if got := relayMenu(context.Background(), nil, strings.NewReader("2\n3\n0\n"), &out, &out, ops); got != 0 {
		t.Fatal(got)
	}
	if selected != "wss://other.example/connects" {
		t.Fatal("menu acted on different relay")
	}
}
