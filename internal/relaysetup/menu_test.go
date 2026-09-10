package relaysetup

import (
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

func menuPublicIDs(t *testing.T) (string, string) {
	t.Helper()
	id, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	return id.String(), route.String()
}

func TestMenuPlanValidationRejectsAmbiguousNamesAndBindings(t *testing.T) {
	id, route := menuPublicIDs(t)
	const url = "wss://relay.example/connects"
	base := tunnelPlans{Schema: "owntransit.relay-menu.v1", URL: url, Items: []tunnelPlan{{Name: "office", ReceiverID: id, RouteID: route}, {Name: "draft"}}}
	if !base.valid(url) {
		t.Fatal("valid bound and pending plans rejected")
	}
	for _, mutate := range []func(*tunnelPlans){
		func(p *tunnelPlans) { p.Schema = "" },
		func(p *tunnelPlans) { p.Schema = "owntransit.relay-menu.v2" },
		func(p *tunnelPlans) { p.URL = "" },
		func(p *tunnelPlans) { p.URL = "wss://other.example/connects" },
		func(p *tunnelPlans) { p.Items = nil },
		func(p *tunnelPlans) { p.URL = "https://relay.example/connects" },
		func(p *tunnelPlans) { p.Items[0].Name = "" },
		func(p *tunnelPlans) { p.Items[0].Name = "../draft" },
		func(p *tunnelPlans) { p.Items[0].Name = "all" },
		func(p *tunnelPlans) { p.Items[0].Name = "Office" },
		func(p *tunnelPlans) { p.Items[0].Name = "office;id" },
		func(p *tunnelPlans) { p.Items[0].Name = strings.Repeat("a", 33) },
		func(p *tunnelPlans) { p.Items[1].Name = p.Items[0].Name },
		func(p *tunnelPlans) { p.Items[0].ReceiverID = "" },
		func(p *tunnelPlans) { p.Items[0].RouteID = "" },
		func(p *tunnelPlans) { p.Items[0].ReceiverID = strings.ToUpper(id) },
		func(p *tunnelPlans) { p.Items[0].ReceiverID = (protocol.ID{}).String() },
		func(p *tunnelPlans) { p.Items[0].RouteID = (protocol.RouteID{}).String() },
		func(p *tunnelPlans) { p.Items[1].ReceiverID, p.Items[1].RouteID = id, route },
		func(p *tunnelPlans) { p.Items = make([]tunnelPlan, maxMenuTunnels+1) },
	} {
		p := base
		p.Items = append([]tunnelPlan(nil), base.Items...)
		mutate(&p)
		if p.valid(url) {
			t.Fatal("ambiguous or malformed plan accepted")
		}
	}
	for _, name := range []string{"office", "office-2", strings.Repeat("a", 32)} {
		if err := boundedMenuName(name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"", " office", "office\n", "all", "../office", "1office", "office;id"} {
		if boundedMenuName(name) == nil {
			t.Fatal("invalid menu name accepted")
		}
	}
}

func TestMenuSelectionRejectsFalseReadyAndIncompleteScope(t *testing.T) {
	id, route := menuPublicIDs(t)
	for _, status := range []string{"approved", "observed", "removed", "unavailable"} {
		if !validMenuTunnel(MenuTunnel{ReceiverID: id, RouteID: route, Status: status}) {
			t.Fatal("valid exact selection rejected")
		}
	}
	if !validMenuTunnel(MenuTunnel{Name: "draft", Status: "under construction"}) {
		t.Fatal("draft selection rejected")
	}
	for _, value := range []MenuTunnel{
		{Name: "draft", Status: "ready"},
		{Name: "draft", Status: "under construction", Active: 1},
		{ReceiverID: id, RouteID: route, Status: "ready"},
		{ReceiverID: id, Status: "approved"},
		{RouteID: route, Status: "approved"},
		{ReceiverID: id, RouteID: route, Status: "approved", Active: -1},
		{ReceiverID: id, RouteID: route, Status: "approved", Active: 1<<20 + 1},
		{Name: "../office", ReceiverID: id, RouteID: route, Status: "removed"},
	} {
		if validMenuTunnel(value) {
			t.Fatal("incomplete or misleading tunnel selection accepted")
		}
	}
}
