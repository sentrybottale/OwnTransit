package relaysetup

import (
	"errors"
	"strings"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

const maxMenuTunnels = 128
const menuPlanFile = "menu-tunnels.v1.json"

var ErrMenuApprovalSaved = errors.New("relay approval was saved; local display-name persistence was not confirmed")
var ErrMenuPlanRemoved = errors.New("local display name removed; no matching relay admission was found or revoked")

type InstanceSummary struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Configured bool   `json:"configured"`
	Running    bool   `json:"running"`
}

// MenuTunnel contains only public local planning and relay-observation data.
// No status here is an end-to-end authentication or readiness claim.
type MenuTunnel struct {
	Name       string `json:"name"`
	ReceiverID string `json:"target_id,omitempty"`
	RouteID    string `json:"route_id,omitempty"`
	Status     string `json:"status"`
	Active     int    `json:"active"`
}

type tunnelPlan struct {
	Name       string `json:"name"`
	ReceiverID string `json:"target_id,omitempty"`
	RouteID    string `json:"route_id,omitempty"`
}
type tunnelPlans struct {
	Schema string       `json:"schema"`
	URL    string       `json:"url"`
	Items  []tunnelPlan `json:"items"`
}

func (p tunnelPlans) valid(url string) bool {
	canonical, err := PublicURL(url)
	if err != nil || canonical != url {
		return false
	}
	if p.Schema != "owntransit.relay-menu.v1" || p.URL != url || p.Items == nil || len(p.Items) > maxMenuTunnels {
		return false
	}
	names, ids := map[string]bool{}, map[string]bool{}
	for _, item := range p.Items {
		if item.Name == "" || ValidateInstanceName(item.Name) != nil || names[item.Name] {
			return false
		}
		names[item.Name] = true
		if (item.ReceiverID == "") != (item.RouteID == "") {
			return false
		}
		if item.ReceiverID != "" {
			id, e := protocol.ParseID(item.ReceiverID)
			route, re := protocol.ParseRouteID(item.RouteID)
			if e != nil || re != nil || id == (protocol.ID{}) || route == (protocol.RouteID{}) || ids[item.ReceiverID] {
				return false
			}
			ids[item.ReceiverID] = true
		}
	}
	return true
}

func validMenuTunnel(t MenuTunnel) bool {
	if t.Name != "" && ValidateInstanceName(t.Name) != nil {
		return false
	}
	if t.ReceiverID == "" {
		return t.RouteID == "" && t.Status == "under construction" && t.Name != "" && t.Active == 0
	}
	id, e := protocol.ParseID(t.ReceiverID)
	route, re := protocol.ParseRouteID(t.RouteID)
	return e == nil && re == nil && id != (protocol.ID{}) && route != (protocol.RouteID{}) && t.Active >= 0 && t.Active <= 1<<20 && (t.Status == "approved" || t.Status == "observed" || t.Status == "removed" || t.Status == "unavailable")
}

func boundedMenuName(name string) error {
	if name == "" || strings.TrimSpace(name) != name || ValidateInstanceName(name) != nil {
		return errors.New("use a short lowercase tunnel name with letters, digits or hyphens")
	}
	return nil
}
