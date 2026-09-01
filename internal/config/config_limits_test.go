package config

import (
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestRelayCarrierGlobalDefaultAndBounds(t *testing.T) {
	limits := RelayLimits{
		OuterHandshakes: 32,
		PendingGlobal:   16,
		PendingPerRoute: 4,
		ActiveGlobal:    16,
		ActivePerRoute:  8,
		Handshake:       Duration(5 * time.Second),
		Preface:         Duration(2 * time.Second),
		Join:            Duration(10 * time.Second),
		Drain:           Duration(5 * time.Second),
	}
	if got := limits.CarrierGlobal(); got != DefaultRelayCarriersGlobal {
		t.Fatalf("CarrierGlobal = %d, want default %d", got, DefaultRelayCarriersGlobal)
	}
	if err := limits.validate(); err != nil {
		t.Fatalf("default carrier limit: %v", err)
	}

	if got := limits.minimumCarriers(1); got != 81 {
		t.Fatalf("minimumCarriers(1) = %d, want 81", got)
	}

	limits.CarriersGlobal = 79
	if err := limits.validate(); err == nil || !strings.Contains(err.Error(), "carrier global") {
		t.Fatalf("undersized carrier limit error = %v", err)
	}
	limits.CarriersGlobal = 1025
	if err := limits.validate(); err == nil || !strings.Contains(err.Error(), "carriers_global") {
		t.Fatalf("oversized carrier limit error = %v", err)
	}
}

func TestRelayPerClientCompatibilityDefaultsAndBounds(t *testing.T) {
	limits := RelayLimits{
		OuterHandshakes: 4,
		PendingGlobal:   16,
		PendingPerRoute: 4,
		ActiveGlobal:    16,
		ActivePerRoute:  8,
		Handshake:       Duration(time.Second),
		Preface:         Duration(time.Second),
		Join:            Duration(time.Second),
		Drain:           Duration(time.Second),
	}
	if got := limits.PendingPerClientValue(); got != DefaultRelayPendingPerClient {
		t.Fatalf("PendingPerClientValue = %d, want %d", got, DefaultRelayPendingPerClient)
	}
	if got := limits.ActivePerClientValue(); got != DefaultRelayActivePerClient {
		t.Fatalf("ActivePerClientValue = %d, want %d", got, DefaultRelayActivePerClient)
	}
	if err := limits.validate(); err != nil {
		t.Fatalf("per-client compatibility defaults: %v", err)
	}

	lowCapacity := limits
	lowCapacity.PendingGlobal = 1
	lowCapacity.PendingPerRoute = 1
	lowCapacity.ActiveGlobal = 1
	lowCapacity.ActivePerRoute = 1
	if lowCapacity.PendingPerClientValue() != 1 || lowCapacity.ActivePerClientValue() != 1 {
		t.Fatalf("low-capacity defaults = %d/%d, want 1/1", lowCapacity.PendingPerClientValue(), lowCapacity.ActivePerClientValue())
	}
	if err := lowCapacity.validate(); err != nil {
		t.Fatalf("low-capacity compatibility defaults: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*RelayLimits)
	}{
		{name: "pending consumes route", mutate: func(value *RelayLimits) { value.PendingPerClient = value.PendingPerRoute }},
		{name: "pending exceeds route", mutate: func(value *RelayLimits) { value.PendingPerClient = value.PendingPerRoute + 1 }},
		{name: "active consumes route", mutate: func(value *RelayLimits) { value.ActivePerClient = value.ActivePerRoute }},
		{name: "active exceeds route", mutate: func(value *RelayLimits) { value.ActivePerClient = value.ActivePerRoute + 1 }},
		{name: "negative pending", mutate: func(value *RelayLimits) { value.PendingPerClient = -1 }},
		{name: "negative active", mutate: func(value *RelayLimits) { value.ActivePerClient = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := limits
			test.mutate(&candidate)
			if err := candidate.validate(); err == nil || (!strings.Contains(err.Error(), "per-client") && !strings.Contains(err.Error(), "per_client")) {
				t.Fatalf("invalid per-client limit error = %v", err)
			}
		})
	}
}

func TestRelayClientAdmissionMapHasExplicitCardinalityBound(t *testing.T) {
	value := Relay{
		Path:   RelayPath,
		Listen: "127.0.0.1:9087",
		OuterTLS: ServerTLS{
			CertFile:     "relay.crt",
			KeyFile:      "relay.key",
			ClientCAFile: "outer-ca.crt",
		},
		Clients: make([]AuthorizedPeer, MaxRelayClients+1),
	}
	if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized relay client allowlist error = %v", err)
	}
}

func TestRelayRejectsClientConnectorRoleNameCollision(t *testing.T) {
	route := protocol.RouteID{1}
	connectorName := OuterConnectorDNSName(route)
	pin := identity.FormatSPKIPin(identity.SPKIHash{1})
	value := Relay{
		Path:   RelayPath,
		Listen: "127.0.0.1:9087",
		OuterTLS: ServerTLS{
			CertFile:     "relay.crt",
			KeyFile:      "relay.key",
			ClientCAFile: "outer-ca.crt",
		},
		Clients: []AuthorizedPeer{{DNSName: connectorName, SPKIPins: []string{pin}}},
		Routes:  []RelayRoute{{RouteID: route.String(), DNSName: connectorName, SPKIPins: []string{pin}}},
	}
	if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "duplicates client DNS name") {
		t.Fatalf("cross-role outer DNS collision error = %v", err)
	}
}

func TestEnrollmentAllocationHashIsCanonical(t *testing.T) {
	if !validCanonicalSHA256(strings.Repeat("ab", 32)) {
		t.Fatal("canonical allocation hash rejected")
	}
	for _, value := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		if validCanonicalSHA256(value) {
			t.Fatalf("noncanonical allocation hash accepted: %q", value)
		}
	}
}

func TestSessionLimitCompatibilityDefaultsAndBounds(t *testing.T) {
	relay := RelayLimits{
		OuterHandshakes: 1,
		PendingGlobal:   1,
		PendingPerRoute: 1,
		ActiveGlobal:    1,
		ActivePerRoute:  1,
		Handshake:       Duration(time.Second),
		Preface:         Duration(time.Second),
		Join:            Duration(time.Second),
		Drain:           Duration(time.Second),
	}
	if relay.SessionIdleValue() != DefaultSessionIdle || relay.SessionLifetimeValue() != DefaultSessionLifetime {
		t.Fatalf("relay compatibility session limits = %s/%s", relay.SessionIdleValue(), relay.SessionLifetimeValue())
	}
	if err := relay.validate(); err != nil {
		t.Fatalf("relay compatibility defaults: %v", err)
	}

	connector := ConnectorLimits{
		Pending:        1,
		Active:         1,
		ConnectTimeout: Duration(time.Second),
		Handshake:      Duration(time.Second),
		LocalDial:      Duration(time.Second),
		Drain:          Duration(time.Second),
		ReconnectMin:   Duration(time.Second),
		ReconnectMax:   Duration(time.Second),
	}
	if connector.SessionIdleValue() != DefaultSessionIdle || connector.SessionLifetimeValue() != DefaultSessionLifetime {
		t.Fatalf("connector compatibility session limits = %s/%s", connector.SessionIdleValue(), connector.SessionLifetimeValue())
	}
	if err := connector.validate(); err != nil {
		t.Fatalf("connector compatibility defaults: %v", err)
	}

	relay.SessionIdle = Duration(2 * time.Hour)
	relay.SessionLifetime = Duration(time.Hour)
	if err := relay.validate(); err == nil || !strings.Contains(err.Error(), "idle") {
		t.Fatalf("relay inverted session limit error = %v", err)
	}
	connector.SessionIdle = Duration(-time.Second)
	connector.SessionLifetime = Duration(time.Hour)
	if err := connector.validate(); err == nil || !strings.Contains(err.Error(), "positive") {
		t.Fatalf("connector negative session limit error = %v", err)
	}
}
