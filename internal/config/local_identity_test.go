package config

import (
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestClientLocalIdentityCompatibilityBoundary(t *testing.T) {
	route := protocol.RouteID{1}
	installationID := protocol.ID{2}
	pin := identity.FormatSPKIPin(identity.SPKIHash{3})
	value := Client{
		RelayURL:     "wss://relay.example.com/connects",
		RouteID:      route.String(),
		InnerProfile: InnerProfileLegacyExactPins,
		OuterTLS: ClientTLS{
			CertFile: "outer.crt", KeyFile: "outer.key", CAFile: "relay-ca.crt",
			ServerName: RelayDNSName, SPKIPins: []string{pin},
		},
		InnerTLS: ClientTLS{
			CertFile: "inner.crt", KeyFile: "inner.key", CAFile: "connector-ca.crt",
			ServerName: ConnectorDNSName(route), SPKIPins: []string{pin},
		},
		ConnectTimeout: Duration(time.Second), HandshakeTimeout: Duration(time.Second),
		ReadyTimeout: Duration(time.Second), DrainTimeout: Duration(time.Second),
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("all-legacy POC compatibility config: %v", err)
	}

	partial := value
	partial.OuterTLS.IssuerCAFile = "relay-ca.crt"
	if err := partial.Validate(); err == nil || !strings.Contains(err.Error(), "set together") {
		t.Fatalf("partial strict profile error = %v", err)
	}

	strictWithoutID := value
	strictWithoutID.OuterTLS.IssuerCAFile = "relay-ca.crt"
	strictWithoutID.OuterTLS.LocalDNSName = OuterClientDNSName(installationID)
	strictWithoutID.InnerTLS.IssuerCAFile = "client-ca.crt"
	strictWithoutID.InnerTLS.LocalDNSName = ClientDNSName(installationID)
	if err := strictWithoutID.Validate(); err == nil || !strings.Contains(err.Error(), "installation_id") {
		t.Fatalf("strict profile without installation ID error = %v", err)
	}

	strict := strictWithoutID
	strict.InstallationID = installationID.String()
	if err := strict.Validate(); err != nil {
		t.Fatalf("strict client config: %v", err)
	}

	strict.InnerTLS.LocalDNSName = ClientDNSName(protocol.ID{4})
	if err := strict.Validate(); err == nil || !strings.Contains(err.Error(), "local DNS name") {
		t.Fatalf("mismatched strict identity error = %v", err)
	}
}

func TestCapabilityDNSNamesBindExactRouteConnectorAndEpoch(t *testing.T) {
	clientID := protocol.ID{1}
	connectorID := protocol.ID{2}
	route := protocol.RouteID{3}
	name := ClientCapabilityDNSName(clientID, connectorID, route, 0x2a)
	parsedClient, parsedConnector, parsedRoute, parsedEpoch, err := ParseClientCapabilityDNSName(name)
	if err != nil {
		t.Fatalf("ParseClientCapabilityDNSName: %v", err)
	}
	if parsedClient != clientID || parsedConnector != connectorID || parsedRoute != route || parsedEpoch != 0x2a {
		t.Fatalf("parsed capability = %v/%v/%v/%x", parsedClient, parsedConnector, parsedRoute, parsedEpoch)
	}
	wantConnector := "i-" + connectorID.String() + ".r-" + route.String() + ".connector.v1.owntransit.invalid"
	if got := CapabilityConnectorDNSName(connectorID, route); got != wantConnector {
		t.Fatalf("CapabilityConnectorDNSName = %q, want %q", got, wantConnector)
	}
	for _, invalid := range []string{
		strings.ToUpper(name),
		strings.Replace(name, ".e-000000000000002a.", ".e-2a.", 1),
		strings.Replace(name, ".e-000000000000002a.", ".e-0000000000000000.", 1),
		strings.Replace(name, ".client-cap.v1.", ".client-cap.v2.", 1),
		name + ".",
	} {
		if _, _, _, _, err := ParseClientCapabilityDNSName(invalid); err == nil {
			t.Errorf("accepted non-canonical capability name %q", invalid)
		}
	}
}

func TestCapabilityConnectorHasNoPositiveClientList(t *testing.T) {
	connectorID := protocol.ID{8}
	clientID := protocol.ID{9}
	route := protocol.RouteID{10}
	pin := identity.FormatSPKIPin(identity.SPKIHash{11})
	connectorName := CapabilityConnectorDNSName(connectorID, route)
	value := Connector{
		RelayURL: "wss://relay.example.com/connects", InstallationID: connectorID.String(), RouteID: route.String(),
		InnerProfile: InnerProfileRouteCapability,
		OuterTLS: ClientTLS{
			CertFile: "outer.crt", KeyFile: "outer.key", CAFile: "relay-ca.crt", ServerName: RelayDNSName,
			SPKIPins: []string{pin}, IssuerCAFile: "relay-ca.crt", LocalDNSName: OuterConnectorDNSName(route),
		},
		InnerTLS: ConnectorInnerTLS{
			CertFile: "inner.crt", KeyFile: "inner.key", ClientCAFiles: []string{"route-client-ca.crt"},
			IssuerCAFile: "connector-ca.crt", LocalDNSName: connectorName, ServerName: connectorName,
		},
		SSHTarget: ConnectorSSHTarget,
		Limits: ConnectorLimits{
			Pending: 1, Active: 1, ConnectTimeout: Duration(time.Second), Handshake: Duration(time.Second),
			LocalDial: Duration(time.Second), Drain: Duration(time.Second), ReconnectMin: Duration(time.Second), ReconnectMax: Duration(time.Second),
		},
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("capability connector: %v", err)
	}

	positiveList := value
	positiveList.InnerTLS.Clients = []AuthorizedPeer{{DNSName: ClientCapabilityDNSName(clientID, connectorID, route, 1), SPKIPins: []string{pin}}}
	if err := positiveList.Validate(); err == nil || !strings.Contains(err.Error(), "positive client allowlist") {
		t.Fatalf("positive list error = %v", err)
	}

	implicitEmpty := value
	implicitEmpty.InnerProfile = ""
	if err := implicitEmpty.Validate(); err == nil || !strings.Contains(err.Error(), "inner_profile") {
		t.Fatalf("implicit profile error = %v", err)
	}

	rotation := value
	rotation.InnerTLS.ClientCAFiles = []string{"old-route-client-ca.crt", "new-route-client-ca.crt"}
	if err := rotation.Validate(); err == nil || !strings.Contains(err.Error(), "client_ca_rotation") {
		t.Fatalf("implicit rotation error = %v", err)
	}
	rotation.InnerTLS.ClientCARotation = true
	if err := rotation.Validate(); err != nil {
		t.Fatalf("explicit two-root rotation: %v", err)
	}
}

func TestCapabilityClientBindsConnectorAndCredentialEpoch(t *testing.T) {
	clientID := protocol.ID{12}
	connectorID := protocol.ID{13}
	route := protocol.RouteID{14}
	pin := identity.FormatSPKIPin(identity.SPKIHash{15})
	value := Client{
		RelayURL: "wss://relay.example.com/connects", InstallationID: clientID.String(), ConnectorInstallationID: connectorID.String(),
		CredentialEpoch: 7, RouteID: route.String(), InnerProfile: InnerProfileRouteCapability,
		OuterTLS: ClientTLS{
			CertFile: "outer.crt", KeyFile: "outer.key", CAFile: "relay-ca.crt", ServerName: RelayDNSName,
			SPKIPins: []string{pin}, IssuerCAFile: "relay-ca.crt", LocalDNSName: OuterClientDNSName(clientID),
		},
		InnerTLS: ClientTLS{
			CertFile: "inner.crt", KeyFile: "inner.key", CAFile: "connector-ca.crt",
			ServerName: CapabilityConnectorDNSName(connectorID, route), SPKIPins: []string{pin},
			IssuerCAFile: "route-client-ca.crt", LocalDNSName: ClientCapabilityDNSName(clientID, connectorID, route, 7),
		},
		ConnectTimeout: Duration(time.Second), HandshakeTimeout: Duration(time.Second), ReadyTimeout: Duration(time.Second), DrainTimeout: Duration(time.Second),
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("capability client: %v", err)
	}
	wrongEpoch := value
	wrongEpoch.CredentialEpoch = 8
	if err := wrongEpoch.Validate(); err == nil || !strings.Contains(err.Error(), "local DNS name") {
		t.Fatalf("wrong epoch binding error = %v", err)
	}
	missingConnector := value
	missingConnector.ConnectorInstallationID = ""
	if err := missingConnector.Validate(); err == nil || !strings.Contains(err.Error(), "connector_installation_id") {
		t.Fatalf("missing connector binding error = %v", err)
	}
}

func TestParseClientInstallationIDRequiresMatchingCanonicalRoles(t *testing.T) {
	id := protocol.ID{5}
	parsed, err := ParseClientInstallationID(OuterClientDNSName(id), ClientDNSName(id))
	if err != nil || parsed != id {
		t.Fatalf("ParseClientInstallationID = %v, %v", parsed, err)
	}
	if _, err := ParseClientInstallationID(OuterClientDNSName(id), ClientDNSName(protocol.ID{6})); err == nil {
		t.Fatal("accepted identities from different installations")
	}
	if _, err := ParseClientInstallationID(ClientDNSName(id), OuterClientDNSName(id)); err == nil {
		t.Fatal("accepted swapped client roles")
	}
}

func TestServerLocalIdentityFieldsAreAtomic(t *testing.T) {
	legacy := ServerTLS{CertFile: "server.crt", KeyFile: "server.key", ClientCAFile: "client-ca.crt"}
	if err := validateServerTLS(legacy); err != nil {
		t.Fatalf("legacy server TLS compatibility: %v", err)
	}
	partial := legacy
	partial.IssuerCAFile = "issuer.crt"
	if err := validateServerTLS(partial); err == nil || !strings.Contains(err.Error(), "set together") {
		t.Fatalf("partial server local identity error = %v", err)
	}
	strict := partial
	strict.LocalDNSName = RelayDNSName
	if err := validateServerTLS(strict); err != nil {
		t.Fatalf("strict server TLS fields: %v", err)
	}
}
