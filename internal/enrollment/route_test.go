package enrollment

import (
	"bytes"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

type requestFixture struct {
	encoded        []byte
	identity       string
	installationID protocol.ID
	outerKeyPEM    []byte
	innerKeyPEM    []byte
}

func TestApproveInitialRouteIssuesOnlyCSRLeavesAndTargetEncryptedResponses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bootstrap := newBootstrapFixture(t, now)
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	relay := newRequestFixture(t, RoleRelay, route, protocol.ID{}, now, bootstrap)
	connector := newRequestFixture(t, RoleConnector, route, protocol.ID{}, now, bootstrap)
	client := newRequestFixture(t, RoleClient, route, connector.installationID, now, bootstrap)

	responses, err := ApproveInitialRoute(RouteApproval{
		RelayRequest: relay.encoded, ConnectorRequest: connector.encoded, ClientRequest: client.encoded,
		RelayURL: "wss://relay.example.com/connects", RelayListen: PackagedRelayListen,
		DeploymentSequence: 1, Now: now, LeafValidity: 24 * time.Hour, DeploymentValidity: time.Hour,
		Issuers: bootstrap.issuers, DeploymentSigner: bootstrap.signer.Private,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, check := range []struct {
		name     string
		envelope []byte
		identity string
		request  []byte
		wantRole Role
	}{
		{"relay", responses.RelayEnvelope, relay.identity, relay.encoded, RoleRelay},
		{"connector", responses.ConnectorEnvelope, connector.identity, connector.encoded, RoleConnector},
		{"client", responses.ClientEnvelope, client.identity, client.encoded, RoleClient},
	} {
		t.Run(check.name, func(t *testing.T) {
			if bytes.Contains(check.envelope, []byte("CERTIFICATE")) || bytes.Contains(check.envelope, []byte("PRIVATE KEY")) || bytes.Contains(check.envelope, []byte("relay.example.com")) {
				t.Fatal("target envelope exposed deployment plaintext")
			}
			plaintext, err := OpenResponse(check.envelope, check.identity, bootstrap.signer.Public)
			if err != nil {
				t.Fatal(err)
			}
			deployment, err := ParseBoundDeployment(plaintext, check.request, now)
			if err != nil {
				t.Fatal(err)
			}
			if deployment.Role != check.wantRole {
				t.Fatalf("deployment role = %q, want %q", deployment.Role, check.wantRole)
			}
			if err := deployment.ValidateRequestBinding(check.request, now); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(plaintext, []byte("PRIVATE KEY")) {
				t.Fatal("provisioner response contained endpoint private-key material")
			}
		})
	}
}

func TestApproveInitialRouteRejectsRoleSubstitution(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bootstrap := newBootstrapFixture(t, now)
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	relay := newRequestFixture(t, RoleRelay, route, protocol.ID{}, now, bootstrap)
	connector := newRequestFixture(t, RoleConnector, route, protocol.ID{}, now, bootstrap)
	client := newRequestFixture(t, RoleClient, route, connector.installationID, now, bootstrap)
	_, err = ApproveInitialRoute(RouteApproval{
		RelayRequest: relay.encoded, ConnectorRequest: client.encoded, ClientRequest: connector.encoded,
		RelayURL: "wss://relay.example.com/connects", RelayListen: PackagedRelayListen,
		DeploymentSequence: 1, Now: now, LeafValidity: time.Hour, DeploymentValidity: time.Hour,
		Issuers: bootstrap.issuers, DeploymentSigner: bootstrap.signer.Private,
	})
	if err == nil {
		t.Fatal("role-substituted route requests were accepted")
	}
}

func TestApproveInitialRouteRejectsRelayListenOutsidePackagedContract(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bootstrap := newBootstrapFixture(t, now)
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	relay := newRequestFixture(t, RoleRelay, route, protocol.ID{}, now, bootstrap)
	connector := newRequestFixture(t, RoleConnector, route, protocol.ID{}, now, bootstrap)
	client := newRequestFixture(t, RoleClient, route, connector.installationID, now, bootstrap)
	for _, listen := range []string{"127.0.0.1:9087", "0.0.0.0:9443", "[::]:9087"} {
		t.Run(listen, func(t *testing.T) {
			_, err := ApproveInitialRoute(RouteApproval{
				RelayRequest: relay.encoded, ConnectorRequest: connector.encoded, ClientRequest: client.encoded,
				RelayURL: "wss://relay.example.com/connects", RelayListen: listen,
				DeploymentSequence: 1, Now: now, LeafValidity: time.Hour, DeploymentValidity: time.Hour,
				Issuers: bootstrap.issuers, DeploymentSigner: bootstrap.signer.Private,
			})
			if err == nil {
				t.Fatalf("relay listen %q was accepted", listen)
			}
		})
	}
}

func TestApproveRouteRotationRequiresOnePostInitialSequence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bootstrap := newBootstrapFixture(t, now)
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	relayID, _ := protocol.NewID()
	connectorID, _ := protocol.NewID()
	clientID, _ := protocol.NewID()
	relay := newRequestFixtureForInstallation(t, RoleRelay, relayID, route, protocol.ID{}, 2, now, bootstrap)
	connector := newRequestFixtureForInstallation(t, RoleConnector, connectorID, route, protocol.ID{}, 2, now, bootstrap)
	client := newRequestFixtureForInstallation(t, RoleClient, clientID, route, connectorID, 2, now, bootstrap)
	approval := RouteApproval{
		RelayRequest: relay.encoded, ConnectorRequest: connector.encoded, ClientRequest: client.encoded,
		RelayURL: "wss://relay.example.com/connects", RelayListen: PackagedRelayListen,
		DeploymentSequence: 2, Now: now, LeafValidity: 24 * time.Hour, DeploymentValidity: time.Hour,
		Issuers: bootstrap.issuers, DeploymentSigner: bootstrap.signer.Private,
	}
	responses, err := ApproveRouteRotation(approval)
	if err != nil {
		t.Fatal(err)
	}
	if responses.ClientDeployment.CredentialEpoch != 2 || responses.ConnectorDeployment.DeploymentSequence != 2 {
		t.Fatalf("rotation did not bind new sequences: %+v", responses.ClientDeployment)
	}
	if _, err := ApproveInitialRoute(approval); err == nil {
		t.Fatal("initial approval accepted post-initial rotation requests")
	}
	mismatched := newRequestFixtureForInstallation(t, RoleClient, clientID, route, connectorID, 3, now, bootstrap)
	approval.ClientRequest = mismatched.encoded
	if _, err := ApproveRouteRotation(approval); err == nil {
		t.Fatal("rotation accepted mismatched credential sequences")
	}
}

func newRequestFixture(t *testing.T, role Role, route protocol.RouteID, connectorID protocol.ID, now time.Time, bootstrap bootstrapFixture) requestFixture {
	t.Helper()
	installationID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return newRequestFixtureForInstallation(t, role, installationID, route, connectorID, 1, now, bootstrap)
}

func newRequestFixtureForInstallation(t *testing.T, role Role, installationID protocol.ID, route protocol.RouteID, connectorID protocol.ID, sequence uint64, now time.Time, bootstrap bootstrapFixture) requestFixture {
	t.Helper()
	nonce, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	var outerName, innerName, routeText string
	switch role {
	case RoleRelay:
		outerName = config.RelayDNSName
	case RoleConnector:
		outerName = config.OuterConnectorDNSName(route)
		innerName = config.CapabilityConnectorDNSName(installationID, route)
		routeText = route.String()
	case RoleClient:
		if connectorID == (protocol.ID{}) {
			t.Fatal("client fixture requires connector installation ID")
		}
		outerName = config.OuterClientDNSName(installationID)
		innerName = config.ClientCapabilityDNSName(installationID, connectorID, route, sequence)
		routeText = route.String()
	default:
		t.Fatalf("unsupported fixture role %q", role)
	}
	outer, err := pki.NewCSR(outerName)
	if err != nil {
		t.Fatal(err)
	}
	var innerPEM string
	var innerKeyPEM []byte
	if innerName != "" {
		inner, err := pki.NewCSR(innerName)
		if err != nil {
			t.Fatal(err)
		}
		innerPEM = string(inner.CSRPEM)
		innerKeyPEM = append([]byte(nil), inner.KeyPEM...)
	}
	identity, recipient, err := GenerateResponseIdentity()
	if err != nil {
		t.Fatal(err)
	}
	payload := RequestPayload{
		Schema: RequestSchema, Role: role, InstallationID: installationID.String(), RouteID: routeText,
		Nonce: nonce.String(), Sequence: sequence, CreatedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(),
		ResponseRecipient: recipient, IssuerPins: bootstrap.pins, DeploymentSignerKeyID: bootstrap.signer.KeyID,
		Runtime: bootstrap.runtime(role), OuterCSR: string(outer.CSRPEM), InnerCSR: innerPEM,
	}
	if role == RoleClient {
		payload.ConnectorInstallationID = connectorID.String()
	}
	encoded, err := SignRequest(payload, outer.Signer, now)
	if err != nil {
		t.Fatal(err)
	}
	return requestFixture{
		encoded: encoded, identity: identity, installationID: installationID,
		outerKeyPEM: append([]byte(nil), outer.KeyPEM...), innerKeyPEM: innerKeyPEM,
	}
}
