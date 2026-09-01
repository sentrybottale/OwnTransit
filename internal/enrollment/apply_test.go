package enrollment

import (
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestVerifyForApplyBindsLocalKeysTrustRuntimeAndFloors(t *testing.T) {
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
		DeploymentSequence: 1, Now: now, LeafValidity: 30 * 24 * time.Hour, DeploymentValidity: 24 * time.Hour,
		Issuers: bootstrap.issuers, DeploymentSigner: bootstrap.signer.Private,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := ParseRequest(client.encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := ApplyPolicy{
		Role: RoleClient, InstallationID: client.installationID.String(), RequestBytes: client.encoded,
		ResponseIdentity: client.identity, DeploymentSigner: bootstrap.signer.Public,
		ExpectedIssuerPins: bootstrap.pins, ExpectedRuntime: request.Runtime, ExpectedRequestSequence: 1,
		OuterPrivateKeyPEM: client.outerKeyPEM, InnerPrivateKeyPEM: client.innerKeyPEM,
	}
	verified, err := VerifyForApply(responses.ClientEnvelope, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.NextDeploymentSequence != 1 || verified.NextCredentialEpoch != 1 || verified.RequestSHA256 == "" {
		t.Fatalf("unexpected verified floors: %#v", verified)
	}

	replay := policy
	replay.HighestDeploymentSequence = 1
	if _, err := VerifyForApply(responses.ClientEnvelope, replay, now); err == nil {
		t.Fatal("deployment replay was accepted")
	}
	wrongKey := policy
	wrongKey.InnerPrivateKeyPEM = connector.innerKeyPEM
	if _, err := VerifyForApply(responses.ClientEnvelope, wrongKey, now); err == nil {
		t.Fatal("deployment was accepted with the wrong retained private key")
	}
}
