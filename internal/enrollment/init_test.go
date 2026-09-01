package enrollment

import (
	"bytes"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestNewPendingClientRequestKeepsSecretsOutOfExport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bootstrap := newBootstrapFixture(t, now)
	clientID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	connectorID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewPendingRequest(InitOptions{
		Role: RoleClient, InstallationID: clientID.String(), RouteID: route.String(),
		ConnectorInstallationID: connectorID.String(), Sequence: 1, Now: now, RequestValidity: time.Hour,
		Trust: Trust{
			RelayAdmissionCA: string(bootstrap.issuers.RelayAdmission.CertPEM),
			InnerClientCA:    string(bootstrap.issuers.InnerClient.CertPEM),
			InnerConnectorCA: string(bootstrap.issuers.InnerConnector.CertPEM),
		},
		DeploymentSigner: bootstrap.signer.Public, Runtime: bootstrap.runtime(RoleClient),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(material.OuterPrivateKey) == 0 || len(material.InnerPrivateKey) == 0 || material.ResponseIdentity == "" {
		t.Fatal("pending target secrets were not generated")
	}
	if bytes.Contains(material.RequestBytes, material.OuterPrivateKey) || bytes.Contains(material.RequestBytes, material.InnerPrivateKey) ||
		bytes.Contains(material.RequestBytes, []byte(material.ResponseIdentity)) {
		t.Fatal("public enrollment request exposed target secret material")
	}
	parsed, err := ParseRequest(material.RequestBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RouteID != route.String() || parsed.ConnectorInstallationID != connectorID.String() {
		t.Fatal("client capability target was not bound into request")
	}
}
