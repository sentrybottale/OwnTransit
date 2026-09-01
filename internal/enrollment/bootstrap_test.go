package enrollment

import (
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

type bootstrapFixture struct {
	issuers   Issuers
	signer    signing.KeyPair
	pins      IssuerPins
	releaseID string
}

func newBootstrapFixture(t *testing.T, now time.Time) bootstrapFixture {
	t.Helper()
	relay, err := pki.NewCA("OwnTransit test relay issuer", now, 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pki.NewCA("OwnTransit test inner client issuer", now, 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	connector, err := pki.NewCA("OwnTransit test inner connector issuer", now, 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	pin := func(certificate *pki.Material) string {
		value, err := pki.CertificatePin(certificate.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	return bootstrapFixture{
		issuers: Issuers{RelayAdmission: relay, InnerClient: client, InnerConnector: connector},
		signer:  signer,
		pins: IssuerPins{
			RelayAdmissionCA: pin(&relay), InnerClientCA: pin(&client), InnerConnectorCA: pin(&connector),
		},
		releaseID: releaseID.String(),
	}
}

func (fixture bootstrapFixture) runtime(role Role) RuntimeBinding {
	binding := RuntimeBinding{
		ReleaseID: fixture.releaseID, ReleaseSequence: 1, ArtifactSHA256: strings.Repeat("a", 64),
		OS: "linux", Arch: "amd64", Role: role, Protocol: DeploymentProtocol,
		LifecycleGeneration: CurrentLifecycleGeneration,
	}
	if role == RoleConnector {
		binding.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
	}
	return binding
}
