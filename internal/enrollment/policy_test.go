package enrollment

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestLifecyclePolicySignatureIsTargetBoundStrictAndRoleSeparated(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newBootstrapFixture(t, now)
	installation, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	pin := identity.FormatSPKIPin(identity.SPKIHash{1})
	policy := LifecyclePolicy{
		Schema: LifecyclePolicySchema, Role: RoleClient, InstallationID: installation.String(), Sequence: 1,
		IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(), ExpectedStateGeneration: 7,
		ExpectedStateSHA256: strings.Repeat("a", 64),
		Trust: Trust{
			RelayAdmissionCA: string(fixture.issuers.RelayAdmission.CertPEM),
			InnerClientCA:    string(fixture.issuers.InnerClient.CertPEM), InnerConnectorCA: string(fixture.issuers.InnerConnector.CertPEM),
		},
		CapabilityClientRoots: []string{}, RelayServerSPKIPins: []string{pin}, ConnectorSPKIPins: []string{pin},
		RelayClients: []config.AuthorizedPeer{}, RelayRoutes: []config.RelayRoute{},
		RevokedClientInstallationIDs: []string{}, RevokedClientSPKIPins: []string{},
	}
	encoded, err := SignLifecyclePolicy(policy, fixture.signer.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyLifecyclePolicy(encoded, fixture.signer.Public, now)
	if err != nil || verified.InstallationID != policy.InstallationID {
		t.Fatalf("verify signed policy: value=%+v err=%v", verified, err)
	}
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)/2] ^= 1
	if _, err := VerifyLifecyclePolicy(tampered, fixture.signer.Public, now); err == nil {
		t.Fatal("tampered signed policy was accepted")
	}
	wrongRole := policy
	wrongRole.RevokedClientInstallationIDs = []string{installation.String()}
	if _, err := SignLifecyclePolicy(wrongRole, fixture.signer.Private, now); err == nil {
		t.Fatal("client policy accepted connector-only revocation state")
	}
	duplicate := policy
	duplicate.RelayServerSPKIPins = []string{pin, pin}
	if _, err := SignLifecyclePolicy(duplicate, fixture.signer.Private, now); err == nil {
		t.Fatal("policy accepted duplicate verifier pins")
	}
	if bytes.Contains(encoded, fixture.signer.PrivatePEM) {
		t.Fatal("signed public policy contains signer private material")
	}
}
