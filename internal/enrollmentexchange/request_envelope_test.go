package enrollmentexchange

import (
	"bytes"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestEncryptedRequestRoundTripIsPaddedSignedAndInvitationBound(t *testing.T) {
	invitation, _, now := invitationFixture(t)
	requestBytes, payload := requestFixture(t, invitation, now)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sealRequest(requestBytes, identity.Recipient().String(), now)
	if err != nil {
		t.Fatal(err)
	}
	opened, parsed, err := openRequest(ciphertext, identity.String(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, requestBytes) || parsed.Nonce != payload.Nonce {
		t.Fatal("encrypted request did not preserve exact signed bytes")
	}
	if err := bindRequestToInvitation(invitation, parsed); err != nil {
		t.Fatal(err)
	}
	phrase, err := derivePhrase([]byte("signed invitation bytes"), requestBytes, ciphertext)
	if err != nil || phrase == (SafetyPhrase{}) {
		t.Fatalf("encrypted request cannot enter safety transcript: phrase=%q err=%v", phrase, err)
	}
}

func TestEncryptedRequestRejectsWrongIdentityTamperingAndRegeneration(t *testing.T) {
	invitation, _, now := invitationFixture(t)
	requestBytes, _ := requestFixture(t, invitation, now)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	first, err := sealRequest(requestBytes, identity.Recipient().String(), now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealRequest(requestBytes, identity.Recipient().String(), now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("sealing twice unexpectedly reproduced ciphertext; callers must retain exact first bytes")
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRequest(first, wrong.String(), now); err == nil {
		t.Fatal("wrong request identity was accepted")
	}
	tampered := append([]byte(nil), first...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := openRequest(tampered, identity.String(), now); err == nil {
		t.Fatal("tampered encrypted request was accepted")
	}
}

func TestRequestInvitationBindingRejectsEveryTentativeAuthorityChange(t *testing.T) {
	invitation, _, now := invitationFixture(t)
	_, request := requestFixture(t, invitation, now)
	checks := []struct {
		name   string
		mutate func(*enrollment.RequestPayload)
	}{
		{"sequence", func(value *enrollment.RequestPayload) { value.Sequence++ }},
		{"role", func(value *enrollment.RequestPayload) { value.Role = enrollment.RoleConnector }},
		{"route", func(value *enrollment.RequestPayload) { value.RouteID = newRouteID(t) }},
		{"connector", func(value *enrollment.RequestPayload) { value.ConnectorInstallationID = newID(t) }},
		{"runtime", func(value *enrollment.RequestPayload) { value.Runtime.ReleaseSequence++ }},
		{"issuer", func(value *enrollment.RequestPayload) {
			value.IssuerPins.InnerClientCA = value.IssuerPins.InnerConnectorCA
		}},
		{"verifier", func(value *enrollment.RequestPayload) {
			value.DeploymentSignerKeyID = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}},
		{"created", func(value *enrollment.RequestPayload) { value.CreatedUnix = invitation.CreatedUnix - 1 }},
		{"expires", func(value *enrollment.RequestPayload) { value.ExpiresUnix = invitation.ExpiresUnix + 1 }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			changed := request
			check.mutate(&changed)
			if err := bindRequestToInvitation(invitation, changed); err == nil {
				t.Fatal("request with changed invitation binding was accepted")
			}
		})
	}
}

func TestRequestPaddingClassesAreExactAndDigestProtected(t *testing.T) {
	for _, size := range []int{1, 64 << 10, enrollment.MaxRequestSize} {
		request := bytes.Repeat([]byte{'x'}, size)
		plaintext, err := padRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := unpadRequest(plaintext)
		if err != nil || !bytes.Equal(opened, request) {
			t.Fatalf("size %d padding round trip failed: %v", size, err)
		}
		plaintext[len(requestPlaintextMagic)+4] ^= 1
		if _, err := unpadRequest(plaintext); err == nil {
			t.Fatal("changed declared request digest was accepted")
		}
	}
	if _, err := unpadRequest(make([]byte, (64<<10)-1)); err == nil {
		t.Fatal("non-class plaintext size was accepted")
	}
}

func requestFixture(t *testing.T, invitation invitation, now time.Time) ([]byte, enrollment.RequestPayload) {
	t.Helper()
	installationID := newID(t)
	clientID, err := protocol.ParseID(installationID)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := protocol.ParseRouteID(invitation.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	connectorID, err := protocol.ParseID(invitation.ConnectorInstallationID)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := pki.NewCSR(config.OuterClientDNSName(clientID))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := pki.NewCSR(config.ClientCapabilityDNSName(clientID, connectorID, routeID, 1))
	if err != nil {
		t.Fatal(err)
	}
	responseIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	payload := enrollment.RequestPayload{
		Schema: enrollment.RequestSchema, Role: invitation.Role, InstallationID: installationID,
		RouteID: invitation.RouteID, ConnectorInstallationID: invitation.ConnectorInstallationID,
		Nonce: newID(t), Sequence: 1, CreatedUnix: now.Unix(), ExpiresUnix: now.Add(30 * time.Minute).Unix(),
		ResponseRecipient: responseIdentity.Recipient().String(), IssuerPins: invitation.IssuerPins,
		DeploymentSignerKeyID: invitation.DeploymentSignerKeyID, Runtime: invitation.Runtime,
		OuterCSR: string(outer.CSRPEM), InnerCSR: string(inner.CSRPEM),
	}
	encoded, err := enrollment.SignRequest(payload, outer.Signer, now)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, payload
}

func newID(t *testing.T) string {
	t.Helper()
	value, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return value.String()
}

func newRouteID(t *testing.T) string {
	t.Helper()
	value, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	return value.String()
}
