package enrollmentexchange

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestInvitationIsCanonicalSignedButExplicitlyTentative(t *testing.T) {
	invitation, signer, now := invitationFixture(t)
	encoded, err := signInvitation(invitation, signer.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTentativeInvitation(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Invitation.InvitationID != invitation.InvitationID || !bytes.Equal(parsed.Encoded, encoded) {
		t.Fatal("parsed invitation does not preserve the exact signed transcript")
	}
	digest := sha256.Sum256(encoded)
	if parsed.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("tentative invitation digest does not bind its exact bytes")
	}

	// Self-signature consistency is intentionally not human identity. An
	// attacker can construct another internally valid invitation, which is why
	// the caller must not bootstrap or activate from this result alone.
	attacker, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	invitation.DeploymentSignerPublicPEM = string(attacker.PublicPEM)
	invitation.DeploymentSignerKeyID = attacker.KeyID
	attackerBytes, err := signInvitation(invitation, attacker.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseTentativeInvitation(attackerBytes, now); err != nil {
		t.Fatalf("self-consistent attacker transcript should remain tentative, not be misclassified as malformed: %v", err)
	}
}

func TestInvitationRejectsTamperingAliasesAndWrongSigner(t *testing.T) {
	invitation, signer, now := invitationFixture(t)
	encoded, err := signInvitation(invitation, signer.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), encoded...)
	for index := 0; index < len(tampered); index++ {
		if tampered[index] == 'a' {
			tampered[index] = 'b'
			break
		}
	}
	if _, err := parseTentativeInvitation(tampered, now); err == nil {
		t.Fatal("tampered invitation was accepted")
	}
	noncanonical := append(append([]byte(nil), encoded[:len(encoded)-1]...), ' ', '\n')
	if _, err := parseTentativeInvitation(noncanonical, now); err == nil {
		t.Fatal("noncanonical envelope whitespace was accepted")
	}
	other, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signInvitation(invitation, other.Private, now); err == nil {
		t.Fatal("private key which differs from embedded verifier was accepted")
	}
}

func TestInvitationRejectsExpiredRoleReleaseTrustAndMailboxAliases(t *testing.T) {
	base, signer, now := invitationFixture(t)
	checks := []struct {
		name   string
		mutate func(*invitation)
	}{
		{"expired", func(value *invitation) { value.ExpiresUnix = now.Unix() }},
		{"role mismatch", func(value *invitation) { value.Role = enrollment.RoleConnector }},
		{"release digest", func(value *invitation) { value.Runtime.ArtifactSHA256 = strings.Repeat("A", 64) }},
		{"issuer pin", func(value *invitation) { value.IssuerPins.InnerClientCA = value.IssuerPins.InnerConnectorCA }},
		{"capability in URL", func(value *invitation) { value.Exchange.Endpoint += "?capability=leak" }},
		{"same capabilities", func(value *invitation) { value.Exchange.ResponseReadCapability = value.Exchange.RequestWriteCapability }},
		{"padded capability", func(value *invitation) { value.Exchange.RequestWriteCapability += "=" }},
		{"mailbox alias", func(value *invitation) { value.Exchange.MailboxID = strings.ToUpper(value.Exchange.MailboxID) }},
		{"request recipient", func(value *invitation) { value.RequestEncryptionRecipient += " " }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			value := base
			check.mutate(&value)
			if _, err := signInvitation(value, signer.Private, now); err == nil {
				t.Fatal("invalid invitation was signed")
			}
		})
	}
}

func TestInvitationRoleBindingsAreExact(t *testing.T) {
	client, signer, now := invitationFixture(t)
	connector := client
	connector.Role = enrollment.RoleConnector
	connector.Runtime.Role = enrollment.RoleConnector
	connector.Runtime.OS = "linux"
	connector.Runtime.Arch = "amd64"
	connector.Runtime.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
	connector.ConnectorInstallationID = ""
	if _, err := signInvitation(connector, signer.Private, now); err != nil {
		t.Fatalf("valid connector invitation rejected: %v", err)
	}

	relay := client
	relay.Role = enrollment.RoleRelay
	relay.Runtime.Role = enrollment.RoleRelay
	relay.Runtime.OS = "linux"
	relay.Runtime.Arch = "amd64"
	relay.Runtime.ConnectorTarget = ""
	relay.RouteID = ""
	relay.ConnectorInstallationID = ""
	if _, err := signInvitation(relay, signer.Private, now); err != nil {
		t.Fatalf("valid relay invitation rejected: %v", err)
	}
}

func TestInvitationRejectsLiteralUnsafeOrAliasedExchangeOrigins(t *testing.T) {
	base, signer, now := invitationFixture(t)
	for _, endpoint := range []string{
		"wss://127.0.0.1/connects/enrollment",
		"wss://[::1]/connects/enrollment",
		"wss://localhost/connects/enrollment",
		"wss://relay.local/connects/enrollment",
		"wss://relay.example.invalid/connects/enrollment",
		"wss://relay.example.com:443/connects/enrollment",
		"wss://relay/connects/enrollment",
		"wss://reläy.example.com/connects/enrollment",
	} {
		t.Run(endpoint, func(t *testing.T) {
			value := base
			value.Exchange.Endpoint = endpoint
			if _, err := signInvitation(value, signer.Private, now); err == nil {
				t.Fatal("unsafe or aliased exchange origin was accepted")
			}
		})
	}
}

func invitationFixture(t *testing.T) (invitation, signing.KeyPair, time.Time) {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	signer, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	relayCA, err := pki.NewCA("relay admission", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCA, err := pki.NewCA("inner client", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	connectorCA, err := pki.NewCA("inner connector", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trust := enrollment.Trust{
		RelayAdmissionCA: string(relayCA.CertPEM),
		InnerClientCA:    string(clientCA.CertPEM),
		InnerConnectorCA: string(connectorCA.CertPEM),
	}
	pins, err := enrollment.IssuerPinsFromTrust(trust, now)
	if err != nil {
		t.Fatal(err)
	}
	invitationID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	mailboxID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	connectorID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	requestIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return invitation{
		Schema:                    invitationSchema,
		InvitationID:              invitationID.String(),
		CreatedUnix:               now.Unix(),
		ExpiresUnix:               now.Add(time.Hour).Unix(),
		MinimumLifecycle:          enrollment.CurrentLifecycleGeneration,
		Role:                      enrollment.RoleClient,
		RouteID:                   routeID.String(),
		ConnectorInstallationID:   connectorID.String(),
		Runtime:                   enrollment.RuntimeBinding{ReleaseID: releaseID.String(), ReleaseSequence: 7, ArtifactSHA256: strings.Repeat("ab", 32), OS: "darwin", Arch: "arm64", Role: enrollment.RoleClient, Protocol: enrollment.DeploymentProtocol, LifecycleGeneration: enrollment.CurrentLifecycleGeneration},
		Trust:                     trust,
		IssuerPins:                pins,
		DeploymentSignerPublicPEM: string(signer.PublicPEM),
		DeploymentSignerKeyID:     signer.KeyID,
		Exchange: targetExchange{
			Endpoint: "wss://relay.example.com/connects/enrollment", MailboxID: mailboxID.String(),
			RequestWriteCapability: testCapability(0x31), ResponseReadCapability: testCapability(0x72),
			RequestReadCapabilityCommitment:   mailboxCapabilityCommitment(mailboxID.String(), "request-read", testCapability(0x18)),
			ResponseWriteCapabilityCommitment: mailboxCapabilityCommitment(mailboxID.String(), "response-write", testCapability(0x93)),
		},
		RequestEncryptionRecipient: requestIdentity.Recipient().String(),
	}, signer, now
}

func testCapability(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, mailboxCapabilitySize))
}
