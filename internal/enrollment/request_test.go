package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestClientRequestBindsCSRProofRecipientNonceAndValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bootstrap := newBootstrapFixture(t, now)
	installationID, err := protocol.NewID()
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
	nonce, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	outer, err := pki.NewCSR(config.OuterClientDNSName(installationID))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := pki.NewCSR(config.ClientCapabilityDNSName(installationID, connectorID, route, 1))
	if err != nil {
		t.Fatal(err)
	}
	_, recipient, err := GenerateResponseIdentity()
	if err != nil {
		t.Fatal(err)
	}
	payload := RequestPayload{
		Schema: RequestSchema, Role: RoleClient,
		InstallationID: installationID.String(), RouteID: route.String(), ConnectorInstallationID: connectorID.String(),
		Nonce: nonce.String(), Sequence: 1,
		CreatedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(),
		ResponseRecipient: recipient, IssuerPins: bootstrap.pins, DeploymentSignerKeyID: bootstrap.signer.KeyID,
		Runtime: bootstrap.runtime(RoleClient), OuterCSR: string(outer.CSRPEM), InnerCSR: string(inner.CSRPEM),
	}
	encoded, err := SignRequest(payload, outer.Signer, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.InstallationID != payload.InstallationID || parsed.Nonce != payload.Nonce || parsed.ResponseRecipient != recipient {
		t.Fatalf("parsed request lost target binding: %#v", parsed)
	}
	if _, err := ParseRequest(encoded, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired request was accepted")
	}
}

func TestRequestRejectsSignerMismatchAndSignedPayloadTampering(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bootstrap := newBootstrapFixture(t, now)
	installationID, err := protocol.NewID()
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
	nonce, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	outer, err := pki.NewCSR(config.OuterClientDNSName(installationID))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := pki.NewCSR(config.ClientCapabilityDNSName(installationID, connectorID, route, 1))
	if err != nil {
		t.Fatal(err)
	}
	_, recipient, err := GenerateResponseIdentity()
	if err != nil {
		t.Fatal(err)
	}
	payload := RequestPayload{
		Schema: RequestSchema, Role: RoleClient,
		InstallationID: installationID.String(), RouteID: route.String(), ConnectorInstallationID: connectorID.String(),
		Nonce: nonce.String(), Sequence: 1,
		CreatedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(),
		ResponseRecipient: recipient, IssuerPins: bootstrap.pins, DeploymentSignerKeyID: bootstrap.signer.KeyID,
		Runtime: bootstrap.runtime(RoleClient), OuterCSR: string(outer.CSRPEM), InnerCSR: string(inner.CSRPEM),
	}
	_, wrongSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRequest(payload, wrongSigner, now); err == nil {
		t.Fatal("request accepted a signer that did not own the outer CSR")
	}

	encoded, err := SignRequest(payload, outer.Signer, now)
	if err != nil {
		t.Fatal(err)
	}
	var envelope signedRequest
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var changed RequestPayload
	if err := json.Unmarshal(payloadBytes, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Sequence++
	payloadBytes, err = json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(payloadBytes)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(tampered, now); err == nil {
		t.Fatal("tampered signed payload was accepted")
	}
}
