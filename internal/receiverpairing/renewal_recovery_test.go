//go:build darwin || linux

package receiverpairing

import (
	"bytes"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestExpiredRenewalRecoveryRequiresExactAuthenticatedReceipt(t *testing.T) {
	receiver, _, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := CreateRequest(CreateRequestOptions{Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin, Now: now, Validity: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := receiver.Claim(request.Encrypted, now, staticIssuer("initial"))
	if err != nil {
		t.Fatal(err)
	}
	paired, err := OpenResponse(attempt.Advertisement, claimed.Response, request.Material, testRelayOrigin, now)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := CreateRenewal(paired.Pairing, testRelayOrigin, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := receiver.Renew(renewal.Encrypted, now, staticIssuer("expired-authorization"))
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(48 * time.Hour)
	if _, err := OpenRenewalResponse(committed.Response, renewal.Material, testRelayOrigin, later); err == nil {
		t.Fatal("expired response activated")
	}
	public, err := signing.ParsePublic(paired.Pairing.receiverPublic)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := openPairResponse(committed.Response, renewal.Material.responseIdentity, public, now)
	if err != nil {
		t.Fatal(err)
	}
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := readSecrets(root, state, now)
	lock.Close()
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	responseIdentity, err := age.ParseX25519Identity(renewal.Material.responseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		mutate      func(*responsePayload)
		wrongSigner bool
	}{
		{"receiver", func(p *responsePayload) { p.ReceiverID, _ = randomID() }, false},
		{"route", func(p *responsePayload) { p.RouteID, _ = randomID() }, false},
		{"client", func(p *responsePayload) { p.ClientID, _ = randomID() }, false},
		{"origin", func(p *responsePayload) { p.RelayOrigin = "wss://other.example/connects" }, false},
		{"request", func(p *responsePayload) { p.RequestSHA256 = digestText([]byte("another request")) }, false},
		{"generation", func(p *responsePayload) { p.CredentialGeneration++ }, false},
		{"pairing key", func(p *responsePayload) { p.PairingPublicKeyPEM = string(otherKey.PublicPEM) }, false},
		{"pair response", func(p *responsePayload) { p.Kind = "pair"; p.CredentialGeneration = 1; p.AttemptID = attempt.AttemptID }, false},
		{"reversed window", func(p *responsePayload) { p.ExpiresUnix = p.IssuedUnix }, false},
		{"oversized window", func(p *responsePayload) { p.ExpiresUnix = p.IssuedUnix + int64(MaxMessageValidity/time.Second) + 1 }, false},
		{"future", func(p *responsePayload) {
			p.IssuedUnix = later.Add(time.Hour).Unix()
			p.ExpiresUnix = later.Add(2 * time.Hour).Unix()
		}, false},
		{"unknown schema", func(p *responsePayload) { p.Schema = "unsupported" }, false},
		{"bad authorization", func(p *responsePayload) { p.Authorization = "!" }, false},
		{"wrong signature", func(p *responsePayload) {}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := payload
			tc.mutate(&changed)
			key := secrets.signingPrivate
			if tc.wrongSigner {
				key = otherKey.Private
			}
			encoded, err := makeResponse(changed, responseIdentity.Recipient().String(), key)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			_, err = RecoverExpiredRenewal(encoded, renewal.Material, testRelayOrigin, later, time.Minute, func(ClientIdentity) ([]byte, error) { called = true; return nil, nil })
			if err == nil || called {
				t.Fatal("invalid receipt advanced renewal")
			}
		})
	}
	if _, err := RecoverExpiredRenewal(committed.Response, renewal.Material, testRelayOrigin, now, time.Minute, nil); err == nil {
		t.Fatal("live response used as expired receipt")
	}
	if _, err := RecoverExpiredRenewal(committed.Response, renewal.Material, "wss://other.example/connects", later, time.Minute, nil); err == nil {
		t.Fatal("changed selected origin accepted")
	}
	// Only a new request is returned: the expired authorization cannot be activated.
	next, err := RecoverExpiredRenewal(committed.Response, renewal.Material, testRelayOrigin, later, time.Minute, func(id ClientIdentity) ([]byte, error) {
		if id.CredentialGeneration != 3 || id.ClientID != paired.Pairing.ClientID() {
			t.Fatal("identity or generation changed")
		}
		return []byte("fresh-csrs"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(next.Encrypted, renewal.Encrypted) || next.Material.responseIdentity == renewal.Material.responseIdentity {
		t.Fatal("reused request or response key")
	}
	if !bytes.Equal(next.Material.pairing.pairingPrivate, paired.Pairing.pairingPrivate) {
		t.Fatal("replaced persistent pairing key")
	}
	encoded, err := next.Material.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ParseRenewalMaterial(encoded)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := receiver.Renew(restored.RequestBytes(), later, func(p PeerRequest) ([]byte, error) {
		if p.CredentialGeneration != 3 || string(p.PublicPayload) != "fresh-csrs" {
			t.Fatal("fresh renewal scope changed")
		}
		return []byte("fresh-authorization"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRenewalResponse(fresh.Response, restored, testRelayOrigin, later)
	if err != nil || string(opened.Authorization) != "fresh-authorization" {
		t.Fatal("fresh renewal failed", err)
	}
	if _, err := OpenRenewalResponse(committed.Response, restored, testRelayOrigin, later); err == nil {
		t.Fatal("old receipt completed fresh renewal")
	}
	// Revocation still wins even with a previously authentic cached receipt.
	if _, err := receiver.RevokePeer(); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Renew(next.Encrypted, later, staticIssuer("forbidden")); err == nil {
		t.Fatal("revoked peer renewed")
	}
}
