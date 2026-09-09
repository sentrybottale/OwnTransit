//go:build darwin || linux

package receiverpairing

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairoffer"
)

func TestShortCodePreservesExactLegacyRequestAndOneUseClaim(t *testing.T) {
	receiver, _, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	short, offer, err := CreateShortOffer(attempt, now)
	if err != nil || len(short) != pairoffer.CodeSize {
		t.Fatal("short offer creation failed")
	}
	defer clear(short)
	legacy, err := RecoverLegacyCode(short, offer, testRelayOrigin, now.Add(time.Minute))
	if err != nil || !bytes.Equal(legacy, attempt.Code) {
		t.Fatal("recovered code was not the exact original legacy code")
	}
	defer clear(legacy)
	ad, err := pairoffer.Verify(short, offer)
	if err != nil || !bytes.Equal(ad, attempt.Advertisement) {
		t.Fatal("short offer changed signed advertisement bytes")
	}
	request, err := CreateRequest(CreateRequestOptions{
		Advertisement: ad, Code: legacy, RelayOrigin: testRelayOrigin,
		Now: now.Add(time.Minute), Validity: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := receiver.Claim(request.Encrypted, now.Add(2*time.Minute), staticIssuer("test authorization"))
	if err != nil {
		t.Fatal("legacy receiver did not accept reconstructed code")
	}
	result, err := OpenResponse(ad, claim.Response, request.Material, testRelayOrigin, now.Add(2*time.Minute))
	if err != nil || string(result.Authorization) != "test authorization" {
		t.Fatal("existing response authentication failed")
	}
	second, err := CreateRequest(CreateRequestOptions{
		Advertisement: ad, Code: legacy, RelayOrigin: testRelayOrigin,
		Now: now.Add(3 * time.Minute), Validity: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Claim(second.Encrypted, now.Add(4*time.Minute), staticIssuer("must not issue")); err == nil {
		t.Fatal("short code allowed a second winning client")
	}
	if retry, err := receiver.Claim(request.Encrypted, now.Add(4*time.Minute), staticIssuer("must not issue")); err != nil || !retry.Idempotent {
		t.Fatal("exact legacy request retry stopped working")
	}
}

func TestCreateShortOfferRejectsChangedAttemptBindings(t *testing.T) {
	receiver, _, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	code, err := parseCode(attempt.Code)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Attempt)
	}{
		{"receiver field", func(a *Attempt) { a.ReceiverID = "" }},
		{"attempt field", func(a *Attempt) { a.AttemptID = "" }},
		{"expiry field", func(a *Attempt) { a.Expires = a.Expires.Add(time.Second) }},
		{"code prefix", func(a *Attempt) { a.Code = []byte("otpair2.invalid") }},
		{"advertisement bytes", func(a *Attempt) { a.Advertisement = append(append([]byte(nil), a.Advertisement...), '\n') }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			changed := attempt
			test.mutate(&changed)
			if short, offer, err := CreateShortOffer(changed, now); err == nil || short != nil || offer != nil {
				t.Fatal("changed attempt produced a short offer")
			}
		})
	}
	for _, mutate := range []func(*codePayload){
		func(c *codePayload) { c.ReceiverID = "11111111111111111111111111111111" },
		func(c *codePayload) { c.AttemptID = "11111111111111111111111111111111" },
		func(c *codePayload) { c.ExpiresUnix++ },
		func(c *codePayload) { c.AdvertisementSHA256 = digestText([]byte("different advertisement")) },
	} {
		changedCode := code
		mutate(&changedCode)
		changed := attempt
		changed.Code, err = encodeCode(changedCode)
		if err != nil {
			t.Fatal(err)
		}
		if short, offer, err := CreateShortOffer(changed, now); err == nil || short != nil || offer != nil {
			t.Fatal("changed code binding produced a short offer")
		}
	}
	for _, invalidTime := range []time.Time{time.Time{}, now.Add(-6 * time.Minute), attempt.Expires} {
		if short, offer, err := CreateShortOffer(attempt, invalidTime); err == nil || short != nil || offer != nil {
			t.Fatal("invalid time produced a short offer")
		}
	}
}

func TestRecoverShortCodeRejectsRelaySubstitutionAndWrongOrigin(t *testing.T) {
	receiver, _, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	short, encoded, err := CreateShortOffer(attempt, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(short)
	attacker, _, attackerNow := newTestReceiver(t)
	attackerAttempt, err := attacker.CreateAttempt(attackerNow, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	attackerCode, attackerOffer, err := CreateShortOffer(attackerAttempt, attackerNow)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(attackerCode)
	offer, err := pairoffer.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// This is a fully valid, independently self-signed attacker advertisement.
	// Its signature is not sufficient: the intended receiver code must bind it.
	if _, err := VerifyAdvertisement(attackerAttempt.Advertisement, attackerNow); err != nil {
		t.Fatal(err)
	}
	changed := offer
	changed.Advertisement = attackerAttempt.Advertisement
	substituted, err := pairoffer.Encode(changed)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		code   []byte
		offer  []byte
		origin string
		now    time.Time
	}{
		{"attacker advertisement", short, substituted, testRelayOrigin, now},
		{"attacker complete offer", short, attackerOffer, testRelayOrigin, now},
		{"crossed private code", attackerCode, encoded, testRelayOrigin, now},
		{"wrong origin", short, encoded, "wss://other.example.com/connects", now},
		{"origin path alias", short, encoded, "wss://relay.example.com/connects/", now},
		{"expired", short, encoded, testRelayOrigin, attempt.Expires},
		{"clock rollback", short, encoded, testRelayOrigin, now.Add(-6 * time.Minute)},
		{"zero time", short, encoded, testRelayOrigin, time.Time{}},
		{"legacy code as short", attempt.Code, encoded, testRelayOrigin, now},
	} {
		t.Run(test.name, func(t *testing.T) {
			if legacy, err := RecoverLegacyCode(test.code, test.offer, test.origin, test.now); err == nil || legacy != nil {
				t.Fatal("untrusted input produced a private legacy code")
			}
		})
	}
}

func TestAuthenticatedOfferStillRequiresSignedAdvertisementProfile(t *testing.T) {
	receiver, _, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	short, _, err := CreateShortOffer(attempt, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(short)
	secret, err := pairoffer.Secret(short)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret[:])
	payload, _, err := parseAdvertisement(attempt.Advertisement, now)
	if err != nil {
		t.Fatal(err)
	}
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer lock.Close()
	secrets, err := readSecrets(root, state, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*advertisementPayload){
		func(p *advertisementPayload) { p.Profile = "owntransit-receiver-pairing/2" },
		func(p *advertisementPayload) { p.Schema = "owntransit.receiver-pairing.advertisement.v2" },
		func(p *advertisementPayload) { p.ExpiresUnix = now.Unix() },
		func(p *advertisementPayload) { p.ReceiverAgeRecipient = "invalid recipient" },
		func(p *advertisementPayload) { p.RelayOrigin = "wss://other.example.com/connects" },
	} {
		changed := payload
		mutate(&changed)
		ad, err := signPayload(advertEnvelopeSchema, advertisementDomain, changed, secrets.signingPrivate, MaxAdvertisementSize)
		if err != nil {
			t.Fatal(err)
		}
		_, offer, err := pairoffer.New(secret, ad)
		if err != nil {
			t.Fatal(err)
		}
		if legacy, err := RecoverLegacyCode(short, offer, testRelayOrigin, now); err == nil || legacy != nil {
			t.Fatal("valid MAC bypassed signed profile, origin, or expiry validation")
		}
	}
	var envelope signedEnvelope
	if err := decodeCanonical(attempt.Advertisement, MaxAdvertisementSize, &envelope); err != nil {
		t.Fatal(err)
	}
	signature, err := decodeBase64(envelope.Signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	envelope.Signature = base64.StdEncoding.EncodeToString(signature)
	invalidSignature, err := encodeCanonical(envelope, MaxAdvertisementSize)
	if err != nil {
		t.Fatal(err)
	}
	_, invalidOffer, err := pairoffer.New(secret, invalidSignature)
	if err != nil {
		t.Fatal(err)
	}
	if legacy, err := RecoverLegacyCode(short, invalidOffer, testRelayOrigin, now); err == nil || legacy != nil {
		t.Fatal("valid MAC bypassed advertisement signature validation")
	}
	legacyPayload, err := parseCode(attempt.Code)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(legacyPayload.Secret)
	defer clear(decoded)
	if err != nil || !bytes.Equal(decoded, secret[:]) {
		t.Fatal("short code changed the original random secret")
	}
}
