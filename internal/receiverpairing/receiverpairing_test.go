//go:build darwin || linux

package receiverpairing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestPairClaimRestartRetryRenewAndPrivatePersistence(t *testing.T) {
	receiver, rootPath, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	info, err := VerifyAdvertisement(attempt.Advertisement, now.Add(time.Minute))
	if err != nil || info.ReceiverID != attempt.ReceiverID || info.AttemptID != attempt.AttemptID {
		t.Fatalf("verify advertisement = %+v, %v", info, err)
	}
	republished, err := receiver.CurrentAdvertisement(now.Add(time.Minute))
	if err != nil || !bytes.Equal(republished, attempt.Advertisement) {
		t.Fatalf("republish advertisement: %v", err)
	}
	trust, err := receiver.PublicTrust(now.Add(time.Minute))
	if err != nil || trust != info.Trust {
		t.Fatalf("public trust = %+v, %v", trust, err)
	}
	if _, err := receiver.LoadPrivateAuthority(now.Add(time.Minute)); err != nil {
		t.Fatalf("load private authority: %v", err)
	}
	code, err := parseCode(attempt.Code)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := base64.RawURLEncoding.DecodeString(code.Secret)
	if len(secret) != secretSize {
		t.Fatalf("code secret size = %d", len(secret))
	}
	attemptJSON, err := json.Marshal(attempt)
	if err != nil || bytes.Contains(attemptJSON, attempt.Code) || strings.Contains(fmt.Sprintf("%v %#v", attempt, attempt), code.Secret) {
		t.Fatal("implicit attempt formatting exposed its private code")
	}

	request, err := CreateRequestWithPayload(CreateRequestOptions{
		Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin,
		Now: now.Add(time.Minute), Validity: 10 * time.Minute,
	}, func(identity ClientIdentity) ([]byte, error) {
		if identity.ReceiverID != attempt.ReceiverID || identity.ClientID == "" || identity.CredentialGeneration != 1 {
			t.Fatalf("unexpected client identity: %+v", identity)
		}
		return []byte("client-public-csrs"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	privateMaterial, err := request.Material.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	restoredMaterial, err := ParseClientMaterial(privateMaterial)
	if err != nil || !bytes.Equal(restoredMaterial.RequestBytes(), request.Encrypted) {
		t.Fatalf("restore client material: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", request.Material, request.Material), code.Secret) {
		t.Fatal("formatted client material exposed a secret")
	}
	encodedJSON, err := json.Marshal(request.Material)
	if err != nil || string(encodedJSON) != "{}" {
		t.Fatalf("implicit JSON material = %q, %v", encodedJSON, err)
	}

	var issueCalls atomic.Int32
	issue := func(value PeerRequest) ([]byte, error) {
		issueCalls.Add(1)
		if value.Kind != "pair" || string(value.PublicPayload) != "client-public-csrs" || value.CredentialGeneration != 1 {
			t.Fatalf("unexpected peer request: %+v", value)
		}
		return []byte("issued-client-credentials-1"), nil
	}
	claimed, err := receiver.Claim(request.Encrypted, now.Add(2*time.Minute), issue)
	if err != nil || claimed.Idempotent || issueCalls.Load() != 1 {
		t.Fatalf("claim = %+v, %v calls=%d", claimed, err, issueCalls.Load())
	}

	reopened, err := Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.Claim(request.Encrypted, now.Add(3*time.Minute), issue)
	if err != nil || !retry.Idempotent || !bytes.Equal(retry.Response, claimed.Response) || issueCalls.Load() != 1 {
		t.Fatalf("claim retry = %+v, %v calls=%d", retry, err, issueCalls.Load())
	}
	opened, err := OpenResponse(attempt.Advertisement, claimed.Response, restoredMaterial, testRelayOrigin, now.Add(3*time.Minute))
	if err != nil || string(opened.Authorization) != "issued-client-credentials-1" {
		t.Fatalf("open response = %+v, %v", opened, err)
	}
	pairingBytes, err := opened.Pairing.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := ParsePairing(pairingBytes)
	if err != nil || pairing.CredentialGeneration() != 1 {
		t.Fatalf("restore pairing = %+v, %v", pairing, err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", pairing, pairing), string(pairing.PairingPrivateKeyPEM())) {
		t.Fatal("formatted pairing exposed its private key")
	}

	renewal, err := CreateRenewalWithPayload(pairing, testRelayOrigin, now.Add(4*time.Minute), 10*time.Minute, func(identity ClientIdentity) ([]byte, error) {
		if identity.ClientID != pairing.ClientID() || identity.CredentialGeneration != 2 {
			t.Fatalf("unexpected renewal identity: %+v", identity)
		}
		return []byte("renewal-public-csrs"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	renewalPrivate, err := renewal.Material.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	renewal.Material, err = ParseRenewalMaterial(renewalPrivate)
	if err != nil || !bytes.Equal(renewal.Material.RequestBytes(), renewal.Encrypted) {
		t.Fatalf("restore renewal material: %v", err)
	}
	renewCalls := atomic.Int32{}
	renewed, err := reopened.Renew(renewal.Encrypted, now.Add(5*time.Minute), func(value PeerRequest) ([]byte, error) {
		renewCalls.Add(1)
		if value.Kind != "renew" || string(value.PublicPayload) != "renewal-public-csrs" || value.CredentialGeneration != 2 {
			t.Fatalf("unexpected renewal request: %+v", value)
		}
		return []byte("issued-client-credentials-2"), nil
	})
	if err != nil || renewed.Idempotent || renewCalls.Load() != 1 {
		t.Fatalf("renew = %+v, %v", renewed, err)
	}
	renewRetry, err := reopened.Renew(renewal.Encrypted, now.Add(6*time.Minute), func(PeerRequest) ([]byte, error) {
		renewCalls.Add(1)
		return nil, nil
	})
	if err != nil || !renewRetry.Idempotent || renewCalls.Load() != 1 || !bytes.Equal(renewRetry.Response, renewed.Response) {
		t.Fatalf("renew retry = %+v, %v calls=%d", renewRetry, err, renewCalls.Load())
	}
	openedRenewal, err := OpenRenewalResponse(renewed.Response, renewal.Material, testRelayOrigin, now.Add(6*time.Minute))
	if err != nil || openedRenewal.Pairing.CredentialGeneration() != 2 || string(openedRenewal.Authorization) != "issued-client-credentials-2" {
		t.Fatalf("open renewal = %+v, %v", openedRenewal, err)
	}

	allFiles, err := os.ReadDir(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range allFiles {
		if entry.IsDir() {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join(rootPath, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(contents, attempt.Code) {
			t.Fatalf("private code persisted in %s", entry.Name())
		}
	}
}

func TestPaddedPlaintextRejectsInvalidClassAndHeader(t *testing.T) {
	padded, err := padPlaintext([]byte("secret request"))
	if err != nil || len(padded) != paddedPlaintextSize {
		t.Fatalf("pad = %d, %v", len(padded), err)
	}
	opened, err := unpadPlaintext(padded)
	if err != nil || string(opened) != "secret request" {
		t.Fatalf("unpad = %q, %v", opened, err)
	}
	for _, mutate := range []func([]byte){
		func(value []byte) { value[0] ^= 1 },
		func(value []byte) { value[4] = 2 },
		func(value []byte) { value[5] = 1 },
		func(value []byte) { value[8], value[9], value[10], value[11] = 0xff, 0xff, 0xff, 0xff },
	} {
		changed := append([]byte(nil), padded...)
		mutate(changed)
		if _, err := unpadPlaintext(changed); err == nil {
			t.Fatal("invalid padded plaintext accepted")
		}
	}
	if _, err := unpadPlaintext(padded[:len(padded)-1]); err == nil {
		t.Fatal("wrong padded class size accepted")
	}
}

func TestPairingRejectsOriginCodeKeyAttemptExpiryAndUnknownFields(t *testing.T) {
	receiver, _, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	base := CreateRequestOptions{Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin, Now: now.Add(time.Minute), Validity: 5 * time.Minute}
	wrongOrigin := base
	wrongOrigin.RelayOrigin = "wss://other.example.com/connects"
	if _, err := CreateRequest(wrongOrigin); err == nil {
		t.Fatal("wrong relay origin accepted")
	}
	other, _, _ := newTestReceiver(t)
	otherAttempt, err := other.CreateAttempt(now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wrongCode := base
	wrongCode.Code = otherAttempt.Code
	if _, err := CreateRequest(wrongCode); err == nil {
		t.Fatal("code for another receiver accepted")
	}
	expired := base
	expired.Now = now.Add(11 * time.Minute)
	if _, err := CreateRequest(expired); err == nil {
		t.Fatal("expired attempt accepted")
	}
	unknown := append([]byte(nil), attempt.Advertisement[:len(attempt.Advertisement)-2]...)
	unknown = append(unknown, []byte(",\"unknown\":true}\n")...)
	withUnknown := base
	withUnknown.Advertisement = unknown
	if _, err := CreateRequest(withUnknown); err == nil {
		t.Fatal("unknown advertisement field accepted")
	}

	request, err := CreateRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), request.Encrypted...)
	tampered[len(tampered)/2] ^= 1
	called := false
	if _, err := receiver.Claim(tampered, now.Add(2*time.Minute), func(PeerRequest) ([]byte, error) {
		called = true
		return []byte("must-not-issue"), nil
	}); err == nil || called {
		t.Fatal("tampered request reached issuance")
	}

	competing, err := CreateRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	first, err := receiver.Claim(request.Encrypted, now.Add(2*time.Minute), staticIssuer("authorization"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Claim(competing.Encrypted, now.Add(2*time.Minute), staticIssuer("other")); err == nil {
		t.Fatal("second peer claimed a spent code")
	}
	wrongMaterial := request.Material
	wrongMaterial.pairingPrivate = competing.Material.pairingPrivate
	if _, err := OpenResponse(attempt.Advertisement, first.Response, wrongMaterial, testRelayOrigin, now.Add(3*time.Minute)); err == nil {
		t.Fatal("response opened under a different client key")
	}
}

func TestConcurrentClaimHasOneWinnerAndLocksDenyRenewal(t *testing.T) {
	receiver, _, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 20*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first, err := CreateRequest(CreateRequestOptions{Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin, Now: now.Add(time.Minute), Validity: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreateRequest(CreateRequestOptions{Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin, Now: now.Add(time.Minute), Validity: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	requests := [][]byte{first.Encrypted, second.Encrypted}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for _, request := range requests {
		wait.Add(1)
		go func(value []byte) {
			defer wait.Done()
			if _, claimErr := receiver.Claim(value, now.Add(2*time.Minute), staticIssuer("authorization")); claimErr == nil {
				successes.Add(1)
			}
		}(request)
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent winners = %d", successes.Load())
	}
	var winner ClientRequest
	for _, candidate := range []ClientRequest{first, second} {
		if candidate.Material.ClientID() == mustStatus(t, receiver).PairedClientID {
			winner = candidate
		}
	}
	claimed, err := receiver.Claim(winner.Encrypted, now.Add(3*time.Minute), staticIssuer("unused"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenResponse(attempt.Advertisement, claimed.Response, winner.Material, testRelayOrigin, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := CreateRenewal(opened.Pairing, testRelayOrigin, now.Add(4*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.SetPeerLocked(true); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Renew(renewal.Encrypted, now.Add(5*time.Minute), staticIssuer("renew")); err == nil {
		t.Fatal("locked peer renewed")
	}
	if _, err := receiver.SetPeerLocked(false); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.SetLocalLocked(true); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Renew(renewal.Encrypted, now.Add(5*time.Minute), staticIssuer("renew")); err == nil {
		t.Fatal("locally locked receiver renewed")
	}
	if _, err := receiver.SetLocalLocked(false); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.RevokePeer(); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Renew(renewal.Encrypted, now.Add(5*time.Minute), staticIssuer("renew")); err == nil {
		t.Fatal("revoked peer renewed")
	}
}

func TestReceiverRejectsSignedUnknownAndExpiredRequestBeforeIssuer(t *testing.T) {
	receiver, rootPath, now := newTestReceiver(t)
	attempt, err := receiver.CreateAttempt(now, 20*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := CreateRequest(CreateRequestOptions{
		Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin,
		Now: now.Add(time.Minute), Validity: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ageBytes, err := os.ReadFile(filepath.Join(rootPath, receiverAgeIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	receiverIdentity := strings.TrimSuffix(string(ageBytes), "\n")
	plaintext, err := openAge(request.Encrypted, requestCipherSchema, receiverIdentity, MaxRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	var envelope signedEnvelope
	if err := decodeCanonical(plaintext, MaxRequestSize, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := decodeBase64(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	unknownPayload := append([]byte(nil), payload[:len(payload)-1]...)
	unknownPayload = append(unknownPayload, []byte(",\"unknown\":true}")...)
	private, err := signing.ParsePrivate(request.Material.pairingPrivate)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signing.Sign(requestDomain, unknownPayload, private)
	if err != nil {
		t.Fatal(err)
	}
	unknownSigned, err := encodeCanonical(signedEnvelope{
		Schema: requestEnvelopeSchema, Payload: base64.StdEncoding.EncodeToString(unknownPayload),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, MaxRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	info, err := VerifyAdvertisement(attempt.Advertisement, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	unknownEncrypted, err := sealAge(requestCipherSchema, unknownSigned, info.ReceiverAgeRecipient, MaxRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err := receiver.Claim(unknownEncrypted, now.Add(2*time.Minute), func(PeerRequest) ([]byte, error) {
		called = true
		return []byte("authorization"), nil
	}); err == nil || called {
		t.Fatal("signed request with unknown field reached issuer")
	}

	expiring, err := CreateRequest(CreateRequestOptions{
		Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin,
		Now: now.Add(3 * time.Minute), Validity: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Claim(expiring.Encrypted, now.Add(3*time.Minute+2*time.Second), func(PeerRequest) ([]byte, error) {
		called = true
		return []byte("authorization"), nil
	}); err == nil || called {
		t.Fatal("expired request reached issuer")
	}
}

const testRelayOrigin = "wss://relay.example.com/connects"

func newTestReceiver(t *testing.T) (*Receiver, string, time.Time) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(base, "receiver")
	now := time.Now().UTC().Truncate(time.Second)
	relayCA, err := pki.NewCA("test relay", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayPin, err := identity.SPKIPin(relayCA.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(InitializeOptions{RootPath: rootPath, RelayOrigin: testRelayOrigin, RelayServerSPKI: relayPin, Now: now}); err != nil {
		t.Fatal(err)
	}
	receiver, err := Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	return receiver, rootPath, now
}

func staticIssuer(value string) IssueFunc {
	return func(PeerRequest) ([]byte, error) { return []byte(value), nil }
}

func mustStatus(t *testing.T, receiver *Receiver) ReceiverStatus {
	t.Helper()
	status, err := receiver.Status()
	if err != nil {
		t.Fatal(err)
	}
	return status
}
