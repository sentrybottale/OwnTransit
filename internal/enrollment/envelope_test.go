package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestResponseEnvelopeIsTargetEncryptedAndOfflineSigned(t *testing.T) {
	identity, recipient, err := GenerateResponseIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"schema":"owntransit.test.v1","secret":"not visible"}`)
	envelope, err := SealResponse(payload, recipient, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(envelope) == string(payload) {
		t.Fatal("response envelope exposed plaintext")
	}
	opened, err := OpenResponse(envelope, identity, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(payload) {
		t.Fatalf("opened payload = %q, want %q", opened, payload)
	}
}

func TestResponseEnvelopeRejectsWrongSignerRecipientAndTampering(t *testing.T) {
	identity, recipient, err := GenerateResponseIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealResponse([]byte("payload"), recipient, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenResponse(envelope, identity, wrongPublic); err == nil {
		t.Fatal("response was accepted from the wrong signer")
	}
	wrongIdentity, _, err := GenerateResponseIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenResponse(envelope, wrongIdentity, publicKey); err == nil {
		t.Fatal("response was decrypted by the wrong target")
	}
	tampered := append([]byte(nil), envelope...)
	for index := range tampered {
		if tampered[index] >= 'A' && tampered[index] <= 'Z' {
			tampered[index] = 'a'
			break
		}
	}
	if _, err := OpenResponse(tampered, identity, publicKey); err == nil {
		t.Fatal("tampered response envelope was accepted")
	}
}
