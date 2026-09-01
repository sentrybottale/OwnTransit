// Package enrollment implements OwnTransit's offline, target-bound enrollment
// request and response formats. It has no network client or server.
package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	ResponseSchema  = "owntransit.enrollment.response-envelope.v1"
	MaxPayloadSize  = 1 << 20
	MaxEnvelopeSize = 2 << 20
)

var responseSignatureDomain = []byte("OwnTransit enrollment response envelope v1\x00")

type responseEnvelope struct {
	Schema      string `json:"schema"`
	SignerKeyID string `json:"signer_key_id"`
	Ciphertext  string `json:"ciphertext"`
	Signature   string `json:"signature"`
}

// GenerateResponseIdentity creates a dedicated age X25519 key pair. The
// identity remains on the requesting target; only the recipient string enters
// the signed enrollment request.
func GenerateResponseIdentity() (identity, recipient string, err error) {
	value, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("enrollment: generate response identity: %w", err)
	}
	return value.String(), value.Recipient().String(), nil
}

// SealResponse encrypts exact payload bytes to one target and authenticates
// the resulting age file with a distinct offline Ed25519 deployment signer.
func SealResponse(payload []byte, recipientText string, signer ed25519.PrivateKey) ([]byte, error) {
	if len(payload) == 0 || len(payload) > MaxPayloadSize {
		return nil, fmt.Errorf("enrollment: response payload size must be within 1..%d bytes", MaxPayloadSize)
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("enrollment: Ed25519 deployment signing key is required")
	}
	recipient, err := age.ParseX25519Recipient(recipientText)
	if err != nil || recipient.String() != recipientText {
		return nil, errors.New("enrollment: response recipient is not a canonical age X25519 recipient")
	}

	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, fmt.Errorf("enrollment: initialize response encryption: %w", err)
	}
	if _, err := writer.Write(payload); err != nil {
		return nil, fmt.Errorf("enrollment: encrypt response: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("enrollment: finalize response encryption: %w", err)
	}
	if ciphertext.Len() > MaxEnvelopeSize {
		return nil, errors.New("enrollment: encrypted response exceeds envelope limit")
	}

	signatureInput := append(append([]byte(nil), responseSignatureDomain...), ciphertext.Bytes()...)
	signature := ed25519.Sign(signer, signatureInput)
	encoded, err := json.Marshal(responseEnvelope{
		Schema:      ResponseSchema,
		SignerKeyID: signing.KeyID(signer.Public().(ed25519.PublicKey)),
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext.Bytes()),
		Signature:   base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment: encode response envelope: %w", err)
	}
	if len(encoded) > MaxEnvelopeSize {
		return nil, errors.New("enrollment: encoded response exceeds envelope limit")
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxEnvelopeSize {
		return nil, errors.New("enrollment: encoded response exceeds envelope limit")
	}
	return encoded, nil
}

// OpenResponse verifies the offline signer before attempting target-only age
// decryption, then returns the exact signed plaintext bytes.
func OpenResponse(encoded []byte, identityText string, signer ed25519.PublicKey) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxEnvelopeSize {
		return nil, fmt.Errorf("enrollment: response envelope size must be within 1..%d bytes", MaxEnvelopeSize)
	}
	if len(signer) != ed25519.PublicKeySize {
		return nil, errors.New("enrollment: Ed25519 deployment verification key is required")
	}
	var envelope responseEnvelope
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return nil, fmt.Errorf("enrollment: decode response envelope: %w", err)
	}
	if envelope.Schema != ResponseSchema {
		return nil, errors.New("enrollment: unsupported response envelope schema")
	}
	if envelope.SignerKeyID != signing.KeyID(signer) {
		return nil, errors.New("enrollment: response signer key ID does not match pinned verifier")
	}
	ciphertext, err := decodeCanonicalBase64(envelope.Ciphertext, "ciphertext")
	if err != nil {
		return nil, err
	}
	signature, err := decodeCanonicalBase64(envelope.Signature, "signature")
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("enrollment: response signature has the wrong size")
	}
	signatureInput := append(append([]byte(nil), responseSignatureDomain...), ciphertext...)
	if !ed25519.Verify(signer, signatureInput, signature) {
		return nil, errors.New("enrollment: response signature verification failed")
	}

	identity, err := age.ParseX25519Identity(identityText)
	if err != nil || identity.String() != identityText {
		return nil, errors.New("enrollment: response identity is not a canonical age X25519 identity")
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("enrollment: decrypt response: %w", err)
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxPayloadSize+1))
	if err != nil {
		return nil, fmt.Errorf("enrollment: read decrypted response: %w", err)
	}
	if len(payload) == 0 || len(payload) > MaxPayloadSize {
		return nil, errors.New("enrollment: decrypted response has an invalid size")
	}
	return payload, nil
}

func decodeCanonicalBase64(value, field string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("enrollment: %s is not canonical padded base64", field)
	}
	return decoded, nil
}
