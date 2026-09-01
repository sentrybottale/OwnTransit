// Package signing provides strict Ed25519 key encoding and domain-separated
// exact-byte signatures for offline OwnTransit release/deployment records.
package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	maximumSignatureDomainSize  = 255
	maximumSignaturePayloadSize = 8 * 1024 * 1024
)

type KeyPair struct {
	Public     ed25519.PublicKey
	Private    ed25519.PrivateKey
	PublicPEM  []byte
	PrivatePEM []byte
	KeyID      string
}

func Generate() (KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing: generate Ed25519 key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing: marshal public key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing: marshal private key: %w", err)
	}
	return KeyPair{
		Public:     publicKey,
		Private:    privateKey,
		PublicPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		KeyID:      KeyID(publicKey),
	}, nil
}

func ParsePublic(encoded []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(encoded, pem.EncodeToMemory(block)) {
		return nil, errors.New("signing: public key must be one headerless PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing: public key is not Ed25519")
	}
	return publicKey, nil
}

func ParsePrivate(encoded []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(encoded, pem.EncodeToMemory(block)) {
		return nil, errors.New("signing: private key must be one headerless PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing: private key is not Ed25519")
	}
	return privateKey, nil
}

func KeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256/" + base64.StdEncoding.EncodeToString(digest[:])
}

// ValidateKeyID accepts only the canonical identifier emitted by KeyID.
func ValidateKeyID(value string) error {
	const prefix = "sha256/"
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return fmt.Errorf("signing: key ID must start with %q", prefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(value[len(prefix):])
	if err != nil || len(decoded) != sha256.Size || prefix+base64.StdEncoding.EncodeToString(decoded) != value {
		return errors.New("signing: key ID is not a canonical SHA-256 digest")
	}
	return nil
}

func Sign(domain string, payload []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if domain == "" || len(domain) > maximumSignatureDomainSize || strings.ContainsRune(domain, '\x00') ||
		len(payload) == 0 || len(payload) > maximumSignaturePayloadSize || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("signing: domain, payload, and Ed25519 private key are required")
	}
	message, err := signatureInput(domain, payload)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privateKey, message), nil
}

func Verify(domain string, payload, signature []byte, publicKey ed25519.PublicKey) error {
	if domain == "" || len(domain) > maximumSignatureDomainSize || strings.ContainsRune(domain, '\x00') ||
		len(payload) == 0 || len(payload) > maximumSignaturePayloadSize || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("signing: invalid verification input")
	}
	message, err := signatureInput(domain, payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("signing: signature verification failed")
	}
	return nil
}

func signatureInput(domain string, payload []byte) ([]byte, error) {
	size, err := signatureInputSize(len(domain), len(payload))
	if err != nil {
		return nil, err
	}
	result := make([]byte, size)
	domainEnd := copy(result, domain)
	result[domainEnd] = 0
	copy(result[domainEnd+1:], payload)
	return result, nil
}

func signatureInputSize(domainLength, payloadLength int) (int, error) {
	if domainLength < 0 || payloadLength < 0 {
		return 0, errors.New("signing: signature input length is invalid")
	}
	maximumInt := int(^uint(0) >> 1)
	if domainLength > maximumInt-payloadLength-1 {
		return 0, errors.New("signing: signature input exceeds the platform limit")
	}
	return domainLength + 1 + payloadLength, nil
}
