// Package pki contains deliberately small, offline certificate-issuance
// primitives used by the POC provisioning command. It is not a network CA.
package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type Material struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	CertPEM     []byte
	KeyPEM      []byte
}

func NewCA(name string, now time.Time, validity time.Duration) (Material, error) {
	if name == "" || validity <= 0 {
		return Material{}, errors.New("pki: CA name and positive validity are required")
	}
	now = now.UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Material{}, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Material{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"OwnTransit offline issuer"}},
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              now.UTC().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          keyID(publicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return Material{}, fmt.Errorf("pki: create CA certificate: %w", err)
	}
	return encodeMaterial(der, privateKey)
}

func IssueLeaf(ca Material, dnsName string, usage x509.ExtKeyUsage, now time.Time, validity time.Duration) (Material, error) {
	if ca.Certificate == nil || ca.Signer == nil || !ca.Certificate.IsCA {
		return Material{}, errors.New("pki: valid issuer material is required")
	}
	if dnsName == "" || validity <= 0 {
		return Material{}, errors.New("pki: leaf DNS name and positive validity are required")
	}
	if usage != x509.ExtKeyUsageClientAuth && usage != x509.ExtKeyUsageServerAuth {
		return Material{}, errors.New("pki: leaf usage must be exactly clientAuth or serverAuth")
	}
	now = now.UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Material{}, fmt.Errorf("pki: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Material{}, err
	}
	notAfter := now.UTC().Add(validity)
	if notAfter.After(ca.Certificate.NotAfter) {
		return Material{}, errors.New("pki: requested leaf validity exceeds issuer validity")
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"OwnTransit development endpoint"}},
		DNSNames:              []string{dnsName},
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyID(publicKey),
		AuthorityKeyId:        append([]byte(nil), ca.Certificate.SubjectKeyId...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.Signer)
	if err != nil {
		return Material{}, fmt.Errorf("pki: create leaf certificate: %w", err)
	}
	return encodeMaterial(der, privateKey)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func keyID(publicKey []byte) []byte {
	digest := sha256.Sum256(publicKey)
	return append([]byte(nil), digest[:20]...)
}

func encodeMaterial(der []byte, signer crypto.Signer) (Material, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return Material{}, fmt.Errorf("pki: parse generated certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return Material{}, fmt.Errorf("pki: marshal private key: %w", err)
	}
	return Material{
		Certificate: certificate,
		Signer:      signer,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}
