package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type testAuthority struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

type testCredential struct {
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
}

func newTestAuthority(t *testing.T) testAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OwnTransit test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return testAuthority{
		cert: cert,
		key:  privateKey,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func newTestCredential(t *testing.T, authority testAuthority, dnsName string, eku x509.ExtKeyUsage, modify func(*x509.Certificate)) testCredential {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ignored-common-name"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		DNSNames:              []string{dnsName},
	}
	if modify != nil {
		modify(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.cert, publicKey, authority.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal leaf private key: %v", err)
	}
	return testCredential{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func cloneCertificate(cert *x509.Certificate) *x509.Certificate {
	clone := *cert
	clone.Raw = append([]byte(nil), cert.Raw...)
	clone.RawSubjectPublicKeyInfo = append([]byte(nil), cert.RawSubjectPublicKeyInfo...)
	clone.DNSNames = append([]string(nil), cert.DNSNames...)
	clone.EmailAddresses = append([]string(nil), cert.EmailAddresses...)
	clone.IPAddresses = append(clone.IPAddresses[:0:0], cert.IPAddresses...)
	clone.URIs = append(clone.URIs[:0:0], cert.URIs...)
	clone.ExtKeyUsage = append([]x509.ExtKeyUsage(nil), cert.ExtKeyUsage...)
	clone.UnknownExtKeyUsage = append([]asn1.ObjectIdentifier(nil), cert.UnknownExtKeyUsage...)
	clone.Extensions = append([]pkix.Extension(nil), cert.Extensions...)
	for i := range clone.Extensions {
		clone.Extensions[i].Value = append([]byte(nil), cert.Extensions[i].Value...)
	}
	return &clone
}
