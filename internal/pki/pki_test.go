package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestIssueExactLeafProfile(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	issuer, err := NewCA("test issuer", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := IssueLeaf(issuer, "fg-test.client.owntransit.invalid", x509.ExtKeyUsageClientAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := leaf.Certificate
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatal("leaf has invalid CA constraints")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("key usage = %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU = %v", cert.ExtKeyUsage)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "fg-test.client.owntransit.invalid" {
		t.Fatalf("DNS names = %v", cert.DNSNames)
	}
	if cert.Subject.CommonName != "" {
		t.Fatalf("leaf common name unexpectedly set to %q", cert.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer.Certificate)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: cert.DNSNames[0], KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("verify generated leaf: %v", err)
	}
}

func TestRejectsInvalidUsageAndIssuerOverrun(t *testing.T) {
	now := time.Now()
	issuer, err := NewCA("test issuer", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueLeaf(issuer, "test.invalid", x509.ExtKeyUsageAny, now, time.Minute); err == nil {
		t.Fatal("accepted any-EKU leaf")
	}
	if _, err := IssueLeaf(issuer, "test.invalid", x509.ExtKeyUsageServerAuth, now, 2*time.Hour); err == nil {
		t.Fatal("accepted leaf validity beyond issuer")
	}
}
