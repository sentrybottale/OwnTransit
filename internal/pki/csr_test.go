package pki

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"
)

func TestCSRLeafIssuanceNeverTransfersEndpointPrivateKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer, err := NewCA("OwnTransit test issuer", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requestMaterial, err := NewCSR("client.owntransit.invalid")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCSR(requestMaterial.CSRPEM, "client.owntransit.invalid")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := IssueCSR(issuer, parsed, "client.owntransit.invalid", x509.ExtKeyUsageClientAuth, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Certificate == nil || len(issued.CertPEM) == 0 {
		t.Fatal("issuer returned no public leaf material")
	}
	if !bytes.Equal(issued.Certificate.RawSubjectPublicKeyInfo, parsed.RawSubjectPublicKeyInfo) {
		t.Fatal("issued leaf does not contain the target-generated CSR key")
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer.Certificate)
	if _, err := issued.Certificate.Verify(x509.VerifyOptions{
		DNSName:     "client.owntransit.invalid",
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify issued leaf: %v", err)
	}
}

func TestCSRValidationRejectsWrongIdentityAndTrailingData(t *testing.T) {
	requestMaterial, err := NewCSR("client.owntransit.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCSR(requestMaterial.CSRPEM, "other.owntransit.invalid"); err == nil {
		t.Fatal("CSR was accepted for another identity")
	}
	withTrailing := append(append([]byte(nil), requestMaterial.CSRPEM...), []byte("junk")...)
	if _, err := ParseCSR(withTrailing, "client.owntransit.invalid"); err == nil {
		t.Fatal("CSR with trailing data was accepted")
	}
}
