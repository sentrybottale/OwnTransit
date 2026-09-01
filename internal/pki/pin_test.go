package pki

import (
	"strings"
	"testing"
	"time"
)

func TestCertificatePinIsExactAndCanonical(t *testing.T) {
	issuer, err := NewCA("OwnTransit pin test", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := CertificatePin(issuer.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificatePin(pin); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificatePin(strings.TrimSuffix(pin, "=")); err == nil {
		t.Fatal("unpadded certificate pin was accepted")
	}
}
