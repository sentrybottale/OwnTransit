package pki

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssuerRoundTripAndPrivateFilePolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	generated, err := NewCA("OwnTransit test issuer", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseIssuer(generated.CertPEM, generated.KeyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Certificate.SerialNumber.Cmp(generated.Certificate.SerialNumber) != 0 {
		t.Fatal("parsed issuer changed certificate")
	}

	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "issuer-cert.pem")
	keyPath := filepath.Join(directory, "issuer-key.pem")
	if err := os.WriteFile(certificatePath, generated.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, generated.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIssuer(certificatePath, keyPath, now); err != nil {
		t.Fatalf("load issuer: %v", err)
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIssuer(certificatePath, keyPath, now); err == nil {
		t.Fatal("group-readable issuer key was accepted")
	}
}
