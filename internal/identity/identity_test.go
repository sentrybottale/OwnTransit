package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadKeyPair(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, "peer.owntransit.invalid", x509.ExtKeyUsageServerAuth, nil)
	directory := t.TempDir()
	certPath := filepath.Join(directory, "leaf.pem")
	keyPath := filepath.Join(directory, "leaf.key")
	if err := os.WriteFile(certPath, credential.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, credential.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	pair, err := LoadKeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadKeyPair: %v", err)
	}
	if pair.Leaf == nil {
		t.Fatal("LoadKeyPair did not retain the parsed leaf")
	}
	if got, want := pair.Leaf.SerialNumber.String(), credential.cert.SerialNumber.String(); got != want {
		t.Fatalf("leaf serial = %s, want %s", got, want)
	}

	if _, err := LoadKeyPair("", keyPath); err == nil {
		t.Fatal("LoadKeyPair accepted an empty certificate path")
	}
	if _, err := LoadKeyPair(certPath, ""); err == nil {
		t.Fatal("LoadKeyPair accepted an empty key path")
	}

	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(certPath, keyPath); err == nil {
		t.Fatal("LoadKeyPair accepted a group-readable private key")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(directory, "leaf-symlink.key")
	if err := os.Symlink(keyPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(certPath, symlinkPath); err == nil {
		t.Fatal("LoadKeyPair accepted a private-key symlink")
	}
}

func TestLoadCertPool(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, "peer.owntransit.invalid", x509.ExtKeyUsageServerAuth, nil)
	directory := t.TempDir()
	poolPath := filepath.Join(directory, "roots.pem")
	contents := append(append([]byte(nil), authority.pem...), credential.certPEM...)
	if err := os.WriteFile(poolPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	pool, err := LoadCertPool(poolPath)
	if err != nil {
		t.Fatalf("LoadCertPool: %v", err)
	}
	if got := len(pool.Subjects()); got != 2 {
		t.Fatalf("pool contains %d certificates, want 2", got)
	}

	tests := map[string][]byte{
		"empty":       nil,
		"whitespace":  []byte(" \n\t"),
		"junk":        []byte("not a certificate"),
		"trailing":    append(append([]byte(nil), authority.pem...), []byte("junk")...),
		"private key": credential.keyPEM,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "roots.pem")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCertPool(path); err == nil {
				t.Fatal("LoadCertPool accepted invalid input")
			}
		})
	}
}

func TestSPKIPinRoundTrip(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, "peer.owntransit.invalid", x509.ExtKeyUsageServerAuth, nil)

	hash, err := HashSPKI(credential.cert)
	if err != nil {
		t.Fatalf("HashSPKI: %v", err)
	}
	wantHash := sha256.Sum256(credential.cert.RawSubjectPublicKeyInfo)
	if hash != SPKIHash(wantHash) {
		t.Fatal("HashSPKI hashed something other than RawSubjectPublicKeyInfo")
	}

	pin, err := SPKIPin(credential.cert)
	if err != nil {
		t.Fatalf("SPKIPin: %v", err)
	}
	wantPin := "sha256/" + base64.StdEncoding.EncodeToString(wantHash[:])
	if pin != wantPin {
		t.Fatalf("SPKIPin = %q, want %q", pin, wantPin)
	}
	parsed, err := ParseSPKIPin(pin)
	if err != nil {
		t.Fatalf("ParseSPKIPin: %v", err)
	}
	if parsed != hash {
		t.Fatal("pin round trip changed the hash")
	}

	set, err := ParsePinAllowlist([]string{pin})
	if err != nil {
		t.Fatalf("ParsePinAllowlist: %v", err)
	}
	if !set.Contains(hash) {
		t.Fatal("parsed allowlist does not contain its pin")
	}
}

func TestSPKIPinRejectsNonCanonicalInput(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, "peer.owntransit.invalid", x509.ExtKeyUsageServerAuth, nil)
	pin, err := SPKIPin(credential.cert)
	if err != nil {
		t.Fatal(err)
	}

	invalid := []string{
		"",
		"sha256/",
		"SHA256/" + strings.TrimPrefix(pin, "sha256/"),
		strings.TrimSuffix(pin, "="),
		" " + pin,
		pin + " ",
		"sha256/AA==",
	}
	for _, candidate := range invalid {
		if _, err := ParseSPKIPin(candidate); err == nil {
			t.Errorf("ParseSPKIPin accepted %q", candidate)
		}
	}
	if _, err := ParsePinAllowlist(nil); err == nil {
		t.Fatal("ParsePinAllowlist accepted an empty list")
	}
	if _, err := ParsePinAllowlist([]string{pin, pin}); err == nil {
		t.Fatal("ParsePinAllowlist accepted a duplicate")
	}
	if _, err := HashSPKI(nil); err == nil {
		t.Fatal("HashSPKI accepted a nil certificate")
	}
	if _, err := HashSPKI(&x509.Certificate{}); err == nil {
		t.Fatal("HashSPKI accepted a certificate without SPKI DER")
	}
}
