package identity

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestValidateLocalCertificateRequiresExactProfileAndChain(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, "client.owntransit.invalid", x509.ExtKeyUsageClientAuth, nil)
	pair, err := tls.X509KeyPair(credential.certPEM, credential.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(authority.cert)
	if err := ValidateLocalCertificate(pair, pool, "client.owntransit.invalid", x509.ExtKeyUsageClientAuth, time.Now()); err != nil {
		t.Fatalf("valid local certificate: %v", err)
	}

	for name, check := range map[string]func() error{
		"wrong name": func() error {
			return ValidateLocalCertificate(pair, pool, "other.owntransit.invalid", x509.ExtKeyUsageClientAuth, time.Now())
		},
		"wrong role": func() error {
			return ValidateLocalCertificate(pair, pool, "client.owntransit.invalid", x509.ExtKeyUsageServerAuth, time.Now())
		},
		"expired": func() error {
			return ValidateLocalCertificate(pair, pool, "client.owntransit.invalid", x509.ExtKeyUsageClientAuth, credential.cert.NotAfter.Add(time.Second))
		},
		"wrong issuer": func() error {
			wrong := x509.NewCertPool()
			wrong.AddCert(newTestAuthority(t).cert)
			return ValidateLocalCertificate(pair, wrong, "client.owntransit.invalid", x509.ExtKeyUsageClientAuth, time.Now())
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("invalid local certificate was accepted")
			}
		})
	}
}

func TestValidateLocalCertificateLegacyModeStillChecksLeaf(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, "server.owntransit.invalid", x509.ExtKeyUsageServerAuth, nil)
	pair, err := tls.X509KeyPair(credential.certPEM, credential.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocalCertificate(pair, nil, "server.owntransit.invalid", x509.ExtKeyUsageServerAuth, time.Now()); err != nil {
		t.Fatalf("legacy structural validation: %v", err)
	}
}
