package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ValidateLocalCertificate proves that a locally loaded key pair has the exact
// leaf profile expected by its OwnTransit role before any network connection is
// opened. When roots is non-nil it also proves the local chain to the explicitly
// installed issuer; nil exists only for backwards-compatible inspection of
// legacy v1 configurations that did not record their local issuer separately.
func ValidateLocalCertificate(pair tls.Certificate, roots *x509.CertPool, expectedDNSName string, requiredEKU x509.ExtKeyUsage, now time.Time) error {
	if err := validateCanonicalDNSName(expectedDNSName); err != nil {
		return fmt.Errorf("identity: invalid local DNS identity: %w", err)
	}
	if requiredEKU != x509.ExtKeyUsageClientAuth && requiredEKU != x509.ExtKeyUsageServerAuth {
		return errors.New("identity: local EKU must be exactly clientAuth or serverAuth")
	}
	if now.IsZero() {
		return errors.New("identity: local validation time is required")
	}
	if len(pair.Certificate) == 0 {
		return errors.New("identity: local key pair contains no certificate")
	}
	leaf := pair.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return fmt.Errorf("identity: parse local leaf: %w", err)
		}
		leaf = parsed
	}
	if len(leaf.Raw) == 0 || !bytes.Equal(leaf.Raw, pair.Certificate[0]) {
		return errors.New("identity: local parsed leaf does not match key-pair DER")
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return errors.New("identity: local leaf must be a non-CA certificate with valid basic constraints")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("identity: local leaf key usage is %v, want digital-signature only", leaf.KeyUsage)
	}
	if len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != requiredEKU {
		return fmt.Errorf("identity: local leaf must have exactly extended key usage %v", requiredEKU)
	}
	if err := verifyExactDNSSAN(leaf, expectedDNSName); err != nil {
		return err
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("identity: local leaf is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	if roots == nil {
		return nil
	}

	intermediates := x509.NewCertPool()
	for index, encoded := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil {
			return fmt.Errorf("identity: parse local intermediate %d: %w", index, err)
		}
		intermediates.AddCert(certificate)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       expectedDNSName,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{requiredEKU},
	})
	if err != nil {
		return fmt.Errorf("identity: verify local certificate chain: %w", err)
	}
	if len(chains) == 0 || len(chains[0]) == 0 || !bytes.Equal(chains[0][0].Raw, leaf.Raw) {
		return errors.New("identity: local certificate has no verified leaf-first chain")
	}
	return nil
}
