package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

var oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}

// PeerProfile defines the exact certificate and TLS properties accepted for a
// peer. ExpectedServerName is optional; when non-empty it is matched exactly
// against ConnectionState.ServerName, which lets a TLS server require its own
// canonical SNI while independently authenticating the client's DNS identity.
type PeerProfile struct {
	ExpectedDNSName    string
	ExpectedServerName string
	RequiredEKU        x509.ExtKeyUsage
	ALPN               string
	AllowedSPKIs       PinSet
}

// VerifyConnection performs OwnTransit's strict post-verification peer checks.
// It is directly usable as tls.Config.VerifyConnection. Normal x509 verification
// must have succeeded: this method requires a non-empty verified chain and never
// substitutes pinning for chain validation.
func (profile PeerProfile) VerifyConnection(state tls.ConnectionState) error {
	if err := profile.validate(); err != nil {
		return fmt.Errorf("identity: invalid peer profile: %w", err)
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("identity: TLS version 0x%04x is not TLS 1.3", state.Version)
	}
	if state.DidResume {
		return errors.New("identity: resumed TLS sessions are forbidden")
	}
	if state.NegotiatedProtocol != profile.ALPN {
		return fmt.Errorf("identity: negotiated ALPN %q, want %q", state.NegotiatedProtocol, profile.ALPN)
	}
	if profile.ExpectedServerName != "" && state.ServerName != profile.ExpectedServerName {
		return fmt.Errorf("identity: received SNI %q, want %q", state.ServerName, profile.ExpectedServerName)
	}
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return errors.New("identity: peer did not present a leaf certificate")
	}
	if len(state.VerifiedChains) == 0 {
		return errors.New("identity: peer has no normally verified certificate chain")
	}

	leaf := state.PeerCertificates[0]
	if len(leaf.Raw) == 0 {
		return errors.New("identity: peer leaf has no DER encoding")
	}
	for i, chain := range state.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil {
			return fmt.Errorf("identity: verified chain %d has no leaf", i)
		}
		if !bytes.Equal(chain[0].Raw, leaf.Raw) {
			return fmt.Errorf("identity: verified chain %d does not begin with the peer leaf", i)
		}
	}

	if !leaf.BasicConstraintsValid {
		return errors.New("identity: peer leaf has no valid basic constraints")
	}
	if leaf.IsCA {
		return errors.New("identity: peer leaf is a CA certificate")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("identity: peer leaf key usage is %v, want digital-signature only", leaf.KeyUsage)
	}
	if len(leaf.UnknownExtKeyUsage) != 0 {
		return errors.New("identity: peer leaf has an unknown extended key usage")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != profile.RequiredEKU {
		return fmt.Errorf("identity: peer leaf must have exactly the required extended key usage %v", profile.RequiredEKU)
	}
	if err := verifyExactDNSSAN(leaf, profile.ExpectedDNSName); err != nil {
		return err
	}

	hash, err := HashSPKI(leaf)
	if err != nil {
		return err
	}
	if !profile.AllowedSPKIs.Contains(hash) {
		return fmt.Errorf("identity: peer SPKI %q is not locally authorized", FormatSPKIPin(hash))
	}
	return nil
}

func (profile PeerProfile) validate() error {
	if err := validateCanonicalDNSName(profile.ExpectedDNSName); err != nil {
		return fmt.Errorf("expected peer DNS name: %w", err)
	}
	if profile.ExpectedServerName != "" {
		if err := validateCanonicalDNSName(profile.ExpectedServerName); err != nil {
			return fmt.Errorf("expected server name: %w", err)
		}
	}
	if profile.RequiredEKU != x509.ExtKeyUsageClientAuth && profile.RequiredEKU != x509.ExtKeyUsageServerAuth {
		return errors.New("required EKU must be exactly clientAuth or serverAuth")
	}
	if profile.ALPN == "" {
		return errors.New("ALPN is empty")
	}
	if len(profile.AllowedSPKIs) == 0 {
		return errors.New("SPKI allowlist is empty")
	}
	return nil
}

func verifyExactDNSSAN(cert *x509.Certificate, expected string) error {
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != expected {
		return fmt.Errorf("identity: peer leaf must contain exactly DNS SAN %q", expected)
	}
	if len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 0 {
		return errors.New("identity: peer leaf contains a non-DNS SAN")
	}

	var sanValue []byte
	count := 0
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidSubjectAlternativeName) {
			count++
			sanValue = extension.Value
		}
	}
	if count != 1 {
		return fmt.Errorf("identity: peer leaf has %d subjectAltName extensions, want 1", count)
	}

	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(sanValue, &names)
	if err != nil || len(rest) != 0 {
		return errors.New("identity: peer leaf has a malformed subjectAltName extension")
	}
	if len(names) != 1 {
		return errors.New("identity: peer leaf subjectAltName must contain exactly one GeneralName")
	}
	name := names[0]
	if name.Class != asn1.ClassContextSpecific || name.Tag != 2 || name.IsCompound {
		return errors.New("identity: peer leaf contains an unsupported subjectAltName profile")
	}
	if string(name.Bytes) != expected {
		return fmt.Errorf("identity: raw DNS SAN %q, want %q", string(name.Bytes), expected)
	}
	return nil
}

func validateCanonicalDNSName(name string) error {
	if name == "" {
		return errors.New("name is empty")
	}
	if len(name) > 253 {
		return errors.New("name exceeds 253 bytes")
	}
	if name != strings.ToLower(name) {
		return errors.New("name must be lowercase")
	}
	if strings.HasSuffix(name, ".") {
		return errors.New("name must not have a trailing dot")
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("name contains an empty or oversized label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("name label begins or ends with a hyphen")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return errors.New("name contains a non-canonical character")
			}
		}
	}
	return nil
}

// ValidateDNSName applies OwnTransit's canonical literal DNS-identity profile
// to enrollment and configuration tooling.
func ValidateDNSName(name string) error {
	return validateCanonicalDNSName(name)
}
