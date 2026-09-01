package pki

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
)

var oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}

// CSRMaterial is created on an endpoint. KeyPEM and Signer never belong in an
// enrollment request or on the offline provisioner.
type CSRMaterial struct {
	Request *x509.CertificateRequest
	Signer  crypto.Signer
	CSRPEM  []byte
	KeyPEM  []byte
}

// IssuedCertificate contains only public leaf material. Issuing from a CSR
// deliberately gives the provisioner no endpoint private key.
type IssuedCertificate struct {
	Certificate *x509.Certificate
	CertPEM     []byte
}

func NewCSR(dnsName string) (CSRMaterial, error) {
	if err := identity.ValidateDNSName(dnsName); err != nil {
		return CSRMaterial{}, fmt.Errorf("pki: invalid CSR DNS identity: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CSRMaterial{}, fmt.Errorf("pki: generate endpoint key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{dnsName},
	}, privateKey)
	if err != nil {
		return CSRMaterial{}, fmt.Errorf("pki: create certificate request: %w", err)
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return CSRMaterial{}, fmt.Errorf("pki: parse generated certificate request: %w", err)
	}
	if err := ValidateCSR(request, dnsName); err != nil {
		return CSRMaterial{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return CSRMaterial{}, fmt.Errorf("pki: marshal endpoint key: %w", err)
	}
	return CSRMaterial{
		Request: request,
		Signer:  privateKey,
		CSRPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func ParseCSR(encoded []byte, expectedDNSName string) (*x509.CertificateRequest, error) {
	block, err := decodeExactPEM(encoded, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, err
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := ValidateCSR(request, expectedDNSName); err != nil {
		return nil, err
	}
	return request, nil
}

func ValidateCSR(request *x509.CertificateRequest, expectedDNSName string) error {
	if request == nil {
		return errors.New("pki: CSR is nil")
	}
	if err := identity.ValidateDNSName(expectedDNSName); err != nil {
		return fmt.Errorf("pki: invalid expected CSR DNS identity: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return fmt.Errorf("pki: CSR proof of possession failed: %w", err)
	}
	if request.SignatureAlgorithm != x509.PureEd25519 {
		return fmt.Errorf("pki: CSR signature algorithm is %v, want Ed25519", request.SignatureAlgorithm)
	}
	if _, ok := request.PublicKey.(ed25519.PublicKey); !ok {
		return errors.New("pki: CSR public key is not Ed25519")
	}
	if request.PublicKeyAlgorithm != x509.Ed25519 || !bytes.Equal(request.RawSubject, []byte{0x30, 0x00}) {
		return errors.New("pki: CSR must use Ed25519 and an empty subject")
	}
	if len(request.DNSNames) != 1 || request.DNSNames[0] != expectedDNSName ||
		len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 || len(request.URIs) != 0 {
		return fmt.Errorf("pki: CSR must contain only exact DNS SAN %q", expectedDNSName)
	}
	sanCount := 0
	for _, extension := range request.Extensions {
		if extension.Id.Equal(oidSubjectAlternativeName) {
			sanCount++
			continue
		}
		return fmt.Errorf("pki: CSR contains unsupported extension %s", extension.Id.String())
	}
	if sanCount != 1 {
		return fmt.Errorf("pki: CSR has %d subjectAltName extensions, want 1", sanCount)
	}
	return nil
}

func IssueCSR(ca Material, request *x509.CertificateRequest, dnsName string, usage x509.ExtKeyUsage, now time.Time, validity time.Duration) (IssuedCertificate, error) {
	if ca.Certificate == nil || ca.Signer == nil || !ca.Certificate.IsCA {
		return IssuedCertificate{}, errors.New("pki: valid issuer material is required")
	}
	if usage != x509.ExtKeyUsageClientAuth && usage != x509.ExtKeyUsageServerAuth {
		return IssuedCertificate{}, errors.New("pki: leaf usage must be exactly clientAuth or serverAuth")
	}
	if validity <= 0 {
		return IssuedCertificate{}, errors.New("pki: positive leaf validity is required")
	}
	if err := ValidateCSR(request, dnsName); err != nil {
		return IssuedCertificate{}, err
	}
	now = now.UTC().Truncate(time.Second)
	notAfter := now.Add(validity)
	if notAfter.After(ca.Certificate.NotAfter) {
		return IssuedCertificate{}, errors.New("pki: requested leaf validity exceeds issuer validity")
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"OwnTransit endpoint"}},
		DNSNames:              []string{dnsName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyID(request.RawSubjectPublicKeyInfo),
		AuthorityKeyId:        append([]byte(nil), ca.Certificate.SubjectKeyId...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, request.PublicKey, ca.Signer)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("pki: issue CSR leaf: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("pki: parse issued CSR leaf: %w", err)
	}
	return IssuedCertificate{
		Certificate: certificate,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}
