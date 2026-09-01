package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

const certificatePinPrefix = "sha256/"

// CertificatePin identifies one exact DER certificate. Enrollment uses exact
// certificate pins—not roots supplied by the response itself—so compromise of
// the deployment signer cannot silently replace an offline issuer.
func CertificatePin(certificate *x509.Certificate) (string, error) {
	if certificate == nil || len(certificate.Raw) == 0 {
		return "", errors.New("pki: cannot pin an empty certificate")
	}
	digest := sha256.Sum256(certificate.Raw)
	return certificatePinPrefix + base64.StdEncoding.EncodeToString(digest[:]), nil
}

// ParseCertificatePin rejects alternative encodings so signed enrollment
// records have one representation for an issuer certificate identity.
func ParseCertificatePin(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) <= len(certificatePinPrefix) || value[:len(certificatePinPrefix)] != certificatePinPrefix {
		return result, fmt.Errorf("pki: certificate pin must start with %q", certificatePinPrefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(value[len(certificatePinPrefix):])
	if err != nil || len(decoded) != sha256.Size {
		return result, errors.New("pki: certificate pin is not a SHA-256 digest")
	}
	copy(result[:], decoded)
	if certificatePinPrefix+base64.StdEncoding.EncodeToString(result[:]) != value {
		return [sha256.Size]byte{}, errors.New("pki: certificate pin is not canonical")
	}
	return result, nil
}
