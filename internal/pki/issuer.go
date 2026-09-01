package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const maxIssuerFileSize = 64 << 10

// LoadIssuer loads one offline CA certificate and matching Ed25519 private key
// from strict regular files. It never creates or rotates issuer material.
func LoadIssuer(certPath, keyPath string, now time.Time) (Material, error) {
	certificatePEM, err := readBoundedRegular(certPath, false)
	if err != nil {
		return Material{}, err
	}
	keyPEM, err := readBoundedRegular(keyPath, true)
	if err != nil {
		return Material{}, err
	}
	return ParseIssuer(certificatePEM, keyPEM, now)
}

func ParseIssuer(certificatePEM, keyPEM []byte, now time.Time) (Material, error) {
	certificateBlock, err := decodeExactPEM(certificatePEM, "CERTIFICATE")
	if err != nil {
		return Material{}, err
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return Material{}, fmt.Errorf("pki: parse issuer certificate: %w", err)
	}
	if now.IsZero() || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return Material{}, errors.New("pki: issuer certificate is not currently valid")
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 {
		return Material{}, errors.New("pki: issuer certificate is not a path-length-zero CA")
	}
	if certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(certificate.ExtKeyUsage) != 0 || len(certificate.UnknownExtKeyUsage) != 0 {
		return Material{}, errors.New("pki: issuer certificate has an unexpected key-usage profile")
	}
	if certificate.SignatureAlgorithm != x509.PureEd25519 {
		return Material{}, errors.New("pki: issuer certificate is not signed with Ed25519")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return Material{}, fmt.Errorf("pki: issuer certificate is not a self-signed root: %w", err)
	}

	keyBlock, err := decodeExactPEM(keyPEM, "PRIVATE KEY")
	if err != nil {
		return Material{}, err
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return Material{}, fmt.Errorf("pki: parse issuer private key: %w", err)
	}
	signer, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return Material{}, errors.New("pki: issuer private key is not Ed25519")
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !publicKey.Equal(signer.Public()) {
		return Material{}, errors.New("pki: issuer private key does not match certificate")
	}
	return Material{
		Certificate: certificate,
		Signer:      crypto.Signer(signer),
		CertPEM:     append([]byte(nil), certificatePEM...),
		KeyPEM:      append([]byte(nil), keyPEM...),
	}, nil
}

func readBoundedRegular(path string, private bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("pki: issuer path is empty")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("pki: open issuer file %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("pki: inspect opened issuer file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxIssuerFileSize {
		return nil, fmt.Errorf("pki: issuer file %q must be a bounded regular non-symlink file", path)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("pki: issuer private key %q has group/world permissions", path)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxIssuerFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("pki: read issuer file %q: %w", path, err)
	}
	if len(contents) < 1 || len(contents) > maxIssuerFileSize {
		return nil, fmt.Errorf("pki: issuer file %q changed size while being read", path)
	}
	return contents, nil
}
