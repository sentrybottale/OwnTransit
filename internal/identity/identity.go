// Package identity contains OwnTransit's certificate-loading and peer-identity
// primitives. It intentionally does not construct tls.Config values: callers
// must explicitly provide the appropriate private roots and normal TLS
// verification settings for each trust domain.
package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const (
	spkiPinPrefix       = "sha256/"
	maxIdentityFileSize = 1 << 20
)

// SPKIHash is the SHA-256 digest of a certificate's DER-encoded
// SubjectPublicKeyInfo.
type SPKIHash [sha256.Size]byte

// PinSet is a non-ordered set of authorized SPKI hashes. A nil or empty set is
// deliberately invalid for a PeerProfile.
type PinSet map[SPKIHash]struct{}

// LoadKeyPair loads a PEM certificate chain and matching private key from the
// two named files. The parsed leaf is retained in Certificate.Leaf.
func LoadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == "" {
		return tls.Certificate{}, errors.New("identity: certificate file is empty")
	}
	if keyFile == "" {
		return tls.Certificate{}, errors.New("identity: private-key file is empty")
	}
	certificatePEM, err := readRegularFile(certFile, maxIdentityFileSize, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateKeyPEM, err := readRegularFile(keyFile, maxIdentityFileSize, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	return ParseKeyPair(certificatePEM, privateKeyPEM)
}

// ParseKeyPair parses bounded certificate and private-key bytes that were
// already read from an authenticated, descriptor-pinned runtime generation.
// Callers loading ordinary path-based configuration must use LoadKeyPair so
// the filesystem mode and link checks are not bypassed.
func ParseKeyPair(certificatePEM, privateKeyPEM []byte) (tls.Certificate, error) {
	if len(certificatePEM) < 1 || len(certificatePEM) > maxIdentityFileSize ||
		len(privateKeyPEM) < 1 || len(privateKeyPEM) > maxIdentityFileSize {
		return tls.Certificate{}, errors.New("identity: bounded certificate and private-key material are required")
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("identity: load key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return tls.Certificate{}, errors.New("identity: key pair contains no certificates")
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("identity: parse key-pair leaf: %w", err)
	}
	pair.Leaf = leaf
	return pair, nil
}

// LoadCertPool loads only certificates present in path into a fresh pool. It
// never consults the operating system's root store. Empty files, non-certificate
// PEM blocks, trailing data, and malformed certificates are rejected.
func LoadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("identity: certificate-pool file is empty")
	}

	contents, err := readRegularFile(path, maxIdentityFileSize, false)
	if err != nil {
		return nil, fmt.Errorf("identity: read certificate pool %q: %w", path, err)
	}
	return parseCertPool(contents, fmt.Sprintf("certificate pool %q", path))
}

// ParseCertPool parses bounded certificate bytes already authenticated by a
// held runtime-generation descriptor. It never consults system roots.
func ParseCertPool(contents []byte) (*x509.CertPool, error) {
	if len(contents) < 1 || len(contents) > maxIdentityFileSize {
		return nil, errors.New("identity: bounded certificate-pool material is required")
	}
	return parseCertPool(contents, "certificate-pool material")
}

func parseCertPool(contents []byte, label string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remaining := contents
	count := 0
	for {
		remaining = bytes.TrimSpace(remaining)
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("identity: %s contains non-PEM data", label)
		}

		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, fmt.Errorf("identity: %s contains malformed PEM", label)
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("identity: %s contains PEM block %q", label, block.Type)
		}
		if len(block.Headers) != 0 {
			return nil, fmt.Errorf("identity: %s contains a certificate with PEM headers", label)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: parse %s: %w", label, err)
		}
		pool.AddCert(cert)
		count++
		remaining = rest
	}

	if count == 0 {
		return nil, fmt.Errorf("identity: %s is empty", label)
	}
	return pool, nil
}

// readRegularFile performs one no-follow open and keeps that descriptor
// through inspection and bounded reading. This avoids the Lstat/open race that
// would otherwise let a path swap redirect credential loading.
func readRegularFile(path string, limit int64, private bool) ([]byte, error) {
	if path == "" || limit <= 0 {
		return nil, errors.New("identity: path and positive read bound are required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("identity: open credential file %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("identity: open credential file %q: invalid descriptor", path)
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, fmt.Errorf("identity: inspect credential file %q: %w", path, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 1 || before.Size > limit {
		return nil, fmt.Errorf("identity: credential file %q must be a bounded single-link regular file", path)
	}
	if private && os.FileMode(before.Mode).Perm()&0o077 != 0 {
		return nil, fmt.Errorf("identity: private-key file %q has group/world permissions", path)
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("identity: read credential file %q: %w", path, err)
	}
	if len(contents) < 1 || int64(len(contents)) > limit {
		return nil, fmt.Errorf("identity: credential file %q changed size while being read", path)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, fmt.Errorf("identity: reinspect credential file %q: %w", path, err)
	}
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Nlink != 1 ||
		after.Size != before.Size || after.Size != int64(len(contents)) {
		return nil, fmt.Errorf("identity: credential file %q changed while being read", path)
	}
	return contents, nil
}

// HashSPKI returns the SHA-256 digest of cert's DER SubjectPublicKeyInfo.
func HashSPKI(cert *x509.Certificate) (SPKIHash, error) {
	if cert == nil {
		return SPKIHash{}, errors.New("identity: cannot hash a nil certificate")
	}
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return SPKIHash{}, errors.New("identity: certificate has no SubjectPublicKeyInfo")
	}
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo), nil
}

// FormatSPKIPin returns the sole accepted textual representation of an SPKI
// hash: sha256/ followed by padded standard base64.
func FormatSPKIPin(hash SPKIHash) string {
	return spkiPinPrefix + base64.StdEncoding.EncodeToString(hash[:])
}

// SPKIPin hashes cert's SubjectPublicKeyInfo and returns its canonical pin.
func SPKIPin(cert *x509.Certificate) (string, error) {
	hash, err := HashSPKI(cert)
	if err != nil {
		return "", err
	}
	return FormatSPKIPin(hash), nil
}

// ParseSPKIPin parses a canonical SPKI pin. Alternative base64 alphabets,
// omitted padding, whitespace, and non-canonical spellings are rejected.
func ParseSPKIPin(pin string) (SPKIHash, error) {
	if len(pin) <= len(spkiPinPrefix) || pin[:len(spkiPinPrefix)] != spkiPinPrefix {
		return SPKIHash{}, fmt.Errorf("identity: SPKI pin must start with %q", spkiPinPrefix)
	}

	decoded, err := base64.StdEncoding.DecodeString(pin[len(spkiPinPrefix):])
	if err != nil {
		return SPKIHash{}, fmt.Errorf("identity: decode SPKI pin: %w", err)
	}
	if len(decoded) != sha256.Size {
		return SPKIHash{}, fmt.Errorf("identity: SPKI pin decoded to %d bytes, want %d", len(decoded), sha256.Size)
	}

	var hash SPKIHash
	copy(hash[:], decoded)
	if FormatSPKIPin(hash) != pin {
		return SPKIHash{}, errors.New("identity: SPKI pin is not canonical")
	}
	return hash, nil
}

// ParsePinAllowlist parses a non-empty list of canonical pins. Duplicate pins
// are rejected so configuration mistakes cannot be silently hidden.
func ParsePinAllowlist(pins []string) (PinSet, error) {
	if len(pins) == 0 {
		return nil, errors.New("identity: SPKI pin allowlist is empty")
	}

	set := make(PinSet, len(pins))
	for i, pin := range pins {
		hash, err := ParseSPKIPin(pin)
		if err != nil {
			return nil, fmt.Errorf("identity: parse SPKI pin %d: %w", i, err)
		}
		if _, exists := set[hash]; exists {
			return nil, fmt.Errorf("identity: duplicate SPKI pin at index %d", i)
		}
		set[hash] = struct{}{}
	}
	return set, nil
}

// Contains reports whether hash is in the allowlist.
func (pins PinSet) Contains(hash SPKIHash) bool {
	_, ok := pins[hash]
	return ok
}
