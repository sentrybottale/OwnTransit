//go:build darwin || linux

package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// VerifiedBundle represents an exact signed manifest whose every named
// artifact and evidence file was hashed through a no-follow descriptor rooted
// in one protected bundle directory. It intentionally exposes no mutable path
// as proof; installers must copy from held package handles or reverify at the
// final activation boundary.
type VerifiedBundle struct {
	Manifest Manifest
	valid    bool
}

type Measurement struct {
	SHA256 string
	Size   int64
}

// MeasureBundleFiles hashes an explicit bounded set of protected bundle files
// through no-follow descriptors. Release construction uses the resulting
// measurements as candidate signing input; VerifyBundle independently repeats
// every measurement after signing.
func MeasureBundleFiles(rootPath string, paths []string) (map[string]Measurement, error) {
	if len(paths) == 0 || len(paths) > 128 {
		return nil, errors.New("release: measurement path set is empty or too large")
	}
	rootFD, err := openProtectedBundleRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	result := make(map[string]Measurement, len(paths))
	for _, path := range paths {
		if !validRelativePath(path) {
			return nil, fmt.Errorf("release: invalid measurement path %q", path)
		}
		if _, exists := result[path]; exists {
			return nil, fmt.Errorf("release: duplicate measurement path %q", path)
		}
		measurement, err := measureBundleRecord(rootFD, path)
		if err != nil {
			return nil, fmt.Errorf("release: measure %q: %w", path, err)
		}
		result[path] = measurement
	}
	return result, nil
}

// VerifyBundle authenticates the release manifest offline, then checks the
// exact size and SHA-256 of every artifact and evidence record. It also parses
// the bound provenance and SPDX documents rather than accepting opaque files
// merely because their digests were signed.
func VerifyBundle(rootPath string, manifestBytes, signatureBytes []byte, publicKey ed25519.PublicKey) (VerifiedBundle, error) {
	manifest, err := Verify(manifestBytes, signatureBytes, publicKey)
	if err != nil {
		return VerifiedBundle{}, err
	}
	rootFD, err := openProtectedBundleRoot(rootPath)
	if err != nil {
		return VerifiedBundle{}, err
	}
	defer unix.Close(rootFD)

	evidenceContents := make(map[string][]byte, len(manifest.Evidence))
	for _, artifact := range manifest.Artifacts {
		if _, err := verifyBundleRecord(rootFD, artifact.File, artifact.SHA256, artifact.Size, false); err != nil {
			return VerifiedBundle{}, fmt.Errorf("release: artifact %q: %w", artifact.Name, err)
		}
	}
	for _, evidence := range manifest.Evidence {
		contents, err := verifyBundleRecord(rootFD, evidence.File, evidence.SHA256, evidence.Size, true)
		if err != nil {
			return VerifiedBundle{}, fmt.Errorf("release: evidence %q: %w", evidence.Name, err)
		}
		evidenceContents[evidence.Name] = contents
	}

	if _, err := ParseProvenance(evidenceContents["provenance"], manifest); err != nil {
		return VerifiedBundle{}, err
	}
	for _, artifact := range manifest.Artifacts {
		if _, err := ParseSPDX(evidenceContents[artifact.SBOM], manifest, artifact); err != nil {
			return VerifiedBundle{}, fmt.Errorf("release: artifact %q SBOM: %w", artifact.Name, err)
		}
	}
	if err := validateLicenseEvidence(evidenceContents["third-party-licenses"]); err != nil {
		return VerifiedBundle{}, err
	}
	projectLicense := evidenceContents["project-license"]
	if manifest.License != "Apache-2.0" || !bytes.Contains(projectLicense, []byte("Apache License")) || !bytes.Contains(projectLicense, []byte("Version 2.0")) {
		return VerifiedBundle{}, errors.New("release: project license evidence does not match the Apache-2.0 identity")
	}
	return VerifiedBundle{Manifest: manifest, valid: true}, nil
}

// VerifyBundleForInstall combines bundle-byte verification, authenticated
// release-policy verification and the local activation policy in one offline
// gate. Policy anchor advancement and file activation remain separate durable
// platform transactions.
func VerifyBundleForInstall(rootPath string, manifestBytes, signatureBytes []byte, releaseKey ed25519.PublicKey, policy InstallPolicy) (VerifiedBundle, Artifact, error) {
	bundle, err := VerifyBundle(rootPath, manifestBytes, signatureBytes, releaseKey)
	if err != nil {
		return VerifiedBundle{}, Artifact{}, err
	}
	manifest, artifact, err := VerifyForInstall(manifestBytes, signatureBytes, releaseKey, policy)
	if err != nil {
		return VerifiedBundle{}, Artifact{}, err
	}
	if manifest.ReleaseID != bundle.Manifest.ReleaseID || manifest.Sequence != bundle.Manifest.Sequence {
		return VerifiedBundle{}, Artifact{}, errors.New("release: internal bundle verification mismatch")
	}
	return bundle, artifact, nil
}

func openProtectedBundleRoot(path string) (int, error) {
	if !strings.HasPrefix(path, "/") || path == "/" || strings.HasSuffix(path, "/") {
		return -1, errors.New("release: bundle root must be a canonical absolute non-root path")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("release: open filesystem root: %w", err)
	}
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			unix.Close(fd)
			return -1, errors.New("release: bundle root is not canonical")
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("release: open bundle directory %q: %w", component, openErr)
		}
		if index == len(components)-1 {
			if err := requireProtectedDirectory(next); err != nil {
				unix.Close(next)
				return -1, err
			}
		}
		fd = next
	}
	return fd, nil
}

func verifyBundleRecord(rootFD int, path, expectedDigest string, expectedSize int64, retain bool) ([]byte, error) {
	if !validRelativePath(path) || !validDigest(expectedDigest) || expectedSize <= 0 || expectedSize > 1<<40 {
		return nil, errors.New("invalid signed record metadata")
	}
	components := strings.Split(path, "/")
	directoryFD, err := unix.Dup(rootFD)
	if err != nil {
		return nil, fmt.Errorf("duplicate bundle descriptor: %w", err)
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(directoryFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(directoryFD)
		if openErr != nil {
			return nil, fmt.Errorf("open bundle directory %q: %w", component, openErr)
		}
		if err := requireProtectedDirectory(next); err != nil {
			unix.Close(next)
			return nil, err
		}
		directoryFD = next
	}
	defer unix.Close(directoryFD)
	fd, err := unix.Openat(directoryFD, components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open signed file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("wrap signed file descriptor")
	}
	defer file.Close()

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, fmt.Errorf("inspect signed file: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || uint64(before.Nlink) != 1 || before.Size != expectedSize || before.Mode&0o022 != 0 {
		return nil, errors.New("signed file is not a protected single-link regular file of the declared size")
	}
	hash := sha256.New()
	var destination io.Writer = hash
	var buffer bytes.Buffer
	if retain {
		if expectedSize > MaxEvidenceDocumentSize {
			return nil, errors.New("evidence file exceeds the semantic verification limit")
		}
		destination = io.MultiWriter(hash, &buffer)
	}
	written, err := io.CopyBuffer(destination, io.LimitReader(file, expectedSize+1), make([]byte, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("hash signed file: %w", err)
	}
	if written != expectedSize {
		return nil, errors.New("signed file changed size while being verified")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, fmt.Errorf("reinspect signed file: %w", err)
	}
	if after.Mode&unix.S_IFMT != unix.S_IFREG || uint64(after.Nlink) != 1 || after.Size != before.Size || after.Mode&0o022 != 0 {
		return nil, errors.New("signed file metadata changed while being verified")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return nil, errors.New("signed file digest mismatch")
	}
	return buffer.Bytes(), nil
}

func measureBundleRecord(rootFD int, path string) (Measurement, error) {
	components := strings.Split(path, "/")
	directoryFD, err := unix.Dup(rootFD)
	if err != nil {
		return Measurement{}, fmt.Errorf("duplicate bundle descriptor: %w", err)
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(directoryFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(directoryFD)
		if openErr != nil {
			return Measurement{}, fmt.Errorf("open bundle directory %q: %w", component, openErr)
		}
		if err := requireProtectedDirectory(next); err != nil {
			unix.Close(next)
			return Measurement{}, err
		}
		directoryFD = next
	}
	defer unix.Close(directoryFD)
	fd, err := unix.Openat(directoryFD, components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return Measurement{}, fmt.Errorf("open measured file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return Measurement{}, errors.New("wrap measured file descriptor")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return Measurement{}, fmt.Errorf("inspect measured file: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || uint64(before.Nlink) != 1 || before.Size <= 0 || before.Size > 1<<40 || before.Mode&0o022 != 0 {
		return Measurement{}, errors.New("measured file is not a protected bounded single-link regular file")
	}
	hash := sha256.New()
	written, err := io.CopyBuffer(hash, io.LimitReader(file, before.Size+1), make([]byte, 64<<10))
	if err != nil || written != before.Size {
		return Measurement{}, errors.New("measured file changed while being hashed")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Mode&unix.S_IFMT != unix.S_IFREG || uint64(after.Nlink) != 1 || after.Size != before.Size || after.Mode&0o022 != 0 {
		return Measurement{}, errors.New("measured file metadata changed while being hashed")
	}
	return Measurement{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: before.Size}, nil
}

func requireProtectedDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("release: inspect bundle directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
		return errors.New("release: bundle directory is not a protected directory")
	}
	return nil
}
