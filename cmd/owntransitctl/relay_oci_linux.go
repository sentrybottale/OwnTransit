//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/sentrybottale/owntransit/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	maxRelayOCIArchive = int64(8 << 30)
	maxRelayOCIJSON    = int64(1 << 20)
)

const (
	relayOCIManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	relayOCIConfigMediaType   = "application/vnd.oci.image.config.v1+json"
	relayOCILayerMediaType    = "application/vnd.oci.image.layer.v1.tar"
)

type relayOCIPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type relayOCIAnnotations struct {
	ReferenceName string `json:"org.opencontainers.image.ref.name"`
}

type relayOCIIndexDescriptor struct {
	MediaType   string              `json:"mediaType"`
	Digest      string              `json:"digest"`
	Size        int64               `json:"size"`
	Platform    relayOCIPlatform    `json:"platform"`
	Annotations relayOCIAnnotations `json:"annotations"`
}

type relayOCIIndex struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Manifests     []relayOCIIndexDescriptor `json:"manifests"`
}

type relayOCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type relayOCIManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Config        relayOCIDescriptor   `json:"config"`
	Layers        []relayOCIDescriptor `json:"layers"`
}

type relayOCILabels struct {
	Licenses  string `json:"org.opencontainers.image.licenses"`
	Revision  string `json:"org.opencontainers.image.revision"`
	Title     string `json:"org.opencontainers.image.title"`
	Version   string `json:"org.opencontainers.image.version"`
	Vendor    string `json:"org.opencontainers.image.vendor"`
	ReleaseID string `json:"org.opencontainers.image.release.id"`
}

type relayOCIContainerConfig struct {
	Command    []string       `json:"Cmd"`
	Entrypoint []string       `json:"Entrypoint"`
	Labels     relayOCILabels `json:"Labels"`
	User       string         `json:"User"`
	WorkingDir string         `json:"WorkingDir"`
}

type relayOCIRootFS struct {
	DiffIDs []string `json:"diff_ids"`
	Type    string   `json:"type"`
}

type relayOCIImageConfig struct {
	Architecture string                  `json:"architecture"`
	Config       relayOCIContainerConfig `json:"config"`
	OS           string                  `json:"os"`
	RootFS       relayOCIRootFS          `json:"rootfs"`
}

type relayOCIBlob struct {
	size     int64
	contents []byte
}

type countingReader struct {
	reader io.Reader
	read   int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.read += int64(count)
	return count, err
}

func expectedRelayImageID(archivePath, releaseID, expectedArch string) (string, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("package supervisor: open authenticated relay OCI: %w", err)
	}
	defer archive.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(archive.Fd()), &stat); err != nil {
		return "", fmt.Errorf("package supervisor: inspect authenticated relay OCI: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || uint32(stat.Mode)&0o7777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxRelayOCIArchive {
		return "", errors.New("package supervisor: authenticated relay OCI metadata is invalid")
	}
	return parseRelayOCIArchive(archive, stat.Size, releaseID, expectedArch)
}

func parseRelayOCIArchive(input io.Reader, archiveSize int64, releaseID, expectedArch string) (string, error) {
	if input == nil || archiveSize <= 0 || archiveSize > maxRelayOCIArchive || !validRelayReleaseID(releaseID) || !validRelayArchitecture(expectedArch) {
		return "", errors.New("package supervisor: relay OCI input is invalid")
	}
	counted := &countingReader{reader: io.LimitReader(input, archiveSize+1)}
	reader := tar.NewReader(counted)
	seen := make(map[string]bool)
	blobs := make(map[string]relayOCIBlob)
	var indexBytes, layoutBytes []byte
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("package supervisor: parse relay OCI tar: %w", err)
		}
		entries++
		if entries > 16 || header.Format != tar.FormatUSTAR || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || header.Linkname != "" || header.Uid != 0 || header.Gid != 0 {
			return "", errors.New("package supervisor: relay OCI tar header is outside the exact profile")
		}
		if seen[header.Name] {
			return "", errors.New("package supervisor: relay OCI tar contains a duplicate path")
		}
		seen[header.Name] = true
		switch header.Name {
		case "blobs/", "blobs/sha256/":
			if header.Typeflag != tar.TypeDir || header.Size != 0 || header.Mode != 0o755 {
				return "", errors.New("package supervisor: relay OCI directory metadata is invalid")
			}
		case "index.json", "oci-layout":
			if header.Typeflag != tar.TypeReg || header.Mode != 0o644 || header.Size <= 0 || header.Size > maxRelayOCIJSON {
				return "", errors.New("package supervisor: relay OCI metadata file is invalid")
			}
			contents, err := readRelayOCIEntry(reader, header.Size, true)
			if err != nil {
				return "", err
			}
			if header.Name == "index.json" {
				indexBytes = contents
			} else {
				layoutBytes = contents
			}
		default:
			const prefix = "blobs/sha256/"
			if header.Typeflag != tar.TypeReg || header.Mode != 0o644 || header.Size <= 0 || !strings.HasPrefix(header.Name, prefix) {
				return "", errors.New("package supervisor: relay OCI tar contains an unexpected path")
			}
			digest := strings.TrimPrefix(header.Name, prefix)
			if !validRelayDigest(digest) || len(blobs) >= 3 {
				return "", errors.New("package supervisor: relay OCI blob path is invalid")
			}
			contents, actualDigest, err := hashRelayOCIEntry(reader, header.Size)
			if err != nil {
				return "", err
			}
			if actualDigest != digest {
				return "", errors.New("package supervisor: relay OCI blob digest differs from its path")
			}
			blobs[digest] = relayOCIBlob{size: header.Size, contents: contents}
		}
	}
	remaining, err := io.ReadAll(counted)
	if err != nil || counted.read != archiveSize || bytes.IndexFunc(remaining, func(value rune) bool { return value != 0 }) >= 0 {
		return "", errors.New("package supervisor: relay OCI archive has invalid trailing bytes or size")
	}
	if entries != 7 || len(blobs) != 3 || !seen["blobs/"] || !seen["blobs/sha256/"] || len(indexBytes) == 0 || !bytes.Equal(layoutBytes, []byte("{\"imageLayoutVersion\":\"1.0.0\"}\n")) {
		return "", errors.New("package supervisor: relay OCI archive file set is not exact")
	}

	var index relayOCIIndex
	if err := decodeCanonicalRelayOCI(indexBytes, &index); err != nil || index.SchemaVersion != 2 || len(index.Manifests) != 1 {
		return "", errors.New("package supervisor: relay OCI index is invalid or noncanonical")
	}
	indexDescriptor := index.Manifests[0]
	if indexDescriptor.MediaType != relayOCIManifestMediaType || indexDescriptor.Platform != (relayOCIPlatform{Architecture: expectedArch, OS: "linux"}) ||
		indexDescriptor.Annotations.ReferenceName != "owntransit-relay:"+releaseID {
		return "", errors.New("package supervisor: relay OCI index selects another image")
	}
	manifestBlob, manifestDigest, err := referencedRelayOCIBlob(indexDescriptor.Digest, indexDescriptor.Size, blobs)
	if err != nil {
		return "", err
	}
	var manifest relayOCIManifest
	if err := decodeCanonicalRelayOCI(manifestBlob.contents, &manifest); err != nil || manifest.SchemaVersion != 2 || len(manifest.Layers) != 1 {
		return "", errors.New("package supervisor: relay OCI manifest is invalid or noncanonical")
	}
	if manifest.Config.MediaType != relayOCIConfigMediaType || manifest.Layers[0].MediaType != relayOCILayerMediaType {
		return "", errors.New("package supervisor: relay OCI descriptor media type is invalid")
	}
	configBlob, configDigest, err := referencedRelayOCIBlob(manifest.Config.Digest, manifest.Config.Size, blobs)
	if err != nil {
		return "", err
	}
	_, layerDigest, err := referencedRelayOCIBlob(manifest.Layers[0].Digest, manifest.Layers[0].Size, blobs)
	if err != nil {
		return "", err
	}
	if manifestDigest == configDigest || manifestDigest == layerDigest || configDigest == layerDigest || len(configBlob.contents) == 0 {
		return "", errors.New("package supervisor: relay OCI descriptor graph is not exact")
	}
	var imageConfig relayOCIImageConfig
	if err := decodeCanonicalRelayOCI(configBlob.contents, &imageConfig); err != nil || !validRelayOCIImageConfig(imageConfig, releaseID, expectedArch, "sha256:"+layerDigest) {
		return "", errors.New("package supervisor: relay OCI image configuration is invalid or noncanonical")
	}
	return "sha256:" + configDigest, nil
}

func readRelayOCIEntry(reader io.Reader, size int64, retain bool) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("package supervisor: relay OCI entry size is invalid")
	}
	var destination io.Writer = io.Discard
	var contents bytes.Buffer
	if retain {
		destination = &contents
	}
	written, err := io.Copy(destination, reader)
	if err != nil || written != size {
		return nil, errors.New("package supervisor: relay OCI entry is truncated")
	}
	return contents.Bytes(), nil
}

func hashRelayOCIEntry(reader io.Reader, size int64) ([]byte, string, error) {
	if size <= 0 || size > maxRelayOCIArchive {
		return nil, "", errors.New("package supervisor: relay OCI blob size is invalid")
	}
	hash := sha256.New()
	var contents bytes.Buffer
	destination := io.Writer(hash)
	if size <= maxRelayOCIJSON {
		destination = io.MultiWriter(hash, &contents)
	}
	written, err := io.Copy(destination, reader)
	if err != nil || written != size {
		return nil, "", errors.New("package supervisor: relay OCI blob is truncated")
	}
	return contents.Bytes(), hex.EncodeToString(hash.Sum(nil)), nil
}

func referencedRelayOCIBlob(digest string, size int64, blobs map[string]relayOCIBlob) (relayOCIBlob, string, error) {
	if !strings.HasPrefix(digest, "sha256:") || !validRelayDigest(strings.TrimPrefix(digest, "sha256:")) || size <= 0 {
		return relayOCIBlob{}, "", errors.New("package supervisor: relay OCI descriptor is invalid")
	}
	value := strings.TrimPrefix(digest, "sha256:")
	blob, ok := blobs[value]
	if !ok || blob.size != size {
		return relayOCIBlob{}, "", errors.New("package supervisor: relay OCI descriptor does not bind an exact blob")
	}
	return blob, value, nil
}

func decodeCanonicalRelayOCI(encoded []byte, value any) error {
	if len(encoded) == 0 || int64(len(encoded)) > maxRelayOCIJSON {
		return errors.New("invalid OCI JSON size")
	}
	if err := strictjson.Decode(encoded, value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(encoded, canonical) {
		return errors.New("noncanonical OCI JSON")
	}
	return nil
}

func validRelayOCIImageConfig(value relayOCIImageConfig, releaseID, expectedArch, layerDigest string) bool {
	return validRelayArchitecture(expectedArch) && value.Architecture == expectedArch && value.OS == "linux" &&
		len(value.Config.Command) == 4 && value.Config.Command[0] == "run" && value.Config.Command[1] == "--runtime-root=/runtime" && value.Config.Command[2] == "--anchor-view-root=/anchor" && value.Config.Command[3] == "--reader-gid=65532" &&
		len(value.Config.Entrypoint) == 1 && value.Config.Entrypoint[0] == "/owntransit-relay" && value.Config.User == "65532:65532" && value.Config.WorkingDir == "/" &&
		value.Config.Labels.Licenses == "Apache-2.0" && value.Config.Labels.Title == "OwnTransit Relay" && value.Config.Labels.Vendor == "OwnTransit" &&
		value.Config.Labels.ReleaseID == releaseID && validRelayRevision(value.Config.Labels.Revision) && validRelayVersion(value.Config.Labels.Version) &&
		value.RootFS.Type == "layers" && len(value.RootFS.DiffIDs) == 1 && value.RootFS.DiffIDs[0] == layerDigest
}

func validRelayArchitecture(value string) bool {
	return value == "amd64" || value == "arm64"
}

func validRelayDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validRelayReleaseID(value string) bool {
	if len(value) != 52 || value == strings.Repeat("a", 52) || (value[51] != 'a' && value[51] != 'q') {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '2' || character > '7') {
			return false
		}
	}
	return true
}

func validRelayRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validRelayVersion(value string) bool {
	if len(value) == 0 || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := range value {
		if !asciiAlphaNumeric(value[index]) && !strings.ContainsRune("._+-", rune(value[index])) {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

type packageCommandRunner func(string, ...string) (string, error)

func bindRelayImage(archive, tag, expectedImageID string, run packageCommandRunner) (string, error) {
	if archive == "" || tag == "" || !strings.HasPrefix(expectedImageID, "sha256:") || !validRelayDigest(strings.TrimPrefix(expectedImageID, "sha256:")) || run == nil {
		return "", errors.New("package supervisor: relay image binding input is invalid")
	}
	_, existsErr := run("/usr/bin/podman", "--remote=false", "image", "exists", tag)
	if existsErr == nil {
		return inspectBoundRelayImage(tag, expectedImageID, run)
	}
	var exit *exec.ExitError
	if !errors.As(existsErr, &exit) || exit.ExitCode() != 1 {
		return "", fmt.Errorf("package supervisor: inspect existing relay image tag: %w", existsErr)
	}
	if output, err := run("/usr/bin/podman", "--remote=false", "load", "--input", archive); err != nil {
		return "", fmt.Errorf("package supervisor: import authenticated relay OCI: %w: %s", err, output)
	}
	return inspectBoundRelayImage(tag, expectedImageID, run)
}

func inspectBoundRelayImage(tag, expectedImageID string, run packageCommandRunner) (string, error) {
	imageID, err := run("/usr/bin/podman", "--remote=false", "image", "inspect", "--format", "{{.Id}}", tag)
	if err != nil {
		return "", fmt.Errorf("package supervisor: inspect relay image: %w", err)
	}
	normalizedImageID, err := normalizeRelayImageID(imageID)
	if err != nil {
		return "", err
	}
	if normalizedImageID != expectedImageID {
		return "", errors.New("package supervisor: relay image tag is not bound to the authenticated OCI config digest")
	}
	return strings.TrimPrefix(normalizedImageID, "sha256:"), nil
}

// Podman 4.x reports the local image configuration ID as bare lowercase hex,
// while later releases may prefix the same digest with "sha256:". Accept only
// those two exact encodings and compare one normalized value to the digest
// authenticated inside the OCI archive.
func normalizeRelayImageID(imageID string) (string, error) {
	digest := imageID
	if strings.HasPrefix(imageID, "sha256:") {
		digest = strings.TrimPrefix(imageID, "sha256:")
	}
	if !validRelayDigest(digest) {
		return "", errors.New("package supervisor: Podman returned a noncanonical image ID")
	}
	return "sha256:" + digest, nil
}
