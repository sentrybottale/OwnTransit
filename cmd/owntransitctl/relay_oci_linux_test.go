//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
)

func TestBindRelayImageRejectsHostilePreexistingTag(t *testing.T) {
	expected := "sha256:" + strings.Repeat("a", 64)
	hostile := "sha256:" + strings.Repeat("b", 64)
	var calls []string
	runner := func(_ string, arguments ...string) (string, error) {
		calls = append(calls, strings.Join(arguments, " "))
		if len(arguments) >= 3 && arguments[2] == "exists" {
			return "", nil
		}
		if len(arguments) >= 3 && arguments[2] == "inspect" {
			return hostile, nil
		}
		return "", errors.New("unexpected command")
	}
	if _, err := bindRelayImage("/authenticated/relay.oci.tar", "owntransit-relay:release", expected, runner); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("hostile preexisting tag error = %v", err)
	}
	for _, call := range calls {
		if strings.Contains(call, " load ") {
			t.Fatalf("collision caused an archive load: calls=%v", calls)
		}
	}
}

func TestParseRelayOCIArchiveReturnsAuthenticatedConfigDigest(t *testing.T) {
	releaseID := strings.Repeat("b", 51) + "a"
	archive, expectedID := relayOCIFixture(t, releaseID)
	actual, err := parseRelayOCIArchive(bytes.NewReader(archive), int64(len(archive)), releaseID)
	if err != nil || actual != expectedID {
		t.Fatalf("parse relay OCI = %q, %v; want %q", actual, err, expectedID)
	}

	mutated := append([]byte(nil), archive...)
	position := bytes.Index(mutated, []byte("OwnTransit Relay"))
	if position < 0 {
		t.Fatal("fixture title absent")
	}
	mutated[position] = 'X'
	if _, err := parseRelayOCIArchive(bytes.NewReader(mutated), int64(len(mutated)), releaseID); err == nil || !strings.Contains(err.Error(), "blob digest") {
		t.Fatalf("mutated authenticated blob error = %v", err)
	}
}

func relayOCIFixture(t *testing.T, releaseID string) ([]byte, string) {
	t.Helper()
	layer := []byte("deterministic-layer-tar-placeholder")
	layerDigest := sha256Hex(layer)
	configuration := relayOCIImageConfig{
		Architecture: "amd64",
		Config: relayOCIContainerConfig{
			Command:    []string{"run", "--runtime-root=/runtime", "--anchor-view-root=/anchor", "--reader-gid=65532"},
			Entrypoint: []string{"/owntransit-relay"},
			Labels: relayOCILabels{
				Licenses: "Apache-2.0", Revision: strings.Repeat("c", 40), Title: "OwnTransit Relay",
				Version: "1.0.0", Vendor: "OwnTransit", ReleaseID: releaseID,
			},
			User: "65532:65532", WorkingDir: "/",
		},
		OS: "linux", RootFS: relayOCIRootFS{DiffIDs: []string{"sha256:" + layerDigest}, Type: "layers"},
	}
	configBytes := canonicalRelayOCITestJSON(t, configuration)
	configDigest := sha256Hex(configBytes)
	manifest := relayOCIManifest{
		SchemaVersion: 2,
		Config:        relayOCIDescriptor{MediaType: relayOCIConfigMediaType, Digest: "sha256:" + configDigest, Size: int64(len(configBytes))},
		Layers:        []relayOCIDescriptor{{MediaType: relayOCILayerMediaType, Digest: "sha256:" + layerDigest, Size: int64(len(layer))}},
	}
	manifestBytes := canonicalRelayOCITestJSON(t, manifest)
	manifestDigest := sha256Hex(manifestBytes)
	index := relayOCIIndex{
		SchemaVersion: 2,
		Manifests: []relayOCIIndexDescriptor{{
			MediaType: relayOCIManifestMediaType, Digest: "sha256:" + manifestDigest, Size: int64(len(manifestBytes)),
			Platform:    relayOCIPlatform{Architecture: "amd64", OS: "linux"},
			Annotations: relayOCIAnnotations{ReferenceName: "owntransit-relay:" + releaseID},
		}},
	}
	indexBytes := canonicalRelayOCITestJSON(t, index)
	blobs := map[string][]byte{configDigest: configBytes, layerDigest: layer, manifestDigest: manifestBytes}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	writeRelayOCITestEntry(t, writer, "blobs/", tar.TypeDir, 0o755, nil)
	writeRelayOCITestEntry(t, writer, "blobs/sha256/", tar.TypeDir, 0o755, nil)
	names := make([]string, 0, len(blobs))
	for digest := range blobs {
		names = append(names, digest)
	}
	sort.Strings(names)
	for _, digest := range names {
		writeRelayOCITestEntry(t, writer, "blobs/sha256/"+digest, tar.TypeReg, 0o644, blobs[digest])
	}
	writeRelayOCITestEntry(t, writer, "index.json", tar.TypeReg, 0o644, indexBytes)
	writeRelayOCITestEntry(t, writer, "oci-layout", tar.TypeReg, 0o644, []byte("{\"imageLayoutVersion\":\"1.0.0\"}\n"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes(), "sha256:" + configDigest
}

func canonicalRelayOCITestJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func writeRelayOCITestEntry(t *testing.T, writer *tar.Writer, name string, kind byte, mode int64, contents []byte) {
	t.Helper()
	header := &tar.Header{Name: name, Typeflag: kind, Mode: mode, Uid: 0, Gid: 0, Size: int64(len(contents)), Format: tar.FormatUSTAR}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if len(contents) > 0 {
		if _, err := writer.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
}

func sha256Hex(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}
