//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

func TestBindRelayImageRejectsHostilePreexistingTag(t *testing.T) {
	expected := "sha256:" + strings.Repeat("a", 64)
	for _, hostile := range []string{strings.Repeat("b", 64), "sha256:" + strings.Repeat("b", 64)} {
		t.Run(hostile[:6], func(t *testing.T) {
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
		})
	}
}

func TestBindRelayImageAcceptsBarePodmanIDAfterAuthenticatedLoad(t *testing.T) {
	digest := strings.Repeat("a", 64)
	expected := "sha256:" + digest
	existsError := exec.Command("/bin/sh", "-c", "exit 1").Run()
	var calls []string
	runner := func(_ string, arguments ...string) (string, error) {
		calls = append(calls, strings.Join(arguments, " "))
		if len(arguments) >= 3 && arguments[2] == "exists" {
			return "", existsError
		}
		if len(arguments) >= 2 && arguments[1] == "load" {
			return "Loaded image", nil
		}
		if len(arguments) >= 3 && arguments[2] == "inspect" {
			return digest, nil
		}
		return "", errors.New("unexpected command")
	}
	actual, err := bindRelayImage("/authenticated/relay.oci.tar", "owntransit-relay:release", expected, runner)
	if err != nil || actual != digest {
		t.Fatalf("bind relay image = %q, %v; want %q", actual, err, digest)
	}
	want := []string{
		"--remote=false image exists owntransit-relay:release",
		"--remote=false load --input /authenticated/relay.oci.tar",
		"--remote=false image inspect --format {{.Id}} owntransit-relay:release",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands = %v; want %v", calls, want)
	}
}

func TestInspectBoundRelayImageAcceptsCanonicalPodmanIDRepresentations(t *testing.T) {
	digest := strings.Repeat("a", 64)
	expected := "sha256:" + digest
	for _, reported := range []string{digest, expected} {
		t.Run(reported[:6], func(t *testing.T) {
			runner := func(path string, arguments ...string) (string, error) {
				if path != "/usr/bin/podman" || strings.Join(arguments, " ") != "--remote=false image inspect --format {{.Id}} owntransit-relay:release" {
					t.Fatalf("unexpected command: %s %v", path, arguments)
				}
				return reported, nil
			}
			actual, err := inspectBoundRelayImage("owntransit-relay:release", expected, runner)
			if err != nil || actual != digest {
				t.Fatalf("inspect relay image = %q, %v; want %q", actual, err, digest)
			}
		})
	}
}

func TestInspectBoundRelayImageRejectsNoncanonicalPodmanIDs(t *testing.T) {
	digest := strings.Repeat("a", 64)
	expected := "sha256:" + digest
	invalid := []string{
		strings.ToUpper(digest),
		"sha256:" + strings.ToUpper(digest),
		"sha512:" + digest,
		"sha256:sha256:" + digest,
		" " + digest,
		digest + "\n",
		digest[:63],
	}
	for _, reported := range invalid {
		runner := func(_ string, _ ...string) (string, error) { return reported, nil }
		if _, err := inspectBoundRelayImage("owntransit-relay:release", expected, runner); err == nil || !strings.Contains(err.Error(), "noncanonical image ID") {
			t.Fatalf("reported ID %q error = %v", reported, err)
		}
	}
}

func TestParseRelayOCIArchiveReturnsAuthenticatedConfigDigest(t *testing.T) {
	releaseID := strings.Repeat("b", 51) + "a"
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			archive, expectedID := relayOCIFixture(t, releaseID, arch)
			actual, err := parseRelayOCIArchive(bytes.NewReader(archive), int64(len(archive)), releaseID, arch)
			if err != nil || actual != expectedID {
				t.Fatalf("parse relay OCI = %q, %v; want %q", actual, err, expectedID)
			}
			wrongArch := "arm64"
			if arch == wrongArch {
				wrongArch = "amd64"
			}
			if _, err := parseRelayOCIArchive(bytes.NewReader(archive), int64(len(archive)), releaseID, wrongArch); err == nil || !strings.Contains(err.Error(), "selects another image") {
				t.Fatalf("wrong-architecture relay OCI error = %v", err)
			}

			mutated := append([]byte(nil), archive...)
			position := bytes.Index(mutated, []byte("OwnTransit Relay"))
			if position < 0 {
				t.Fatal("fixture title absent")
			}
			mutated[position] = 'X'
			if _, err := parseRelayOCIArchive(bytes.NewReader(mutated), int64(len(mutated)), releaseID, arch); err == nil || !strings.Contains(err.Error(), "blob digest") {
				t.Fatalf("mutated authenticated blob error = %v", err)
			}
		})
	}
}

func relayOCIFixture(t *testing.T, releaseID, arch string) ([]byte, string) {
	t.Helper()
	layer := []byte("deterministic-layer-tar-placeholder")
	layerDigest := sha256Hex(layer)
	configuration := relayOCIImageConfig{
		Architecture: arch,
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
			Platform:    relayOCIPlatform{Architecture: arch, OS: "linux"},
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
