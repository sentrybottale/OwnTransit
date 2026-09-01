package release

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

const testDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func validManifest() Manifest {
	releaseID := protocol.ID{1}
	artifacts := ArtifactMatrix()
	for index := range artifacts {
		artifacts[index].SHA256 = testDigest
		artifacts[index].Size = int64(101 + index)
	}
	evidence := make([]Evidence, 0, len(artifacts)+1)
	for index, artifact := range artifacts {
		evidence = append(evidence, Evidence{
			Name: artifact.SBOM, File: "evidence/" + artifact.File[strings.LastIndex(artifact.File, "/")+1:] + ".spdx.json", SHA256: testDigest,
			Size: int64(201 + index), Kind: "sbom",
		})
	}
	evidence = append(evidence,
		Evidence{Name: "project-license", File: "LICENSE", SHA256: testDigest, Size: 301, Kind: "project-license"},
		Evidence{Name: "provenance", File: "evidence/PROVENANCE.json", SHA256: testDigest, Size: 302, Kind: "provenance"},
		Evidence{Name: "third-party-licenses", File: "evidence/THIRD_PARTY_LICENSES.txt", SHA256: testDigest, Size: 303, Kind: "licenses"},
	)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Name < evidence[j].Name })

	return Manifest{
		Schema: ManifestSchema, Product: "owntransit", Version: "0.1.0", ReleaseID: releaseID.String(),
		Sequence: 1, CreatedUnix: 1700000000, Protocol: wireprofile.LegacyV1Protocol, License: "Apache-2.0", MinimumLifecycle: 1,
		Source:    Source{Repository: canonicalRepository, Commit: strings.Repeat("b", 40), ManifestSHA256: testDigest},
		Toolchain: Toolchain{GoVersion: "go1.26.7", BuilderImage: "registry.example/build/go@sha256:" + testDigest},
		Artifacts: artifacts,
		Evidence:  evidence,
	}
}

func TestSignedManifestBindsExactBytes(t *testing.T) {
	keys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, signatureBytes, err := Sign(validManifest(), keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(manifestBytes, signatureBytes, keys.Public); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), manifestBytes...)
	changed[len(changed)-2] ^= 1
	if _, err := Verify(changed, signatureBytes, keys.Public); err == nil {
		t.Fatal("changed manifest bytes were accepted")
	}
}

func TestVerifyForInstallRejectsDowngradeAndWrongPlatform(t *testing.T) {
	keys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	manifestBytes, signatureBytes, err := Sign(manifest, keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	connector := manifest.Artifacts[2]
	policyKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policyRecord := Policy{Schema: PolicySchema, Product: "owntransit", Sequence: 1, CreatedUnix: 1700000000, ReleaseKeyID: signing.KeyID(keys.Public), MinimumReleaseSequence: 1, MinimumLifecycle: 1}
	policyBytes, policySignature, err := SignPolicy(policyRecord, policyKeys.Private)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPolicy, err := VerifyPolicyAdvance(policyBytes, policySignature, policyKeys.Public, PolicyAnchor{})
	if err != nil {
		t.Fatal(err)
	}
	policy := InstallPolicy{
		RunningLifecycle: 1, ArtifactName: connector.Name, ExpectedOS: "linux", ExpectedArch: "amd64",
		ExpectedRole: "connector", ExpectedArtifactSHA256: connector.SHA256, VerifiedReleasePolicy: &verifiedPolicy,
	}
	if _, _, err := VerifyForInstall(manifestBytes, signatureBytes, keys.Public, policy); err != nil {
		t.Fatal(err)
	}
	policy.HighestSequence = manifest.Sequence
	if _, _, err := VerifyForInstall(manifestBytes, signatureBytes, keys.Public, policy); err == nil {
		t.Fatal("release downgrade was accepted")
	}
	policy.HighestSequence = 0
	policy.ExpectedOS = "darwin"
	if _, _, err := VerifyForInstall(manifestBytes, signatureBytes, keys.Public, policy); err == nil {
		t.Fatal("connector release was accepted for the wrong platform")
	}
}

func TestExampleManifestMatchesStrictSchema(t *testing.T) {
	encoded, err := os.ReadFile("../../RELEASE_MANIFEST.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxManifestSize {
		t.Fatal("example manifest exceeds the input size limit")
	}
	var manifest Manifest
	if err := strictjson.Decode(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRequiresExactInitialArtifactMatrix(t *testing.T) {
	tests := map[string]func(*Manifest){
		"missing artifact": func(manifest *Manifest) {
			manifest.Artifacts = manifest.Artifacts[:len(manifest.Artifacts)-1]
		},
		"unknown replacement": func(manifest *Manifest) {
			manifest.Artifacts[0].Name = "client-linux-arm64"
		},
		"wrong platform": func(manifest *Manifest) {
			manifest.Artifacts[0].Arch = "amd64"
		},
		"relay is not OCI": func(manifest *Manifest) {
			manifest.Artifacts[3].Format = ArtifactFormatExecutable
		},
		"POC connector target": func(manifest *Manifest) {
			manifest.Artifacts[2].SSHTarget = "tcp4/127.0.0.1:2222"
		},
		"client target selector": func(manifest *Manifest) {
			manifest.Artifacts[0].SSHTarget = productionConnectorTarget
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest()
			mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("invalid initial artifact matrix was accepted")
			}
		})
	}

	manifest := validManifest()
	for left, right := 0, len(manifest.Artifacts)-1; left < right; left, right = left+1, right-1 {
		manifest.Artifacts[left], manifest.Artifacts[right] = manifest.Artifacts[right], manifest.Artifacts[left]
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("noncanonical artifact order was accepted")
	}
}

func TestManifestBindsOneNamedSBOMPerArtifactAndLicenses(t *testing.T) {
	tests := map[string]func(*Manifest){
		"missing SBOM reference": func(manifest *Manifest) {
			manifest.Artifacts[0].SBOM = "missing-sbom"
		},
		"SBOM reference has wrong kind": func(manifest *Manifest) {
			manifest.Evidence[0].Kind = "test-report"
		},
		"SBOM reused": func(manifest *Manifest) {
			manifest.Artifacts[1].SBOM = manifest.Artifacts[0].SBOM
		},
		"unreferenced SBOM": func(manifest *Manifest) {
			manifest.Evidence = append(manifest.Evidence, Evidence{Name: "sbom-extra", File: "extra.spdx.json", SHA256: testDigest, Size: 1, Kind: "sbom"})
		},
		"missing licenses": func(manifest *Manifest) {
			manifest.Evidence = manifest.Evidence[:len(manifest.Evidence)-1]
		},
		"two license records": func(manifest *Manifest) {
			manifest.Evidence = append(manifest.Evidence, Evidence{Name: "licenses-two", File: "MORE_LICENSES.txt", SHA256: testDigest, Size: 1, Kind: "licenses"})
		},
		"SBOM digest missing": func(manifest *Manifest) {
			manifest.Evidence[0].SHA256 = ""
		},
		"SBOM size missing": func(manifest *Manifest) {
			manifest.Evidence[0].Size = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest()
			mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("invalid SBOM or license evidence was accepted")
			}
		})
	}
}

func TestManifestRequiresTrueBuilderDigestReference(t *testing.T) {
	valid := validManifest()
	valid.Toolchain.BuilderImage = "registry.example:443/build/go@sha256:" + testDigest
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid registry-port digest reference was rejected: %v", err)
	}

	tests := []string{
		"registry.example/build/go:latest",
		"registry.example/build/go@sha256:" + strings.Repeat("a", 63),
		"registry.example/build/go@sha256:" + strings.Repeat("a", 65),
		"registry.example/build/go@sha256:" + strings.Repeat("A", 64),
		"registry.example/build/go:latest@sha256:" + testDigest,
		"build/go@sha256:" + testDigest,
		"registry.example:99999/build/go@sha256:" + testDigest,
		"registry..example/build/go@sha256:" + testDigest,
		"Registry.example/build/go@sha256:" + testDigest,
		"registry.example//go@sha256:" + testDigest,
		"registry.example/build/go@sha512:" + testDigest,
	}
	for _, builder := range tests {
		t.Run(builder, func(t *testing.T) {
			manifest := validManifest()
			manifest.Toolchain.BuilderImage = builder
			if err := manifest.Validate(); err == nil {
				t.Fatal("invalid builder image reference was accepted")
			}
		})
	}
}

func TestVerifyRejectsDuplicateJSONKeys(t *testing.T) {
	keys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, signatureBytes, err := Sign(validManifest(), keys.Private)
	if err != nil {
		t.Fatal(err)
	}

	duplicateSignature := strings.Replace(
		string(signatureBytes),
		`{"schema":"`+SignatureSchema+`"`,
		`{"schema":"`+SignatureSchema+`","schema":"`+SignatureSchema+`"`,
		1,
	)
	if _, err := Verify(manifestBytes, []byte(duplicateSignature), keys.Public); err == nil {
		t.Fatal("duplicate signature-record key was accepted")
	}

	duplicateManifest := strings.Replace(
		string(manifestBytes),
		`"product":"owntransit"`,
		`"product":"owntransit","product":"owntransit"`,
		1,
	)
	duplicateManifestBytes := []byte(duplicateManifest)
	rawSignature, err := signing.Sign(signatureDomain, duplicateManifestBytes, keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(duplicateManifestBytes)
	record := Signature{
		Schema: SignatureSchema, KeyID: keys.KeyID, ManifestSHA256: hex.EncodeToString(digest[:]),
		Signature: base64.StdEncoding.EncodeToString(rawSignature),
	}
	duplicateManifestSignature, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(duplicateManifestBytes, append(duplicateManifestSignature, '\n'), keys.Public); err == nil {
		t.Fatal("signed manifest with duplicate key was accepted")
	}
}

func TestEncodeCountsFinalNewlineInManifestSize(t *testing.T) {
	manifest := validManifest()
	baseline, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != len(baseline)+1 || encoded[len(encoded)-1] != '\n' {
		t.Fatalf("manifest newline was not included in canonical bytes: json=%d encoded=%d", len(baseline), len(encoded))
	}
}
