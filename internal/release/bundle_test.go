//go:build darwin || linux

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestVerifyBundleBindsArtifactsSPDXProvenanceAndLicenses(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	manifest.Evidence = nil
	for index := range manifest.Artifacts {
		contents := []byte("artifact-" + manifest.Artifacts[index].Name)
		if err := os.WriteFile(filepath.Join(root, manifest.Artifacts[index].File), contents, 0o644); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		manifest.Artifacts[index].SHA256 = hex.EncodeToString(digest[:])
		manifest.Artifacts[index].Size = int64(len(contents))
	}
	licenseBytes, err := os.ReadFile("../../LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), licenseBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	thirdParty := []byte(LicenseEvidenceHeader + "\nComponent: fixture v1\nFile: LICENSE\n---\nfixture\n---\n")
	if err := os.WriteFile(filepath.Join(root, "evidence/THIRD_PARTY_LICENSES.txt"), thirdParty, 0o644); err != nil {
		t.Fatal(err)
	}

	packages := []SPDXPackage{{Name: "Go standard library", SPDXID: "SPDXRef-Package-0000", VersionInfo: "go1.26.7", DownloadLocation: "https://go.dev/", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "BSD-3-Clause", CopyrightText: "NOASSERTION", ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/std@go1.26.7"}}}}
	for _, artifact := range manifest.Artifacts {
		relationships := []SPDXRelationship{{SPDXElementID: SPDXDocumentID, RelationshipType: "DESCRIBES", RelatedSPDXElement: SPDXArtifactID}}
		for _, pkg := range packages {
			relationships = append(relationships, SPDXRelationship{SPDXElementID: pkg.SPDXID, RelationshipType: "BUILD_DEPENDENCY_OF", RelatedSPDXElement: SPDXArtifactID})
		}
		document := SPDXDocument{SPDXVersion: SPDXVersion, DataLicense: SPDXDataLicense, SPDXID: SPDXDocumentID, Name: "owntransit-" + artifact.Name,
			DocumentNamespace: "https://spdx.org/spdxdocs/owntransit-" + manifest.ReleaseID + "-" + artifact.Name,
			CreationInfo:      SPDXCreationInfo{Created: time.Unix(manifest.CreatedUnix, 0).UTC().Format(time.RFC3339), Creators: []string{EvidenceToolCreator}},
			Files:             []SPDXFile{{FileName: artifact.File, SPDXID: SPDXArtifactID, Checksums: []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: artifact.SHA256}}, LicenseConcluded: "NOASSERTION", CopyrightText: "NOASSERTION"}}, Packages: packages,
			Relationships: relationships}
		encoded, err := EncodeSPDX(document, manifest, artifact)
		if err != nil {
			t.Fatal(err)
		}
		file := "evidence/" + filepath.Base(artifact.File) + ".spdx.json"
		if err := os.WriteFile(filepath.Join(root, file), encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	provenance := Provenance{Schema: ProvenanceSchema, Product: manifest.Product, Version: manifest.Version, ReleaseID: manifest.ReleaseID, Sequence: manifest.Sequence, CreatedUnix: manifest.CreatedUnix, Protocol: manifest.Protocol, License: manifest.License, Source: manifest.Source, Toolchain: manifest.Toolchain, BuildProfile: BuildProfile, SourceDateEpoch: manifest.CreatedUnix, Trimpath: true}
	for _, artifact := range manifest.Artifacts {
		provenance.Subjects = append(provenance.Subjects, ProvenanceSubject{Name: artifact.Name, File: artifact.File, SHA256: artifact.SHA256, Size: artifact.Size})
	}
	provenanceBytes, err := EncodeProvenance(provenance, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "evidence/PROVENANCE.json"), provenanceBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	records := []Evidence{{Name: "project-license", File: "LICENSE", Kind: "project-license"}, {Name: "provenance", File: "evidence/PROVENANCE.json", Kind: "provenance"}, {Name: "third-party-licenses", File: "evidence/THIRD_PARTY_LICENSES.txt", Kind: "licenses"}}
	for _, artifact := range manifest.Artifacts {
		records = append(records, Evidence{Name: artifact.SBOM, File: "evidence/" + filepath.Base(artifact.File) + ".spdx.json", Kind: "sbom"})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	for index := range records {
		contents, err := os.ReadFile(filepath.Join(root, records[index].File))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		records[index].SHA256 = hex.EncodeToString(digest[:])
		records[index].Size = int64(len(contents))
	}
	manifest.Evidence = records
	keys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, signatureBytes, err := Sign(manifest, keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(root, manifestBytes, signatureBytes, keys.Public); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, manifest.Artifacts[0].File)
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(root, manifestBytes, signatureBytes, keys.Public); err == nil {
		t.Fatal("tampered artifact was accepted")
	}
}
