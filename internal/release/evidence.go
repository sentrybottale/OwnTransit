package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	ProvenanceSchema        = "owntransit.build-provenance.v1"
	BuildProfile            = "owntransit.v1.exact-nine"
	SPDXVersion             = "SPDX-2.3"
	SPDXDataLicense         = "CC0-1.0"
	SPDXDocumentID          = "SPDXRef-DOCUMENT"
	SPDXArtifactID          = "SPDXRef-Artifact"
	EvidenceToolCreator     = "Tool: OwnTransit release evidence v1"
	LicenseEvidenceHeader   = "OwnTransit third-party license evidence v1\n"
	MaxEvidenceDocumentSize = 16 << 20
	BIP39PackageName        = "BIP-39 English word list"
	BIP39PackageVersion     = "ce1862ac6bcffa1dd20aad858380e51e66e949ea"
	BIP39DownloadLocation   = "https://raw.githubusercontent.com/bitcoin/bips/ce1862ac6bcffa1dd20aad858380e51e66e949ea/bip-0039/english.txt"
	BIP39PackagePURL        = "pkg:generic/bip39-english-wordlist@ce1862ac6bcffa1dd20aad858380e51e66e949ea"
	BIP39CopyrightText      = "Copyright (c) 2013 BIP-39 authors"
)

type Provenance struct {
	Schema          string              `json:"schema"`
	Product         string              `json:"product"`
	Version         string              `json:"version"`
	ReleaseID       string              `json:"release_id"`
	Sequence        uint64              `json:"sequence"`
	CreatedUnix     int64               `json:"created_unix"`
	Protocol        string              `json:"protocol"`
	License         string              `json:"license"`
	Source          Source              `json:"source"`
	Toolchain       Toolchain           `json:"toolchain"`
	BuildProfile    string              `json:"build_profile"`
	SourceDateEpoch int64               `json:"source_date_epoch"`
	CGOEnabled      bool                `json:"cgo_enabled"`
	Trimpath        bool                `json:"trimpath"`
	BuildVCS        bool                `json:"build_vcs"`
	Subjects        []ProvenanceSubject `json:"subjects"`
}

type ProvenanceSubject struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	Files             []SPDXFile         `json:"files"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXFile struct {
	FileName         string         `json:"fileName"`
	SPDXID           string         `json:"SPDXID"`
	Checksums        []SPDXChecksum `json:"checksums"`
	LicenseConcluded string         `json:"licenseConcluded"`
	CopyrightText    string         `json:"copyrightText"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs"`
}

type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func EncodeProvenance(provenance Provenance, manifest Manifest) ([]byte, error) {
	if err := provenance.ValidateForManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(provenance)
	if err != nil {
		return nil, fmt.Errorf("release: encode provenance: %w", err)
	}
	if len(encoded) >= MaxEvidenceDocumentSize {
		return nil, errors.New("release: provenance exceeds size limit")
	}
	return append(encoded, '\n'), nil
}

func ParseProvenance(encoded []byte, manifest Manifest) (Provenance, error) {
	if len(encoded) == 0 || len(encoded) > MaxEvidenceDocumentSize {
		return Provenance{}, errors.New("release: provenance has an invalid size")
	}
	var provenance Provenance
	if err := strictjson.Decode(encoded, &provenance); err != nil {
		return Provenance{}, fmt.Errorf("release: provenance: %w", err)
	}
	if err := provenance.ValidateForManifest(manifest); err != nil {
		return Provenance{}, err
	}
	canonical, err := EncodeProvenance(provenance, manifest)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Provenance{}, errors.New("release: provenance is not canonical JSON")
	}
	return provenance, nil
}

func (provenance Provenance) ValidateForManifest(manifest Manifest) error {
	if provenance.Schema != ProvenanceSchema || provenance.Product != manifest.Product || provenance.Version != manifest.Version ||
		provenance.ReleaseID != manifest.ReleaseID || provenance.Sequence != manifest.Sequence || provenance.CreatedUnix != manifest.CreatedUnix ||
		provenance.Protocol != manifest.Protocol || provenance.License != manifest.License || provenance.Source != manifest.Source || provenance.Toolchain != manifest.Toolchain {
		return errors.New("release: provenance does not bind the signed release identity and inputs")
	}
	if provenance.BuildProfile != BuildProfile || provenance.SourceDateEpoch != manifest.CreatedUnix || provenance.CGOEnabled || !provenance.Trimpath || provenance.BuildVCS {
		return errors.New("release: provenance does not bind the required reproducible build profile")
	}
	if len(provenance.Subjects) != len(manifest.Artifacts) {
		return errors.New("release: provenance does not contain every artifact subject")
	}
	for index, artifact := range manifest.Artifacts {
		subject := provenance.Subjects[index]
		if subject.Name != artifact.Name || subject.File != artifact.File || subject.SHA256 != artifact.SHA256 || subject.Size != artifact.Size {
			return fmt.Errorf("release: provenance subject %d does not bind its artifact", index)
		}
	}
	return nil
}

func EncodeSPDX(document SPDXDocument, manifest Manifest, artifact Artifact) ([]byte, error) {
	if err := document.ValidateForArtifact(manifest, artifact); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("release: encode SPDX: %w", err)
	}
	if len(encoded) >= MaxEvidenceDocumentSize {
		return nil, errors.New("release: SPDX document exceeds size limit")
	}
	return append(encoded, '\n'), nil
}

func ParseSPDX(encoded []byte, manifest Manifest, artifact Artifact) (SPDXDocument, error) {
	if len(encoded) == 0 || len(encoded) > MaxEvidenceDocumentSize {
		return SPDXDocument{}, errors.New("release: SPDX document has an invalid size")
	}
	var document SPDXDocument
	if err := strictjson.Decode(encoded, &document); err != nil {
		return SPDXDocument{}, fmt.Errorf("release: SPDX document: %w", err)
	}
	if err := document.ValidateForArtifact(manifest, artifact); err != nil {
		return SPDXDocument{}, err
	}
	canonical, err := EncodeSPDX(document, manifest, artifact)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return SPDXDocument{}, errors.New("release: SPDX document is not canonical JSON")
	}
	return document, nil
}

func (document SPDXDocument) ValidateForArtifact(manifest Manifest, artifact Artifact) error {
	expectedNamespace := "https://spdx.org/spdxdocs/owntransit-" + manifest.ReleaseID + "-" + artifact.Name
	expectedCreated := time.Unix(manifest.CreatedUnix, 0).UTC().Format(time.RFC3339)
	if document.SPDXVersion != SPDXVersion || document.DataLicense != SPDXDataLicense || document.SPDXID != SPDXDocumentID ||
		document.Name != "owntransit-"+artifact.Name || document.DocumentNamespace != expectedNamespace ||
		document.CreationInfo.Created != expectedCreated || len(document.CreationInfo.Creators) != 1 || document.CreationInfo.Creators[0] != EvidenceToolCreator {
		return errors.New("release: SPDX document identity or creation metadata is invalid")
	}
	if parsed, err := url.Parse(document.DocumentNamespace); err != nil || parsed.Scheme != "https" || parsed.Host != "spdx.org" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("release: SPDX document namespace is invalid")
	}
	if len(document.Files) != 1 {
		return errors.New("release: SPDX document must bind exactly one artifact file")
	}
	file := document.Files[0]
	if file.FileName != artifact.File || file.SPDXID != SPDXArtifactID || file.LicenseConcluded != "NOASSERTION" || file.CopyrightText != "NOASSERTION" ||
		len(file.Checksums) != 1 || file.Checksums[0].Algorithm != "SHA256" || file.Checksums[0].ChecksumValue != artifact.SHA256 {
		return errors.New("release: SPDX artifact subject does not bind the signed artifact")
	}
	if len(document.Packages) == 0 || len(document.Packages) > 4096 {
		return errors.New("release: SPDX package inventory is empty or too large")
	}
	previousID := ""
	seenIDs := map[string]struct{}{SPDXDocumentID: {}, SPDXArtifactID: {}}
	for index, pkg := range document.Packages {
		if !validSPDXText(pkg.Name) || !safeToken.MatchString(pkg.SPDXID) || !validSPDXText(pkg.VersionInfo) ||
			pkg.FilesAnalyzed || pkg.LicenseConcluded == "" || pkg.LicenseDeclared == "" || pkg.CopyrightText == "" || len(pkg.ExternalRefs) != 1 {
			return fmt.Errorf("release: SPDX package %d is incomplete", index)
		}
		if index > 0 && pkg.SPDXID <= previousID {
			return errors.New("release: SPDX packages are not in canonical ID order")
		}
		if _, exists := seenIDs[pkg.SPDXID]; exists {
			return errors.New("release: SPDX package ID is duplicated")
		}
		seenIDs[pkg.SPDXID] = struct{}{}
		previousID = pkg.SPDXID
		if !validSPDXPackageReference(pkg) {
			return fmt.Errorf("release: SPDX package %d has an invalid module reference", index)
		}
		if pkg.DownloadLocation != "NOASSERTION" {
			location, err := url.Parse(pkg.DownloadLocation)
			if err != nil || location.Scheme != "https" || location.Host == "" || location.User != nil || location.Fragment != "" {
				return fmt.Errorf("release: SPDX package %d has an invalid download location", index)
			}
		}
	}
	if len(document.Relationships) != len(document.Packages)+1 || document.Relationships[0] != (SPDXRelationship{
		SPDXElementID: SPDXDocumentID, RelationshipType: "DESCRIBES", RelatedSPDXElement: SPDXArtifactID,
	}) {
		return errors.New("release: SPDX document has an invalid subject relationship")
	}
	for index, pkg := range document.Packages {
		if document.Relationships[index+1] != (SPDXRelationship{SPDXElementID: pkg.SPDXID, RelationshipType: "BUILD_DEPENDENCY_OF", RelatedSPDXElement: SPDXArtifactID}) {
			return errors.New("release: SPDX document has an invalid build-dependency relationship")
		}
	}
	return nil
}

func validSPDXPackageReference(pkg SPDXPackage) bool {
	if len(pkg.ExternalRefs) != 1 {
		return false
	}
	ref := pkg.ExternalRefs[0]
	if ref.ReferenceCategory != "PACKAGE-MANAGER" || ref.ReferenceType != "purl" {
		return false
	}
	if pkg.Name == "Go standard library" {
		return strings.HasPrefix(pkg.VersionInfo, "go1.") &&
			ref.ReferenceLocator == "pkg:golang/std@"+url.QueryEscape(pkg.VersionInfo) &&
			pkg.DownloadLocation == "https://go.dev/" && pkg.LicenseDeclared == "BSD-3-Clause"
	}
	if pkg.Name == BIP39PackageName {
		return pkg.VersionInfo == BIP39PackageVersion && pkg.DownloadLocation == BIP39DownloadLocation &&
			pkg.LicenseDeclared == "MIT" && pkg.CopyrightText == BIP39CopyrightText &&
			ref.ReferenceLocator == BIP39PackagePURL
	}
	return pkg.DownloadLocation == "NOASSERTION" &&
		ref.ReferenceLocator == "pkg:golang/"+url.PathEscape(pkg.Name)+"@"+url.QueryEscape(pkg.VersionInfo)
}

func validSPDXText(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateLicenseEvidence(encoded []byte) error {
	if len(encoded) <= len(LicenseEvidenceHeader) || len(encoded) > MaxEvidenceDocumentSize || !bytes.HasPrefix(encoded, []byte(LicenseEvidenceHeader)) || encoded[len(encoded)-1] != '\n' {
		return errors.New("release: third-party license evidence is empty or noncanonical")
	}
	return nil
}

func sortedEvidenceCopy(records []Evidence) []Evidence {
	result := append([]Evidence(nil), records...)
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}
