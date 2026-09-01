// Package release defines the signed, deployment-free OwnTransit software
// release record consumed by offline installers.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

const (
	ManifestSchema  = "owntransit.software-release.v1"
	SignatureSchema = "owntransit.software-release-signature.v1"
	signatureDomain = "OwnTransit software release manifest v1"
	MaxManifestSize = 1 << 20

	ArtifactFormatExecutable = "executable"
	ArtifactFormatOCI        = "oci"

	productionConnectorTarget = "tcp4/127.0.0.1:22"
	canonicalRepository       = "https://github.com/sentrybottale/owntransit"
)

var (
	safeToken           = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$`)
	goVersion           = regexp.MustCompile(`^go1\.[0-9]+(\.[0-9]+)?$`)
	repositoryComponent = regexp.MustCompile(`^[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*$`)
)

type artifactProfile struct {
	File      string
	OS        string
	Arch      string
	Role      string
	Format    string
	SSHTarget string
}

// initialArtifactMatrix is deliberately exact. Adding a platform or role is a
// release-contract change that requires its own clean-host qualification.
var initialArtifactMatrix = map[string]artifactProfile{
	"client-darwin-arm64":      {File: "artifacts/owntransit-darwin-arm64", OS: "darwin", Arch: "arm64", Role: "client", Format: ArtifactFormatExecutable},
	"client-linux-amd64":       {File: "artifacts/owntransit-linux-amd64", OS: "linux", Arch: "amd64", Role: "client", Format: ArtifactFormatExecutable},
	"connector-linux-amd64":    {File: "artifacts/owntransit-connector-linux-amd64", OS: "linux", Arch: "amd64", Role: "connector", Format: ArtifactFormatExecutable, SSHTarget: productionConnectorTarget},
	"relay-linux-amd64":        {File: "artifacts/owntransit-relay-linux-amd64.oci.tar", OS: "linux", Arch: "amd64", Role: "relay", Format: ArtifactFormatOCI},
	"lifecycle-darwin-arm64":   {File: "artifacts/owntransitctl-darwin-arm64", OS: "darwin", Arch: "arm64", Role: "lifecycle", Format: ArtifactFormatExecutable},
	"lifecycle-linux-amd64":    {File: "artifacts/owntransitctl-linux-amd64", OS: "linux", Arch: "amd64", Role: "lifecycle", Format: ArtifactFormatExecutable},
	"provisioner-darwin-arm64": {File: "artifacts/owntransit-provision-darwin-arm64", OS: "darwin", Arch: "arm64", Role: "provisioner", Format: ArtifactFormatExecutable},
	"provisioner-linux-amd64":  {File: "artifacts/owntransit-provision-linux-amd64", OS: "linux", Arch: "amd64", Role: "provisioner", Format: ArtifactFormatExecutable},
	"launcher-darwin-arm64":    {File: "artifacts/owntransit-launcher-darwin-arm64", OS: "darwin", Arch: "arm64", Role: "launcher", Format: ArtifactFormatExecutable},
}

// initialArtifactOrder is part of the canonical v1 manifest representation.
// A verifier therefore has one logical ordering to review and sign, rather
// than accepting permutation aliases of the same release matrix.
var initialArtifactOrder = []string{
	"client-darwin-arm64",
	"client-linux-amd64",
	"connector-linux-amd64",
	"relay-linux-amd64",
	"lifecycle-darwin-arm64",
	"lifecycle-linux-amd64",
	"provisioner-darwin-arm64",
	"provisioner-linux-amd64",
	"launcher-darwin-arm64",
}

// ArtifactMatrix returns a fresh copy of the exact v1 artifact metadata. The
// caller must measure and fill SHA256 and Size before constructing a manifest.
func ArtifactMatrix() []Artifact {
	artifacts := make([]Artifact, 0, len(initialArtifactOrder))
	for _, name := range initialArtifactOrder {
		profile := initialArtifactMatrix[name]
		artifacts = append(artifacts, Artifact{
			Name: name, File: profile.File, OS: profile.OS, Arch: profile.Arch,
			Role: profile.Role, Format: profile.Format, SSHTarget: profile.SSHTarget,
			SBOM: "sbom-" + name,
		})
	}
	return artifacts
}

type Manifest struct {
	Schema           string     `json:"schema"`
	Product          string     `json:"product"`
	Version          string     `json:"version"`
	ReleaseID        string     `json:"release_id"`
	Sequence         uint64     `json:"sequence"`
	CreatedUnix      int64      `json:"created_unix"`
	Protocol         string     `json:"protocol"`
	License          string     `json:"license"`
	MinimumLifecycle uint64     `json:"minimum_lifecycle"`
	Source           Source     `json:"source"`
	Toolchain        Toolchain  `json:"toolchain"`
	Artifacts        []Artifact `json:"artifacts"`
	Evidence         []Evidence `json:"evidence"`
}

type Source struct {
	Repository     string `json:"repository"`
	Commit         string `json:"commit"`
	Dirty          bool   `json:"dirty"`
	ManifestSHA256 string `json:"source_manifest_sha256"`
}

type Toolchain struct {
	GoVersion    string `json:"go_version"`
	BuilderImage string `json:"builder_image"`
}

type Artifact struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Role      string `json:"role"`
	Format    string `json:"format"`
	SSHTarget string `json:"ssh_target,omitempty"`
	SBOM      string `json:"sbom"`
}

type Evidence struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Kind   string `json:"kind"`
}

type Signature struct {
	Schema         string `json:"schema"`
	KeyID          string `json:"key_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Signature      string `json:"signature"`
}

// InstallPolicy comes only from durable target-local lifecycle state and the
// running lifecycle binary. It turns raw signature validity into a
// downgrade-resistant, exact-artifact installation decision.
type InstallPolicy struct {
	HighestSequence        uint64
	RunningLifecycle       uint64
	ArtifactName           string
	ExpectedOS             string
	ExpectedArch           string
	ExpectedRole           string
	ExpectedArtifactSHA256 string
	TombstonedReleaseIDs   []string
	VerifiedReleasePolicy  *VerifiedPolicy
	// ExactReplayReleaseID permits only the exact highest-sequence release to
	// be reverified for an interrupted transaction or idempotent reinstall.
	// It does not authorize an older release or a different release at the same
	// sequence.
	ExactReplayReleaseID string
}

func Encode(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("release: encode manifest: %w", err)
	}
	// The authenticated manifest bytes include the final newline.
	if len(encoded) >= MaxManifestSize {
		return nil, errors.New("release: manifest exceeds size limit")
	}
	return append(encoded, '\n'), nil
}

// ParseManifest accepts only the one canonical JSON representation produced by
// Encode. It is used on an offline signer before any signature is created.
func ParseManifest(encoded []byte) (Manifest, error) {
	if len(encoded) == 0 || len(encoded) > MaxManifestSize {
		return Manifest{}, errors.New("release: manifest has an invalid size")
	}
	var manifest Manifest
	if err := strictjson.Decode(encoded, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("release: manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	canonical, err := Encode(manifest)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Manifest{}, errors.New("release: manifest is not canonical JSON")
	}
	return manifest, nil
}

func Sign(manifest Manifest, privateKey ed25519.PrivateKey) (manifestBytes, signatureBytes []byte, err error) {
	manifestBytes, err = Encode(manifest)
	if err != nil {
		return nil, nil, err
	}
	signature, err := signing.Sign(signatureDomain, manifestBytes, privateKey)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(manifestBytes)
	record := Signature{
		Schema:         SignatureSchema,
		KeyID:          signing.KeyID(privateKey.Public().(ed25519.PublicKey)),
		ManifestSHA256: hex.EncodeToString(digest[:]),
		Signature:      base64.StdEncoding.EncodeToString(signature),
	}
	signatureBytes, err = encodeSignature(record)
	if err != nil {
		return nil, nil, fmt.Errorf("release: encode signature record: %w", err)
	}
	return manifestBytes, signatureBytes, nil
}

func encodeSignature(record Signature) ([]byte, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("release: encode signature record: %w", err)
	}
	return append(encoded, '\n'), nil
}

func Verify(manifestBytes, signatureBytes []byte, publicKey ed25519.PublicKey) (Manifest, error) {
	if len(manifestBytes) == 0 || len(manifestBytes) > MaxManifestSize || len(signatureBytes) == 0 || len(signatureBytes) > 16<<10 {
		return Manifest{}, errors.New("release: manifest or signature record has an invalid size")
	}
	var record Signature
	if err := strictjson.Decode(signatureBytes, &record); err != nil {
		return Manifest{}, fmt.Errorf("release: signature record: %w", err)
	}
	if record.Schema != SignatureSchema || record.KeyID != signing.KeyID(publicKey) {
		return Manifest{}, errors.New("release: signature record has the wrong schema or key ID")
	}
	canonicalSignature, err := encodeSignature(record)
	if err != nil || !bytes.Equal(signatureBytes, canonicalSignature) {
		return Manifest{}, errors.New("release: signature record is not canonical JSON")
	}
	digest := sha256.Sum256(manifestBytes)
	if record.ManifestSHA256 != hex.EncodeToString(digest[:]) {
		return Manifest{}, errors.New("release: manifest digest does not match signature record")
	}
	signature, err := base64.StdEncoding.DecodeString(record.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != record.Signature {
		return Manifest{}, errors.New("release: signature is not canonical base64")
	}
	if err := signing.Verify(signatureDomain, manifestBytes, signature, publicKey); err != nil {
		return Manifest{}, err
	}
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// VerifyForInstall is the activation-safe release gate. Verify remains useful
// for offline inspection, but installers must use this method with durable
// sequence/tombstone state and an exact platform artifact expectation.
func VerifyForInstall(manifestBytes, signatureBytes []byte, publicKey ed25519.PublicKey, policy InstallPolicy) (Manifest, Artifact, error) {
	if policy.RunningLifecycle == 0 || policy.ArtifactName == "" || policy.ExpectedOS == "" || policy.ExpectedArch == "" || policy.ExpectedRole == "" {
		return Manifest{}, Artifact{}, errors.New("release: complete install policy is required")
	}
	if policy.ExpectedArtifactSHA256 != "" && !validDigest(policy.ExpectedArtifactSHA256) {
		return Manifest{}, Artifact{}, errors.New("release: expected artifact digest is invalid")
	}
	if policy.VerifiedReleasePolicy == nil || !policy.VerifiedReleasePolicy.valid {
		return Manifest{}, Artifact{}, errors.New("release: an authenticated release policy is required")
	}
	verifiedPolicy := policy.VerifiedReleasePolicy.policy
	if verifiedPolicy.ReleaseKeyID != signing.KeyID(publicKey) {
		return Manifest{}, Artifact{}, errors.New("release: manifest signer is not authorized by release policy")
	}
	manifest, err := Verify(manifestBytes, signatureBytes, publicKey)
	if err != nil {
		return Manifest{}, Artifact{}, err
	}
	if manifest.Sequence <= policy.HighestSequence {
		if manifest.Sequence != policy.HighestSequence || manifest.ReleaseID != policy.ExactReplayReleaseID {
			return Manifest{}, Artifact{}, errors.New("release: sequence is a replay or downgrade")
		}
	}
	if manifest.Sequence < verifiedPolicy.MinimumReleaseSequence {
		return Manifest{}, Artifact{}, errors.New("release: manifest is below the authenticated release floor")
	}
	if policy.RunningLifecycle < verifiedPolicy.MinimumLifecycle {
		return Manifest{}, Artifact{}, errors.New("release: running lifecycle is below the authenticated lifecycle floor")
	}
	if manifest.MinimumLifecycle > policy.RunningLifecycle {
		return Manifest{}, Artifact{}, errors.New("release: running lifecycle does not satisfy manifest floor")
	}
	for _, tombstone := range append(append([]string(nil), policy.TombstonedReleaseIDs...), verifiedPolicy.TombstonedReleaseIDs...) {
		id, err := protocol.ParseID(tombstone)
		if err != nil || id == (protocol.ID{}) {
			return Manifest{}, Artifact{}, errors.New("release: durable release tombstone is invalid")
		}
		if tombstone == manifest.ReleaseID {
			return Manifest{}, Artifact{}, errors.New("release: release ID is tombstoned")
		}
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Name != policy.ArtifactName {
			continue
		}
		if artifact.OS != policy.ExpectedOS || artifact.Arch != policy.ExpectedArch || artifact.Role != policy.ExpectedRole ||
			(policy.ExpectedArtifactSHA256 != "" && artifact.SHA256 != policy.ExpectedArtifactSHA256) {
			return Manifest{}, Artifact{}, errors.New("release: selected artifact does not match local install policy")
		}
		return manifest, artifact, nil
	}
	return Manifest{}, Artifact{}, errors.New("release: required artifact is absent")
}

func (manifest Manifest) Validate() error {
	if manifest.Schema != ManifestSchema || manifest.Product != "owntransit" || manifest.Protocol != wireprofile.LegacyV1Protocol || manifest.License != "Apache-2.0" {
		return errors.New("release: unsupported schema, product, or protocol")
	}
	if !safeToken.MatchString(manifest.Version) || manifest.Sequence == 0 || manifest.CreatedUnix <= 0 || manifest.MinimumLifecycle == 0 {
		return errors.New("release: invalid version, sequence, creation time, or lifecycle floor")
	}
	releaseID, err := protocol.ParseID(manifest.ReleaseID)
	if err != nil || releaseID == (protocol.ID{}) {
		return errors.New("release: release_id must be a nonzero canonical ID")
	}
	if manifest.Source.Dirty || !validDigest(manifest.Source.ManifestSHA256) || !validCommit(manifest.Source.Commit) {
		return errors.New("release: source must be clean with canonical commit and manifest digests")
	}
	repository, err := url.Parse(manifest.Source.Repository)
	if err != nil || repository.String() != canonicalRepository || repository.Scheme != "https" || repository.User != nil || repository.RawQuery != "" || repository.Fragment != "" {
		return errors.New("release: source repository is not the canonical OwnTransit HTTPS repository")
	}
	if !goVersion.MatchString(manifest.Toolchain.GoVersion) || !validBuilderImage(manifest.Toolchain.BuilderImage) {
		return errors.New("release: toolchain must name Go and a digest-addressed builder")
	}
	if len(manifest.Artifacts) != len(initialArtifactMatrix) {
		return errors.New("release: manifest does not contain the exact initial artifact matrix")
	}
	if len(manifest.Evidence) == 0 || len(manifest.Evidence) > 32 {
		return errors.New("release: a bounded nonempty evidence list is required")
	}
	seenNames := make(map[string]struct{}, len(manifest.Artifacts)+len(manifest.Evidence))
	seenFiles := make(map[string]struct{}, len(manifest.Artifacts)+len(manifest.Evidence))
	for index, artifact := range manifest.Artifacts {
		if err := validateRecord(artifact.Name, artifact.File, artifact.SHA256, artifact.Size, seenNames, seenFiles); err != nil {
			return fmt.Errorf("release: artifact %d: %w", index, err)
		}
		expected, required := initialArtifactMatrix[artifact.Name]
		if !required {
			return fmt.Errorf("release: artifact %d is not in the initial artifact matrix", index)
		}
		if artifact.Name != initialArtifactOrder[index] {
			return fmt.Errorf("release: artifact %d is outside canonical matrix order", index)
		}
		if artifact.File != expected.File || artifact.OS != expected.OS || artifact.Arch != expected.Arch || artifact.Role != expected.Role || artifact.Format != expected.Format || artifact.SSHTarget != expected.SSHTarget {
			return fmt.Errorf("release: artifact %d does not match its required platform, role, format, or fixed target", index)
		}
		if !safeToken.MatchString(artifact.SBOM) {
			return fmt.Errorf("release: artifact %d has an invalid SBOM reference", index)
		}
	}

	evidenceByName := make(map[string]Evidence, len(manifest.Evidence))
	licenseRecords := 0
	projectLicenseRecords := 0
	provenanceRecords := 0
	previousEvidenceName := ""
	for index, evidence := range manifest.Evidence {
		if err := validateRecord(evidence.Name, evidence.File, evidence.SHA256, evidence.Size, seenNames, seenFiles); err != nil {
			return fmt.Errorf("release: evidence %d: %w", index, err)
		}
		if !validEvidenceKind(evidence.Kind) {
			return fmt.Errorf("release: evidence %d has an unsupported kind", index)
		}
		if index > 0 && evidence.Name <= previousEvidenceName {
			return fmt.Errorf("release: evidence %d is outside canonical name order", index)
		}
		previousEvidenceName = evidence.Name
		evidenceByName[evidence.Name] = evidence
		if evidence.Name == "third-party-licenses" && evidence.Kind == "licenses" {
			licenseRecords++
		}
		if evidence.Name == "project-license" && evidence.Kind == "project-license" && evidence.File == "LICENSE" {
			projectLicenseRecords++
		}
		if evidence.Name == "provenance" && evidence.Kind == "provenance" {
			provenanceRecords++
		}
	}
	if licenseRecords != 1 {
		return errors.New("release: exactly one third-party licenses evidence record is required")
	}
	if projectLicenseRecords != 1 {
		return errors.New("release: exactly one Apache-2.0 project license evidence record is required")
	}
	if provenanceRecords != 1 {
		return errors.New("release: exactly one provenance evidence record is required")
	}

	usedSBOMs := make(map[string]struct{}, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		evidence, exists := evidenceByName[artifact.SBOM]
		if !exists || evidence.Kind != "sbom" {
			return fmt.Errorf("release: artifact %d does not reference a named SBOM evidence record", index)
		}
		if _, reused := usedSBOMs[artifact.SBOM]; reused {
			return fmt.Errorf("release: artifact %d reuses another artifact's SBOM evidence record", index)
		}
		usedSBOMs[artifact.SBOM] = struct{}{}
	}
	for name, evidence := range evidenceByName {
		if evidence.Kind != "sbom" {
			continue
		}
		if _, used := usedSBOMs[name]; !used {
			return errors.New("release: unreferenced SBOM evidence record")
		}
	}
	return nil
}

func validateRecord(name, file, digest string, size int64, names, files map[string]struct{}) error {
	if !safeToken.MatchString(name) || !validRelativePath(file) || !validDigest(digest) || size <= 0 || size > 1<<40 {
		return errors.New("invalid name, file, digest, or size")
	}
	if _, exists := names[name]; exists {
		return errors.New("duplicate record name")
	}
	if _, exists := files[file]; exists {
		return errors.New("duplicate record file")
	}
	names[name] = struct{}{}
	files[file] = struct{}{}
	return nil
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if !safeToken.MatchString(component) || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validBuilderImage(value string) bool {
	if strings.Count(value, "@") != 1 {
		return false
	}
	image, digest, found := strings.Cut(value, "@sha256:")
	if !found || !validDigest(digest) {
		return false
	}
	registry, repository, found := strings.Cut(image, "/")
	if !found || !validRegistry(registry) || repository == "" {
		return false
	}
	for _, component := range strings.Split(repository, "/") {
		if !repositoryComponent.MatchString(component) {
			return false
		}
	}
	return true
}

func validRegistry(registry string) bool {
	host := registry
	hasPort := false
	if strings.Contains(registry, ":") {
		var portText string
		var found bool
		host, portText, found = strings.Cut(registry, ":")
		if !found || strings.Contains(portText, ":") {
			return false
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		hasPort = true
	}
	// A dot, explicit port, or the reserved local-registry name distinguishes
	// a registry from an implicit Docker Hub namespace.
	if host != "localhost" && !strings.Contains(host, ".") && !hasPort {
		return false
	}
	return validRegistryHost(host)
}

func validRegistryHost(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !isLowerAlphaNumeric(label[0]) || !isLowerAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !isLowerAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func isLowerAlphaNumeric(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')
}

func validEvidenceKind(kind string) bool {
	switch kind {
	case "sbom", "licenses", "project-license", "provenance", "package-payload", "test-report", "race-report", "vet-report", "vulnerability-report", "reproducibility-report", "platform-signature", "notarization":
		return true
	default:
		return false
	}
}
