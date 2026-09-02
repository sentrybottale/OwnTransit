//go:build darwin || linux

// Package packagetxn provides the privileged, offline transaction boundary
// beneath platform packaging. It deliberately does not bootstrap release
// trust; create or mutate users or groups; manage services; import images; or
// create, select, store, or edit any SSH material. Those are explicit,
// unimplemented integration gates rather than implied side effects.
package packagetxn

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/sentrybottale/owntransit/internal/release"
)

const decisionSeal = "owntransit authenticated package decision v1"

type decisionOperation string

const (
	operationInstall  decisionOperation = "install"
	operationRollback decisionOperation = "rollback"
)

// verification contains the already selected, independently trusted release
// key and target-local install policy required by release verification. The
// release key and policy must not come from the candidate bundle. This API
// remains package-private until verification, the external policy anchor and
// selector commit share one manager-bound compare-and-swap transaction.
type verification struct {
	BundleRoot    string
	ManifestBytes []byte
	Signature     []byte
	ReleaseKey    ed25519.PublicKey
	InstallPolicy release.InstallPolicy
	LocalOS       string
	LocalArch     string
	OwnerGID      uint32
	ReaderGID     uint32
}

// decision is an opaque capability produced only after the complete bundle,
// release signature, authenticated policy, floors, tombstones, platform, role,
// and selected artifact pass release.VerifyBundleForInstall. Its zero value is
// invalid and Install rejects it.
type decision struct {
	seal           string
	operation      decisionOperation
	bundleRoot     string
	releaseID      string
	sequence       uint64
	manifestSHA256 string
	role           string
	os             string
	arch           string
	files          []decisionFile
	anchorBefore   string
	anchorTarget   string
	policySHA256   string
}

type decisionFile struct {
	ArtifactName string
	SourcePath   string
	InstallName  string
	SHA256       string
	Size         int64
	Mode         fs.FileMode
	GID          uint32
}

// verifyDecision accepts no caller-supplied artifact hashes: file identity
// comes from the authenticated release manifest and policy decision. It is an
// internal construction helper, not an install authorization API; a stale or
// cross-root policy snapshot must never be passed directly to Manager.Install.
func verifyDecision(input verification) (decision, error) {
	if input.BundleRoot == "" || !filepath.IsAbs(input.BundleRoot) || filepath.Clean(input.BundleRoot) != input.BundleRoot || input.BundleRoot == string(filepath.Separator) {
		return decision{}, errors.New("packagetxn: bundle root must be a canonical absolute non-root path")
	}
	verified, selected, err := release.VerifyBundleForInstall(
		input.BundleRoot,
		input.ManifestBytes,
		input.Signature,
		input.ReleaseKey,
		input.InstallPolicy,
	)
	if err != nil {
		return decision{}, fmt.Errorf("packagetxn: authenticate release decision: %w", err)
	}
	localOS, localArch := input.LocalOS, input.LocalArch
	if localOS == "" {
		localOS = runtime.GOOS
	}
	if localArch == "" {
		localArch = runtime.GOARCH
	}
	if selected.OS != localOS || selected.Arch != localArch {
		return decision{}, errors.New("packagetxn: authenticated artifact does not match the local platform")
	}

	primaryName, primaryMode, primaryGID, needsLifecycle, err := primaryInstallProfile(selected, input.OwnerGID, input.ReaderGID)
	if err != nil {
		return decision{}, err
	}
	files := []decisionFile{artifactDecisionFile(selected, primaryName, primaryMode, primaryGID)}
	if selected.Role == "client" && selected.OS == "linux" {
		files = append(files, artifactDecisionFile(selected, "owntransit-proxy", fs.ModeSetgid|0o750, input.ReaderGID))
	}
	if needsLifecycle {
		var lifecycle *release.Artifact
		for index := range verified.Manifest.Artifacts {
			candidate := &verified.Manifest.Artifacts[index]
			if candidate.Role != "lifecycle" || candidate.OS != selected.OS || candidate.Arch != selected.Arch {
				continue
			}
			if lifecycle != nil {
				return decision{}, errors.New("packagetxn: release has multiple matching lifecycle artifacts")
			}
			lifecycle = candidate
		}
		if lifecycle == nil {
			return decision{}, errors.New("packagetxn: release has no matching lifecycle artifact")
		}
		if lifecycle.Format != release.ArtifactFormatExecutable {
			return decision{}, errors.New("packagetxn: lifecycle artifact is not executable")
		}
		files = append(files, artifactDecisionFile(*lifecycle, "owntransitctl", 0o700, input.OwnerGID))
	}
	if selected.Role == "client" && selected.OS == "darwin" {
		var launcher *release.Artifact
		for index := range verified.Manifest.Artifacts {
			candidate := &verified.Manifest.Artifacts[index]
			if candidate.Role == "launcher" && candidate.OS == selected.OS && candidate.Arch == selected.Arch {
				if launcher != nil {
					return decision{}, errors.New("packagetxn: release has multiple matching client launchers")
				}
				launcher = candidate
			}
		}
		if launcher == nil || launcher.Format != release.ArtifactFormatExecutable {
			return decision{}, errors.New("packagetxn: release has no matching executable client launcher")
		}
		files = append(files, artifactDecisionFile(*launcher, "owntransit", fs.ModeSetgid|0o751, input.ReaderGID))
	}
	licenseEvidence := []struct {
		name        string
		kind        string
		installName string
	}{
		{name: "project-license", kind: "project-license", installName: "LICENSE"},
		{name: "third-party-licenses", kind: "licenses", installName: "THIRD_PARTY_LICENSES.txt"},
	}
	for _, required := range licenseEvidence {
		var evidence *release.Evidence
		for index := range verified.Manifest.Evidence {
			candidate := &verified.Manifest.Evidence[index]
			if candidate.Name == required.name {
				evidence = candidate
				break
			}
		}
		if evidence == nil || evidence.Kind != required.kind {
			return decision{}, errors.New("packagetxn: authenticated release license evidence is incomplete")
		}
		files = append(files, evidenceDecisionFile(*evidence, required.installName, input.OwnerGID))
	}
	sort.Slice(files, func(left, right int) bool { return files[left].InstallName < files[right].InstallName })
	if err := validateDecisionFiles(files); err != nil {
		return decision{}, err
	}

	manifestDigest := sha256.Sum256(input.ManifestBytes)
	return decision{
		seal:           decisionSeal,
		operation:      operationInstall,
		bundleRoot:     input.BundleRoot,
		releaseID:      verified.Manifest.ReleaseID,
		sequence:       verified.Manifest.Sequence,
		manifestSHA256: hex.EncodeToString(manifestDigest[:]),
		role:           selected.Role,
		os:             selected.OS,
		arch:           selected.Arch,
		files:          files,
	}, nil
}

func evidenceDecisionFile(evidence release.Evidence, installName string, gid uint32) decisionFile {
	return decisionFile{
		ArtifactName: evidence.Name,
		SourcePath:   evidence.File,
		InstallName:  installName,
		SHA256:       evidence.SHA256,
		Size:         evidence.Size,
		Mode:         0o644,
		GID:          gid,
	}
}

func primaryInstallProfile(artifact release.Artifact, ownerGID, readerGID uint32) (string, fs.FileMode, uint32, bool, error) {
	switch artifact.Role {
	case "client":
		if artifact.Format != release.ArtifactFormatExecutable {
			return "", 0, 0, false, errors.New("packagetxn: client artifact is not executable")
		}
		if readerGID == 0 {
			return "", 0, 0, false, errors.New("packagetxn: client reader GID is required")
		}
		if artifact.OS == "darwin" {
			return "owntransit-real", 0o750, readerGID, true, nil
		}
		return "owntransit", 0o755, ownerGID, true, nil
	case "connector":
		if artifact.Format != release.ArtifactFormatExecutable {
			return "", 0, 0, false, errors.New("packagetxn: connector artifact is not executable")
		}
		if readerGID == 0 {
			return "", 0, 0, false, errors.New("packagetxn: connector reader GID is required")
		}
		return "owntransit-connector", 0o750, readerGID, true, nil
	case "relay":
		if artifact.Format != release.ArtifactFormatOCI {
			return "", 0, 0, false, errors.New("packagetxn: relay artifact is not OCI")
		}
		return "owntransit-relay.oci.tar", 0o600, ownerGID, true, nil
	case "provisioner":
		if artifact.Format != release.ArtifactFormatExecutable {
			return "", 0, 0, false, errors.New("packagetxn: provisioner artifact is not executable")
		}
		// The provisioner itself remains an ordinary on-demand executable. The
		// authenticated owntransitctl copy is installed only to bind future
		// package apply/rollback/recovery to this role's current selector.
		return "owntransit-provision", 0o755, ownerGID, true, nil
	default:
		return "", 0, 0, false, errors.New("packagetxn: selected release role is unsupported")
	}
}

func artifactDecisionFile(artifact release.Artifact, installName string, mode fs.FileMode, gid uint32) decisionFile {
	return decisionFile{
		ArtifactName: artifact.Name,
		SourcePath:   artifact.File,
		InstallName:  installName,
		SHA256:       artifact.SHA256,
		Size:         artifact.Size,
		Mode:         mode,
		GID:          gid,
	}
}

func validateDecisionFiles(files []decisionFile) error {
	if len(files) == 0 || len(files) > 8 {
		return errors.New("packagetxn: authenticated file set is empty or too large")
	}
	for index, file := range files {
		if !validToken(file.ArtifactName) || !validRelativePath(file.SourcePath) || !validComponent(file.InstallName) ||
			!validDigest(file.SHA256) || file.Size <= 0 || file.Size > 1<<40 || !validInstallMode(file.Mode) ||
			(file.Mode&fs.ModeSetgid != 0 && file.GID == 0) {
			return errors.New("packagetxn: authenticated file record is invalid")
		}
		if file.InstallName == receiptFileName || file.InstallName == receiptStageName {
			return errors.New("packagetxn: authenticated file name is reserved")
		}
		if index > 0 && files[index-1].InstallName >= file.InstallName {
			return errors.New("packagetxn: authenticated file names are not unique and sorted")
		}
	}
	return nil
}

func rollbackDecisionFromReceipt(receipt receiptRecord, anchorBefore, anchorTarget, policySHA256 string) (decision, error) {
	return decisionFromReceipt(operationRollback, receipt, anchorBefore, anchorTarget, policySHA256)
}

func decisionFromReceipt(operation decisionOperation, receipt receiptRecord, anchorBefore, anchorTarget, policySHA256 string) (decision, error) {
	if err := validateReceipt(receipt); err != nil {
		return decision{}, err
	}
	files := make([]decisionFile, len(receipt.Files))
	for index, file := range receipt.Files {
		files[index] = decisionFile{
			ArtifactName: file.ArtifactName, SourcePath: file.Name, InstallName: file.Name,
			SHA256: file.SHA256, Size: file.Size, Mode: decodeInstallMode(file.Mode), GID: file.GID,
		}
	}
	result := decision{
		seal: decisionSeal, operation: operation, releaseID: receipt.ReleaseID,
		sequence: receipt.Sequence, manifestSHA256: receipt.ManifestSHA256,
		role: receipt.Role, os: receipt.OS, arch: receipt.Arch, files: files,
		anchorBefore: anchorBefore, anchorTarget: anchorTarget, policySHA256: policySHA256,
	}
	if operation == operationInstall {
		// Recovery reaches this construction only after the complete release was
		// durably staged. Resume never opens this sentinel path.
		result.bundleRoot = "/unavailable-after-authenticated-staging"
	}
	if err := validateDecision(result); err != nil {
		return decision{}, err
	}
	return result, nil
}
