//go:build darwin || linux

package packagetxn

import (
	"errors"
	"fmt"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func emptyPackageAnchor(role string) packageAnchor {
	return packageAnchor{Schema: packageAnchorSchema, Role: role}
}

func encodePackageAnchor(anchor packageAnchor) ([]byte, error) {
	if err := validatePackageAnchor(anchor); err != nil {
		return nil, err
	}
	return encodeCanonical(anchor)
}

func validatePackageAnchor(anchor packageAnchor) error {
	if anchor.Schema != packageAnchorSchema || !validRole(anchor.Role) || anchor.Role == "provisioner" {
		return errors.New("packagetxn: package anchor identity is invalid")
	}
	if anchor.Generation == 0 {
		if anchor.PreviousSHA256 != "" || anchor.PolicyKeyID != "" || anchor.PolicySHA256 != "" || anchor.ReleaseKeyID != "" ||
			anchor.HighestPolicySequence != 0 || anchor.MinimumReleaseSequence != 0 || anchor.MinimumLifecycle != 0 ||
			len(anchor.TombstonedReleaseIDs) != 0 || anchor.HighestReleaseSequence != 0 || anchor.SelectorGeneration != 0 ||
			anchor.CurrentReleaseID != "" || anchor.CurrentReceiptSHA256 != "" || anchor.PreviousReleaseID != "" || anchor.PreviousReceiptSHA256 != "" {
			return errors.New("packagetxn: empty package anchor contains state")
		}
		return nil
	}
	if !validDigest(anchor.PreviousSHA256) || !validDigest(anchor.PolicySHA256) ||
		signing.ValidateKeyID(anchor.PolicyKeyID) != nil || signing.ValidateKeyID(anchor.ReleaseKeyID) != nil ||
		anchor.HighestPolicySequence == 0 || anchor.MinimumReleaseSequence == 0 || anchor.MinimumLifecycle == 0 ||
		anchor.HighestReleaseSequence == 0 || anchor.SelectorGeneration == 0 ||
		!validReleaseID(anchor.CurrentReleaseID) || !validDigest(anchor.CurrentReceiptSHA256) {
		return errors.New("packagetxn: package anchor is incomplete")
	}
	if (anchor.PreviousReleaseID == "") != (anchor.PreviousReceiptSHA256 == "") {
		return errors.New("packagetxn: package anchor previous release is incomplete")
	}
	if anchor.PreviousReleaseID != "" && (!validReleaseID(anchor.PreviousReleaseID) || !validDigest(anchor.PreviousReceiptSHA256) || anchor.PreviousReleaseID == anchor.CurrentReleaseID) {
		return errors.New("packagetxn: package anchor previous release is invalid")
	}
	if len(anchor.TombstonedReleaseIDs) > 4096 {
		return errors.New("packagetxn: package anchor has too many tombstones")
	}
	previous := ""
	for index, releaseID := range anchor.TombstonedReleaseIDs {
		parsed, err := protocol.ParseID(releaseID)
		if err != nil || parsed == (protocol.ID{}) || (index > 0 && releaseID <= previous) {
			return errors.New("packagetxn: package anchor tombstones are invalid or noncanonical")
		}
		previous = releaseID
	}
	return nil
}

func (manager *Manager) readPackageAnchor(anchorRoleFD int) (packageAnchor, []byte, string, error) {
	if err := removeAuthorizedStage(anchorRoleFD, packageAnchorStageName, manager); err != nil {
		return packageAnchor{}, nil, "", err
	}
	contents, exists, err := readOptionalExactFile(anchorRoleFD, packageAnchorFileName, 0o600, maximumMetadataSize, manager)
	if err != nil {
		return packageAnchor{}, nil, "", err
	}
	allowed := map[string]struct{}{packageAnchorLockFileName: {}}
	if exists {
		allowed[packageAnchorFileName] = struct{}{}
	}
	if err := requireAllowedDirectoryEntries(anchorRoleFD, allowed, "rollback-anchor role"); err != nil {
		return packageAnchor{}, nil, "", err
	}
	if !exists {
		anchor := emptyPackageAnchor(manager.role)
		encoded, err := encodePackageAnchor(anchor)
		if err != nil {
			return packageAnchor{}, nil, "", err
		}
		return anchor, encoded, digestBytes(encoded), nil
	}
	var anchor packageAnchor
	if err := decodeCanonical(contents, &anchor, encodePackageAnchor); err != nil {
		return packageAnchor{}, nil, "", fmt.Errorf("%w: package anchor: %v", ErrResidue, err)
	}
	if anchor.Role != manager.role {
		return packageAnchor{}, nil, "", fmt.Errorf("%w: package anchor belongs to another role", ErrResidue)
	}
	return anchor, contents, digestBytes(contents), nil
}

func (manager *Manager) replacePackageAnchor(anchorRoleFD int, contents []byte) error {
	var anchor packageAnchor
	if err := decodeCanonical(contents, &anchor, encodePackageAnchor); err != nil {
		return fmt.Errorf("packagetxn: replacement package anchor: %w", err)
	}
	if anchor.Role != manager.role {
		return errors.New("packagetxn: replacement package anchor belongs to another role")
	}
	return replaceCanonicalFile(anchorRoleFD, packageAnchorFileName, packageAnchorStageName, contents, manager)
}

func validateAnchorAgainstSnapshot(anchor packageAnchor, anchorDigest string, state transactionState) error {
	if !validDigest(anchorDigest) {
		return errors.New("packagetxn: external anchor digest is invalid")
	}
	selectorMatches := anchor.SelectorGeneration == state.selector.Generation &&
		anchor.CurrentReleaseID == state.selector.Current && anchor.CurrentReceiptSHA256 == state.selector.CurrentReceiptSHA256 &&
		anchor.PreviousReleaseID == state.selector.Previous && anchor.PreviousReceiptSHA256 == state.selector.PreviousReceiptSHA256
	if anchor.Generation == 0 {
		selectorMatches = state.selector.Generation == 0
	}
	if selectorMatches {
		return nil
	}
	if state.journal == nil || state.journal.Phase == phaseComplete || state.journal.AnchorTargetSHA256 != anchorDigest ||
		anchor.SelectorGeneration != state.journal.Target.Generation || anchor.CurrentReleaseID != state.journal.Target.Current ||
		anchor.CurrentReceiptSHA256 != state.journal.Target.CurrentReceiptSHA256 || anchor.PreviousReleaseID != state.journal.Target.Previous ||
		anchor.PreviousReceiptSHA256 != state.journal.Target.PreviousReceiptSHA256 {
		return errors.New("packagetxn: external rollback anchor and package selector disagree")
	}
	return nil
}
