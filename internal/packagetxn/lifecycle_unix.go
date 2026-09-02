//go:build darwin || linux

package packagetxn

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sentrybottale/owntransit/internal/release"
	"github.com/sentrybottale/owntransit/internal/signing"
	"golang.org/x/sys/unix"
)

const (
	packageAnchorSchema               = "owntransit.package-anchor.v1"
	packageAnchorFileName             = "anchor.json"
	packageAnchorStageName            = ".anchor.stage"
	packageAnchorLockFileName         = "anchor.lock"
	packageLifecycleGeneration uint64 = 1
)

// ApplyInput contains only independently obtained release and policy material.
// Neither signer key may be loaded from the candidate bundle or relay.
type ApplyInput struct {
	BundleRoot        string
	ManifestBytes     []byte
	ManifestSignature []byte
	ReleaseKey        ed25519.PublicKey
	PolicyBytes       []byte
	PolicySignature   []byte
	PolicyKey         ed25519.PublicKey
}

// RollbackInput selects the exact retained previous release. The currently
// committed signed policy remains authoritative for floors and tombstones.
type RollbackInput struct {
	ToReleaseID string
}

type packageMeasurement struct {
	Path   string
	SHA256 string
	Size   int64
}

type packageAnchor struct {
	Schema                 string   `json:"schema"`
	Generation             uint64   `json:"generation"`
	Role                   string   `json:"role"`
	PreviousSHA256         string   `json:"previous_sha256,omitempty"`
	PolicyKeyID            string   `json:"policy_key_id,omitempty"`
	PolicySHA256           string   `json:"policy_sha256,omitempty"`
	ReleaseKeyID           string   `json:"release_key_id,omitempty"`
	HighestPolicySequence  uint64   `json:"highest_policy_sequence"`
	MinimumReleaseSequence uint64   `json:"minimum_release_sequence"`
	MinimumLifecycle       uint64   `json:"minimum_lifecycle"`
	TombstonedReleaseIDs   []string `json:"tombstoned_release_ids"`
	HighestReleaseSequence uint64   `json:"highest_release_sequence"`
	SelectorGeneration     uint64   `json:"selector_generation"`
	CurrentReleaseID       string   `json:"current_release_id,omitempty"`
	CurrentReceiptSHA256   string   `json:"current_receipt_sha256,omitempty"`
	PreviousReleaseID      string   `json:"previous_release_id,omitempty"`
	PreviousReceiptSHA256  string   `json:"previous_receipt_sha256,omitempty"`
}

type lifecycleSnapshot struct {
	state           transactionState
	currentReceipt  *receiptRecord
	previousReceipt *receiptRecord
	runningReceipt  *receiptRecord
}

// OpenLifecycle opens a package root together with a distinct, independently
// protected rollback-anchor root. All supported package mutations use both.
// Online roles require their dedicated non-root runtime reader GID. The
// offline provisioner has no runtime reader and therefore requires readerGID
// zero; its manager controls only the signed software package lifecycle.
func OpenLifecycle(packageRoot, rollbackAnchorRoot, role string, readerGID int) (*Manager, error) {
	if unix.Geteuid() != 0 {
		return nil, errors.New("packagetxn: lifecycle manager requires root")
	}
	if role == "provisioner" {
		if readerGID != 0 {
			return nil, errors.New("packagetxn: provisioner package lifecycle has no runtime reader GID")
		}
	} else if readerGID <= 0 || uint64(readerGID) >= 1<<32 {
		return nil, errors.New("packagetxn: a dedicated non-root runtime reader GID is required")
	}
	manager, err := openLifecycleManager(packageRoot, rollbackAnchorRoot, role, 0, 0, true, verifyPackageACL)
	if err != nil {
		return nil, err
	}
	manager.readerGID = uint32(readerGID)
	return manager, nil
}

func openLifecycleManager(packageRoot, rollbackAnchorRoot, role string, ownerUID, ownerGID uint32, strictRoot bool, aclCheck func(int, bool) error) (*Manager, error) {
	if nestedPath(packageRoot, rollbackAnchorRoot) || nestedPath(rollbackAnchorRoot, packageRoot) {
		return nil, errors.New("packagetxn: package and rollback-anchor roots must not contain one another")
	}
	manager, err := openManager(packageRoot, role, ownerUID, ownerGID, strictRoot, aclCheck)
	if err != nil {
		return nil, err
	}
	anchorFD, err := openRootChain(rollbackAnchorRoot, ownerUID, ownerGID, 0o700, strictRoot, aclCheck)
	if err != nil {
		_ = manager.Close()
		return nil, fmt.Errorf("packagetxn: open rollback-anchor root: %w", err)
	}
	var packageStat, anchorStat unix.Stat_t
	if err := unix.Fstat(manager.rootFD, &packageStat); err != nil {
		_ = unix.Close(anchorFD)
		_ = manager.Close()
		return nil, fmt.Errorf("packagetxn: inspect package root: %w", err)
	}
	if err := unix.Fstat(anchorFD, &anchorStat); err != nil {
		_ = unix.Close(anchorFD)
		_ = manager.Close()
		return nil, fmt.Errorf("packagetxn: inspect rollback-anchor root: %w", err)
	}
	if packageStat.Dev == anchorStat.Dev && packageStat.Ino == anchorStat.Ino {
		_ = unix.Close(anchorFD)
		_ = manager.Close()
		return nil, errors.New("packagetxn: rollback anchor must be outside the package root")
	}
	manager.anchorFD = anchorFD
	manager.anchorDevice = uint64(anchorStat.Dev)
	manager.hasAnchor = true
	manager.runningMeasurement = measureRunningExecutable
	manager.enforceExecutablePath = strictRoot
	return manager, nil
}

// Apply verifies the exact signed bundle and monotonic policy while both the
// external anchor and role transaction locks are held. The anchor compare-and-
// swap is the selector's mandatory publication gate.
func (manager *Manager) Apply(input ApplyInput) (Result, error) {
	return manager.apply(input, false)
}

// PreflightApply runs the exact Apply decision path through executable
// measurement and anchor construction without publishing package state. A
// service supervisor uses it before stopping a live role; Apply repeats every
// check after the stop and remains the only mutation entry point.
func (manager *Manager) PreflightApply(input ApplyInput) error {
	_, err := manager.apply(input, true)
	return err
}

func (manager *Manager) apply(input ApplyInput, preflight bool) (Result, error) {
	if err := manager.requireLifecycleManager(); err != nil {
		return Result{}, err
	}
	anchorRoleFD, anchorLock, err := manager.lockAnchorRole()
	if err != nil {
		return Result{}, err
	}
	defer unix.Close(anchorRoleFD)
	defer anchorLock.close()

	anchor, _, anchorDigest, err := manager.readPackageAnchor(anchorRoleFD)
	if err != nil {
		return Result{}, err
	}
	snapshot, err := manager.readLifecycleSnapshot()
	if err != nil {
		return Result{}, err
	}
	if err := validateAnchorAgainstSnapshot(anchor, anchorDigest, snapshot.state); err != nil {
		return Result{}, err
	}

	verifiedPolicy, policyAdvanced, policyDigest, err := verifyPolicyForPackageAnchor(input, anchor)
	if err != nil {
		return Result{}, err
	}
	artifactName, err := artifactNameForRole(manager.role, manager.platformOS, manager.platformArch)
	if err != nil {
		return Result{}, err
	}
	installPolicy := release.InstallPolicy{
		HighestSequence:  anchor.HighestReleaseSequence,
		RunningLifecycle: packageLifecycleGeneration,
		ArtifactName:     artifactName, ExpectedOS: manager.platformOS, ExpectedArch: manager.platformArch,
		ExpectedRole: manager.role, TombstonedReleaseIDs: append([]string(nil), anchor.TombstonedReleaseIDs...),
		VerifiedReleasePolicy: &verifiedPolicy,
	}
	if anchor.CurrentReleaseID != "" {
		installPolicy.ExactReplayReleaseID = anchor.CurrentReleaseID
	}
	decision, err := verifyDecision(verification{
		BundleRoot: input.BundleRoot, ManifestBytes: input.ManifestBytes, Signature: input.ManifestSignature,
		ReleaseKey: input.ReleaseKey, InstallPolicy: installPolicy, LocalOS: manager.platformOS, LocalArch: manager.platformArch,
		OwnerGID: manager.ownerGID, ReaderGID: manager.readerGID,
	})
	if err != nil {
		return Result{}, err
	}
	if signing.KeyID(input.PolicyKey) != anchorPolicyKeyID(anchor, input.PolicyKey) {
		return Result{}, errors.New("packagetxn: release-policy signer differs from the pinned anchor")
	}
	if err := manager.verifyRunningLifecycle(snapshot, decision); err != nil {
		return Result{}, err
	}

	receipt, _, receiptDigest, err := receiptForDecision(decision)
	if err != nil {
		return Result{}, err
	}
	_ = receipt
	if snapshot.state.journal != nil && snapshot.state.journal.Phase != phaseComplete {
		journal := *snapshot.state.journal
		decision.policySHA256 = journal.PolicySHA256
		decision.anchorBefore = journal.AnchorBeforeSHA256
		decision.anchorTarget = journal.AnchorTargetSHA256
		if !journalMatchesDecision(journal, decision, receiptDigest) {
			return Result{}, fmt.Errorf("%w: signed input does not match the interrupted package transaction", ErrResidue)
		}
		if policyDigest != journal.PolicySHA256 {
			return Result{}, errors.New("packagetxn: interrupted transaction requires the exact signed policy bytes")
		}
		if anchorDigest != journal.AnchorBeforeSHA256 && anchorDigest != journal.AnchorTargetSHA256 {
			return Result{}, errors.New("packagetxn: interrupted transaction does not match the external anchor")
		}
		var targetAnchor packageAnchor
		if anchorDigest == journal.AnchorTargetSHA256 {
			targetAnchor = anchor
		} else {
			targetAnchor, err = targetAnchorForInstall(anchor, verifiedPolicy, policyDigest, signing.KeyID(input.PolicyKey), journal.Target, decision)
			if err != nil {
				return Result{}, err
			}
			if digestPackageAnchor(targetAnchor) != journal.AnchorTargetSHA256 {
				return Result{}, errors.New("packagetxn: reconstructed anchor differs from the interrupted transaction")
			}
		}
		gate := manager.anchorGate(anchorRoleFD, anchorDigest, targetAnchor)
		if preflight {
			return Result{}, nil
		}
		return manager.install(decision, manager.failureHook, gate)
	}

	if snapshot.state.selector.Current == decision.releaseID {
		if policyAdvanced || policyDigest != anchor.PolicySHA256 {
			return Result{}, errors.New("packagetxn: policy-only advancement requires a distinct authenticated release transaction")
		}
		if snapshot.state.journal == nil || snapshot.state.journal.Phase != phaseComplete {
			return Result{}, fmt.Errorf("%w: installed release has no complete journal", ErrResidue)
		}
		decision.policySHA256 = snapshot.state.journal.PolicySHA256
		decision.anchorBefore = snapshot.state.journal.AnchorBeforeSHA256
		decision.anchorTarget = snapshot.state.journal.AnchorTargetSHA256
		if preflight {
			return Result{}, nil
		}
		return manager.install(decision, manager.failureHook, manager.anchorGate(anchorRoleFD, anchorDigest, anchor))
	}

	if snapshot.state.selector.Generation == ^uint64(0) {
		return Result{}, fmt.Errorf("%w: selector generation is exhausted", ErrResidue)
	}
	targetSelector := selectorRecord{
		Schema: selectorSchema, Generation: snapshot.state.selector.Generation + 1,
		Current: decision.releaseID, CurrentReceiptSHA256: receiptDigest,
		Previous: snapshot.state.selector.Current, PreviousReceiptSHA256: snapshot.state.selector.CurrentReceiptSHA256,
	}
	targetAnchor, err := targetAnchorForInstall(anchor, verifiedPolicy, policyDigest, signing.KeyID(input.PolicyKey), targetSelector, decision)
	if err != nil {
		return Result{}, err
	}
	targetBytes, err := encodePackageAnchor(targetAnchor)
	if err != nil {
		return Result{}, err
	}
	decision.policySHA256 = policyDigest
	decision.anchorBefore = anchorDigest
	decision.anchorTarget = digestBytes(targetBytes)
	gate := manager.anchorGate(anchorRoleFD, anchorDigest, targetAnchor)
	if preflight {
		return Result{}, nil
	}
	return manager.install(decision, manager.failureHook, gate)
}

// Rollback atomically swaps to the exact retained previous release only when
// the committed external anchor still authorizes its sequence and ID.
func (manager *Manager) Rollback(input RollbackInput) (Result, error) {
	return manager.rollback(input, false)
}

// PreflightRollback runs the exact Rollback decision path without publishing
// package state so a live role is not stopped for an invalid rollback request.
func (manager *Manager) PreflightRollback(input RollbackInput) error {
	_, err := manager.rollback(input, true)
	return err
}

func (manager *Manager) rollback(input RollbackInput, preflight bool) (Result, error) {
	if err := manager.requireLifecycleManager(); err != nil {
		return Result{}, err
	}
	anchorRoleFD, anchorLock, err := manager.lockAnchorRole()
	if err != nil {
		return Result{}, err
	}
	defer unix.Close(anchorRoleFD)
	defer anchorLock.close()
	anchor, _, anchorDigest, err := manager.readPackageAnchor(anchorRoleFD)
	if err != nil {
		return Result{}, err
	}
	snapshot, err := manager.readLifecycleSnapshot()
	if err != nil {
		return Result{}, err
	}
	if err := validateAnchorAgainstSnapshot(anchor, anchorDigest, snapshot.state); err != nil {
		return Result{}, err
	}
	if snapshot.state.journal == nil || snapshot.state.journal.Phase != phaseComplete {
		return Result{}, errors.New("packagetxn: interrupted transaction must be recovered before rollback")
	}
	if snapshot.previousReceipt == nil || input.ToReleaseID == "" || input.ToReleaseID != snapshot.state.selector.Previous || input.ToReleaseID != anchor.PreviousReleaseID {
		return Result{}, errors.New("packagetxn: rollback target must be the exact retained previous release")
	}
	if snapshot.previousReceipt.Sequence < anchor.MinimumReleaseSequence || packageLifecycleGeneration < anchor.MinimumLifecycle {
		return Result{}, errors.New("packagetxn: retained release is below an authenticated rollback floor")
	}
	for _, tombstone := range anchor.TombstonedReleaseIDs {
		if tombstone == input.ToReleaseID {
			return Result{}, errors.New("packagetxn: retained release is tombstoned")
		}
	}
	if err := manager.verifyRunningLifecycle(snapshot, decision{}); err != nil {
		return Result{}, err
	}
	if snapshot.state.selector.Generation == ^uint64(0) || anchor.Generation == ^uint64(0) {
		return Result{}, fmt.Errorf("%w: lifecycle generation is exhausted", ErrResidue)
	}
	targetSelector := selectorRecord{
		Schema: selectorSchema, Generation: snapshot.state.selector.Generation + 1,
		Current: snapshot.state.selector.Previous, CurrentReceiptSHA256: snapshot.state.selector.PreviousReceiptSHA256,
		Previous: snapshot.state.selector.Current, PreviousReceiptSHA256: snapshot.state.selector.CurrentReceiptSHA256,
	}
	targetAnchor := anchor
	targetAnchor.Generation++
	targetAnchor.PreviousSHA256 = anchorDigest
	targetAnchor.SelectorGeneration = targetSelector.Generation
	targetAnchor.CurrentReleaseID = targetSelector.Current
	targetAnchor.CurrentReceiptSHA256 = targetSelector.CurrentReceiptSHA256
	targetAnchor.PreviousReleaseID = targetSelector.Previous
	targetAnchor.PreviousReceiptSHA256 = targetSelector.PreviousReceiptSHA256
	targetBytes, err := encodePackageAnchor(targetAnchor)
	if err != nil {
		return Result{}, err
	}
	decision, err := rollbackDecisionFromReceipt(*snapshot.previousReceipt, anchorDigest, digestBytes(targetBytes), anchor.PolicySHA256)
	if err != nil {
		return Result{}, err
	}
	if preflight {
		return Result{}, nil
	}
	return manager.install(decision, manager.failureHook, manager.anchorGate(anchorRoleFD, anchorDigest, targetAnchor))
}

// Recover completes only a transaction whose external anchor already contains
// the exact journal target. Pre-anchor interruptions still require Apply with
// the original signed bundle and policy bytes.
func (manager *Manager) Recover() (Result, error) {
	return manager.recover(false)
}

// PreflightRecover runs the exact Recover decision path without publishing
// package state so a live role is not stopped for unrecoverable residue.
func (manager *Manager) PreflightRecover() error {
	_, err := manager.recover(true)
	return err
}

func (manager *Manager) recover(preflight bool) (Result, error) {
	if err := manager.requireLifecycleManager(); err != nil {
		return Result{}, err
	}
	anchorRoleFD, anchorLock, err := manager.lockAnchorRole()
	if err != nil {
		return Result{}, err
	}
	defer unix.Close(anchorRoleFD)
	defer anchorLock.close()
	anchor, _, anchorDigest, err := manager.readPackageAnchor(anchorRoleFD)
	if err != nil {
		return Result{}, err
	}
	snapshot, err := manager.readLifecycleSnapshot()
	if err != nil {
		return Result{}, err
	}
	if err := validateAnchorAgainstSnapshot(anchor, anchorDigest, snapshot.state); err != nil {
		return Result{}, err
	}
	if snapshot.state.journal == nil || snapshot.state.journal.Phase == phaseComplete {
		if snapshot.currentReceipt != nil {
			if err := manager.verifyRunningLifecycle(snapshot, decision{}); err != nil {
				return Result{}, err
			}
		}
		return resultFromSelector(manager, snapshot.state.selector, snapshot.currentReceipt, false, false, true)
	}
	journal := *snapshot.state.journal
	if journal.Phase == phasePlanned || journal.AnchorTargetSHA256 != anchorDigest || journal.PolicySHA256 != anchor.PolicySHA256 || anchor.PreviousSHA256 != journal.AnchorBeforeSHA256 {
		return Result{}, errors.New("packagetxn: original signed input is required before external-anchor commitment")
	}
	if err := manager.verifyRunningLifecycle(snapshot, decision{}); err != nil {
		return Result{}, err
	}
	receipt, receiptDigest, err := manager.readLifecycleReceipt(journal.ReleaseID)
	if err != nil {
		return Result{}, err
	}
	if receiptDigest != journal.ReceiptSHA256 || receipt.Sequence != journal.Sequence || receipt.ManifestSHA256 != journal.ManifestSHA256 {
		return Result{}, fmt.Errorf("%w: recovery receipt differs from the journal", ErrResidue)
	}
	decision, err := decisionFromReceipt(journal.Operation, receipt, journal.AnchorBeforeSHA256, journal.AnchorTargetSHA256, journal.PolicySHA256)
	if err != nil {
		return Result{}, err
	}
	if preflight {
		return Result{}, nil
	}
	return manager.install(decision, manager.failureHook, manager.anchorGate(anchorRoleFD, journal.AnchorBeforeSHA256, anchor))
}

func (manager *Manager) requireLifecycleManager() error {
	if manager == nil || manager.self != manager || !manager.open || !manager.hasAnchor || manager.anchorFD < 0 || manager.runningMeasurement == nil {
		return errors.New("packagetxn: complete lifecycle manager is required")
	}
	return nil
}

func (manager *Manager) lockAnchorRole() (int, *descriptorLock, error) {
	roleFD, err := ensurePrivateDirectory(manager.anchorFD, manager.role, manager.ownerUID, manager.ownerGID, manager.anchorDevice, manager.checkACL)
	if err != nil {
		return -1, nil, err
	}
	lock, err := acquireDescriptorLock(roleFD, packageAnchorLockFileName, manager.ownerUID, manager.ownerGID, manager.checkACL, nil)
	if err != nil {
		_ = unix.Close(roleFD)
		return -1, nil, err
	}
	return roleFD, lock, nil
}

func (manager *Manager) readLifecycleSnapshot() (lifecycleSnapshot, error) {
	roleFD, err := ensurePackageDirectory(manager.rootFD, manager.role, manager)
	if err != nil {
		return lifecycleSnapshot{}, err
	}
	defer unix.Close(roleFD)
	roleLock, err := acquireDescriptorLock(roleFD, lockFileName, manager.ownerUID, manager.ownerGID, manager.checkACL, manager.lockOpenHook)
	if err != nil {
		return lifecycleSnapshot{}, err
	}
	defer roleLock.close()
	return manager.readLifecycleSnapshotLocked(roleFD)
}

// readLifecycleSnapshotLocked requires the caller to hold the descriptor-bound
// role transaction lock for roleFD. Keeping the lock outside this helper lets a
// narrowly scoped reader keep one exact selector stable while it performs the
// local operation that consumes the returned runtime identity.
func (manager *Manager) readLifecycleSnapshotLocked(roleFD int) (lifecycleSnapshot, error) {
	releasesFD, err := ensurePackageDirectory(roleFD, releasesDirectory, manager)
	if err != nil {
		return lifecycleSnapshot{}, err
	}
	defer unix.Close(releasesFD)
	state, err := inspectTransactionState(roleFD, releasesFD, manager)
	if err != nil {
		return lifecycleSnapshot{}, err
	}
	result := lifecycleSnapshot{state: state}
	if state.selector.Current != "" {
		receipt, _, _, err := loadAndVerifyRelease(releasesFD, state.selector.Current, manager)
		if err != nil {
			return lifecycleSnapshot{}, err
		}
		result.currentReceipt = &receipt
	}
	if state.selector.Previous != "" {
		receipt, _, _, err := loadAndVerifyRelease(releasesFD, state.selector.Previous, manager)
		if err != nil {
			return lifecycleSnapshot{}, err
		}
		result.previousReceipt = &receipt
	}
	if state.activeReleaseID != "" {
		receipt, _, _, err := loadAndVerifyRelease(releasesFD, state.activeReleaseID, manager)
		if err != nil {
			return lifecycleSnapshot{}, err
		}
		result.runningReceipt = &receipt
	}
	return result, nil
}

func (manager *Manager) readLifecycleReceipt(releaseID string) (receiptRecord, string, error) {
	roleFD, err := ensurePackageDirectory(manager.rootFD, manager.role, manager)
	if err != nil {
		return receiptRecord{}, "", err
	}
	defer unix.Close(roleFD)
	roleLock, err := acquireDescriptorLock(roleFD, lockFileName, manager.ownerUID, manager.ownerGID, manager.checkACL, manager.lockOpenHook)
	if err != nil {
		return receiptRecord{}, "", err
	}
	defer roleLock.close()
	releasesFD, err := ensurePackageDirectory(roleFD, releasesDirectory, manager)
	if err != nil {
		return receiptRecord{}, "", err
	}
	defer unix.Close(releasesFD)
	receipt, _, digest, err := loadAndVerifyRelease(releasesFD, releaseID, manager)
	return receipt, digest, err
}

func (manager *Manager) verifyRunningLifecycle(snapshot lifecycleSnapshot, candidate decision) error {
	var expected receiptFile
	expectedPath := ""
	if snapshot.runningReceipt != nil {
		for _, file := range snapshot.runningReceipt.Files {
			if file.Name == "owntransitctl" {
				expected = file
				expectedPath = filepath.Join(manager.rootPath, manager.role, releasesDirectory, snapshot.runningReceipt.ReleaseID, file.Name)
				break
			}
		}
	} else if snapshot.currentReceipt != nil {
		if candidate.seal != decisionSeal {
			return errors.New("packagetxn: original signed input is required before active lifecycle publication")
		}
		for _, file := range snapshot.currentReceipt.Files {
			if file.Name == "owntransitctl" {
				expected = file
				break
			}
		}
	} else {
		for _, file := range candidate.files {
			if file.InstallName == "owntransitctl" {
				expected = receiptFile{Name: file.InstallName, SHA256: file.SHA256, Size: file.Size}
				expectedPath = filepath.Join(candidate.bundleRoot, filepath.FromSlash(file.SourcePath))
				break
			}
		}
	}
	if expected.Name == "" || !validDigest(expected.SHA256) || expected.Size <= 0 {
		return errors.New("packagetxn: authenticated lifecycle executable is absent")
	}
	measured, err := manager.runningMeasurement()
	if err != nil {
		return fmt.Errorf("packagetxn: measure running lifecycle executable: %w", err)
	}
	if measured.SHA256 != expected.SHA256 || measured.Size != expected.Size {
		return errors.New("packagetxn: running lifecycle executable differs from the authenticated installed release")
	}
	if manager.enforceExecutablePath && (expectedPath == "" || measured.Path != expectedPath) {
		return errors.New("packagetxn: lifecycle executable was not invoked from this role's authenticated fixed path")
	}
	return nil
}

func verifyPolicyForPackageAnchor(input ApplyInput, anchor packageAnchor) (release.VerifiedPolicy, bool, string, error) {
	if len(input.ReleaseKey) != ed25519.PublicKeySize || len(input.PolicyKey) != ed25519.PublicKeySize {
		return release.VerifiedPolicy{}, false, "", errors.New("packagetxn: release and policy Ed25519 public keys are required")
	}
	if signing.KeyID(input.ReleaseKey) == signing.KeyID(input.PolicyKey) {
		return release.VerifiedPolicy{}, false, "", errors.New("packagetxn: release and release-policy signers must be distinct")
	}
	policyDigest := digestBytes(input.PolicyBytes)
	policyAnchor := release.PolicyAnchor{
		HighestPolicySequence:  anchor.HighestPolicySequence,
		MinimumReleaseSequence: anchor.MinimumReleaseSequence,
		MinimumLifecycle:       anchor.MinimumLifecycle,
		TombstonedReleaseIDs:   append([]string(nil), anchor.TombstonedReleaseIDs...),
	}
	if anchor.Generation != 0 {
		if signing.KeyID(input.PolicyKey) != anchor.PolicyKeyID {
			return release.VerifiedPolicy{}, false, "", errors.New("packagetxn: release-policy signer differs from the pinned anchor")
		}
		if policyDigest == anchor.PolicySHA256 {
			verified, err := release.VerifyPolicyAtAnchor(input.PolicyBytes, input.PolicySignature, input.PolicyKey, policyAnchor)
			if err != nil {
				return release.VerifiedPolicy{}, false, "", err
			}
			return verified, false, policyDigest, nil
		}
	}
	verified, err := release.VerifyPolicyAdvance(input.PolicyBytes, input.PolicySignature, input.PolicyKey, policyAnchor)
	if err != nil {
		return release.VerifiedPolicy{}, false, "", err
	}
	return verified, true, policyDigest, nil
}

func targetAnchorForInstall(before packageAnchor, policy release.VerifiedPolicy, policyDigest, policyKeyID string, selector selectorRecord, decision decision) (packageAnchor, error) {
	if before.Generation == ^uint64(0) {
		return packageAnchor{}, fmt.Errorf("%w: package-anchor generation is exhausted", ErrResidue)
	}
	nextPolicy, err := policy.NextAnchor()
	if err != nil {
		return packageAnchor{}, err
	}
	if selector.Current != decision.releaseID || selector.CurrentReceiptSHA256 == "" {
		return packageAnchor{}, errors.New("packagetxn: selector target differs from authenticated release")
	}
	beforeBytes, err := encodePackageAnchor(before)
	if err != nil {
		return packageAnchor{}, err
	}
	highest := before.HighestReleaseSequence
	if decision.sequence > highest {
		highest = decision.sequence
	}
	return packageAnchor{
		Schema: packageAnchorSchema, Generation: before.Generation + 1, Role: decision.role,
		PreviousSHA256: digestBytes(beforeBytes), PolicyKeyID: policyKeyID, PolicySHA256: policyDigest,
		ReleaseKeyID:           policy.Value().ReleaseKeyID,
		HighestPolicySequence:  nextPolicy.HighestPolicySequence,
		MinimumReleaseSequence: nextPolicy.MinimumReleaseSequence, MinimumLifecycle: nextPolicy.MinimumLifecycle,
		TombstonedReleaseIDs:   append([]string(nil), nextPolicy.TombstonedReleaseIDs...),
		HighestReleaseSequence: highest, SelectorGeneration: selector.Generation,
		CurrentReleaseID: selector.Current, CurrentReceiptSHA256: selector.CurrentReceiptSHA256,
		PreviousReleaseID: selector.Previous, PreviousReceiptSHA256: selector.PreviousReceiptSHA256,
	}, nil
}

func (manager *Manager) anchorGate(anchorRoleFD int, expectedBefore string, target packageAnchor) selectionGate {
	return func(journal journalRecord, selector selectorRecord) error {
		targetBytes, err := encodePackageAnchor(target)
		if err != nil {
			return err
		}
		targetDigest := digestBytes(targetBytes)
		if journal.AnchorBeforeSHA256 != expectedBefore || journal.AnchorTargetSHA256 != targetDigest || journal.PolicySHA256 != target.PolicySHA256 {
			return errors.New("packagetxn: journal differs from the external-anchor decision")
		}
		if !selectorsEqual(selector, journal.Before) {
			return fmt.Errorf("%w: selector changed before external-anchor compare-and-swap", ErrResidue)
		}
		_, _, currentDigest, err := manager.readPackageAnchor(anchorRoleFD)
		if err != nil {
			return err
		}
		if currentDigest == targetDigest {
			return nil
		}
		if currentDigest != expectedBefore {
			return errors.New("packagetxn: external rollback anchor changed during transaction")
		}
		return manager.replacePackageAnchor(anchorRoleFD, targetBytes)
	}
}

func anchorPolicyKeyID(anchor packageAnchor, supplied ed25519.PublicKey) string {
	if anchor.Generation == 0 {
		return signing.KeyID(supplied)
	}
	return anchor.PolicyKeyID
}

func artifactNameForRole(role, goos, goarch string) (string, error) {
	switch role + "/" + goos + "/" + goarch {
	case "client/darwin/arm64":
		return "client-darwin-arm64", nil
	case "client/linux/amd64":
		return "client-linux-amd64", nil
	case "connector/linux/amd64":
		return "connector-linux-amd64", nil
	case "relay/linux/amd64":
		return "relay-linux-amd64", nil
	case "provisioner/darwin/arm64":
		return "provisioner-darwin-arm64", nil
	case "provisioner/linux/amd64":
		return "provisioner-linux-amd64", nil
	default:
		return "", errors.New("packagetxn: role is unsupported on the local platform")
	}
}

func digestPackageAnchor(anchor packageAnchor) string {
	encoded, err := encodePackageAnchor(anchor)
	if err != nil {
		return ""
	}
	return digestBytes(encoded)
}

func nestedPath(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil || relative == "." || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
