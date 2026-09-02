//go:build darwin || linux

package packagetxn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	journalSchema       = "owntransit.package-journal.v1"
	receiptSchema       = "owntransit.package-receipt.v1"
	selectorSchema      = "owntransit.package-selector.v1"
	lockFileName        = "transaction.lock"
	releasesDirectory   = "releases"
	journalFileName     = "journal.json"
	journalStageName    = ".journal.stage"
	selectorFileName    = "selector.json"
	selectorStageName   = ".selector.stage"
	activeLinkName      = "current"
	activeLinkStageName = ".current.stage"
	receiptFileName     = "receipt.json"
	receiptStageName    = ".receipt.stage"
	maximumMetadataSize = 64 << 10
	maximumFileCount    = 8
)

var (
	// ErrLocked means another process holds the exact descriptor-bound role
	// transaction lock.
	ErrLocked = errors.New("packagetxn: role transaction is locked")
	// ErrReplay means an ordinary install attempted to select a release at or
	// below the current local sequence. Authenticated rollback uses Rollback.
	ErrReplay = errors.New("packagetxn: release install is a replay or downgrade")
	// ErrResidue means disk state cannot be explained by the durable journal,
	// selector, and exact receipts. The package never guesses or recursively
	// cleans such state.
	ErrResidue = errors.New("packagetxn: unexplained package residue")
	// ErrInvalidDecision means the transaction did not receive the opaque result of a
	// successful release and policy verification.
	ErrInvalidDecision = errors.New("packagetxn: authenticated install decision is required")
)

type journalPhase string

const (
	phasePlanned  journalPhase = "planned"
	phaseStaged   journalPhase = "staged"
	phaseSelected journalPhase = "selected"
	phaseRetiring journalPhase = "retiring"
	phaseComplete journalPhase = "complete"
)

type failurePoint string

const (
	pointJournalPlanned  failurePoint = "journal-planned"
	pointReleaseStaged   failurePoint = "release-staged"
	pointJournalStaged   failurePoint = "journal-staged"
	pointSelectorCommit  failurePoint = "selector-committed"
	pointActiveCommit    failurePoint = "active-link-committed"
	pointJournalSelected failurePoint = "journal-selected"
	pointJournalRetiring failurePoint = "journal-retiring"
	pointReleaseRetired  failurePoint = "release-retired"
	pointJournalComplete failurePoint = "journal-complete"
)

// Result describes the single durable selector observed after Install.
type Result struct {
	Role       string
	Current    string
	Previous   string
	Generation uint64
	Installed  bool
	Resumed    bool
	Idempotent bool
	Runtime    RuntimeIdentity
}

// Manager holds the exact package-root descriptor. Open requires a canonical,
// root:root mode-0700 root and refuses Darwin until exact ACL verification is
// available. It never creates the package root or trusts its path after open.
type Manager struct {
	mu                    sync.RWMutex
	self                  *Manager
	rootFD                int
	rootDevice            uint64
	anchorFD              int
	anchorDevice          uint64
	hasAnchor             bool
	open                  bool
	role                  string
	ownerUID              uint32
	ownerGID              uint32
	readerGID             uint32
	checkACL              func(int, bool) error
	lockOpenHook          func(int, int, string) error
	runningMeasurement    func() (packageMeasurement, error)
	failureHook           func(failurePoint) error
	platformOS            string
	platformArch          string
	rootPath              string
	enforceExecutablePath bool
}

type selectorRecord struct {
	Schema                string `json:"schema"`
	Generation            uint64 `json:"generation"`
	Current               string `json:"current"`
	CurrentReceiptSHA256  string `json:"current_receipt_sha256"`
	Previous              string `json:"previous"`
	PreviousReceiptSHA256 string `json:"previous_receipt_sha256"`
}

type journalRecord struct {
	Schema               string            `json:"schema"`
	Phase                journalPhase      `json:"phase"`
	Operation            decisionOperation `json:"operation"`
	Role                 string            `json:"role"`
	ReleaseID            string            `json:"release_id"`
	Sequence             uint64            `json:"sequence"`
	ManifestSHA256       string            `json:"manifest_sha256"`
	ReceiptSHA256        string            `json:"receipt_sha256"`
	PolicySHA256         string            `json:"policy_sha256,omitempty"`
	AnchorBeforeSHA256   string            `json:"anchor_before_sha256,omitempty"`
	AnchorTargetSHA256   string            `json:"anchor_target_sha256,omitempty"`
	RetiredReleaseID     string            `json:"retired_release_id,omitempty"`
	RetiredReceiptSHA256 string            `json:"retired_receipt_sha256,omitempty"`
	Before               selectorRecord    `json:"before"`
	Target               selectorRecord    `json:"target"`
}

type selectionGate func(journalRecord, selectorRecord) error

type receiptRecord struct {
	Schema         string        `json:"schema"`
	Role           string        `json:"role"`
	OS             string        `json:"os"`
	Arch           string        `json:"arch"`
	ReleaseID      string        `json:"release_id"`
	Sequence       uint64        `json:"sequence"`
	ManifestSHA256 string        `json:"manifest_sha256"`
	Files          []receiptFile `json:"files"`
}

type receiptFile struct {
	ArtifactName string `json:"artifact_name"`
	Name         string `json:"name"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Mode         uint32 `json:"mode"`
	GID          uint32 `json:"gid"`
}

func openManager(rootPath, role string, ownerUID, ownerGID uint32, strictRoot bool, aclCheck func(int, bool) error) (*Manager, error) {
	if !validRole(role) {
		return nil, errors.New("packagetxn: role must be client, connector, relay, or provisioner")
	}
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || rootPath == string(filepath.Separator) {
		return nil, errors.New("packagetxn: package root must be a canonical absolute non-root path")
	}
	if aclCheck == nil {
		return nil, errors.New("packagetxn: ACL verifier is required")
	}
	fd, err := openRootChain(rootPath, ownerUID, ownerGID, 0o755, strictRoot, aclCheck)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("packagetxn: inspect package root device: %w", err)
	}
	manager := &Manager{
		rootFD: fd, anchorFD: -1, open: true, role: role, ownerUID: ownerUID, ownerGID: ownerGID,
		readerGID:  ownerGID,
		rootDevice: uint64(stat.Dev), checkACL: aclCheck, platformOS: runtime.GOOS, platformArch: runtime.GOARCH,
		rootPath: rootPath,
	}
	manager.self = manager
	return manager, nil
}

// Close releases the held package-root descriptor. It does not remove state.
func (manager *Manager) Close() error {
	if manager == nil {
		return nil
	}
	if manager.self != manager {
		return errors.New("packagetxn: copied package manager handle is invalid")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.open {
		return nil
	}
	manager.open = false
	if manager.hasAnchor {
		if err := unix.Close(manager.anchorFD); err != nil {
			_ = unix.Close(manager.rootFD)
			return fmt.Errorf("packagetxn: close rollback-anchor root: %w", err)
		}
	}
	if err := unix.Close(manager.rootFD); err != nil {
		return fmt.Errorf("packagetxn: close package root: %w", err)
	}
	return nil
}

// installVerified exposes the transaction engine only to package-local tests.
// Production callers must use Apply, Rollback, or Recover so the external
// anchor gate and running-executable measurement cannot be omitted.
func (manager *Manager) installVerified(decision decision) (Result, error) {
	return manager.install(decision, nil, nil)
}

func (manager *Manager) install(decision decision, hook func(failurePoint) error, gate selectionGate) (Result, error) {
	if manager == nil {
		return Result{}, errors.New("packagetxn: package manager is nil")
	}
	if manager.self != manager {
		return Result{}, errors.New("packagetxn: copied package manager handle is invalid")
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if !manager.open {
		return Result{}, errors.New("packagetxn: package manager is closed")
	}
	if err := validateDecision(decision); err != nil {
		return Result{}, err
	}
	if decision.role != manager.role {
		return Result{}, fmt.Errorf("%w: authenticated decision selects another role", ErrInvalidDecision)
	}
	if decision.os != manager.platformOS || decision.arch != manager.platformArch {
		return Result{}, fmt.Errorf("%w: authenticated decision selects another local platform", ErrInvalidDecision)
	}
	for _, file := range decision.files {
		if file.GID != manager.ownerGID && file.GID != manager.readerGID {
			return Result{}, fmt.Errorf("%w: authenticated file selects an unexpected installed group", ErrInvalidDecision)
		}
	}

	roleFD, err := ensurePackageDirectory(manager.rootFD, manager.role, manager)
	if err != nil {
		return Result{}, err
	}
	defer unix.Close(roleFD)

	roleLock, err := acquireDescriptorLock(roleFD, lockFileName, manager.ownerUID, manager.ownerGID, manager.checkACL, manager.lockOpenHook)
	if err != nil {
		return Result{}, err
	}
	defer roleLock.close()
	releasesFD, err := ensurePackageDirectory(roleFD, releasesDirectory, manager)
	if err != nil {
		return Result{}, err
	}
	defer unix.Close(releasesFD)

	receipt, receiptBytes, receiptDigest, err := receiptForDecision(decision)
	if err != nil {
		return Result{}, err
	}
	state, err := inspectTransactionState(roleFD, releasesFD, manager)
	if err != nil {
		return Result{}, err
	}
	if state.journal != nil && state.journal.Phase != phaseComplete {
		if !journalMatchesDecision(*state.journal, decision, receiptDigest) {
			return Result{}, fmt.Errorf("%w: another authenticated transaction must be resumed first", ErrResidue)
		}
		return manager.resume(roleFD, releasesFD, decision, receipt, receiptBytes, receiptDigest, state, hook, gate, true)
	}

	if decision.operation == operationInstall && state.selector.Current == decision.releaseID {
		if err := verifyReleaseDirectory(releasesFD, decision.releaseID, &receipt, receiptDigest, manager); err != nil {
			return Result{}, err
		}
		if state.selector.CurrentReceiptSHA256 != receiptDigest {
			return Result{}, fmt.Errorf("%w: current selector does not bind the authenticated receipt", ErrResidue)
		}
		if state.journal == nil || state.journal.Phase != phaseComplete || !journalMatchesDecision(*state.journal, decision, receiptDigest) {
			return Result{}, fmt.Errorf("%w: current release has no exact complete journal", ErrResidue)
		}
		if state.activeReleaseID != decision.releaseID {
			return Result{}, fmt.Errorf("%w: active executable path differs from the current selector", ErrResidue)
		}
		return resultFromSelector(manager, state.selector, &receipt, false, false, true)
	}
	if state.selector.Current != "" && decision.operation == operationInstall {
		currentReceipt, _, _, err := loadAndVerifyRelease(releasesFD, state.selector.Current, manager)
		if err != nil {
			return Result{}, err
		}
		if decision.sequence <= currentReceipt.Sequence {
			return Result{}, ErrReplay
		}
	}
	if state.selector.Generation == ^uint64(0) {
		return Result{}, fmt.Errorf("%w: selector generation is exhausted", ErrResidue)
	}

	var target selectorRecord
	var retiredReleaseID, retiredReceiptSHA256 string
	if decision.operation == operationInstall {
		target = selectorRecord{
			Schema: selectorSchema, Generation: state.selector.Generation + 1,
			Current: decision.releaseID, CurrentReceiptSHA256: receiptDigest,
			Previous: state.selector.Current, PreviousReceiptSHA256: state.selector.CurrentReceiptSHA256,
		}
		retiredReleaseID, retiredReceiptSHA256 = state.selector.Previous, state.selector.PreviousReceiptSHA256
	} else {
		if state.selector.Previous != decision.releaseID || state.selector.PreviousReceiptSHA256 != receiptDigest {
			return Result{}, errors.New("packagetxn: rollback target is not the exact retained previous release")
		}
		target = selectorRecord{
			Schema: selectorSchema, Generation: state.selector.Generation + 1,
			Current: state.selector.Previous, CurrentReceiptSHA256: state.selector.PreviousReceiptSHA256,
			Previous: state.selector.Current, PreviousReceiptSHA256: state.selector.CurrentReceiptSHA256,
		}
	}
	journal := journalRecord{
		Schema: journalSchema, Phase: phasePlanned, Operation: decision.operation, Role: manager.role,
		ReleaseID: decision.releaseID, Sequence: decision.sequence,
		ManifestSHA256: decision.manifestSHA256, ReceiptSHA256: receiptDigest,
		PolicySHA256: decision.policySHA256, AnchorBeforeSHA256: decision.anchorBefore,
		AnchorTargetSHA256: decision.anchorTarget,
		RetiredReleaseID:   retiredReleaseID, RetiredReceiptSHA256: retiredReceiptSHA256,
		Before: state.selector, Target: target,
	}
	if err := replaceJournal(roleFD, journal, manager); err != nil {
		return Result{}, err
	}
	if err := runHook(hook, pointJournalPlanned); err != nil {
		return Result{}, err
	}
	state.journal = &journal
	return manager.resume(roleFD, releasesFD, decision, receipt, receiptBytes, receiptDigest, state, hook, gate, false)
}

type transactionState struct {
	selector        selectorRecord
	journal         *journalRecord
	activeReleaseID string
}

func (manager *Manager) resume(
	roleFD, releasesFD int,
	decision decision,
	receipt receiptRecord,
	receiptBytes []byte,
	receiptDigest string,
	state transactionState,
	hook func(failurePoint) error,
	gate selectionGate,
	resuming bool,
) (Result, error) {
	journal := *state.journal
	if err := validateResumeSelector(journal, state.selector); err != nil {
		return Result{}, err
	}
	if err := cleanAuthorizedMetadataStages(roleFD, journal.Phase, manager); err != nil {
		return Result{}, err
	}

	if journal.Phase == phasePlanned {
		if decision.operation == operationInstall {
			bundleFD, err := openProtectedBundleRoot(decision.bundleRoot, manager.checkACL)
			if err != nil {
				return Result{}, err
			}
			err = stageReleaseDirectory(releasesFD, bundleFD, decision, receipt, receiptBytes, receiptDigest, manager)
			_ = unix.Close(bundleFD)
			if err != nil {
				return Result{}, err
			}
		} else if err := verifyReleaseDirectory(releasesFD, decision.releaseID, &receipt, receiptDigest, manager); err != nil {
			return Result{}, err
		}
		if err := runHook(hook, pointReleaseStaged); err != nil {
			return Result{}, err
		}
		journal.Phase = phaseStaged
		if err := replaceJournal(roleFD, journal, manager); err != nil {
			return Result{}, err
		}
		if err := runHook(hook, pointJournalStaged); err != nil {
			return Result{}, err
		}
	} else {
		if err := verifyReleaseDirectory(releasesFD, decision.releaseID, &receipt, receiptDigest, manager); err != nil {
			return Result{}, err
		}
	}

	selected := state.selector.Current == journal.Target.Current && state.selector.Generation == journal.Target.Generation
	if !selected {
		if gate != nil {
			if err := gate(journal, state.selector); err != nil {
				return Result{}, err
			}
		} else if journal.AnchorTargetSHA256 != "" {
			return Result{}, errors.New("packagetxn: external anchor gate is required before selector publication")
		}
		if err := replaceSelector(roleFD, journal.Target, manager); err != nil {
			return Result{}, err
		}
		state.selector = journal.Target
		if err := runHook(hook, pointSelectorCommit); err != nil {
			return Result{}, err
		}
	}
	if state.activeReleaseID != journal.Target.Current {
		if state.activeReleaseID != journal.Before.Current {
			return Result{}, fmt.Errorf("%w: active executable path is not an authenticated transition endpoint", ErrResidue)
		}
		if err := replaceActiveLink(roleFD, journal.Target.Current, manager); err != nil {
			return Result{}, err
		}
		state.activeReleaseID = journal.Target.Current
		if err := runHook(hook, pointActiveCommit); err != nil {
			return Result{}, err
		}
	}
	if journal.Phase == phaseStaged || journal.Phase == phasePlanned {
		journal.Phase = phaseSelected
		if err := replaceJournal(roleFD, journal, manager); err != nil {
			return Result{}, err
		}
		if err := runHook(hook, pointJournalSelected); err != nil {
			return Result{}, err
		}
	}
	if journal.RetiredReleaseID != "" {
		if journal.Phase != phaseRetiring {
			journal.Phase = phaseRetiring
			if err := replaceJournal(roleFD, journal, manager); err != nil {
				return Result{}, err
			}
			if err := runHook(hook, pointJournalRetiring); err != nil {
				return Result{}, err
			}
		}
		if err := retireReleaseDirectory(releasesFD, journal.RetiredReleaseID, journal.RetiredReceiptSHA256, manager); err != nil {
			return Result{}, err
		}
		if err := runHook(hook, pointReleaseRetired); err != nil {
			return Result{}, err
		}
	}
	journal.Phase = phaseComplete
	if err := replaceJournal(roleFD, journal, manager); err != nil {
		return Result{}, err
	}
	if err := runHook(hook, pointJournalComplete); err != nil {
		return Result{}, err
	}
	if err := verifyReleaseDirectory(releasesFD, decision.releaseID, &receipt, receiptDigest, manager); err != nil {
		return Result{}, err
	}
	if state.activeReleaseID != decision.releaseID {
		return Result{}, fmt.Errorf("%w: active executable path differs from the completed release", ErrResidue)
	}
	return resultFromSelector(manager, journal.Target, &receipt, true, resuming, false)
}

func runHook(hook func(failurePoint) error, point failurePoint) error {
	if hook == nil {
		return nil
	}
	if err := hook(point); err != nil {
		return fmt.Errorf("packagetxn: injected interruption after %s: %w", point, err)
	}
	return nil
}

func resultFromSelector(manager *Manager, selector selectorRecord, receipt *receiptRecord, installed, resumed, idempotent bool) (Result, error) {
	if manager == nil {
		return Result{}, errors.New("packagetxn: result requires its package manager")
	}
	result := Result{
		Role: manager.role, Current: selector.Current, Previous: selector.Previous,
		Generation: selector.Generation, Installed: installed, Resumed: resumed, Idempotent: idempotent,
	}
	if selector.Current == "" {
		if receipt != nil {
			return Result{}, errors.New("packagetxn: empty selector unexpectedly has a runtime receipt")
		}
		return result, nil
	}
	if receipt == nil || receipt.Role != manager.role || receipt.ReleaseID != selector.Current {
		return Result{}, errors.New("packagetxn: result selector has no matching authenticated runtime receipt")
	}
	identity, err := runtimeIdentityFromReceipt(*receipt)
	if err != nil {
		if manager.hasAnchor {
			return Result{}, err
		}
		return result, nil
	}
	result.Runtime = identity
	return result, nil
}

func validateDecision(decision decision) error {
	if decision.seal != decisionSeal || (decision.operation != operationInstall && decision.operation != operationRollback) ||
		!validRole(decision.role) || !validReleaseID(decision.releaseID) || decision.sequence == 0 || !validDigest(decision.manifestSHA256) ||
		!validToken(decision.os) || !validToken(decision.arch) {
		return ErrInvalidDecision
	}
	if decision.operation == operationInstall {
		if decision.bundleRoot == "" || !filepath.IsAbs(decision.bundleRoot) || filepath.Clean(decision.bundleRoot) != decision.bundleRoot {
			return ErrInvalidDecision
		}
	} else if decision.bundleRoot != "" {
		return ErrInvalidDecision
	}
	anchorEmpty := decision.policySHA256 == "" && decision.anchorBefore == "" && decision.anchorTarget == ""
	anchorComplete := validDigest(decision.policySHA256) && validDigest(decision.anchorBefore) && validDigest(decision.anchorTarget) && decision.anchorBefore != decision.anchorTarget
	if !anchorEmpty && !anchorComplete {
		return ErrInvalidDecision
	}
	if err := validateDecisionFiles(decision.files); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDecision, err)
	}
	return nil
}

func receiptForDecision(decision decision) (receiptRecord, []byte, string, error) {
	files := make([]receiptFile, len(decision.files))
	for index, file := range decision.files {
		files[index] = receiptFile{
			ArtifactName: file.ArtifactName, Name: file.InstallName, SHA256: file.SHA256,
			Size: file.Size, Mode: unixInstallMode(file.Mode), GID: file.GID,
		}
	}
	receipt := receiptRecord{
		Schema: receiptSchema, Role: decision.role, OS: decision.os, Arch: decision.arch,
		ReleaseID: decision.releaseID, Sequence: decision.sequence,
		ManifestSHA256: decision.manifestSHA256, Files: files,
	}
	encoded, err := encodeReceipt(receipt)
	if err != nil {
		return receiptRecord{}, nil, "", err
	}
	return receipt, encoded, digestBytes(encoded), nil
}

func journalMatchesDecision(journal journalRecord, decision decision, receiptDigest string) bool {
	return journal.Schema == journalSchema && journal.Operation == decision.operation && journal.Role == decision.role && journal.ReleaseID == decision.releaseID &&
		journal.Sequence == decision.sequence && journal.ManifestSHA256 == decision.manifestSHA256 && journal.ReceiptSHA256 == receiptDigest &&
		journal.PolicySHA256 == decision.policySHA256 && journal.AnchorBeforeSHA256 == decision.anchorBefore && journal.AnchorTargetSHA256 == decision.anchorTarget
}

func validateResumeSelector(journal journalRecord, selector selectorRecord) error {
	switch journal.Phase {
	case phasePlanned:
		if !selectorsEqual(selector, journal.Before) {
			return fmt.Errorf("%w: planned journal does not match the selected release", ErrResidue)
		}
	case phaseStaged:
		if !selectorsEqual(selector, journal.Before) && !selectorsEqual(selector, journal.Target) {
			return fmt.Errorf("%w: staged journal has an unexplained selector", ErrResidue)
		}
	case phaseSelected, phaseRetiring, phaseComplete:
		if !selectorsEqual(selector, journal.Target) {
			return fmt.Errorf("%w: selected journal does not match the selector", ErrResidue)
		}
	default:
		return fmt.Errorf("%w: journal phase is invalid", ErrResidue)
	}
	return nil
}

func selectorsEqual(left, right selectorRecord) bool {
	return left == right
}

func inspectTransactionState(roleFD, releasesFD int, manager *Manager) (transactionState, error) {
	// A metadata stage which still has its reserved name was never committed by
	// rename. Under the exact role lock, the durable target remains authoritative
	// and the safe root-owned stage can always be discarded and reconstructed.
	for _, stage := range []string{journalStageName, selectorStageName} {
		if err := removeAuthorizedStage(roleFD, stage, manager); err != nil {
			return transactionState{}, err
		}
	}
	if err := removeActiveLinkStage(roleFD, manager); err != nil {
		return transactionState{}, err
	}
	selector, selectorExists, err := readSelector(roleFD, manager)
	if err != nil {
		return transactionState{}, err
	}
	if !selectorExists {
		selector = emptySelector()
	}
	journal, journalExists, err := readJournal(roleFD, manager)
	if err != nil {
		return transactionState{}, err
	}
	if selectorExists && !journalExists {
		return transactionState{}, fmt.Errorf("%w: selector exists without a durable journal", ErrResidue)
	}
	activeReleaseID, activeExists, err := readActiveLink(roleFD, activeLinkName, manager)
	if err != nil {
		return transactionState{}, err
	}

	allowedRole := map[string]struct{}{lockFileName: {}, releasesDirectory: {}}
	if selectorExists {
		allowedRole[selectorFileName] = struct{}{}
	}
	if journalExists {
		allowedRole[journalFileName] = struct{}{}
	}
	if activeExists {
		allowedRole[activeLinkName] = struct{}{}
	}
	if err := requireAllowedDirectoryEntries(roleFD, allowedRole, "role"); err != nil {
		return transactionState{}, err
	}

	allowedReleases := make(map[string]struct{})
	if selector.Current != "" {
		allowedReleases[selector.Current] = struct{}{}
		if _, _, digest, err := loadAndVerifyRelease(releasesFD, selector.Current, manager); err != nil {
			return transactionState{}, err
		} else if digest != selector.CurrentReceiptSHA256 {
			return transactionState{}, fmt.Errorf("%w: current receipt digest differs from selector", ErrResidue)
		}
	}
	if selector.Previous != "" {
		allowedReleases[selector.Previous] = struct{}{}
		if _, _, digest, err := loadAndVerifyRelease(releasesFD, selector.Previous, manager); err != nil {
			return transactionState{}, err
		} else if digest != selector.PreviousReceiptSHA256 {
			return transactionState{}, fmt.Errorf("%w: previous receipt digest differs from selector", ErrResidue)
		}
	}
	if journalExists {
		if err := validateJournal(*journal); err != nil {
			return transactionState{}, err
		}
		if journal.Role != manager.role {
			return transactionState{}, fmt.Errorf("%w: journal is in another role namespace", ErrResidue)
		}
		if journal.Phase != phaseComplete {
			allowedReleases[journal.ReleaseID] = struct{}{}
			if journal.RetiredReleaseID != "" {
				allowedReleases[journal.RetiredReleaseID] = struct{}{}
			}
		}
		if err := validateResumeSelector(*journal, selector); err != nil {
			return transactionState{}, err
		}
		if err := validateResumeActiveLink(*journal, selector, activeReleaseID); err != nil {
			return transactionState{}, err
		}
		if journal.Before.Current != "" {
			if prior, _, digest, err := loadAndVerifyRelease(releasesFD, journal.Before.Current, manager); err != nil {
				return transactionState{}, err
			} else if digest != journal.Before.CurrentReceiptSHA256 ||
				(journal.Operation == operationInstall && prior.Sequence >= journal.Sequence) ||
				(journal.Operation == operationRollback && prior.Sequence <= journal.Sequence) {
				return transactionState{}, fmt.Errorf("%w: journal predecessor has an invalid release ordering", ErrResidue)
			}
		}
		if journal.Before.Previous != "" && journal.Phase != phaseRetiring && journal.Phase != phaseComplete {
			if _, _, digest, err := loadAndVerifyRelease(releasesFD, journal.Before.Previous, manager); err != nil {
				return transactionState{}, err
			} else if digest != journal.Before.PreviousReceiptSHA256 {
				return transactionState{}, fmt.Errorf("%w: journal retirement predecessor receipt differs", ErrResidue)
			}
		}
		if journal.Phase == phaseStaged || journal.Phase == phaseSelected || journal.Phase == phaseComplete {
			if receipt, _, digest, err := loadAndVerifyRelease(releasesFD, journal.ReleaseID, manager); err != nil {
				return transactionState{}, err
			} else if digest != journal.ReceiptSHA256 {
				return transactionState{}, fmt.Errorf("%w: transaction receipt digest differs from journal", ErrResidue)
			} else if receipt.Role != journal.Role || receipt.ReleaseID != journal.ReleaseID ||
				receipt.Sequence != journal.Sequence || receipt.ManifestSHA256 != journal.ManifestSHA256 {
				return transactionState{}, fmt.Errorf("%w: receipt semantics differ from journal", ErrResidue)
			}
		}
	}
	if err := requireAllowedDirectoryEntries(releasesFD, allowedReleases, "releases"); err != nil {
		return transactionState{}, err
	}
	if !journalExists && activeReleaseID != selector.Current {
		return transactionState{}, fmt.Errorf("%w: active executable path differs from the selector", ErrResidue)
	}
	return transactionState{selector: selector, journal: journal, activeReleaseID: activeReleaseID}, nil
}

func validateResumeActiveLink(journal journalRecord, selector selectorRecord, activeReleaseID string) error {
	switch journal.Phase {
	case phasePlanned:
		if activeReleaseID != journal.Before.Current {
			return fmt.Errorf("%w: planned journal does not match the active executable path", ErrResidue)
		}
	case phaseStaged:
		if activeReleaseID == journal.Before.Current {
			return nil
		}
		if selectorsEqual(selector, journal.Target) && activeReleaseID == journal.Target.Current {
			return nil
		}
		return fmt.Errorf("%w: staged journal has an unexplained active executable path", ErrResidue)
	case phaseSelected, phaseRetiring, phaseComplete:
		if activeReleaseID != journal.Target.Current {
			return fmt.Errorf("%w: selected journal does not match the active executable path", ErrResidue)
		}
	default:
		return fmt.Errorf("%w: journal phase is invalid", ErrResidue)
	}
	return nil
}

func emptySelector() selectorRecord {
	return selectorRecord{Schema: selectorSchema}
}

func readSelector(roleFD int, manager *Manager) (selectorRecord, bool, error) {
	contents, exists, err := readOptionalExactFile(roleFD, selectorFileName, 0o600, maximumMetadataSize, manager)
	if err != nil || !exists {
		return selectorRecord{}, exists, err
	}
	var selector selectorRecord
	if err := decodeCanonical(contents, &selector, encodeSelector); err != nil {
		return selectorRecord{}, false, fmt.Errorf("%w: selector: %v", ErrResidue, err)
	}
	return selector, true, nil
}

func readJournal(roleFD int, manager *Manager) (*journalRecord, bool, error) {
	contents, exists, err := readOptionalExactFile(roleFD, journalFileName, 0o600, maximumMetadataSize, manager)
	if err != nil || !exists {
		return nil, exists, err
	}
	var journal journalRecord
	if err := decodeCanonical(contents, &journal, encodeJournal); err != nil {
		return nil, false, fmt.Errorf("%w: journal: %v", ErrResidue, err)
	}
	return &journal, true, nil
}

func replaceJournal(roleFD int, journal journalRecord, manager *Manager) error {
	encoded, err := encodeJournal(journal)
	if err != nil {
		return err
	}
	return replaceCanonicalFile(roleFD, journalFileName, journalStageName, encoded, manager)
}

func replaceSelector(roleFD int, selector selectorRecord, manager *Manager) error {
	encoded, err := encodeSelector(selector)
	if err != nil {
		return err
	}
	return replaceCanonicalFile(roleFD, selectorFileName, selectorStageName, encoded, manager)
}

func cleanAuthorizedMetadataStages(roleFD int, phase journalPhase, manager *Manager) error {
	switch phase {
	case phasePlanned:
		return removeAuthorizedStage(roleFD, journalStageName, manager)
	case phaseStaged:
		if err := removeAuthorizedStage(roleFD, journalStageName, manager); err != nil {
			return err
		}
		return removeAuthorizedStage(roleFD, selectorStageName, manager)
	case phaseSelected:
		return removeAuthorizedStage(roleFD, journalStageName, manager)
	case phaseRetiring:
		return removeAuthorizedStage(roleFD, journalStageName, manager)
	case phaseComplete:
		return nil
	default:
		return fmt.Errorf("%w: journal phase is invalid", ErrResidue)
	}
}

func encodeJournal(journal journalRecord) ([]byte, error) {
	if err := validateJournal(journal); err != nil {
		return nil, err
	}
	return encodeCanonical(journal)
}

func validateJournal(journal journalRecord) error {
	if journal.Schema != journalSchema || (journal.Phase != phasePlanned && journal.Phase != phaseStaged && journal.Phase != phaseSelected && journal.Phase != phaseRetiring && journal.Phase != phaseComplete) ||
		(journal.Operation != operationInstall && journal.Operation != operationRollback) || !validRole(journal.Role) || !validReleaseID(journal.ReleaseID) || journal.Sequence == 0 ||
		!validDigest(journal.ManifestSHA256) || !validDigest(journal.ReceiptSHA256) ||
		validateSelector(journal.Before) != nil || validateSelector(journal.Target) != nil ||
		journal.Target.Generation != journal.Before.Generation+1 || journal.Target.Current != journal.ReleaseID ||
		journal.Target.CurrentReceiptSHA256 != journal.ReceiptSHA256 ||
		!validJournalAnchorBinding(journal) {
		return fmt.Errorf("%w: package journal is invalid", ErrResidue)
	}
	if journal.Operation == operationInstall {
		if journal.Target.Previous != journal.Before.Current || journal.Target.PreviousReceiptSHA256 != journal.Before.CurrentReceiptSHA256 ||
			journal.RetiredReleaseID != journal.Before.Previous || journal.RetiredReceiptSHA256 != journal.Before.PreviousReceiptSHA256 {
			return fmt.Errorf("%w: install journal transition is invalid", ErrResidue)
		}
	} else if journal.Before.Previous == "" || journal.Target.Current != journal.Before.Previous ||
		journal.Target.CurrentReceiptSHA256 != journal.Before.PreviousReceiptSHA256 || journal.Target.Previous != journal.Before.Current ||
		journal.Target.PreviousReceiptSHA256 != journal.Before.CurrentReceiptSHA256 || journal.RetiredReleaseID != "" || journal.RetiredReceiptSHA256 != "" {
		return fmt.Errorf("%w: rollback journal transition is invalid", ErrResidue)
	}
	if (journal.RetiredReleaseID == "") != (journal.RetiredReceiptSHA256 == "") ||
		(journal.RetiredReleaseID != "" && (!validReleaseID(journal.RetiredReleaseID) || !validDigest(journal.RetiredReceiptSHA256))) {
		return fmt.Errorf("%w: retirement binding is invalid", ErrResidue)
	}
	return nil
}

func validJournalAnchorBinding(journal journalRecord) bool {
	empty := journal.PolicySHA256 == "" && journal.AnchorBeforeSHA256 == "" && journal.AnchorTargetSHA256 == ""
	complete := validDigest(journal.PolicySHA256) && validDigest(journal.AnchorBeforeSHA256) && validDigest(journal.AnchorTargetSHA256) && journal.AnchorBeforeSHA256 != journal.AnchorTargetSHA256
	return empty || complete
}

func encodeSelector(selector selectorRecord) ([]byte, error) {
	if err := validateSelector(selector); err != nil {
		return nil, err
	}
	return encodeCanonical(selector)
}

func validateSelector(selector selectorRecord) error {
	if selector.Schema != selectorSchema {
		return errors.New("packagetxn: selector schema is invalid")
	}
	if selector.Generation == 0 {
		if selector.Current != "" || selector.CurrentReceiptSHA256 != "" || selector.Previous != "" || selector.PreviousReceiptSHA256 != "" {
			return errors.New("packagetxn: empty selector has release state")
		}
		return nil
	}
	if !validReleaseID(selector.Current) || !validDigest(selector.CurrentReceiptSHA256) {
		return errors.New("packagetxn: selector current release is invalid")
	}
	if (selector.Previous == "") != (selector.PreviousReceiptSHA256 == "") {
		return errors.New("packagetxn: selector previous release is incomplete")
	}
	if selector.Previous != "" && (!validReleaseID(selector.Previous) || !validDigest(selector.PreviousReceiptSHA256) || selector.Previous == selector.Current) {
		return errors.New("packagetxn: selector previous release is invalid")
	}
	return nil
}

func encodeReceipt(receipt receiptRecord) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	return encodeCanonical(receipt)
}

func validateReceipt(receipt receiptRecord) error {
	if receipt.Schema != receiptSchema || !validRole(receipt.Role) || !validToken(receipt.OS) || !validToken(receipt.Arch) ||
		!validReleaseID(receipt.ReleaseID) || receipt.Sequence == 0 || !validDigest(receipt.ManifestSHA256) ||
		len(receipt.Files) == 0 || len(receipt.Files) > maximumFileCount {
		return errors.New("packagetxn: package receipt is invalid")
	}
	for index, file := range receipt.Files {
		if !validToken(file.ArtifactName) || !validComponent(file.Name) || file.Name == receiptFileName || file.Name == receiptStageName ||
			!validDigest(file.SHA256) || file.Size <= 0 || file.Size > 1<<40 || !validInstallMode(decodeInstallMode(file.Mode)) ||
			(file.Mode&0o2000 != 0 && file.GID == 0) {
			return errors.New("packagetxn: package receipt file is invalid")
		}
		if index > 0 && receipt.Files[index-1].Name >= file.Name {
			return errors.New("packagetxn: package receipt files are not unique and sorted")
		}
	}
	return nil
}

func encodeCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("packagetxn: encode canonical metadata: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) == 0 || len(encoded) > maximumMetadataSize {
		return nil, errors.New("packagetxn: canonical metadata is empty or too large")
	}
	return encoded, nil
}

func decodeCanonical[T any](encoded []byte, destination *T, encoder func(T) ([]byte, error)) error {
	if len(encoded) == 0 || len(encoded) > maximumMetadataSize {
		return errors.New("metadata size is invalid")
	}
	if err := strictjson.Decode(encoded, destination); err != nil {
		return err
	}
	reencoded, err := encoder(*destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, reencoded) {
		return errors.New("metadata is not canonical JSON")
	}
	return nil
}

func validRole(role string) bool {
	return role == "client" || role == "connector" || role == "relay" || role == "provisioner"
}

func validReleaseID(value string) bool {
	identifier, err := protocol.ParseID(value)
	return err == nil && identifier != (protocol.ID{})
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := range value {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := range value {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validComponent(value string) bool {
	return validToken(value) && value != "." && value != ".."
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") || filepath.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if !validComponent(component) {
			return false
		}
	}
	return true
}

func validInstallMode(mode fs.FileMode) bool {
	switch unixInstallMode(mode) {
	case 0o600, 0o644, 0o700, 0o750, 0o755, 0o2750, 0o2751:
		return true
	default:
		return false
	}
}

func unixInstallMode(mode fs.FileMode) uint32 {
	value := uint32(mode.Perm())
	if mode&fs.ModeSetgid != 0 {
		value |= 0o2000
	}
	return value
}

func decodeInstallMode(mode uint32) fs.FileMode {
	value := fs.FileMode(mode & 0o777)
	if mode&0o2000 != 0 {
		value |= fs.ModeSetgid
	}
	return value
}

func digestBytes(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func openRootChain(path string, ownerUID, ownerGID, finalMode uint32, strictAncestors bool, aclCheck func(int, bool) error) (int, error) {
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("packagetxn: open filesystem root: %w", err)
	}
	if strictAncestors {
		if err := requireProtectedAncestor(fd, ownerUID, ownerGID, aclCheck); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
	}
	for index, component := range components {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("packagetxn: open package root component: %w", openErr)
		}
		fd = next
		if strictAncestors || index == len(components)-1 {
			if err := requireProtectedAncestor(fd, ownerUID, ownerGID, aclCheck); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
		}
	}
	if err := requireDirectory(fd, ownerUID, ownerGID, finalMode, aclCheck); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func requireProtectedAncestor(fd int, ownerUID, ownerGID uint32, aclCheck func(int, bool) error) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("packagetxn: inspect package root component: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != ownerUID || stat.Gid != ownerGID || stat.Mode&0o022 != 0 {
		return errors.New("packagetxn: package root ancestry is not protected by the expected owner")
	}
	if err := aclCheck(fd, true); err != nil {
		return fmt.Errorf("packagetxn: package root ancestry ACL: %w", err)
	}
	return nil
}

func ensurePrivateDirectory(parent int, name string, ownerUID, ownerGID uint32, expectedDevice uint64, aclCheck func(int, bool) error) (int, error) {
	return ensureDirectory(parent, name, ownerUID, ownerGID, 0o700, expectedDevice, aclCheck)
}

func ensurePackageDirectory(parent int, name string, manager *Manager) (int, error) {
	gid, mode := packageDirectoryProfile(manager)
	return ensureDirectory(parent, name, manager.ownerUID, gid, mode, manager.rootDevice, manager.checkACL)
}

func requirePackageDirectory(fd int, manager *Manager) error {
	gid, mode := packageDirectoryProfile(manager)
	return requireDirectory(fd, manager.ownerUID, gid, mode, manager.checkACL)
}

// Linux reaches the ordinary provisioner through a public symlink and relies
// on its qualified protected-hardlink policy, so that package namespace is
// root-owned and traversable. Darwin instead publishes a distinct ordinary
// frontend copy: its authenticated provisioner package tree remains
// non-traversable so an unprivileged hard link cannot poison package identity.
// Every runtime-bearing role stays restricted to its dedicated reader group.
func packageDirectoryProfile(manager *Manager) (uint32, uint32) {
	if manager.role == "provisioner" && manager.platformOS == "linux" {
		return manager.ownerGID, 0o755
	}
	return manager.readerGID, 0o750
}

func ensureDirectory(parent int, name string, ownerUID, ownerGID, mode uint32, expectedDevice uint64, aclCheck func(int, bool) error) (int, error) {
	if !validComponent(name) {
		return -1, errors.New("packagetxn: directory name is invalid")
	}
	created := false
	if err := unix.Mkdirat(parent, name, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("packagetxn: create directory %q: %w", name, err)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("packagetxn: open directory %q: %w", name, err)
	}
	if created {
		if err := unix.Fchown(fd, int(ownerUID), int(ownerGID)); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("packagetxn: own directory %q: %w", name, err)
		}
		if err := unix.Fchmod(fd, mode); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("packagetxn: protect directory %q: %w", name, err)
		}
	}
	if err := requireDirectory(fd, ownerUID, ownerGID, mode, aclCheck); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("packagetxn: inspect directory device %q: %w", name, err)
	}
	if uint64(stat.Dev) != expectedDevice {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%w: package transaction crosses a filesystem boundary", ErrResidue)
	}
	if created {
		if err := unix.Fsync(fd); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("packagetxn: sync directory %q: %w", name, err)
		}
		if err := unix.Fsync(parent); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("packagetxn: sync parent of %q: %w", name, err)
		}
	}
	return fd, nil
}

func requireDirectory(fd int, ownerUID, ownerGID, mode uint32, aclCheck func(int, bool) error) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("packagetxn: inspect directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != ownerUID || stat.Gid != ownerGID || uint32(stat.Mode)&0o7777 != mode {
		return fmt.Errorf("%w: directory ownership or mode is not exact", ErrResidue)
	}
	if err := aclCheck(fd, true); err != nil {
		return fmt.Errorf("packagetxn: directory ACL: %w", err)
	}
	return nil
}

type descriptorLock struct{ fd int }

func (lock *descriptorLock) close() error {
	if lock == nil || lock.fd < 0 {
		return nil
	}
	fd := lock.fd
	lock.fd = -1
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	closeErr := unix.Close(fd)
	if unlockErr != nil {
		return fmt.Errorf("packagetxn: unlock role: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("packagetxn: close role lock: %w", closeErr)
	}
	return nil
}

func acquireDescriptorLock(directory int, name string, ownerUID, ownerGID uint32, aclCheck func(int, bool) error, openedHook func(int, int, string) error) (*descriptorLock, error) {
	created := false
	fd, err := unix.Openat(directory, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err == nil {
		created = true
	} else if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(directory, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.EACCES) {
			fd, err = unix.Openat(directory, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		}
		if errors.Is(err, unix.EACCES) {
			fd, err = unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("packagetxn: open role lock: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(fd)
		}
	}()
	if created {
		if err := unix.Fchown(fd, int(ownerUID), int(ownerGID)); err != nil {
			return nil, fmt.Errorf("packagetxn: own role lock: %w", err)
		}
		if err := unix.Fchmod(fd, 0o600); err != nil {
			return nil, fmt.Errorf("packagetxn: protect role lock: %w", err)
		}
	}
	before, err := normalizeRoleLock(fd, ownerUID, ownerGID, aclCheck)
	if err != nil {
		return nil, err
	}
	if openedHook != nil {
		if err := openedHook(directory, fd, name); err != nil {
			return nil, err
		}
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("packagetxn: lock role: %w", err)
	}
	locked := true
	defer func() {
		if locked {
			_ = unix.Flock(fd, unix.LOCK_UN)
		}
	}()
	var selected unix.Stat_t
	if err := unix.Fstatat(directory, name, &selected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fmt.Errorf("packagetxn: reselect role lock: %w", err)
	}
	if selected.Mode&unix.S_IFMT != unix.S_IFREG || selected.Dev != before.Dev || selected.Ino != before.Ino {
		return nil, fmt.Errorf("%w: role lock name changed during acquisition", ErrResidue)
	}
	if before.Size != 0 {
		return nil, fmt.Errorf("%w: role lock must remain empty", ErrResidue)
	}
	if created {
		if err := unix.Fsync(fd); err != nil {
			return nil, fmt.Errorf("packagetxn: sync role lock: %w", err)
		}
		if err := unix.Fsync(directory); err != nil {
			return nil, fmt.Errorf("packagetxn: sync role lock parent: %w", err)
		}
	}
	after, err := requireRegularFile(fd, ownerUID, ownerGID, 0o600, 0, aclCheck)
	if err != nil {
		return nil, err
	}
	if after.Dev != before.Dev || after.Ino != before.Ino {
		return nil, fmt.Errorf("%w: role lock inode changed", ErrResidue)
	}
	closeOnError = false
	locked = false
	return &descriptorLock{fd: fd}, nil
}

func normalizeRoleLock(fd int, ownerUID, ownerGID uint32, aclCheck func(int, bool) error) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("packagetxn: inspect role lock: %w", err)
	}
	mode := uint32(stat.Mode) & 0o7777
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 || stat.Uid != ownerUID || stat.Gid != ownerGID ||
		mode&^uint32(0o600) != 0 || stat.Size != 0 {
		return unix.Stat_t{}, fmt.Errorf("%w: role lock ownership, type, links, size, or mode is invalid", ErrResidue)
	}
	if err := aclCheck(fd, false); err != nil {
		return unix.Stat_t{}, fmt.Errorf("packagetxn: role lock ACL: %w", err)
	}
	if mode != 0o600 {
		if err := unix.Fchmod(fd, 0o600); err != nil {
			return unix.Stat_t{}, fmt.Errorf("packagetxn: normalize interrupted role lock: %w", err)
		}
		if err := unix.Fsync(fd); err != nil {
			return unix.Stat_t{}, fmt.Errorf("packagetxn: sync normalized role lock: %w", err)
		}
	}
	return requireRegularFile(fd, ownerUID, ownerGID, 0o600, 0, aclCheck)
}

func requireRegularFile(fd int, ownerUID, ownerGID, mode uint32, exactSize int64, aclCheck func(int, bool) error) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("packagetxn: inspect file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 || stat.Uid != ownerUID || stat.Gid != ownerGID || uint32(stat.Mode)&0o7777 != mode || (exactSize >= 0 && stat.Size != exactSize) {
		return unix.Stat_t{}, fmt.Errorf("%w: file ownership, type, links, size, or mode is not exact", ErrResidue)
	}
	if err := aclCheck(fd, false); err != nil {
		return unix.Stat_t{}, fmt.Errorf("packagetxn: file ACL: %w", err)
	}
	return stat, nil
}

func readFD(fd int, limit int64) ([]byte, error) {
	if limit < 0 || limit > 1<<40 {
		return nil, errors.New("packagetxn: read limit is invalid")
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, fmt.Errorf("packagetxn: seek file: %w", err)
	}
	result := make([]byte, 0, minInt64(limit, 32<<10))
	buffer := make([]byte, 32<<10)
	for {
		n, err := unix.Read(fd, buffer)
		if n > 0 {
			if int64(len(result))+int64(n) > limit {
				return nil, errors.New("packagetxn: file exceeds read limit")
			}
			result = append(result, buffer[:n]...)
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("packagetxn: read file: %w", err)
		}
		if n == 0 {
			return result, nil
		}
	}
}

func minInt64(left, right int64) int {
	if left < right {
		return int(left)
	}
	return int(right)
}

func writeAll(fd int, contents []byte) error {
	for len(contents) > 0 {
		written, err := unix.Write(fd, contents)
		if written > 0 {
			contents = contents[written:]
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("short write")
		}
	}
	return nil
}

func readOptionalExactFile(directory int, name string, mode uint32, limit int64, manager *Manager) ([]byte, bool, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: open %s: %v", ErrResidue, name, err)
	}
	defer unix.Close(fd)
	before, err := requireRegularFile(fd, manager.ownerUID, manager.ownerGID, mode, -1, manager.checkACL)
	if err != nil {
		return nil, false, err
	}
	if before.Size < 0 || before.Size > limit {
		return nil, false, fmt.Errorf("%w: %s exceeds its limit", ErrResidue, name)
	}
	contents, err := readFD(fd, limit)
	if err != nil {
		return nil, false, err
	}
	after, err := requireRegularFile(fd, manager.ownerUID, manager.ownerGID, mode, before.Size, manager.checkACL)
	if err != nil {
		return nil, false, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || len(contents) != int(after.Size) {
		return nil, false, fmt.Errorf("%w: %s changed while read", ErrResidue, name)
	}
	return contents, true, nil
}

func replaceCanonicalFile(directory int, target, stage string, contents []byte, manager *Manager) error {
	if err := removeAuthorizedStage(directory, stage, manager); err != nil {
		return err
	}
	fd, err := unix.Openat(directory, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("packagetxn: create metadata stage %s: %w", stage, err)
	}
	stageExists := true
	defer func() {
		_ = unix.Close(fd)
		if stageExists {
			_ = unix.Unlinkat(directory, stage, 0)
		}
	}()
	if err := unix.Fchown(fd, int(manager.ownerUID), int(manager.ownerGID)); err != nil {
		return fmt.Errorf("packagetxn: own metadata stage: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("packagetxn: protect metadata stage: %w", err)
	}
	if _, err := requireRegularFile(fd, manager.ownerUID, manager.ownerGID, 0o600, 0, manager.checkACL); err != nil {
		return err
	}
	if err := writeAll(fd, contents); err != nil {
		return fmt.Errorf("packagetxn: write metadata stage: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("packagetxn: sync metadata stage: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		fd = -1
		return fmt.Errorf("packagetxn: close metadata stage: %w", err)
	}
	fd = -1
	if _, _, err := readOptionalExactFile(directory, target, 0o600, maximumMetadataSize, manager); err != nil {
		return err
	}
	if err := unix.Renameat(directory, stage, directory, target); err != nil {
		return fmt.Errorf("packagetxn: atomically replace %s: %w", target, err)
	}
	stageExists = false
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("packagetxn: sync metadata selector directory: %w", err)
	}
	return nil
}

func removeAuthorizedStage(directory int, stage string, manager *Manager) error {
	fd, err := unix.Openat(directory, stage, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EACCES) {
		// A crash between O_CREAT and the following exact Fchmod may leave a
		// safe owner-write-only subset under a restrictive process umask.
		fd, err = unix.Openat(directory, stage, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: open metadata stage %s: %v", ErrResidue, stage, err)
	}
	defer unix.Close(fd)
	if err := requireAuthorizedMetadataStage(fd, manager); err != nil {
		return err
	}
	if err := unix.Unlinkat(directory, stage, 0); err != nil {
		return fmt.Errorf("packagetxn: remove interrupted metadata stage: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("packagetxn: sync metadata stage removal: %w", err)
	}
	return nil
}

func requireAuthorizedMetadataStage(fd int, manager *Manager) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("packagetxn: inspect metadata stage: %w", err)
	}
	mode := uint32(stat.Mode) & 0o7777
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 || stat.Uid != manager.ownerUID || stat.Gid != manager.ownerGID ||
		mode&^uint32(0o600) != 0 || stat.Size < 0 || stat.Size > maximumMetadataSize {
		return fmt.Errorf("%w: metadata stage is not attributable to this transaction", ErrResidue)
	}
	if err := manager.checkACL(fd, false); err != nil {
		return fmt.Errorf("packagetxn: metadata stage ACL: %w", err)
	}
	return nil
}

func activeLinkTarget(releaseID string) string {
	return releasesDirectory + "/" + releaseID
}

func readActiveLink(directory int, name string, manager *Manager) (string, bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(directory, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return "", false, nil
	} else if err != nil {
		return "", false, fmt.Errorf("%w: inspect active executable link: %v", ErrResidue, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFLNK || uint64(stat.Nlink) != 1 || stat.Uid != manager.ownerUID || stat.Gid != manager.ownerGID {
		return "", false, fmt.Errorf("%w: active executable path is not an owned single-link symlink", ErrResidue)
	}
	buffer := make([]byte, 512)
	length, err := unix.Readlinkat(directory, name, buffer)
	if err != nil || length <= 0 || length == len(buffer) {
		return "", false, fmt.Errorf("%w: read active executable link", ErrResidue)
	}
	target := string(buffer[:length])
	prefix := releasesDirectory + "/"
	if !strings.HasPrefix(target, prefix) {
		return "", false, fmt.Errorf("%w: active executable link has an invalid target", ErrResidue)
	}
	releaseID := strings.TrimPrefix(target, prefix)
	if !validReleaseID(releaseID) || target != activeLinkTarget(releaseID) {
		return "", false, fmt.Errorf("%w: active executable link target is not canonical", ErrResidue)
	}
	return releaseID, true, nil
}

func removeActiveLinkStage(directory int, manager *Manager) error {
	_, exists, err := readActiveLink(directory, activeLinkStageName, manager)
	if err != nil || !exists {
		return err
	}
	if err := unix.Unlinkat(directory, activeLinkStageName, 0); err != nil {
		return fmt.Errorf("packagetxn: remove interrupted active-link stage: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("packagetxn: sync active-link stage removal: %w", err)
	}
	return nil
}

func replaceActiveLink(directory int, releaseID string, manager *Manager) error {
	if !validReleaseID(releaseID) {
		return errors.New("packagetxn: active release ID is invalid")
	}
	if err := removeActiveLinkStage(directory, manager); err != nil {
		return err
	}
	if err := unix.Symlinkat(activeLinkTarget(releaseID), directory, activeLinkStageName); err != nil {
		return fmt.Errorf("packagetxn: create active-link stage: %w", err)
	}
	stageExists := true
	defer func() {
		if stageExists {
			_ = unix.Unlinkat(directory, activeLinkStageName, 0)
		}
	}()
	if err := unix.Fchownat(directory, activeLinkStageName, int(manager.ownerUID), int(manager.ownerGID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("packagetxn: own active-link stage: %w", err)
	}
	if actual, exists, err := readActiveLink(directory, activeLinkStageName, manager); err != nil || !exists || actual != releaseID {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: active-link stage target differs from the transaction", ErrResidue)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("packagetxn: sync active-link stage: %w", err)
	}
	if err := unix.Renameat(directory, activeLinkStageName, directory, activeLinkName); err != nil {
		return fmt.Errorf("packagetxn: publish active executable link: %w", err)
	}
	stageExists = false
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("packagetxn: sync active executable link: %w", err)
	}
	actual, exists, err := readActiveLink(directory, activeLinkName, manager)
	if err != nil || !exists || actual != releaseID {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: active executable link differs after publication", ErrResidue)
	}
	return nil
}

func requireAllowedDirectoryEntries(directory int, allowed map[string]struct{}, label string) error {
	names, err := directoryNames(directory)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("%w: %s directory contains %q", ErrResidue, label, name)
		}
	}
	return nil
}

func directoryNames(directory int) ([]string, error) {
	duplicate, err := unix.Openat(directory, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("packagetxn: reopen directory descriptor: %w", err)
	}
	file := os.NewFile(uintptr(duplicate), "packagetxn-directory")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, errors.New("packagetxn: wrap directory descriptor")
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("packagetxn: enumerate directory: %w", err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return names, nil
}
