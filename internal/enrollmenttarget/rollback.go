//go:build darwin || linux

package enrollmenttarget

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

type RollbackResult struct {
	SourceRecordID     string
	ActivatedRecordID  string
	DeploymentSequence uint64
	CredentialSequence uint64
	ReleaseSequence    uint64
	RecoverySequence   uint64
	StateGeneration    uint64
}

// Rollback selects one exact signed record tuple only with a fresh offline
// authorization. A new immutable generation is rendered from those exact
// credentials plus the *current* verifier and revocation overlay, so rollback
// cannot resurrect a tombstoned credential or forgotten denial.
func Rollback(rootPath string, authorization []byte, now time.Time) (RollbackResult, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || len(authorization) == 0 || len(authorization) > enrollment.MaxRollbackAuthorization {
		return RollbackResult{}, errors.New("enrollmenttarget: bounded rollback authorization and current time are required")
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return RollbackResult{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return RollbackResult{}, err
	}
	defer lock.Close()
	boundary, err := acquireLifecycleBoundary(root)
	if err != nil {
		return RollbackResult{}, err
	}
	defer boundary.Close()
	state, stateDigest, err := readAnchoredState(root)
	if err != nil {
		return RollbackResult{}, err
	}
	if state.ActiveRecordID == "" || state.StateGeneration == math.MaxUint64 || state.RecoverySequence == math.MaxUint64 {
		return RollbackResult{}, errors.New("enrollmenttarget: enrolled state with available recovery sequence space is required")
	}
	bootstrap, signer, err := readBootstrap(root, state, now)
	if err != nil {
		return RollbackResult{}, err
	}
	value, err := enrollment.VerifyRollbackAuthorization(authorization, signer, now)
	if err != nil {
		return RollbackResult{}, err
	}
	role, err := enrollmentRole(state.Role)
	if err != nil {
		return RollbackResult{}, err
	}
	if value.Role != role || value.InstallationID != state.InstallationID || value.Sequence != state.RecoverySequence+1 ||
		value.ExpectedStateGeneration != state.StateGeneration || value.ExpectedStateSHA256 != stateDigest {
		return RollbackResult{}, errors.New("enrollmenttarget: rollback authorization does not bind the exact current state")
	}
	if value.DeploymentSequence < state.RollbackFloors.DeploymentSequence || value.DeploymentSequence > state.HighestDeploymentSequence ||
		value.CredentialSequence < state.RollbackFloors.CredentialSequence || value.CredentialSequence > state.HighestCredentialSequence ||
		value.ReleaseSequence < state.RollbackFloors.ReleaseSequence || value.ReleaseSequence > state.HighestReleaseSequence {
		return RollbackResult{}, errors.New("enrollmenttarget: authorized rollback tuple is outside durable floors or high-waters")
	}
	recordName, err := recordDirectoryName(value.RecordID)
	if err != nil {
		return RollbackResult{}, err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return RollbackResult{}, err
	}
	manifest, contents, err := readVerifiedRecord(record, value.RecordSHA256)
	_ = record.Close()
	if err != nil {
		return RollbackResult{}, err
	}
	if manifest.Role != role || manifest.InstallationID != state.InstallationID || manifest.RecordID != value.RecordID ||
		manifest.DeploymentSequence != value.DeploymentSequence || manifest.CredentialSequence != value.CredentialSequence ||
		manifest.Runtime.ReleaseSequence != value.ReleaseSequence {
		return RollbackResult{}, errors.New("enrollmenttarget: authorized rollback tuple does not match the retained record")
	}
	deployment, err := enrollment.ParseBoundDeployment(contents[deploymentFile], contents[requestFile], now)
	if err != nil {
		return RollbackResult{}, fmt.Errorf("enrollmenttarget: rollback deployment: %w", err)
	}
	if err := enrollment.RejectTombstonedCredentials(deployment, state.CredentialTombstoneSPKIPins); err != nil {
		return RollbackResult{}, err
	}
	policy, err := effectiveLifecyclePolicy(root, state, bootstrap, signer)
	if err != nil {
		return RollbackResult{}, err
	}
	activatedID, activatedDigest, err := createDerivedRecord(
		rootPath, root, manifest, contents, deployment, runtimePolicyFromLifecycle(policy),
		state.PolicySequence, state.TombstoneSequence, now,
	)
	if err != nil {
		return RollbackResult{}, err
	}
	next := state
	next.StateGeneration++
	next.RecoverySequence = value.Sequence
	next.ActiveRecordID, next.ActiveRecordSHA256 = activatedID, activatedDigest
	next.ActiveDeploymentSequence, next.ActiveCredentialSequence = value.DeploymentSequence, value.CredentialSequence
	next.ActiveReleaseSequence = value.ReleaseSequence
	next.ActivePolicySequence, next.ActiveTombstoneSequence = state.PolicySequence, state.TombstoneSequence
	if err := commitState(root, state, next, boundary); err != nil {
		return RollbackResult{}, err
	}
	return RollbackResult{
		SourceRecordID: value.RecordID, ActivatedRecordID: activatedID,
		DeploymentSequence: value.DeploymentSequence, CredentialSequence: value.CredentialSequence,
		ReleaseSequence: value.ReleaseSequence, RecoverySequence: value.Sequence, StateGeneration: next.StateGeneration,
	}, nil
}
