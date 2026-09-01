//go:build darwin || linux

package enrollmenttarget

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/localstate"
	"github.com/sentrybottale/owntransit/internal/runtimebundle"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const deploymentFile = "deployment.json"

// ApplyResult is a non-secret receipt for one committed target generation.
type ApplyResult struct {
	Role                 enrollment.Role
	InstallationID       string
	RecordID             string
	DeploymentSequence   uint64
	CredentialEpoch      uint64
	RequestSHA256        string
	StateGeneration      uint64
	OneTimeSecretRemoved bool
}

// ApplyResponse authenticates, decrypts and request-binds one offline response,
// re-proves possession of the retained endpoint keys, renders an immutable
// generation, and atomically selects it by replacing only state.json. Exact
// ensured files make a crash before the state commit safely resumable.
func ApplyResponse(rootPath string, envelope []byte, now time.Time) (ApplyResult, error) {
	return applyResponse(rootPath, envelope, now, nil)
}

// applyResponse keeps the optional test observation inside the held exclusive
// lifecycle boundary, after one-time response-identity retirement and before
// the boundary's deferred release. Production always passes nil.
func applyResponse(rootPath string, envelope []byte, now time.Time, afterSecretRetirement func()) (ApplyResult, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || len(envelope) == 0 || len(envelope) > enrollment.MaxEnvelopeSize {
		return ApplyResult{}, errors.New("enrollmenttarget: bounded response envelope and current time are required")
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return ApplyResult{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return ApplyResult{}, err
	}
	defer lock.Close()
	boundary, err := acquireLifecycleBoundary(root)
	if err != nil {
		return ApplyResult{}, err
	}
	defer boundary.Close()

	state, err := readState(root)
	if err != nil {
		return ApplyResult{}, err
	}
	if state.PendingRequest == nil {
		return ApplyResult{}, errors.New("enrollmenttarget: no pending request is available for this response")
	}
	if state.StateGeneration == math.MaxUint64 {
		return ApplyResult{}, errors.New("enrollmenttarget: local lifecycle sequence space is exhausted")
	}
	bootstrap, signer, err := readBootstrap(root, state, now)
	if err != nil {
		return ApplyResult{}, err
	}
	recordName, err := recordDirectoryName(state.PendingRequest.Nonce)
	if err != nil {
		return ApplyResult{}, err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return ApplyResult{}, err
	}
	defer record.Close()

	requestBytes, err := record.ReadFile(requestFile, enrollment.MaxRequestSize)
	if err != nil {
		return ApplyResult{}, err
	}
	if _, err := enrollment.ParseRequest(requestBytes, now); err != nil {
		return ApplyResult{}, fmt.Errorf("enrollmenttarget: retained request: %w", err)
	}
	outerKey, err := record.ReadFile(outerPrivateKeyFile, maxPrivateKeySize)
	if err != nil {
		return ApplyResult{}, err
	}
	var innerKey []byte
	if bootstrap.Role != enrollment.RoleRelay {
		innerKey, err = record.ReadFile(innerPrivateKeyFile, maxPrivateKeySize)
		if err != nil {
			return ApplyResult{}, err
		}
	}
	responseIdentity, err := record.ReadFile(responseIdentityFile, maxAgeIdentity)
	if err != nil {
		return ApplyResult{}, err
	}
	role, err := enrollmentRole(state.Role)
	if err != nil {
		return ApplyResult{}, err
	}
	effectivePolicy, err := effectiveLifecyclePolicy(root, state, bootstrap, signer)
	if err != nil {
		return ApplyResult{}, err
	}
	bootstrapPins, err := enrollment.IssuerPinsFromTrust(effectivePolicy.Trust, now)
	if err != nil {
		return ApplyResult{}, err
	}
	verified, err := enrollment.VerifyForApply(envelope, enrollment.ApplyPolicy{
		Role: role, InstallationID: state.InstallationID,
		RequestBytes: requestBytes, ResponseIdentity: string(responseIdentity), DeploymentSigner: signer,
		ExpectedIssuerPins: bootstrapPins, ExpectedRuntime: bootstrap.Runtime,
		ExpectedRequestSequence:   state.PendingRequest.Sequence,
		HighestDeploymentSequence: state.HighestDeploymentSequence,
		HighestCredentialEpoch:    state.HighestCredentialSequence,
		OuterPrivateKeyPEM:        outerKey, InnerPrivateKeyPEM: innerKey,
		ConsumedRequestSHA256:        append([]string(nil), state.ConsumedRequestSHA256...),
		TombstonedCredentialSPKIPins: append([]string(nil), state.CredentialTombstoneSPKIPins...),
	}, now)
	if err != nil {
		return ApplyResult{}, err
	}
	if verified.RequestSHA256 != state.PendingRequest.RequestSHA256 ||
		verified.Request.Nonce != state.PendingRequest.Nonce ||
		verified.Request.Role != bootstrap.Role || verified.Request.Runtime != bootstrap.Runtime ||
		verified.Request.Runtime.ReleaseSequence != state.HighestReleaseSequence {
		return ApplyResult{}, errors.New("enrollmenttarget: verified response does not match durable pending or release state")
	}

	generationDirectory := filepath.Join(rootPath, recordName)
	files, err := runtimebundle.RenderWithPolicy(
		verified.Deployment,
		generationDirectory,
		runtimebundle.PrivateKeys{OuterPEM: outerKey, InnerPEM: innerKey},
		runtimePolicyFromLifecycle(effectivePolicy),
		now,
	)
	if err != nil {
		return ApplyResult{}, err
	}
	for _, file := range files {
		if filepath.Dir(file.Path) != generationDirectory || filepath.Base(file.Path) == "." || filepath.Base(file.Path) == string(filepath.Separator) {
			return ApplyResult{}, errors.New("enrollmenttarget: renderer returned a path outside the immutable generation")
		}
		if err := record.EnsureFile(filepath.Base(file.Path), file.Contents, file.Mode); err != nil {
			return ApplyResult{}, err
		}
	}
	if err := record.EnsureFile(deploymentFile, verified.DeploymentBytes, 0o600); err != nil {
		return ApplyResult{}, err
	}
	responseDigest := sha256.Sum256(envelope)
	recordBytes, recordDigest, err := buildRecordManifest(
		verified, files, requestBytes, hex.EncodeToString(responseDigest[:]), state.PolicySequence, state.TombstoneSequence,
	)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := record.EnsureFile(recordFile, recordBytes, 0o600); err != nil {
		return ApplyResult{}, err
	}
	if err := record.Sync(); err != nil {
		return ApplyResult{}, err
	}

	next := state
	next.StateGeneration++
	next.ActiveRecordID = state.PendingRequest.Nonce
	next.ActiveRecordSHA256 = recordDigest
	next.ActiveDeploymentSequence = verified.NextDeploymentSequence
	next.ActiveCredentialSequence = verified.NextCredentialEpoch
	next.ActiveReleaseSequence = verified.Deployment.Runtime.ReleaseSequence
	next.ActivePolicySequence = state.PolicySequence
	next.ActiveTombstoneSequence = state.TombstoneSequence
	next.HighestDeploymentSequence = verified.NextDeploymentSequence
	next.HighestCredentialSequence = verified.NextCredentialEpoch
	next.ConsumedRequestSHA256, err = insertSortedBounded(
		state.ConsumedRequestSHA256,
		verified.RequestSHA256,
		localstate.MaxConsumedRequestDigests,
	)
	if err != nil {
		return ApplyResult{}, err
	}
	next.PendingRequest = nil
	if err := commitState(root, state, next, boundary); err != nil {
		return ApplyResult{}, err
	}
	oneTimeSecretRemoved := record.UnlinkFile(responseIdentityFile) == nil
	if afterSecretRetirement != nil {
		afterSecretRetirement()
	}
	return ApplyResult{
		Role: verified.Deployment.Role, InstallationID: verified.Deployment.InstallationID,
		RecordID: next.ActiveRecordID, DeploymentSequence: next.HighestDeploymentSequence,
		CredentialEpoch: next.HighestCredentialSequence, RequestSHA256: verified.RequestSHA256,
		StateGeneration: next.StateGeneration, OneTimeSecretRemoved: oneTimeSecretRemoved,
	}, nil
}

// ReconcileAppliedResponse proves that the exact response was already
// committed by ApplyResponse. It is the crash-safe bridge for a coordinator
// which durably retained the response before activation but did not yet record
// its own applied phase. It never decrypts or reapplies the response.
func ReconcileAppliedResponse(rootPath string, envelope []byte, requestSHA256 string) (ApplyResult, error) {
	var result ApplyResult
	err := WithReconciledAppliedResponse(rootPath, envelope, requestSHA256, func(value ApplyResult) error {
		result = value
		return nil
	})
	return result, err
}

// WithReconciledAppliedResponse proves the exact committed response and keeps
// the target lifecycle lock held while operation consumes its immutable apply
// receipt. This is the narrow linearization gate used by READY: a concurrent
// policy, rollback, recovery, rotation, or response apply cannot replace the
// active record between reconciliation and the carrier proof being committed.
func WithReconciledAppliedResponse(rootPath string, envelope []byte, requestSHA256 string, operation func(ApplyResult) error) error {
	if len(envelope) == 0 || len(envelope) > enrollment.MaxEnvelopeSize || !validDigest(requestSHA256) || operation == nil {
		return errors.New("enrollmenttarget: bounded response, request binding, and reconciliation operation are required")
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, _, err := readAnchoredState(root)
	if err != nil {
		return err
	}
	if state.PendingRequest != nil || state.ActiveRecordID == "" {
		return errors.New("enrollmenttarget: response has not been committed")
	}
	recordName, err := recordDirectoryName(state.ActiveRecordID)
	if err != nil {
		return err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return err
	}
	defer record.Close()
	manifest, _, err := readAndVerifyRecord(record, state)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(envelope)
	if manifest.RequestSHA256 != requestSHA256 || manifest.AppliedResponseSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("enrollmenttarget: active record does not bind the exact retained response")
	}
	if err := record.UnlinkFile(responseIdentityFile); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return operation(ApplyResult{
		Role: manifest.Role, InstallationID: manifest.InstallationID, RecordID: manifest.RecordID,
		DeploymentSequence: manifest.DeploymentSequence, CredentialEpoch: manifest.CredentialSequence,
		RequestSHA256: manifest.RequestSHA256, StateGeneration: state.StateGeneration,
		OneTimeSecretRemoved: true,
	})
}
