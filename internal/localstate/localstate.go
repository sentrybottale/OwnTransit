// Package localstate defines the strict, durable, target-local OwnTransit
// lifecycle state. It contains no private key material and accepts no path.
package localstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	Schema       = "owntransit.local-state.v1"
	MaxStateSize = 1 << 20

	MaxConsumedRequestDigests = 4096
	MaxCredentialTombstones   = 1024
	MaxRevokedClientIDs       = 1024
	MaxPendingRequestValidity = 24 * 60 * 60
)

// Role is the immutable role of one target-local state root.
type Role string

const (
	RoleClient    Role = "client"
	RoleConnector Role = "connector"
	RoleRelay     Role = "relay"
)

// State is one complete durable lifecycle snapshot. ActiveRecordID and its
// digest select one immutable record while the active sequence tuple is
// independently checked against monotonic high-waters and rollback floors.
// PendingRequest is a singular pointer by design: a target may retain at most
// one live enrollment request. Consumed digests and credential tombstones are
// explicit bounded arrays and must be sorted, unique and canonical.
type State struct {
	Schema                       string                  `json:"schema"`
	Role                         Role                    `json:"role"`
	InstallationID               string                  `json:"installation_id"`
	StateGeneration              uint64                  `json:"state_generation"`
	RequestSequenceHighWater     uint64                  `json:"request_sequence_high_water"`
	HighestDeploymentSequence    uint64                  `json:"highest_deployment_sequence"`
	HighestReleaseSequence       uint64                  `json:"highest_release_sequence"`
	HighestCredentialSequence    uint64                  `json:"highest_credential_sequence"`
	RollbackFloors               RollbackFloors          `json:"rollback_floors"`
	ActiveRecordID               string                  `json:"active_record_id"`
	ActiveRecordSHA256           string                  `json:"active_record_sha256"`
	ActiveDeploymentSequence     uint64                  `json:"active_deployment_sequence"`
	ActiveCredentialSequence     uint64                  `json:"active_credential_sequence"`
	ActiveReleaseSequence        uint64                  `json:"active_release_sequence"`
	ActivePolicySequence         uint64                  `json:"active_policy_sequence"`
	ActiveTombstoneSequence      uint64                  `json:"active_tombstone_sequence"`
	PendingRequest               *PendingRequestMetadata `json:"pending_request"`
	ConsumedRequestSHA256        []string                `json:"consumed_request_sha256"`
	RevokedClientInstallationIDs []string                `json:"revoked_client_installation_ids"`
	CredentialTombstoneSPKIPins  []string                `json:"credential_tombstone_spki_sha256"`
	PolicySequence               uint64                  `json:"policy_sequence"`
	PolicySHA256                 string                  `json:"policy_sha256"`
	TombstoneSequence            uint64                  `json:"tombstone_sequence"`
	RecoverySequence             uint64                  `json:"recovery_sequence"`
}

// RollbackFloors are monotonic lower bounds for locally selectable durable
// records. A floor may be zero until its corresponding sequence exists.
type RollbackFloors struct {
	DeploymentSequence uint64 `json:"deployment_sequence"`
	ReleaseSequence    uint64 `json:"release_sequence"`
	CredentialSequence uint64 `json:"credential_sequence"`
	PolicySequence     uint64 `json:"policy_sequence"`
	TombstoneSequence  uint64 `json:"tombstone_sequence"`
}

// PendingRequestMetadata binds the sole retained enrollment request without
// embedding its request bytes, age identity or endpoint private keys.
type PendingRequestMetadata struct {
	Sequence      uint64 `json:"sequence"`
	RequestSHA256 string `json:"request_sha256"`
	Nonce         string `json:"nonce"`
	CreatedUnix   int64  `json:"created_unix"`
	ExpiresUnix   int64  `json:"expires_unix"`
}

// Encode validates and emits one newline-terminated state record.
func Encode(state State) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("localstate: encode: %w", err)
	}
	if len(encoded) >= MaxStateSize {
		return nil, errors.New("localstate: encoded state exceeds size limit")
	}
	return append(encoded, '\n'), nil
}

// Decode parses exactly one bounded state value with duplicate and unknown
// field rejection, then validates every invariant.
func Decode(encoded []byte) (State, error) {
	if len(encoded) == 0 || len(encoded) > MaxStateSize {
		return State{}, fmt.Errorf("localstate: state size must be within 1..%d bytes", MaxStateSize)
	}
	var state State
	if err := strictjson.Decode(encoded, &state); err != nil {
		return State{}, fmt.Errorf("localstate: decode: %w", err)
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

// Validate checks one state snapshot without consulting network or clock
// state. Expired pending requests remain parseable so they can be explicitly
// consumed or replaced; only their encoded validity window is bounded here.
func (state State) Validate() error {
	if state.Schema != Schema {
		return errors.New("localstate: unsupported schema")
	}
	if !validRole(state.Role) {
		return errors.New("localstate: role is invalid")
	}
	if err := validNonzeroID(state.InstallationID); err != nil {
		return errors.New("localstate: installation ID is not a nonzero canonical ID")
	}
	if state.StateGeneration == 0 {
		return errors.New("localstate: state generation must be positive")
	}
	if state.HighestReleaseSequence == 0 {
		return errors.New("localstate: an active state must have a positive release sequence")
	}
	if (state.HighestDeploymentSequence == 0) != (state.HighestCredentialSequence == 0) {
		return errors.New("localstate: deployment and credential activation must be present together")
	}
	if state.RequestSequenceHighWater < state.HighestCredentialSequence {
		return errors.New("localstate: request sequence high-water is below the active credential sequence")
	}
	if err := state.RollbackFloors.validate(state); err != nil {
		return err
	}
	if err := state.validateActiveRecord(); err != nil {
		return err
	}
	if state.ConsumedRequestSHA256 == nil || state.RevokedClientInstallationIDs == nil || state.CredentialTombstoneSPKIPins == nil {
		return errors.New("localstate: bounded state arrays must be present, not null")
	}
	if err := validateDigests(state.ConsumedRequestSHA256); err != nil {
		return err
	}
	if err := validateTombstones(state.CredentialTombstoneSPKIPins); err != nil {
		return err
	}
	if err := validateRevokedClientIDs(state.RevokedClientInstallationIDs); err != nil {
		return err
	}
	if len(state.RevokedClientInstallationIDs)+len(state.CredentialTombstoneSPKIPins) > MaxCredentialTombstones {
		return errors.New("localstate: combined credential revocation set exceeds its bound")
	}
	if (len(state.RevokedClientInstallationIDs) > 0 || len(state.CredentialTombstoneSPKIPins) > 0) && state.TombstoneSequence == 0 {
		return errors.New("localstate: credential revocations require a positive tombstone sequence")
	}
	if (state.PolicySequence == 0) != (state.PolicySHA256 == "") ||
		state.PolicySequence != 0 && !validDigest(state.PolicySHA256) {
		return errors.New("localstate: policy sequence and digest must be present together")
	}
	if state.PendingRequest != nil {
		if err := state.PendingRequest.validate(); err != nil {
			return err
		}
		if state.PendingRequest.Sequence != state.RequestSequenceHighWater {
			return errors.New("localstate: pending request must equal the request sequence high-water")
		}
		if state.PendingRequest.Sequence <= state.HighestCredentialSequence {
			return errors.New("localstate: pending request sequence is already active or stale")
		}
		if contains(state.ConsumedRequestSHA256, state.PendingRequest.RequestSHA256) {
			return errors.New("localstate: pending request digest is already consumed")
		}
	}
	return nil
}

func (state State) validateActiveRecord() error {
	if state.ActiveReleaseSequence == 0 ||
		state.ActiveReleaseSequence > state.HighestReleaseSequence ||
		state.ActiveReleaseSequence < state.RollbackFloors.ReleaseSequence {
		return errors.New("localstate: active release sequence is outside its durable bounds")
	}
	if state.HighestDeploymentSequence == 0 {
		if state.ActiveRecordID != "" || state.ActiveRecordSHA256 != "" ||
			state.ActiveDeploymentSequence != 0 || state.ActiveCredentialSequence != 0 ||
			state.ActivePolicySequence != 0 || state.ActiveTombstoneSequence != 0 {
			return errors.New("localstate: an unenrolled state cannot bind an active deployment record")
		}
		if state.ActiveReleaseSequence != state.HighestReleaseSequence {
			return errors.New("localstate: an unenrolled state must bind its current release high-water")
		}
		return nil
	}
	if err := validNonzeroID(state.ActiveRecordID); err != nil {
		return errors.New("localstate: active record ID is not a nonzero canonical ID")
	}
	if !validDigest(state.ActiveRecordSHA256) {
		return errors.New("localstate: active record digest is not canonical SHA-256")
	}
	if state.ActiveDeploymentSequence == 0 || state.ActiveCredentialSequence == 0 {
		return errors.New("localstate: enrolled active deployment and credential sequences must both be positive")
	}
	if state.ActiveDeploymentSequence > state.HighestDeploymentSequence ||
		state.ActiveCredentialSequence > state.HighestCredentialSequence {
		return errors.New("localstate: active deployment or credential sequence exceeds its high-water")
	}
	if state.ActiveDeploymentSequence < state.RollbackFloors.DeploymentSequence ||
		state.ActiveCredentialSequence < state.RollbackFloors.CredentialSequence {
		return errors.New("localstate: active deployment or credential sequence is below its rollback floor")
	}
	// Policy and tombstone state are overlays, not rollbackable credential
	// record contents. Every selected runtime generation must therefore bind
	// the current epochs exactly; selecting an old manifest must never discard
	// a revocation or verifier-first trust change.
	if state.ActivePolicySequence != state.PolicySequence ||
		state.ActiveTombstoneSequence != state.TombstoneSequence {
		return errors.New("localstate: active record does not bind current policy and tombstone state")
	}
	return nil
}

// ValidateTransition proves that next is one atomic forward state generation.
// It rejects counter rollback, request reuse, forgotten consumed requests and
// credential resurrection. Exact-record rollback remains possible by changing
// the active record ID, digest, and sequence tuple within retained monotonic
// high-waters and floors.
func ValidateTransition(previous, next State) error {
	if err := previous.Validate(); err != nil {
		return fmt.Errorf("localstate: previous state: %w", err)
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("localstate: next state: %w", err)
	}
	if previous.Role != next.Role || previous.InstallationID != next.InstallationID {
		return errors.New("localstate: role and installation ID are immutable")
	}
	if previous.StateGeneration == ^uint64(0) || next.StateGeneration != previous.StateGeneration+1 {
		return errors.New("localstate: next state generation must increase by exactly one")
	}
	if next.RequestSequenceHighWater < previous.RequestSequenceHighWater ||
		next.HighestDeploymentSequence < previous.HighestDeploymentSequence ||
		next.HighestReleaseSequence < previous.HighestReleaseSequence ||
		next.HighestCredentialSequence < previous.HighestCredentialSequence ||
		next.PolicySequence < previous.PolicySequence ||
		next.TombstoneSequence < previous.TombstoneSequence ||
		next.RecoverySequence < previous.RecoverySequence {
		return errors.New("localstate: a monotonic sequence decreased")
	}
	if next.RollbackFloors.DeploymentSequence < previous.RollbackFloors.DeploymentSequence ||
		next.RollbackFloors.ReleaseSequence < previous.RollbackFloors.ReleaseSequence ||
		next.RollbackFloors.CredentialSequence < previous.RollbackFloors.CredentialSequence ||
		next.RollbackFloors.PolicySequence < previous.RollbackFloors.PolicySequence ||
		next.RollbackFloors.TombstoneSequence < previous.RollbackFloors.TombstoneSequence {
		return errors.New("localstate: a rollback floor decreased")
	}
	if !containsAll(next.ConsumedRequestSHA256, previous.ConsumedRequestSHA256) {
		return errors.New("localstate: consumed request history cannot be removed")
	}
	if !containsAll(next.CredentialTombstoneSPKIPins, previous.CredentialTombstoneSPKIPins) {
		return errors.New("localstate: credential tombstones cannot be removed")
	}
	if !containsAll(next.RevokedClientInstallationIDs, previous.RevokedClientInstallationIDs) {
		return errors.New("localstate: revoked client installations cannot be removed")
	}
	if next.RollbackFloors != previous.RollbackFloors && next.PolicySequence == previous.PolicySequence {
		return errors.New("localstate: changing rollback floors requires a newer policy sequence")
	}
	if next.PolicySequence == previous.PolicySequence && next.PolicySHA256 != previous.PolicySHA256 {
		return errors.New("localstate: one policy sequence cannot change its digest")
	}
	if next.PolicySequence > previous.PolicySequence && next.PolicySHA256 == previous.PolicySHA256 {
		return errors.New("localstate: a newer policy sequence requires distinct signed bytes")
	}
	if (!equalStrings(next.CredentialTombstoneSPKIPins, previous.CredentialTombstoneSPKIPins) ||
		!equalStrings(next.RevokedClientInstallationIDs, previous.RevokedClientInstallationIDs)) &&
		next.TombstoneSequence == previous.TombstoneSequence {
		return errors.New("localstate: changing credential revocations requires a newer tombstone sequence")
	}
	if previous.ActiveRecordID != "" && next.ActiveRecordID == previous.ActiveRecordID &&
		(next.ActiveRecordSHA256 != previous.ActiveRecordSHA256 ||
			next.ActiveDeploymentSequence != previous.ActiveDeploymentSequence ||
			next.ActiveCredentialSequence != previous.ActiveCredentialSequence ||
			next.ActiveReleaseSequence != previous.ActiveReleaseSequence ||
			next.ActivePolicySequence != previous.ActivePolicySequence ||
			next.ActiveTombstoneSequence != previous.ActiveTombstoneSequence) {
		return errors.New("localstate: one active record ID cannot change its digest or sequence binding")
	}

	if previous.PendingRequest == nil {
		if next.PendingRequest != nil && next.PendingRequest.Sequence <= previous.RequestSequenceHighWater {
			return errors.New("localstate: new pending request does not advance the request sequence")
		}
		return nil
	}
	if next.PendingRequest != nil && *next.PendingRequest == *previous.PendingRequest {
		return nil
	}
	if !contains(next.ConsumedRequestSHA256, previous.PendingRequest.RequestSHA256) {
		return errors.New("localstate: replaced or cleared pending request was not durably consumed")
	}
	if next.PendingRequest != nil && next.PendingRequest.Sequence <= previous.RequestSequenceHighWater {
		return errors.New("localstate: replacement pending request does not advance the request sequence")
	}
	return nil
}

func (floors RollbackFloors) validate(state State) error {
	if floors.DeploymentSequence > state.HighestDeploymentSequence ||
		floors.ReleaseSequence > state.HighestReleaseSequence ||
		floors.CredentialSequence > state.HighestCredentialSequence ||
		floors.PolicySequence > state.PolicySequence ||
		floors.TombstoneSequence > state.TombstoneSequence {
		return errors.New("localstate: rollback floor exceeds its sequence high-water")
	}
	return nil
}

func (pending PendingRequestMetadata) validate() error {
	if pending.Sequence == 0 || !validDigest(pending.RequestSHA256) {
		return errors.New("localstate: pending request sequence or digest is invalid")
	}
	if err := validNonzeroID(pending.Nonce); err != nil {
		return errors.New("localstate: pending request nonce is not a nonzero canonical ID")
	}
	if pending.CreatedUnix <= 0 || pending.ExpiresUnix <= pending.CreatedUnix ||
		pending.ExpiresUnix-pending.CreatedUnix > MaxPendingRequestValidity {
		return errors.New("localstate: pending request validity window is invalid")
	}
	return nil
}

func validateDigests(values []string) error {
	if len(values) > MaxConsumedRequestDigests {
		return errors.New("localstate: consumed request digest list exceeds its bound")
	}
	for index, value := range values {
		if !validDigest(value) {
			return fmt.Errorf("localstate: consumed request digest %d is not canonical SHA-256", index)
		}
		if index > 0 && values[index-1] >= value {
			return errors.New("localstate: consumed request digests must be sorted and unique")
		}
	}
	return nil
}

func validateTombstones(values []string) error {
	if len(values) > MaxCredentialTombstones {
		return errors.New("localstate: credential tombstone list exceeds its bound")
	}
	for index, value := range values {
		if _, err := identity.ParseSPKIPin(value); err != nil {
			return fmt.Errorf("localstate: credential tombstone %d is not a canonical SPKI pin: %w", index, err)
		}
		if index > 0 && values[index-1] >= value {
			return errors.New("localstate: credential tombstones must be sorted and unique")
		}
	}
	return nil
}

func validateRevokedClientIDs(values []string) error {
	if len(values) > MaxRevokedClientIDs {
		return errors.New("localstate: revoked client installation list exceeds its bound")
	}
	for index, value := range values {
		if err := validNonzeroID(value); err != nil {
			return fmt.Errorf("localstate: revoked client installation %d is not a canonical ID", index)
		}
		if index > 0 && values[index-1] >= value {
			return errors.New("localstate: revoked client installations must be sorted and unique")
		}
	}
	return nil
}

func validRole(role Role) bool {
	return role == RoleClient || role == RoleConnector || role == RoleRelay
}

func validNonzeroID(value string) error {
	id, err := protocol.ParseID(value)
	if err != nil || id == (protocol.ID{}) || id.String() != value {
		return errors.New("invalid canonical ID")
	}
	return nil
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func contains(sorted []string, value string) bool {
	for _, candidate := range sorted {
		if candidate == value {
			return true
		}
		if candidate > value {
			return false
		}
	}
	return false
}

func containsAll(haystack, needles []string) bool {
	for _, needle := range needles {
		if !contains(haystack, needle) {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
