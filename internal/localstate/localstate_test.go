package localstate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestEncodeDecodeFreshInstalledState(t *testing.T) {
	state := freshState()
	encoded, err := Encode(state)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(decoded, state) {
		t.Fatalf("decoded state differs:\n got %#v\nwant %#v", decoded, state)
	}
}

func TestDecodeRejectsDuplicateAndUnknownJSONFields(t *testing.T) {
	encoded, err := Encode(freshState())
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte(`{"schema":"` + Schema + `"`)
	duplicatePrefix := []byte(`{"schema":"` + Schema + `","schema":"` + Schema + `"`)
	duplicate := bytes.Replace(encoded, prefix, duplicatePrefix, 1)
	if _, err := Decode(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate field error = %v", err)
	}
	unknown := bytes.Replace(encoded, []byte("}\n"), []byte(",\"unexpected\":true}\n"), 1)
	if _, err := Decode(unknown); err == nil {
		t.Fatal("Decode accepted an unknown field")
	}
}

func TestStateRejectsNoncanonicalAndReplayMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*State)
	}{
		{"role", func(state *State) { state.Role = "server" }},
		{"installation ID", func(state *State) { state.InstallationID = strings.ToUpper(state.InstallationID) }},
		{"generation", func(state *State) { state.StateGeneration = 0 }},
		{"null consumed", func(state *State) { state.ConsumedRequestSHA256 = nil }},
		{"null tombstones", func(state *State) { state.CredentialTombstoneSPKIPins = nil }},
		{"release sequence", func(state *State) { state.HighestReleaseSequence = 0 }},
		{"release floor", func(state *State) { state.RollbackFloors.ReleaseSequence = state.HighestReleaseSequence + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := freshState()
			test.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatal("Validate accepted malformed state")
			}
		})
	}

	state := enrolledPendingState()
	state.ConsumedRequestSHA256 = []string{state.PendingRequest.RequestSHA256}
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted an already-consumed pending request")
	}
	state = enrolledPendingState()
	state.PendingRequest.Sequence--
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted pending sequence below high-water")
	}
	state = enrolledPendingState()
	state.PendingRequest.RequestSHA256 = strings.Repeat("A", sha256.Size*2)
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted a noncanonical digest")
	}
}

func TestActiveRecordInvariant(t *testing.T) {
	state := freshState()
	if err := state.Validate(); err != nil {
		t.Fatalf("fresh installed state: %v", err)
	}
	state.ActiveRecordID = canonicalID(3)
	if err := state.Validate(); err == nil {
		t.Fatal("unenrolled state accepted an active deployment record")
	}
	state = freshState()
	state.ActiveReleaseSequence--
	if err := state.Validate(); err == nil {
		t.Fatal("unenrolled state accepted a release below its current high-water")
	}
	state = freshState()
	state.HighestDeploymentSequence = 1
	state.HighestCredentialSequence = 1
	state.RequestSequenceHighWater = 1
	if err := state.Validate(); err == nil {
		t.Fatal("enrolled state accepted an empty active record")
	}
	state.ActiveRecordID = canonicalID(3)
	state.ActiveRecordSHA256 = digest(3)
	state.ActiveDeploymentSequence = 1
	state.ActiveCredentialSequence = 1
	if err := state.Validate(); err != nil {
		t.Fatalf("valid active record rejected: %v", err)
	}
}

func TestActiveRecordSequencesEnforceHighWatersAndFloors(t *testing.T) {
	state := enrolledPendingState()
	state.ActiveDeploymentSequence = state.HighestDeploymentSequence + 1
	if err := state.Validate(); err == nil {
		t.Fatal("active deployment sequence exceeded its high-water")
	}
	state = enrolledPendingState()
	state.PendingRequest = nil
	state.RequestSequenceHighWater = 3
	state.HighestCredentialSequence = 3
	state.RollbackFloors.CredentialSequence = 2
	state.ActiveCredentialSequence = 1
	if err := state.Validate(); err == nil {
		t.Fatal("active credential sequence fell below its rollback floor")
	}
	state = enrolledPendingState()
	state.ActiveRecordSHA256 = strings.Repeat("A", sha256.Size*2)
	if err := state.Validate(); err == nil {
		t.Fatal("active record accepted a noncanonical digest")
	}
	state = enrolledPendingState()
	state.ActivePolicySequence--
	if err := state.Validate(); err == nil {
		t.Fatal("active record accepted a stale verifier policy epoch")
	}
}

func TestCollectionsAreBoundedCanonicalSortedAndUnique(t *testing.T) {
	state := freshState()
	state.ConsumedRequestSHA256 = []string{digest(2), digest(1)}
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted unsorted digests")
	}
	state.ConsumedRequestSHA256 = []string{digest(1), digest(1)}
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted duplicate digests")
	}
	state = freshState()
	state.RevokedClientInstallationIDs = []string{canonicalID(2), canonicalID(1)}
	state.TombstoneSequence = 1
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted unsorted revoked client installations")
	}
	state = freshState()
	state.CredentialTombstoneSPKIPins = []string{spkiPin(1), spkiPin(1)}
	state.TombstoneSequence = 1
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted duplicate tombstones")
	}
	state = freshState()
	state.ConsumedRequestSHA256 = make([]string, MaxConsumedRequestDigests+1)
	for index := range state.ConsumedRequestSHA256 {
		state.ConsumedRequestSHA256[index] = fmt.Sprintf("%064x", index+1)
	}
	if err := state.Validate(); err == nil {
		t.Fatal("Validate accepted an oversized consumed-request list")
	}
}

func TestValidateTransitionConsumesPendingAtomically(t *testing.T) {
	previous := enrolledPendingState()
	next := previous
	next.StateGeneration++
	next.HighestDeploymentSequence++
	next.HighestCredentialSequence = previous.PendingRequest.Sequence
	next.ActiveRecordID = canonicalID(8)
	next.ActiveRecordSHA256 = digest(8)
	next.ActiveDeploymentSequence = next.HighestDeploymentSequence
	next.ActiveCredentialSequence = next.HighestCredentialSequence
	next.ConsumedRequestSHA256 = []string{previous.PendingRequest.RequestSHA256}
	next.PendingRequest = nil
	if err := ValidateTransition(previous, next); err != nil {
		t.Fatalf("valid transition rejected: %v", err)
	}

	unconsumed := next
	unconsumed.ConsumedRequestSHA256 = []string{}
	if err := ValidateTransition(previous, unconsumed); err == nil {
		t.Fatal("transition cleared pending request without consuming it")
	}

	replay := next
	replay.StateGeneration++
	replay.PendingRequest = &PendingRequestMetadata{
		Sequence:      previous.PendingRequest.Sequence,
		RequestSHA256: digest(9),
		Nonce:         canonicalID(9),
		CreatedUnix:   1_700_000_000,
		ExpiresUnix:   1_700_003_600,
	}
	if err := ValidateTransition(next, replay); err == nil {
		t.Fatal("transition reused a request sequence")
	}
}

func TestValidateTransitionRejectsRollbackAndForgottenTombstones(t *testing.T) {
	previous := enrolledPendingState()
	previous.PendingRequest = nil
	previous.RequestSequenceHighWater = previous.HighestCredentialSequence
	previous.CredentialTombstoneSPKIPins = []string{spkiPin(1)}
	previous.TombstoneSequence = 2
	previous.ActiveTombstoneSequence = 2

	tests := []struct {
		name   string
		mutate func(*State)
	}{
		{"generation gap", func(next *State) { next.StateGeneration += 2 }},
		{"release rollback", func(next *State) { next.HighestReleaseSequence-- }},
		{"request rollback", func(next *State) { next.RequestSequenceHighWater-- }},
		{"removed tombstone", func(next *State) { next.CredentialTombstoneSPKIPins = []string{} }},
		{"changed role", func(next *State) { next.Role = RoleRelay }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := previous
			next.StateGeneration++
			test.mutate(&next)
			if err := ValidateTransition(previous, next); err == nil {
				t.Fatal("ValidateTransition accepted invalid transition")
			}
		})
	}

	next := previous
	next.StateGeneration++
	next.RollbackFloors.DeploymentSequence++
	if err := ValidateTransition(previous, next); err == nil {
		t.Fatal("rollback floor changed without a policy sequence")
	}
	next = previous
	next.StateGeneration++
	next.CredentialTombstoneSPKIPins = []string{spkiPin(1), spkiPin(2)}
	if err := ValidateTransition(previous, next); err == nil {
		t.Fatal("tombstone changed without a tombstone sequence")
	}
}

func TestValidateTransitionAllowsActiveRecordRollbackWithinFloors(t *testing.T) {
	previous := enrolledPendingState()
	previous.PendingRequest = nil
	rebound := previous
	rebound.StateGeneration++
	rebound.ActiveRecordSHA256 = digest(10)
	if err := ValidateTransition(previous, rebound); err == nil {
		t.Fatal("one record ID was rebound to a different digest")
	}

	next := previous
	next.StateGeneration++
	next.ActiveRecordID = canonicalID(9)
	next.ActiveRecordSHA256 = digest(9)
	next.ActiveDeploymentSequence = 2
	next.ActiveCredentialSequence = 1
	next.ActiveReleaseSequence = 3
	if err := ValidateTransition(previous, next); err != nil {
		t.Fatalf("bounded active-record rollback rejected: %v", err)
	}

	belowFloor := next
	belowFloor.StateGeneration++
	belowFloor.ActiveDeploymentSequence = belowFloor.RollbackFloors.DeploymentSequence - 1
	if err := ValidateTransition(next, belowFloor); err == nil {
		t.Fatal("active-record rollback below its floor was accepted")
	}
}

func freshState() State {
	return State{
		Schema:                    Schema,
		Role:                      RoleClient,
		InstallationID:            canonicalID(1),
		StateGeneration:           1,
		RequestSequenceHighWater:  0,
		HighestDeploymentSequence: 0,
		HighestReleaseSequence:    4,
		HighestCredentialSequence: 0,
		RollbackFloors: RollbackFloors{
			ReleaseSequence: 1,
		},
		ActiveRecordID:               "",
		ActiveRecordSHA256:           "",
		ActiveDeploymentSequence:     0,
		ActiveCredentialSequence:     0,
		ActiveReleaseSequence:        4,
		PendingRequest:               nil,
		ConsumedRequestSHA256:        []string{},
		RevokedClientInstallationIDs: []string{},
		CredentialTombstoneSPKIPins:  []string{},
		PolicySequence:               0,
		TombstoneSequence:            0,
	}
}

func enrolledPendingState() State {
	state := freshState()
	state.StateGeneration = 7
	state.HighestDeploymentSequence = 3
	state.HighestCredentialSequence = 1
	state.RequestSequenceHighWater = 2
	state.ActiveRecordID = canonicalID(4)
	state.ActiveRecordSHA256 = digest(4)
	state.ActiveDeploymentSequence = 3
	state.ActiveCredentialSequence = 1
	state.ActiveReleaseSequence = 4
	state.RollbackFloors.DeploymentSequence = 1
	state.RollbackFloors.CredentialSequence = 1
	state.PolicySequence = 2
	state.PolicySHA256 = digest(20)
	state.ActivePolicySequence = 2
	state.RollbackFloors.PolicySequence = 1
	state.PendingRequest = &PendingRequestMetadata{
		Sequence:      2,
		RequestSHA256: digest(2),
		Nonce:         canonicalID(2),
		CreatedUnix:   1_700_000_000,
		ExpiresUnix:   1_700_003_600,
	}
	return state
}

func canonicalID(value byte) string {
	var id protocol.ID
	id[0] = value
	return id.String()
}

func digest(value int) string {
	return fmt.Sprintf("%064x", value)
}

func spkiPin(value byte) string {
	var hash identity.SPKIHash
	hash[len(hash)-1] = value
	return identity.FormatSPKIPin(hash)
}
