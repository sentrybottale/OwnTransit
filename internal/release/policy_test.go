package release

import (
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestPolicyAdvanceIsSignedMonotonicAndAuthorizesReleaseKey(t *testing.T) {
	policyKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	releaseKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tombstone := protocol.ID{2}.String()
	policy := Policy{Schema: PolicySchema, Product: "owntransit", Sequence: 8, CreatedUnix: 1700000000,
		ReleaseKeyID: signing.KeyID(releaseKeys.Public), MinimumReleaseSequence: 11, MinimumLifecycle: 3,
		TombstonedReleaseIDs: []string{tombstone}}
	policyBytes, signatureBytes, err := SignPolicy(policy, policyKeys.Private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPolicyAdvance(policyBytes, signatureBytes, policyKeys.Public, PolicyAnchor{
		HighestPolicySequence: 7, MinimumReleaseSequence: 10, MinimumLifecycle: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := verified.NextAnchor()
	if err != nil {
		t.Fatal(err)
	}
	if anchor.HighestPolicySequence != 8 || anchor.MinimumReleaseSequence != 11 || anchor.MinimumLifecycle != 3 || len(anchor.TombstonedReleaseIDs) != 1 {
		t.Fatalf("wrong next anchor: %+v", anchor)
	}

	if _, err := VerifyPolicyAdvance(policyBytes, signatureBytes, policyKeys.Public, anchor); err == nil {
		t.Fatal("replayed policy was accepted")
	}
	tampered := append([]byte(nil), policyBytes...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifyPolicyAdvance(tampered, signatureBytes, policyKeys.Public, PolicyAnchor{}); err == nil {
		t.Fatal("tampered policy was accepted")
	}
}

func TestPolicyCannotLowerFloorOrRemoveTombstone(t *testing.T) {
	policyKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	releaseKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldTombstone := protocol.ID{1}.String()
	anchor := PolicyAnchor{HighestPolicySequence: 4, MinimumReleaseSequence: 9, MinimumLifecycle: 2, TombstonedReleaseIDs: []string{oldTombstone}}
	tests := []Policy{
		{Schema: PolicySchema, Product: "owntransit", Sequence: 5, CreatedUnix: 1700000000, ReleaseKeyID: signing.KeyID(releaseKeys.Public), MinimumReleaseSequence: 8, MinimumLifecycle: 2, TombstonedReleaseIDs: []string{oldTombstone}},
		{Schema: PolicySchema, Product: "owntransit", Sequence: 5, CreatedUnix: 1700000000, ReleaseKeyID: signing.KeyID(releaseKeys.Public), MinimumReleaseSequence: 9, MinimumLifecycle: 1, TombstonedReleaseIDs: []string{oldTombstone}},
		{Schema: PolicySchema, Product: "owntransit", Sequence: 5, CreatedUnix: 1700000000, ReleaseKeyID: signing.KeyID(releaseKeys.Public), MinimumReleaseSequence: 9, MinimumLifecycle: 2},
	}
	for index, policy := range tests {
		policyBytes, signatureBytes, err := SignPolicy(policy, policyKeys.Private)
		if err != nil {
			t.Fatalf("case %d sign: %v", index, err)
		}
		if _, err := VerifyPolicyAdvance(policyBytes, signatureBytes, policyKeys.Public, anchor); err == nil {
			t.Fatalf("case %d weakened anchor", index)
		}
	}
}

func TestPolicyAtAnchorAcceptsOnlyTheExactCommittedPolicy(t *testing.T) {
	policyKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	releaseKeys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Schema: PolicySchema, Product: "owntransit", Sequence: 3, CreatedUnix: 1700000000,
		ReleaseKeyID: signing.KeyID(releaseKeys.Public), MinimumReleaseSequence: 7, MinimumLifecycle: 2}
	encoded, signature, err := SignPolicy(policy, policyKeys.Private)
	if err != nil {
		t.Fatal(err)
	}
	anchor := PolicyAnchor{HighestPolicySequence: 3, MinimumReleaseSequence: 7, MinimumLifecycle: 2}
	if _, err := VerifyPolicyAtAnchor(encoded, signature, policyKeys.Public, anchor); err != nil {
		t.Fatalf("exact committed policy: %v", err)
	}
	wrong := anchor
	wrong.MinimumReleaseSequence = 8
	if _, err := VerifyPolicyAtAnchor(encoded, signature, policyKeys.Public, wrong); err == nil {
		t.Fatal("committed policy with a different rollback floor was accepted")
	}
}
