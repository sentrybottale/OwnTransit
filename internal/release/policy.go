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
	"sort"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	PolicySchema          = "owntransit.software-release-policy.v1"
	PolicySignatureSchema = "owntransit.software-release-policy-signature.v1"
	policySignatureDomain = "OwnTransit software release policy v1"
	MaxPolicySize         = 256 << 10
)

// Policy is the offline-signed authorization and monotonic floor for software
// release activation. It is intentionally independent from endpoint deployment
// signing: a deployment signer cannot authorize software and a software signer
// cannot issue endpoint state.
type Policy struct {
	Schema                 string   `json:"schema"`
	Product                string   `json:"product"`
	Sequence               uint64   `json:"sequence"`
	CreatedUnix            int64    `json:"created_unix"`
	ReleaseKeyID           string   `json:"release_key_id"`
	MinimumReleaseSequence uint64   `json:"minimum_release_sequence"`
	MinimumLifecycle       uint64   `json:"minimum_lifecycle"`
	TombstonedReleaseIDs   []string `json:"tombstoned_release_ids"`
}

type PolicySignature struct {
	Schema       string `json:"schema"`
	KeyID        string `json:"key_id"`
	PolicySHA256 string `json:"policy_sha256"`
	Signature    string `json:"signature"`
}

// PolicyAnchor is the minimum state an independently protected local rollback
// anchor must retain. VerifyPolicyAdvance never mutates or stores the anchor;
// platform lifecycle code must durably advance it outside ordinary mutable
// release state before activating the corresponding policy.
type PolicyAnchor struct {
	HighestPolicySequence  uint64
	MinimumReleaseSequence uint64
	MinimumLifecycle       uint64
	TombstonedReleaseIDs   []string
}

// VerifiedPolicy cannot be constructed by another package. Install decisions
// accept it only after exact-byte signature and monotonic-anchor verification.
type VerifiedPolicy struct {
	policy Policy
	keyID  string
	valid  bool
}

// Value returns a copy suitable for inspection or durable anchor derivation.
func (verified VerifiedPolicy) Value() Policy {
	value := verified.policy
	value.TombstonedReleaseIDs = append([]string(nil), value.TombstonedReleaseIDs...)
	return value
}

// NextAnchor returns the monotonic values which platform lifecycle code must
// commit to its separately protected rollback anchor before release activation.
func (verified VerifiedPolicy) NextAnchor() (PolicyAnchor, error) {
	if !verified.valid {
		return PolicyAnchor{}, errors.New("release: policy has not been verified")
	}
	return PolicyAnchor{
		HighestPolicySequence:  verified.policy.Sequence,
		MinimumReleaseSequence: verified.policy.MinimumReleaseSequence,
		MinimumLifecycle:       verified.policy.MinimumLifecycle,
		TombstonedReleaseIDs:   append([]string(nil), verified.policy.TombstonedReleaseIDs...),
	}, nil
}

func EncodePolicy(policy Policy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("release: encode policy: %w", err)
	}
	if len(encoded) >= MaxPolicySize {
		return nil, errors.New("release: policy exceeds size limit")
	}
	return append(encoded, '\n'), nil
}

func ParsePolicy(encoded []byte) (Policy, error) {
	if len(encoded) == 0 || len(encoded) > MaxPolicySize {
		return Policy{}, errors.New("release: policy has an invalid size")
	}
	var policy Policy
	if err := strictjson.Decode(encoded, &policy); err != nil {
		return Policy{}, fmt.Errorf("release: policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	canonical, err := EncodePolicy(policy)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Policy{}, errors.New("release: policy is not canonical JSON")
	}
	return policy, nil
}

func SignPolicy(policy Policy, privateKey ed25519.PrivateKey) (policyBytes, signatureBytes []byte, err error) {
	policyBytes, err = EncodePolicy(policy)
	if err != nil {
		return nil, nil, err
	}
	signature, err := signing.Sign(policySignatureDomain, policyBytes, privateKey)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(policyBytes)
	record := PolicySignature{
		Schema:       PolicySignatureSchema,
		KeyID:        signing.KeyID(privateKey.Public().(ed25519.PublicKey)),
		PolicySHA256: hex.EncodeToString(digest[:]),
		Signature:    base64.StdEncoding.EncodeToString(signature),
	}
	signatureBytes, err = mustEncodePolicySignature(record)
	if err != nil {
		return nil, nil, err
	}
	return policyBytes, signatureBytes, nil
}

func mustEncodePolicySignature(record PolicySignature) ([]byte, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("release: encode policy signature record: %w", err)
	}
	return append(encoded, '\n'), nil
}

// VerifyPolicyAdvance authenticates one canonical policy and proves that it
// only advances, never weakens, an independently supplied rollback anchor.
func VerifyPolicyAdvance(policyBytes, signatureBytes []byte, publicKey ed25519.PublicKey, anchor PolicyAnchor) (VerifiedPolicy, error) {
	verified, err := verifySignedPolicy(policyBytes, signatureBytes, publicKey)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	if len(policyBytes) == 0 || len(policyBytes) > MaxPolicySize || len(signatureBytes) == 0 || len(signatureBytes) > 16<<10 {
		return VerifiedPolicy{}, errors.New("release: policy or signature record has an invalid size")
	}
	if err := validatePolicyAnchor(anchor); err != nil {
		return VerifiedPolicy{}, err
	}
	policy := verified.policy
	if policy.Sequence <= anchor.HighestPolicySequence {
		return VerifiedPolicy{}, errors.New("release: policy sequence is a replay or downgrade")
	}
	if policy.MinimumReleaseSequence < anchor.MinimumReleaseSequence || policy.MinimumLifecycle < anchor.MinimumLifecycle {
		return VerifiedPolicy{}, errors.New("release: policy weakens a rollback floor")
	}
	if !containsEvery(policy.TombstonedReleaseIDs, anchor.TombstonedReleaseIDs) {
		return VerifiedPolicy{}, errors.New("release: policy removes a durable release tombstone")
	}
	return verified, nil
}

// VerifyPolicyAtAnchor authenticates an exact already-committed policy. It is
// used only for idempotent reinstall and interrupted-transaction recovery; it
// never treats an older or merely equivalent policy as current.
func VerifyPolicyAtAnchor(policyBytes, signatureBytes []byte, publicKey ed25519.PublicKey, anchor PolicyAnchor) (VerifiedPolicy, error) {
	if err := validatePolicyAnchor(anchor); err != nil {
		return VerifiedPolicy{}, err
	}
	if anchor.HighestPolicySequence == 0 {
		return VerifiedPolicy{}, errors.New("release: no committed policy exists")
	}
	verified, err := verifySignedPolicy(policyBytes, signatureBytes, publicKey)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	next, err := verified.NextAnchor()
	if err != nil {
		return VerifiedPolicy{}, err
	}
	if next.HighestPolicySequence != anchor.HighestPolicySequence ||
		next.MinimumReleaseSequence != anchor.MinimumReleaseSequence ||
		next.MinimumLifecycle != anchor.MinimumLifecycle ||
		!equalStrings(next.TombstonedReleaseIDs, anchor.TombstonedReleaseIDs) {
		return VerifiedPolicy{}, errors.New("release: policy does not exactly match the committed anchor")
	}
	return verified, nil
}

// AuthorizeRetainedRelease applies the authenticated floors and tombstones to
// an already installed, receipt-bound release selected for local rollback.
func (verified VerifiedPolicy) AuthorizeRetainedRelease(releaseID string, sequence, runningLifecycle uint64) error {
	if !verified.valid {
		return errors.New("release: policy has not been verified")
	}
	parsed, err := protocol.ParseID(releaseID)
	if err != nil || parsed == (protocol.ID{}) || sequence == 0 || runningLifecycle == 0 {
		return errors.New("release: retained release identity is invalid")
	}
	if sequence < verified.policy.MinimumReleaseSequence {
		return errors.New("release: retained release is below the authenticated release floor")
	}
	if runningLifecycle < verified.policy.MinimumLifecycle {
		return errors.New("release: running lifecycle is below the authenticated lifecycle floor")
	}
	for _, tombstone := range verified.policy.TombstonedReleaseIDs {
		if tombstone == releaseID {
			return errors.New("release: retained release ID is tombstoned")
		}
	}
	return nil
}

func verifySignedPolicy(policyBytes, signatureBytes []byte, publicKey ed25519.PublicKey) (VerifiedPolicy, error) {
	if len(policyBytes) == 0 || len(policyBytes) > MaxPolicySize || len(signatureBytes) == 0 || len(signatureBytes) > 16<<10 {
		return VerifiedPolicy{}, errors.New("release: policy or signature record has an invalid size")
	}
	var record PolicySignature
	if err := strictjson.Decode(signatureBytes, &record); err != nil {
		return VerifiedPolicy{}, fmt.Errorf("release: policy signature record: %w", err)
	}
	if record.Schema != PolicySignatureSchema || record.KeyID != signing.KeyID(publicKey) {
		return VerifiedPolicy{}, errors.New("release: policy signature has the wrong schema or key ID")
	}
	canonicalSignature, err := mustEncodePolicySignature(record)
	if err != nil || !bytes.Equal(signatureBytes, canonicalSignature) {
		return VerifiedPolicy{}, errors.New("release: policy signature record is not canonical JSON")
	}
	digest := sha256.Sum256(policyBytes)
	if record.PolicySHA256 != hex.EncodeToString(digest[:]) {
		return VerifiedPolicy{}, errors.New("release: policy digest does not match signature record")
	}
	signature, err := base64.StdEncoding.DecodeString(record.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != record.Signature {
		return VerifiedPolicy{}, errors.New("release: policy signature is not canonical base64")
	}
	if err := signing.Verify(policySignatureDomain, policyBytes, signature, publicKey); err != nil {
		return VerifiedPolicy{}, err
	}
	policy, err := ParsePolicy(policyBytes)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	return VerifiedPolicy{policy: policy, keyID: record.KeyID, valid: true}, nil
}

func (policy Policy) Validate() error {
	if policy.Schema != PolicySchema || policy.Product != "owntransit" || policy.Sequence == 0 || policy.CreatedUnix <= 0 ||
		policy.MinimumReleaseSequence == 0 || policy.MinimumLifecycle == 0 {
		return errors.New("release: invalid policy schema, product, sequence, time, or floor")
	}
	if err := signing.ValidateKeyID(policy.ReleaseKeyID); err != nil {
		return fmt.Errorf("release: invalid policy release key: %w", err)
	}
	if len(policy.TombstonedReleaseIDs) > 4096 {
		return errors.New("release: too many tombstoned release IDs")
	}
	previous := ""
	for index, releaseID := range policy.TombstonedReleaseIDs {
		parsed, err := protocol.ParseID(releaseID)
		if err != nil || parsed == (protocol.ID{}) {
			return fmt.Errorf("release: tombstoned release ID %d is invalid", index)
		}
		if index > 0 && releaseID <= previous {
			return errors.New("release: tombstoned release IDs are not canonical and unique")
		}
		previous = releaseID
	}
	return nil
}

func validatePolicyAnchor(anchor PolicyAnchor) error {
	if anchor.HighestPolicySequence == 0 {
		if anchor.MinimumReleaseSequence != 0 || anchor.MinimumLifecycle != 0 || len(anchor.TombstonedReleaseIDs) != 0 {
			return errors.New("release: empty policy anchor has nonempty floors or tombstones")
		}
		return nil
	}
	if anchor.MinimumReleaseSequence == 0 || anchor.MinimumLifecycle == 0 || len(anchor.TombstonedReleaseIDs) > 4096 {
		return errors.New("release: policy anchor is incomplete")
	}
	copyIDs := append([]string(nil), anchor.TombstonedReleaseIDs...)
	sort.Strings(copyIDs)
	for index, releaseID := range copyIDs {
		parsed, err := protocol.ParseID(releaseID)
		if err != nil || parsed == (protocol.ID{}) || (index > 0 && releaseID == copyIDs[index-1]) || releaseID != anchor.TombstonedReleaseIDs[index] {
			return errors.New("release: policy anchor tombstones are invalid or noncanonical")
		}
	}
	return nil
}

func containsEvery(values, required []string) bool {
	index := 0
	for _, value := range values {
		for index < len(required) && required[index] < value {
			return false
		}
		if index < len(required) && required[index] == value {
			index++
		}
	}
	return index == len(required)
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
