package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/signing"
)

// ApplyPolicy is assembled only from durable target-local state. None of its
// authority, floors, private keys, or expected identity may come from the
// response bundle or relay.
type ApplyPolicy struct {
	Role                         Role
	InstallationID               string
	RequestBytes                 []byte
	ResponseIdentity             string
	DeploymentSigner             ed25519.PublicKey
	ExpectedIssuerPins           IssuerPins
	ExpectedRuntime              RuntimeBinding
	ExpectedRequestSequence      uint64
	HighestDeploymentSequence    uint64
	HighestCredentialEpoch       uint64
	OuterPrivateKeyPEM           []byte
	InnerPrivateKeyPEM           []byte
	ConsumedRequestSHA256        []string
	TombstonedCredentialSPKIPins []string
}

// VerifiedApply is a fully authenticated, target-bound activation plan. A
// filesystem transaction must durably consume RequestSHA256 and advance both
// returned floors in the same commit that activates the rendered generation.
type VerifiedApply struct {
	Deployment             Deployment
	DeploymentBytes        []byte
	Request                RequestPayload
	RequestSHA256          string
	NextDeploymentSequence uint64
	NextCredentialEpoch    uint64
	VerifiedAt             time.Time
}

// VerifyForApply is the sole high-level enrollment activation gate. It
// verifies the signed envelope, target-only encryption, exact pending request,
// bootstrap issuers, release binding, local private keys, monotonic floors and
// tombstones before returning any renderable deployment.
func VerifyForApply(envelope []byte, policy ApplyPolicy, now time.Time) (VerifiedApply, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || policy.Role == "" || policy.InstallationID == "" || policy.ExpectedRequestSequence == 0 {
		return VerifiedApply{}, errors.New("enrollment: complete target-local apply policy and time are required")
	}
	if len(policy.DeploymentSigner) != ed25519.PublicKeySize {
		return VerifiedApply{}, errors.New("enrollment: deployment verifier is not Ed25519")
	}
	request, err := ParseRequest(policy.RequestBytes, now)
	if err != nil {
		return VerifiedApply{}, fmt.Errorf("enrollment: pending request: %w", err)
	}
	if request.Role != policy.Role || request.InstallationID != policy.InstallationID || request.Sequence != policy.ExpectedRequestSequence ||
		request.IssuerPins != policy.ExpectedIssuerPins || request.Runtime != policy.ExpectedRuntime {
		return VerifiedApply{}, errors.New("enrollment: pending request does not match durable target state")
	}
	if signing.KeyID(policy.DeploymentSigner) != request.DeploymentSignerKeyID {
		return VerifiedApply{}, errors.New("enrollment: deployment verifier does not match target bootstrap state")
	}
	requestDigest := sha256.Sum256(policy.RequestBytes)
	requestDigestText := hex.EncodeToString(requestDigest[:])
	for _, consumed := range policy.ConsumedRequestSHA256 {
		if !validSHA256(consumed) {
			return VerifiedApply{}, errors.New("enrollment: durable consumed-request state is invalid")
		}
		if consumed == requestDigestText {
			return VerifiedApply{}, errors.New("enrollment: pending request was already consumed")
		}
	}

	plaintext, err := OpenResponse(envelope, policy.ResponseIdentity, policy.DeploymentSigner)
	if err != nil {
		return VerifiedApply{}, err
	}
	deployment, err := ParseBoundDeployment(plaintext, policy.RequestBytes, now)
	if err != nil {
		return VerifiedApply{}, err
	}
	if deployment.DeploymentSequence <= policy.HighestDeploymentSequence || deployment.CredentialEpoch <= policy.HighestCredentialEpoch {
		return VerifiedApply{}, errors.New("enrollment: deployment or credential sequence is a replay or rollback")
	}
	if err := verifyTargetPrivateKeys(deployment, request, policy.OuterPrivateKeyPEM, policy.InnerPrivateKeyPEM); err != nil {
		return VerifiedApply{}, err
	}
	if err := rejectTombstonedLeaves(deployment, policy.TombstonedCredentialSPKIPins); err != nil {
		return VerifiedApply{}, err
	}
	return VerifiedApply{
		Deployment: deployment, DeploymentBytes: append([]byte(nil), plaintext...), Request: request,
		RequestSHA256: requestDigestText, NextDeploymentSequence: deployment.DeploymentSequence,
		NextCredentialEpoch: deployment.CredentialEpoch, VerifiedAt: now,
	}, nil
}

func verifyTargetPrivateKeys(deployment Deployment, request RequestPayload, outerPEM, innerPEM []byte) error {
	outerRequest, innerRequest, _, err := requestCSRs(request)
	if err != nil {
		return err
	}
	outerKey, err := signing.ParsePrivate(outerPEM)
	if err != nil || !bytes.Equal(outerKey.Public().(ed25519.PublicKey), outerRequest.PublicKey.(ed25519.PublicKey)) {
		return errors.New("enrollment: local outer private key does not match the retained request")
	}
	outerCertificate, err := parseCertificate([]byte(deployment.OuterCertificate))
	if err != nil || !bytes.Equal(outerCertificate.RawSubjectPublicKeyInfo, outerRequest.RawSubjectPublicKeyInfo) {
		return errors.New("enrollment: outer certificate does not match the local private key")
	}
	if request.Role == RoleRelay {
		if len(innerPEM) != 0 {
			return errors.New("enrollment: relay target unexpectedly retained an inner private key")
		}
		return nil
	}
	innerKey, err := signing.ParsePrivate(innerPEM)
	if err != nil || !bytes.Equal(innerKey.Public().(ed25519.PublicKey), innerRequest.PublicKey.(ed25519.PublicKey)) {
		return errors.New("enrollment: local inner private key does not match the retained request")
	}
	if bytes.Equal(outerKey, innerKey) {
		return errors.New("enrollment: outer and inner private keys are not separated")
	}
	innerCertificate, err := parseCertificate([]byte(deployment.InnerCertificate))
	if err != nil || !bytes.Equal(innerCertificate.RawSubjectPublicKeyInfo, innerRequest.RawSubjectPublicKeyInfo) {
		return errors.New("enrollment: inner certificate does not match the local private key")
	}
	return nil
}

func rejectTombstonedLeaves(deployment Deployment, tombstones []string) error {
	denied := make(map[identity.SPKIHash]struct{}, len(tombstones))
	for _, pin := range tombstones {
		hash, err := identity.ParseSPKIPin(pin)
		if err != nil {
			return errors.New("enrollment: durable credential tombstone is invalid")
		}
		denied[hash] = struct{}{}
	}
	for _, encoded := range []string{deployment.OuterCertificate, deployment.InnerCertificate} {
		if encoded == "" {
			continue
		}
		certificate, err := parseCertificate([]byte(encoded))
		if err != nil {
			return err
		}
		hash, err := identity.HashSPKI(certificate)
		if err != nil {
			return err
		}
		if _, revoked := denied[hash]; revoked {
			return errors.New("enrollment: deployment attempts to reactivate a tombstoned credential")
		}
	}
	return nil
}

// RejectTombstonedCredentials exposes the same fail-closed activation check to
// exact rollback/recovery transactions.
func RejectTombstonedCredentials(deployment Deployment, tombstones []string) error {
	return rejectTombstonedLeaves(deployment, tombstones)
}
