package enrollment

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	RollbackAuthorizationSchema = "owntransit.rollback-authorization.v1"
	rollbackEnvelopeSchema      = "owntransit.rollback-authorization-envelope.v1"
	MaxRollbackAuthorization    = 64 << 10
)

const rollbackSignatureDomain = "owntransit.rollback-authorization.v1"

// RollbackAuthorization binds one explicit retained record and the exact
// state from which it may be selected. The target still overlays current
// revocations and verifier policy when materializing the rollback generation.
type RollbackAuthorization struct {
	Schema                  string `json:"schema"`
	Role                    Role   `json:"role"`
	InstallationID          string `json:"installation_id"`
	Sequence                uint64 `json:"sequence"`
	IssuedUnix              int64  `json:"issued_unix"`
	ExpiresUnix             int64  `json:"expires_unix"`
	ExpectedStateGeneration uint64 `json:"expected_state_generation"`
	ExpectedStateSHA256     string `json:"expected_state_sha256"`
	RecordID                string `json:"record_id"`
	RecordSHA256            string `json:"record_sha256"`
	DeploymentSequence      uint64 `json:"deployment_sequence"`
	CredentialSequence      uint64 `json:"credential_sequence"`
	ReleaseSequence         uint64 `json:"release_sequence"`
}

type rollbackEnvelope struct {
	Schema      string `json:"schema"`
	SignerKeyID string `json:"signer_key_id"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

func SignRollbackAuthorization(value RollbackAuthorization, privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("enrollment: rollback signer is not Ed25519")
	}
	if err := value.Validate(now); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	signature, err := signing.Sign(rollbackSignatureDomain, payload, privateKey)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(rollbackEnvelope{
		Schema: rollbackEnvelopeSchema, SignerKeyID: signing.KeyID(privateKey.Public().(ed25519.PublicKey)),
		Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxRollbackAuthorization {
		return nil, errors.New("enrollment: rollback authorization exceeds its size limit")
	}
	return encoded, nil
}

func VerifyRollbackAuthorization(encoded []byte, publicKey ed25519.PublicKey, now time.Time) (RollbackAuthorization, error) {
	if len(encoded) == 0 || len(encoded) > MaxRollbackAuthorization || len(publicKey) != ed25519.PublicKeySize {
		return RollbackAuthorization{}, errors.New("enrollment: bounded rollback authorization and verifier are required")
	}
	var envelope rollbackEnvelope
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return RollbackAuthorization{}, fmt.Errorf("enrollment: decode rollback authorization: %w", err)
	}
	if envelope.Schema != rollbackEnvelopeSchema || envelope.SignerKeyID != signing.KeyID(publicKey) {
		return RollbackAuthorization{}, errors.New("enrollment: rollback authorization signer is invalid")
	}
	payload, err := decodeCanonicalBase64(envelope.Payload, "rollback payload")
	if err != nil {
		return RollbackAuthorization{}, err
	}
	signature, err := decodeCanonicalBase64(envelope.Signature, "rollback signature")
	if err != nil {
		return RollbackAuthorization{}, err
	}
	if err := signing.Verify(rollbackSignatureDomain, payload, signature, publicKey); err != nil {
		return RollbackAuthorization{}, err
	}
	var value RollbackAuthorization
	if err := strictjson.Decode(payload, &value); err != nil {
		return RollbackAuthorization{}, fmt.Errorf("enrollment: decode rollback payload: %w", err)
	}
	if err := value.Validate(now); err != nil {
		return RollbackAuthorization{}, err
	}
	return value, nil
}

func (value RollbackAuthorization) Validate(now time.Time) error {
	installation, installErr := protocol.ParseID(value.InstallationID)
	record, recordErr := protocol.ParseID(value.RecordID)
	if value.Schema != RollbackAuthorizationSchema || value.Sequence == 0 || value.ExpectedStateGeneration == 0 ||
		!validSHA256(value.ExpectedStateSHA256) || !validSHA256(value.RecordSHA256) ||
		installErr != nil || installation == (protocol.ID{}) || installation.String() != value.InstallationID ||
		recordErr != nil || record == (protocol.ID{}) || record.String() != value.RecordID ||
		value.DeploymentSequence == 0 || value.CredentialSequence == 0 || value.ReleaseSequence == 0 {
		return errors.New("enrollment: rollback authorization identity, state, record, or tuple is invalid")
	}
	if value.Role != RoleClient && value.Role != RoleConnector && value.Role != RoleRelay {
		return errors.New("enrollment: rollback authorization role is invalid")
	}
	if value.IssuedUnix <= 0 || value.ExpiresUnix <= value.IssuedUnix || value.ExpiresUnix-value.IssuedUnix > int64((24*time.Hour)/time.Second) ||
		now.Before(time.Unix(value.IssuedUnix, 0).Add(-5*time.Minute)) || !now.Before(time.Unix(value.ExpiresUnix, 0)) {
		return errors.New("enrollment: rollback authorization is not currently valid")
	}
	return nil
}
