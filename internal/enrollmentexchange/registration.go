package enrollmentexchange

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	courierRegistrationSchema          = "owntransit.enrollment-courier-registration.v1"
	courierRegistrationEnvelopeSchema  = "owntransit.enrollment-courier-registration-envelope.v1"
	courierRegistrationSignatureDomain = "OwnTransit enrollment courier registration v1"
	MaxCourierRegistrationSize         = 1 << 20
)

type courierRegistrationPayload struct {
	Schema                  string `json:"schema"`
	Invitation              string `json:"invitation"`
	InvitationSHA256        string `json:"invitation_sha256"`
	Endpoint                string `json:"endpoint"`
	MailboxID               string `json:"mailbox_id"`
	ExpiresUnix             int64  `json:"expires_unix"`
	RequestWriteCapability  string `json:"request_write_capability"`
	RequestReadCapability   string `json:"request_read_capability"`
	ResponseWriteCapability string `json:"response_write_capability"`
	ResponseReadCapability  string `json:"response_read_capability"`
}

type courierRegistrationEnvelope struct {
	Schema      string `json:"schema"`
	SignerKeyID string `json:"signer_key_id"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

// CourierRegistration contains only relay-visible allocation material. It has
// no request-decryption identity, response identity, signer, issuer key, human
// record or enrollment approval authority.
type CourierRegistration struct {
	endpoint      string
	mailboxID     string
	expires       time.Time
	requestWrite  string
	requestRead   string
	responseWrite string
	responseRead  string
}

func signCourierRegistration(invitationBytes []byte, target targetExchange, operator operatorExchange, signer ed25519.PrivateKey, now time.Time) ([]byte, error) {
	tentative, err := parseTentativeInvitation(invitationBytes, now)
	if err != nil {
		return nil, err
	}
	if tentative.Invitation.Exchange != target {
		return nil, errors.New("enrollmentexchange: courier target exchange differs from invitation")
	}
	if err := operator.validateAgainst(target, tentative.Invitation.RequestEncryptionRecipient); err != nil {
		return nil, err
	}
	payload := courierRegistrationPayload{
		Schema:     courierRegistrationSchema,
		Invitation: base64.StdEncoding.EncodeToString(invitationBytes), InvitationSHA256: tentative.SHA256,
		Endpoint: target.Endpoint, MailboxID: target.MailboxID, ExpiresUnix: tentative.Invitation.ExpiresUnix,
		RequestWriteCapability: target.RequestWriteCapability, RequestReadCapability: operator.RequestReadCapability,
		ResponseWriteCapability: operator.ResponseWriteCapability, ResponseReadCapability: target.ResponseReadCapability,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	signature, err := signing.Sign(courierRegistrationSignatureDomain, payloadBytes, signer)
	if err != nil {
		return nil, err
	}
	envelope := courierRegistrationEnvelope{
		Schema: courierRegistrationEnvelopeSchema, SignerKeyID: tentative.Invitation.DeploymentSignerKeyID,
		Payload: base64.StdEncoding.EncodeToString(payloadBytes), Signature: base64.StdEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxCourierRegistrationSize {
		return nil, errors.New("enrollmentexchange: courier registration exceeds its size limit")
	}
	return encoded, nil
}

// ParseCourierRegistration verifies self-consistency and exact invitation,
// commitment and expiry binding. Like the invitation signature, this is not
// human authentication and grants no enrollment authority.
func ParseCourierRegistration(encoded []byte, now time.Time) (CourierRegistration, error) {
	if len(encoded) == 0 || len(encoded) > MaxCourierRegistrationSize {
		return CourierRegistration{}, errors.New("enrollmentexchange: courier registration has an invalid size")
	}
	var envelope courierRegistrationEnvelope
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return CourierRegistration{}, fmt.Errorf("enrollmentexchange: decode courier registration envelope: %w", err)
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil {
		return CourierRegistration{}, err
	}
	canonicalEnvelope = append(canonicalEnvelope, '\n')
	if !bytes.Equal(encoded, canonicalEnvelope) || envelope.Schema != courierRegistrationEnvelopeSchema {
		return CourierRegistration{}, errors.New("enrollmentexchange: courier registration envelope is noncanonical or unsupported")
	}
	payloadBytes, err := decodeCanonicalBase64(envelope.Payload)
	if err != nil {
		return CourierRegistration{}, errors.New("enrollmentexchange: courier registration payload is not canonical base64")
	}
	var payload courierRegistrationPayload
	if err := strictjson.Decode(payloadBytes, &payload); err != nil {
		return CourierRegistration{}, fmt.Errorf("enrollmentexchange: decode courier registration payload: %w", err)
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonicalPayload, payloadBytes) || payload.Schema != courierRegistrationSchema {
		return CourierRegistration{}, errors.New("enrollmentexchange: courier registration payload is noncanonical or unsupported")
	}
	invitationBytes, err := decodeSessionBytes(payload.Invitation, MaxInvitationSize, "courier registration invitation")
	if err != nil {
		return CourierRegistration{}, err
	}
	tentative, err := parseTentativeInvitation(invitationBytes, now)
	if err != nil {
		return CourierRegistration{}, err
	}
	public, err := signing.ParsePublic([]byte(tentative.Invitation.DeploymentSignerPublicPEM))
	if err != nil {
		return CourierRegistration{}, err
	}
	signature, err := decodeCanonicalBase64(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || envelope.SignerKeyID != tentative.Invitation.DeploymentSignerKeyID {
		return CourierRegistration{}, errors.New("enrollmentexchange: courier registration signature encoding or identity is invalid")
	}
	if err := signing.Verify(courierRegistrationSignatureDomain, payloadBytes, signature, public); err != nil {
		return CourierRegistration{}, fmt.Errorf("enrollmentexchange: courier registration signature: %w", err)
	}
	target := tentative.Invitation.Exchange
	if payload.InvitationSHA256 != tentative.SHA256 || payload.Endpoint != target.Endpoint || payload.MailboxID != target.MailboxID ||
		payload.ExpiresUnix != tentative.Invitation.ExpiresUnix || payload.RequestWriteCapability != target.RequestWriteCapability ||
		payload.ResponseReadCapability != target.ResponseReadCapability ||
		mailboxCapabilityCommitment(payload.MailboxID, "request-read", payload.RequestReadCapability) != target.RequestReadCapabilityCommitment ||
		mailboxCapabilityCommitment(payload.MailboxID, "response-write", payload.ResponseWriteCapability) != target.ResponseWriteCapabilityCommitment {
		return CourierRegistration{}, errors.New("enrollmentexchange: courier registration differs from invitation commitments")
	}
	capabilities := []string{payload.RequestWriteCapability, payload.RequestReadCapability, payload.ResponseWriteCapability, payload.ResponseReadCapability}
	decoded := make([][]byte, len(capabilities))
	for index, capability := range capabilities {
		decoded[index], err = parseMailboxCapability(capability)
		if err != nil {
			return CourierRegistration{}, err
		}
		for prior := 0; prior < index; prior++ {
			if bytes.Equal(decoded[index], decoded[prior]) {
				return CourierRegistration{}, errors.New("enrollmentexchange: courier registration capabilities are not independent")
			}
		}
	}
	return CourierRegistration{
		endpoint: payload.Endpoint, mailboxID: payload.MailboxID, expires: time.Unix(payload.ExpiresUnix, 0).UTC(),
		requestWrite: payload.RequestWriteCapability, requestRead: payload.RequestReadCapability,
		responseWrite: payload.ResponseWriteCapability, responseRead: payload.ResponseReadCapability,
	}, nil
}
