package enrollmentexchange

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	boundResponseSchema          = "owntransit.enrollment-bound-response.v1"
	boundResponseEnvelopeSchema  = "owntransit.enrollment-bound-response-envelope.v1"
	boundResponseSignatureDomain = "OwnTransit enrollment bound response v1"
	approvedRequestSetDomain     = "OwnTransit approved enrollment request set v1"
	MaxBoundResponseSize         = 2 * enrollment.MaxEnvelopeSize
)

type boundResponsePayload struct {
	Schema                   string `json:"schema"`
	InvitationSHA256         string `json:"invitation_sha256"`
	EncryptedRequestSHA256   string `json:"encrypted_request_sha256"`
	TranscriptSHA256         string `json:"transcript_sha256"`
	ApprovedRequestSetSHA256 string `json:"approved_request_set_sha256"`
	EnrollmentResponse       string `json:"enrollment_response"`
}

type boundResponseEnvelope struct {
	Schema      string `json:"schema"`
	SignerKeyID string `json:"signer_key_id"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

// ApprovedRequestSetSHA256 binds the exact relay, connector and client signed
// requests in one fixed role order. Parsing first prevents a caller from
// labeling three arbitrary blobs as an approved route set.
func ApprovedRequestSetSHA256(relayRequest, connectorRequest, clientRequest []byte, now time.Time) (string, error) {
	requests := []struct {
		role enrollment.Role
		data []byte
	}{
		{enrollment.RoleRelay, relayRequest},
		{enrollment.RoleConnector, connectorRequest},
		{enrollment.RoleClient, clientRequest},
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(approvedRequestSetDomain))
	_, _ = hash.Write([]byte{0})
	var routeID, connectorID string
	var runtime enrollment.RuntimeBinding
	for index, item := range requests {
		request, err := enrollment.ParseRequest(item.data, now)
		if err != nil {
			return "", fmt.Errorf("enrollmentexchange: approved %s request: %w", item.role, err)
		}
		if request.Role != item.role {
			return "", errors.New("enrollmentexchange: approved request set role order is invalid")
		}
		if index == 0 {
			runtime = request.Runtime
		} else if request.Runtime.ReleaseID != runtime.ReleaseID ||
			request.Runtime.ReleaseSequence != runtime.ReleaseSequence ||
			request.Runtime.Protocol != runtime.Protocol ||
			request.Runtime.LifecycleGeneration != runtime.LifecycleGeneration {
			return "", errors.New("enrollmentexchange: approved request set runtime generation differs")
		}
		switch item.role {
		case enrollment.RoleConnector:
			routeID, connectorID = request.RouteID, request.InstallationID
		case enrollment.RoleClient:
			if request.RouteID != routeID || request.ConnectorInstallationID != connectorID {
				return "", errors.New("enrollmentexchange: approved client request is cross-wired")
			}
		}
		writeTranscriptField(hash, item.data)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// BindResponse signs the exchange-specific transcript and three-target
// approval-set bindings around the existing independently signed, encrypted
// enrollment response. It does not decrypt or replace that response.
func BindResponse(
	invitationSHA256, encryptedRequestSHA256, transcriptSHA256, approvedSetSHA256 string,
	enrollmentResponse []byte,
	signer ed25519.PrivateKey,
) ([]byte, error) {
	if !validSHA256Hex(invitationSHA256) || !validSHA256Hex(encryptedRequestSHA256) ||
		!validSHA256Hex(transcriptSHA256) || !validSHA256Hex(approvedSetSHA256) {
		return nil, errors.New("enrollmentexchange: complete canonical response bindings are required")
	}
	if len(enrollmentResponse) == 0 || len(enrollmentResponse) > enrollment.MaxEnvelopeSize || len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("enrollmentexchange: bounded enrollment response and Ed25519 signer are required")
	}
	payload := boundResponsePayload{
		Schema:                   boundResponseSchema,
		InvitationSHA256:         invitationSHA256,
		EncryptedRequestSHA256:   encryptedRequestSHA256,
		TranscriptSHA256:         transcriptSHA256,
		ApprovedRequestSetSHA256: approvedSetSHA256,
		EnrollmentResponse:       base64.StdEncoding.EncodeToString(enrollmentResponse),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("enrollmentexchange: encode bound response: %w", err)
	}
	signature, err := signing.Sign(boundResponseSignatureDomain, payloadBytes, signer)
	if err != nil {
		return nil, err
	}
	envelope := boundResponseEnvelope{
		Schema:      boundResponseEnvelopeSchema,
		SignerKeyID: signing.KeyID(signer.Public().(ed25519.PublicKey)),
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signature:   base64.StdEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("enrollmentexchange: encode bound response envelope: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxBoundResponseSize {
		return nil, errors.New("enrollmentexchange: bound response exceeds its size limit")
	}
	return encoded, nil
}

// AcceptBoundResponse verifies the offline signature and every exact exchange
// binding, then returns only the existing target-encrypted enrollment response
// for the ordinary lifecycle apply gate. It requires target-local transcript
// confirmation first and advances no applied/READY state.
func (session *TargetSession) AcceptBoundResponse(encoded []byte) ([]byte, error) {
	if session == nil || session.phase != PhaseTranscriptConfirmed || session.confirmedTranscriptSHA256 != session.transcriptSHA256 {
		return nil, errors.New("enrollmentexchange: target-local transcript confirmation is required before response verification")
	}
	response, err := session.verifyBoundResponse(encoded)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	session.generation++
	session.phase = PhaseResponseVerified
	session.responseSHA256 = digest
	session.boundResponseBytes = append([]byte(nil), encoded...)
	return response, nil
}

func (session *TargetSession) verifyBoundResponse(encoded []byte) ([]byte, error) {
	if session == nil || len(encoded) == 0 || len(encoded) > MaxBoundResponseSize {
		return nil, errors.New("enrollmentexchange: bound response has an invalid size")
	}
	var envelope boundResponseEnvelope
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return nil, fmt.Errorf("enrollmentexchange: decode bound response envelope: %w", err)
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	canonicalEnvelope = append(canonicalEnvelope, '\n')
	if !bytes.Equal(encoded, canonicalEnvelope) || envelope.Schema != boundResponseEnvelopeSchema {
		return nil, errors.New("enrollmentexchange: bound response envelope is noncanonical or unsupported")
	}
	payloadBytes, err := decodeCanonicalBase64(envelope.Payload)
	if err != nil {
		return nil, errors.New("enrollmentexchange: bound response payload is not canonical base64")
	}
	signature, err := decodeCanonicalBase64(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("enrollmentexchange: bound response signature encoding is invalid")
	}
	publicKey, err := signing.ParsePublic([]byte(session.invitation.DeploymentSignerPublicPEM))
	if err != nil {
		return nil, err
	}
	if envelope.SignerKeyID != session.invitation.DeploymentSignerKeyID || envelope.SignerKeyID != signing.KeyID(publicKey) {
		return nil, errors.New("enrollmentexchange: bound response signer differs from the invitation verifier")
	}
	if err := signing.Verify(boundResponseSignatureDomain, payloadBytes, signature, publicKey); err != nil {
		return nil, fmt.Errorf("enrollmentexchange: bound response signature: %w", err)
	}
	var payload boundResponsePayload
	if err := strictjson.Decode(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("enrollmentexchange: decode bound response payload: %w", err)
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonicalPayload, payloadBytes) || payload.Schema != boundResponseSchema {
		return nil, errors.New("enrollmentexchange: bound response payload is noncanonical or unsupported")
	}
	if payload.InvitationSHA256 != hex.EncodeToString(session.invitationSHA256[:]) ||
		payload.EncryptedRequestSHA256 != hex.EncodeToString(session.encryptedRequestSHA256[:]) ||
		payload.TranscriptSHA256 != hex.EncodeToString(session.transcriptSHA256[:]) ||
		!validSHA256Hex(payload.ApprovedRequestSetSHA256) {
		return nil, errors.New("enrollmentexchange: response does not bind this exact confirmed transcript and request set")
	}
	response, err := decodeCanonicalBase64(payload.EnrollmentResponse)
	if err != nil || len(response) == 0 || len(response) > enrollment.MaxEnvelopeSize {
		return nil, errors.New("enrollmentexchange: embedded enrollment response is invalid")
	}
	return response, nil
}

// VerifiedEnrollmentResponse returns the exact target-encrypted response
// retained before lifecycle apply. It allows a crash or relay restart after
// verification to resume without fetching or regenerating any artifact.
func (session *TargetSession) VerifiedEnrollmentResponse() ([]byte, error) {
	if session == nil || session.phase != PhaseResponseVerified || len(session.boundResponseBytes) == 0 {
		return nil, errors.New("enrollmentexchange: no verified response is ready for apply")
	}
	return session.verifyBoundResponse(session.boundResponseBytes)
}

// ReconcileAppliedResponse supplies the exact verified enrollment response to
// one target-local reconciliation callback only while the session is Applied.
// It does not expose the response in READY or any earlier/later phase and does
// not itself mutate session state.
func (session *TargetSession) ReconcileAppliedResponse(reconcile func([]byte) error) error {
	if session == nil || session.phase != PhaseApplied || reconcile == nil || len(session.boundResponseBytes) == 0 {
		return errors.New("enrollmentexchange: an applied response reconciliation is required")
	}
	response, err := session.verifyBoundResponse(session.boundResponseBytes)
	if err != nil {
		return err
	}
	defer wipe(response)
	return reconcile(response)
}

// RecordApplied may be called only after the ordinary target lifecycle gate
// has successfully applied the exact response returned by AcceptBoundResponse.
// The exchange package does not substitute for that gate.
func (session *TargetSession) RecordApplied() error {
	if session == nil || session.phase != PhaseResponseVerified || len(session.boundResponseBytes) == 0 {
		return errors.New("enrollmentexchange: one verified bound response is required before recording apply")
	}
	digest := sha256.Sum256(session.boundResponseBytes)
	if digest != session.responseSHA256 {
		return errors.New("enrollmentexchange: applied response differs from the verified response")
	}
	session.generation++
	session.phase = PhaseApplied
	return nil
}

// CompleteReadyProbe runs the supplied carrier-only operation and records
// READY only when it returns after authenticating the connector's protocol
// marker. A failed/cancelled probe leaves the durable phase NOT READY.
func (session *TargetSession) CompleteReadyProbe(ctx context.Context, probe func(context.Context) error) error {
	if session == nil || session.phase != PhaseApplied || ctx == nil || probe == nil {
		return errors.New("enrollmentexchange: an applied session is required before READY")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := probe(ctx); err != nil {
		return fmt.Errorf("enrollmentexchange: carrier-only READY probe failed: %w", err)
	}
	session.generation++
	session.phase = PhaseReady
	return nil
}
