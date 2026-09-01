package enrollmentexchange

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	targetSessionSchema   = "owntransit.enrollment-target-session.v1"
	operatorSessionSchema = "owntransit.enrollment-operator-session.v1"
	MaxSessionSize        = 8 << 20
)

// SessionPhase is one fail-closed step in the enrollment comparison and
// activation workflow. READY is deliberately distinct from applied: only a
// successful carrier-only probe may make that final transition.
type SessionPhase string

const (
	PhasePendingComparison   SessionPhase = "pending-comparison"
	PhaseTranscriptConfirmed SessionPhase = "transcript-confirmed"
	PhaseResponseVerified    SessionPhase = "response-verified"
	PhaseApplied             SessionPhase = "applied-not-ready"
	PhaseReady               SessionPhase = "ready"
	PhaseCancelled           SessionPhase = "cancelled"
)

// ConfirmationOutcome avoids an error path that could accidentally discard a
// terminal mismatch mutation. A caller must durably store the returned session
// after OutcomeCancelled before reporting the mismatch.
type ConfirmationOutcome string

const (
	OutcomeDeferred  ConfirmationOutcome = "deferred"
	OutcomeConfirmed ConfirmationOutcome = "confirmed"
	OutcomeCancelled ConfirmationOutcome = "cancelled"
)

// TargetMailboxAction is the only target-side material an untrusted courier
// needs. Capabilities limit abuse against the already-untrusted mailbox; they
// are not authentication roots. Values must never be put in a URL or log.
type TargetMailboxAction struct {
	Endpoint               string
	MailboxID              string
	RequestWriteCapability string
	ResponseReadCapability string
	EncryptedRequest       []byte
}

type TargetMailboxTombstone struct {
	Endpoint               string
	MailboxID              string
	ResponseReadCapability string
}

// TargetSession retains the exact transcript bytes and the full-digest
// confirmation. Its fields are intentionally opaque so JSON/logging cannot
// accidentally serialize mailbox capabilities or enrollment material.
type TargetSession struct {
	generation                uint64
	phase                     SessionPhase
	invitationBytes           []byte
	requestBytes              []byte
	encryptedRequestBytes     []byte
	invitationSHA256          [sha256.Size]byte
	requestSHA256             [sha256.Size]byte
	encryptedRequestSHA256    [sha256.Size]byte
	transcriptSHA256          [sha256.Size]byte
	confirmedTranscriptSHA256 [sha256.Size]byte
	responseSHA256            [sha256.Size]byte
	boundResponseBytes        []byte
	phrase                    SafetyPhrase
	invitation                invitation
}

type encodedTargetSession struct {
	Schema                    string       `json:"schema"`
	Generation                uint64       `json:"generation"`
	Phase                     SessionPhase `json:"phase"`
	Invitation                string       `json:"invitation"`
	Request                   string       `json:"signed_request"`
	EncryptedRequest          string       `json:"encrypted_request"`
	InvitationSHA256          string       `json:"invitation_sha256"`
	RequestSHA256             string       `json:"request_sha256"`
	EncryptedRequestSHA256    string       `json:"encrypted_request_sha256"`
	TranscriptSHA256          string       `json:"transcript_sha256"`
	ConfirmedTranscriptSHA256 string       `json:"confirmed_transcript_sha256,omitempty"`
	ResponseSHA256            string       `json:"response_sha256,omitempty"`
	BoundResponse             string       `json:"bound_response,omitempty"`
}

// NewTargetSession verifies one tentative signed invitation, binds one exact
// already-signed target request to it, seals that request exactly once and
// returns resumable state. Recreating a session intentionally produces another
// ciphertext and therefore another transcript; callers must retain this value.
func NewTargetSession(invitationBytes, signedRequestBytes []byte, now time.Time) (*TargetSession, error) {
	tentative, err := parseTentativeInvitation(invitationBytes, now)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareTargetTranscript(tentative, signedRequestBytes, now)
	if err != nil {
		return nil, err
	}
	return targetSessionFromPrepared(tentative.Invitation, tentative.Encoded, prepared, 1, PhasePendingComparison, [sha256.Size]byte{}, nil)
}

func targetSessionFromPrepared(
	inv invitation,
	invitationBytes []byte,
	prepared preparedTranscript,
	generation uint64,
	phase SessionPhase,
	confirmed [sha256.Size]byte,
	boundResponse []byte,
) (*TargetSession, error) {
	if generation == 0 || !validTargetPhase(phase) {
		return nil, errors.New("enrollmentexchange: target session generation or phase is invalid")
	}
	session := &TargetSession{
		generation: generation, phase: phase, invitation: inv,
		invitationBytes:           append([]byte(nil), invitationBytes...),
		requestBytes:              append([]byte(nil), prepared.requestBytes...),
		encryptedRequestBytes:     append([]byte(nil), prepared.encryptedRequestBytes...),
		invitationSHA256:          prepared.invitationSHA256,
		requestSHA256:             prepared.requestSHA256,
		encryptedRequestSHA256:    prepared.encryptedRequestSHA256,
		transcriptSHA256:          prepared.fullSHA256,
		confirmedTranscriptSHA256: confirmed,
		boundResponseBytes:        append([]byte(nil), boundResponse...),
		phrase:                    prepared.phrase,
	}
	if len(boundResponse) != 0 {
		session.responseSHA256 = sha256.Sum256(boundResponse)
	}
	if err := session.validateShape(); err != nil {
		return nil, err
	}
	return session, nil
}

// Encode emits one strict canonical, newline-terminated durable target state.
func (session *TargetSession) Encode() ([]byte, error) {
	if err := session.validateShape(); err != nil {
		return nil, err
	}
	value := encodedTargetSession{
		Schema: targetSessionSchema, Generation: session.generation, Phase: session.phase,
		Invitation:             base64.StdEncoding.EncodeToString(session.invitationBytes),
		Request:                base64.StdEncoding.EncodeToString(session.requestBytes),
		EncryptedRequest:       base64.StdEncoding.EncodeToString(session.encryptedRequestBytes),
		InvitationSHA256:       hex.EncodeToString(session.invitationSHA256[:]),
		RequestSHA256:          hex.EncodeToString(session.requestSHA256[:]),
		EncryptedRequestSHA256: hex.EncodeToString(session.encryptedRequestSHA256[:]),
		TranscriptSHA256:       hex.EncodeToString(session.transcriptSHA256[:]),
	}
	if session.confirmedTranscriptSHA256 != ([sha256.Size]byte{}) {
		value.ConfirmedTranscriptSHA256 = hex.EncodeToString(session.confirmedTranscriptSHA256[:])
	}
	if session.responseSHA256 != ([sha256.Size]byte{}) {
		value.ResponseSHA256 = hex.EncodeToString(session.responseSHA256[:])
		value.BoundResponse = base64.StdEncoding.EncodeToString(session.boundResponseBytes)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("enrollmentexchange: encode target session: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxSessionSize {
		return nil, errors.New("enrollmentexchange: target session exceeds its size limit")
	}
	return encoded, nil
}

// ParseTargetSession revalidates every retained exact byte and digest. An
// expired invitation/request fails closed rather than being revived by state.
func ParseTargetSession(encoded []byte, now time.Time) (*TargetSession, error) {
	if len(encoded) == 0 || len(encoded) > MaxSessionSize {
		return nil, errors.New("enrollmentexchange: target session has an invalid size")
	}
	var value encodedTargetSession
	if err := strictjson.Decode(encoded, &value); err != nil {
		return nil, fmt.Errorf("enrollmentexchange: decode target session: %w", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(encoded, canonical) || value.Schema != targetSessionSchema || value.Generation == 0 || !validTargetPhase(value.Phase) {
		return nil, errors.New("enrollmentexchange: target session is noncanonical or unsupported")
	}
	invitationBytes, err := decodeSessionBytes(value.Invitation, MaxInvitationSize, "invitation")
	if err != nil {
		return nil, err
	}
	requestBytes, err := decodeSessionBytes(value.Request, enrollment.MaxRequestSize, "signed request")
	if err != nil {
		return nil, err
	}
	encryptedBytes, err := decodeSessionBytes(value.EncryptedRequest, MaxEncryptedRequestSize, "encrypted request")
	if err != nil {
		return nil, err
	}
	tentative, err := parseTentativeInvitation(invitationBytes, now)
	if err != nil {
		return nil, err
	}
	request, err := enrollment.ParseRequest(requestBytes, now)
	if err != nil {
		return nil, err
	}
	if err := bindRequestToInvitation(tentative.Invitation, request); err != nil {
		return nil, err
	}
	prepared, err := buildPreparedTranscript(invitationBytes, requestBytes, encryptedBytes, request)
	if err != nil {
		return nil, err
	}
	for label, check := range map[string]struct {
		encoded string
		actual  [sha256.Size]byte
	}{
		"invitation":        {value.InvitationSHA256, prepared.invitationSHA256},
		"request":           {value.RequestSHA256, prepared.requestSHA256},
		"encrypted request": {value.EncryptedRequestSHA256, prepared.encryptedRequestSHA256},
		"transcript":        {value.TranscriptSHA256, prepared.fullSHA256},
	} {
		if check.encoded != hex.EncodeToString(check.actual[:]) {
			return nil, fmt.Errorf("enrollmentexchange: target session %s digest mismatch", label)
		}
	}
	confirmed, err := decodeOptionalDigest(value.ConfirmedTranscriptSHA256, "confirmed transcript")
	if err != nil {
		return nil, err
	}
	response, err := decodeOptionalDigest(value.ResponseSHA256, "response")
	if err != nil {
		return nil, err
	}
	var boundResponse []byte
	if value.BoundResponse != "" {
		boundResponse, err = decodeSessionBytes(value.BoundResponse, MaxBoundResponseSize, "bound response")
		if err != nil {
			return nil, err
		}
	}
	if (len(boundResponse) == 0) != (response == ([sha256.Size]byte{})) || len(boundResponse) != 0 && sha256.Sum256(boundResponse) != response {
		return nil, errors.New("enrollmentexchange: target session bound response digest mismatch")
	}
	session, err := targetSessionFromPrepared(tentative.Invitation, invitationBytes, prepared, value.Generation, value.Phase, confirmed, boundResponse)
	if err != nil {
		return nil, err
	}
	if err := session.validateShape(); err != nil {
		return nil, err
	}
	if len(boundResponse) != 0 {
		if _, err := session.verifyBoundResponse(boundResponse); err != nil {
			return nil, fmt.Errorf("enrollmentexchange: retained bound response: %w", err)
		}
	}
	return session, nil
}

// Generation is the compare-and-swap value a durable store must match.
func (session *TargetSession) Generation() uint64 {
	if session == nil {
		return 0
	}
	return session.generation
}

func (session *TargetSession) Phase() SessionPhase {
	if session == nil {
		return ""
	}
	return session.phase
}

// TargetWords returns only the first direction. The reverse-direction words
// remain hidden and are accepted only as user input.
func (session *TargetSession) TargetWords() ([3]string, error) {
	var words [3]string
	if session == nil || session.phase == PhaseCancelled {
		return words, errors.New("enrollmentexchange: target words are unavailable")
	}
	copy(words[:], session.phrase[:safetyWordsPerDirection])
	return words, nil
}

func (session *TargetSession) MailboxAction() (TargetMailboxAction, error) {
	if session == nil || session.phase == PhaseCancelled || session.phase == PhaseReady {
		return TargetMailboxAction{}, errors.New("enrollmentexchange: target mailbox action is unavailable")
	}
	return TargetMailboxAction{
		Endpoint:               session.invitation.Exchange.Endpoint,
		MailboxID:              session.invitation.Exchange.MailboxID,
		RequestWriteCapability: session.invitation.Exchange.RequestWriteCapability,
		ResponseReadCapability: session.invitation.Exchange.ResponseReadCapability,
		EncryptedRequest:       append([]byte(nil), session.encryptedRequestBytes...),
	}, nil
}

func (session *TargetSession) MailboxTombstone() (TargetMailboxTombstone, error) {
	if session == nil || session.phase != PhaseReady {
		return TargetMailboxTombstone{}, errors.New("enrollmentexchange: mailbox tombstone requires READY")
	}
	return TargetMailboxTombstone{
		Endpoint: session.invitation.Exchange.Endpoint, MailboxID: session.invitation.Exchange.MailboxID,
		ResponseReadCapability: session.invitation.Exchange.ResponseReadCapability,
	}, nil
}

// ConfirmProvisionerWords implements the target-side reverse comparison. An
// all-empty group defers without mutation. Any submitted non-exact group is a
// terminal cancellation and reveals no position information.
func (session *TargetSession) ConfirmProvisionerWords(words [3]string) (ConfirmationOutcome, error) {
	if session == nil || session.phase != PhasePendingComparison {
		return "", errors.New("enrollmentexchange: target comparison is not pending")
	}
	allEmpty := true
	for _, word := range words {
		allEmpty = allEmpty && strings.TrimSpace(word) == ""
	}
	if allEmpty {
		return OutcomeDeferred, nil
	}
	actual, valid := canonicalComparisonGroup(words)
	expected := strings.Join(session.phrase[safetyWordsPerDirection:], "\x00")
	matched := valid && subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
	session.generation++
	if !matched {
		session.phase = PhaseCancelled
		session.confirmedTranscriptSHA256 = [sha256.Size]byte{}
		return OutcomeCancelled, nil
	}
	session.phase = PhaseTranscriptConfirmed
	session.confirmedTranscriptSHA256 = session.transcriptSHA256
	return OutcomeConfirmed, nil
}

// Cancel is explicit and idempotent only for an already-cancelled session.
func (session *TargetSession) Cancel() error {
	if session == nil {
		return errors.New("enrollmentexchange: target session is absent")
	}
	if session.phase == PhaseCancelled {
		return nil
	}
	if session.phase == PhaseApplied || session.phase == PhaseReady {
		return errors.New("enrollmentexchange: an applied session cannot be cancelled")
	}
	session.generation++
	session.phase = PhaseCancelled
	session.confirmedTranscriptSHA256 = [sha256.Size]byte{}
	session.responseSHA256 = [sha256.Size]byte{}
	wipe(session.boundResponseBytes)
	session.boundResponseBytes = nil
	return nil
}

func validTargetPhase(phase SessionPhase) bool {
	switch phase {
	case PhasePendingComparison, PhaseTranscriptConfirmed, PhaseResponseVerified, PhaseApplied, PhaseReady, PhaseCancelled:
		return true
	default:
		return false
	}
}

func (session *TargetSession) validateShape() error {
	if session == nil || session.generation == 0 || !validTargetPhase(session.phase) ||
		len(session.invitationBytes) == 0 || len(session.requestBytes) == 0 || len(session.encryptedRequestBytes) == 0 {
		return errors.New("enrollmentexchange: target session is incomplete")
	}
	confirmed := session.confirmedTranscriptSHA256 != ([sha256.Size]byte{})
	response := session.responseSHA256 != ([sha256.Size]byte{})
	retainedResponse := len(session.boundResponseBytes) != 0
	switch session.phase {
	case PhasePendingComparison:
		if confirmed || response || retainedResponse {
			return errors.New("enrollmentexchange: pending session contains later authority")
		}
	case PhaseTranscriptConfirmed:
		if !confirmed || response || retainedResponse {
			return errors.New("enrollmentexchange: confirmed session state is inconsistent")
		}
	case PhaseResponseVerified, PhaseApplied, PhaseReady:
		if !confirmed || !response || !retainedResponse || sha256.Sum256(session.boundResponseBytes) != session.responseSHA256 {
			return errors.New("enrollmentexchange: activated session lacks its exact bindings")
		}
	case PhaseCancelled:
		if confirmed || response || retainedResponse {
			return errors.New("enrollmentexchange: cancelled session retains activation authority")
		}
	}
	if confirmed && session.confirmedTranscriptSHA256 != session.transcriptSHA256 {
		return errors.New("enrollmentexchange: confirmation does not bind the full transcript")
	}
	return nil
}

func canonicalComparisonGroup(words [3]string) (string, bool) {
	canonical := make([]string, len(words))
	for index, word := range words {
		word = strings.ToLower(strings.TrimSpace(word))
		if len(word) < 3 || len(word) > 8 {
			return "", false
		}
		for _, character := range word {
			if character < 'a' || character > 'z' {
				return "", false
			}
		}
		canonical[index] = word
	}
	return strings.Join(canonical, "\x00"), true
}

func decodeSessionBytes(value string, limit int, field string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value || len(decoded) == 0 || len(decoded) > limit {
		return nil, fmt.Errorf("enrollmentexchange: target session %s is not bounded canonical base64", field)
	}
	return decoded, nil
}

func decodeOptionalDigest(value, field string) ([sha256.Size]byte, error) {
	if value == "" {
		return [sha256.Size]byte{}, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return [sha256.Size]byte{}, fmt.Errorf("enrollmentexchange: %s digest is invalid", field)
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result, nil
}
