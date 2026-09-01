package enrollmentexchange

import (
	"bytes"
	"crypto/ed25519"
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
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

// OperatorSession is offline provisioner-side comparison state. It never
// exposes the expected target words. Reverse words become available only after
// an exact target-first input has been durably confirmed.
type OperatorSession struct {
	generation                uint64
	phase                     SessionPhase
	receiptBytes              []byte
	encryptedRequestBytes     []byte
	transcriptSHA256          [sha256.Size]byte
	confirmedTranscriptSHA256 [sha256.Size]byte
	phrase                    SafetyPhrase
	receipt                   parsedOperatorReceipt
	prepared                  preparedTranscript
}

// OperatorMailboxAction is the complete online courier view for the
// provisioner. It intentionally excludes the request-decryption identity,
// human records, signer and every issuance key retained in the receipt.
type OperatorMailboxAction struct {
	Endpoint                string
	MailboxID               string
	RequestReadCapability   string
	ResponseWriteCapability string
}

// OperatorReview is the offline, capability-free identity and routing view the
// administrator must inspect against pre-existing records before confirming
// any words. It contains no mailbox capability, decryption identity, signer or
// issuer private material.
type OperatorReview struct {
	Role                     enrollment.Role
	InstallationID           string
	RouteID                  string
	ConnectorInstallationID  string
	IntendedRecipient        string
	IdentityContactReference string
}

type encodedOperatorSession struct {
	Schema                    string       `json:"schema"`
	Generation                uint64       `json:"generation"`
	Phase                     SessionPhase `json:"phase"`
	OperatorReceipt           string       `json:"operator_receipt"`
	EncryptedRequest          string       `json:"encrypted_request"`
	TranscriptSHA256          string       `json:"transcript_sha256"`
	ConfirmedTranscriptSHA256 string       `json:"confirmed_transcript_sha256,omitempty"`
}

func NewOperatorSession(operatorReceipt, encryptedRequest []byte, now time.Time) (*OperatorSession, error) {
	receipt, err := parseOperatorReceipt(operatorReceipt, now)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareOperatorTranscript(receipt.tentative, receipt.operator, encryptedRequest, now)
	if err != nil {
		return nil, err
	}
	return operatorSessionFromPrepared(receipt, prepared, encryptedRequest, 1, PhasePendingComparison, [sha256.Size]byte{})
}

func operatorSessionFromPrepared(receipt parsedOperatorReceipt, prepared preparedTranscript, encryptedRequest []byte, generation uint64, phase SessionPhase, confirmed [sha256.Size]byte) (*OperatorSession, error) {
	if generation == 0 || phase != PhasePendingComparison && phase != PhaseTranscriptConfirmed && phase != PhaseCancelled {
		return nil, errors.New("enrollmentexchange: operator session generation or phase is invalid")
	}
	session := &OperatorSession{
		generation: generation, phase: phase,
		receiptBytes:              append([]byte(nil), receipt.encoded...),
		encryptedRequestBytes:     append([]byte(nil), encryptedRequest...),
		transcriptSHA256:          prepared.fullSHA256,
		confirmedTranscriptSHA256: confirmed,
		phrase:                    prepared.phrase, receipt: receipt, prepared: prepared,
	}
	if err := session.validateShape(); err != nil {
		return nil, err
	}
	return session, nil
}

func (session *OperatorSession) Encode() ([]byte, error) {
	if err := session.validateShape(); err != nil {
		return nil, err
	}
	value := encodedOperatorSession{
		Schema: operatorSessionSchema, Generation: session.generation, Phase: session.phase,
		OperatorReceipt:  base64.StdEncoding.EncodeToString(session.receiptBytes),
		EncryptedRequest: base64.StdEncoding.EncodeToString(session.encryptedRequestBytes),
		TranscriptSHA256: hex.EncodeToString(session.transcriptSHA256[:]),
	}
	if session.confirmedTranscriptSHA256 != ([sha256.Size]byte{}) {
		value.ConfirmedTranscriptSHA256 = hex.EncodeToString(session.confirmedTranscriptSHA256[:])
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxSessionSize {
		return nil, errors.New("enrollmentexchange: operator session exceeds its size limit")
	}
	return encoded, nil
}

func ParseOperatorSession(encoded []byte, now time.Time) (*OperatorSession, error) {
	if len(encoded) == 0 || len(encoded) > MaxSessionSize {
		return nil, errors.New("enrollmentexchange: operator session has an invalid size")
	}
	var value encodedOperatorSession
	if err := strictjson.Decode(encoded, &value); err != nil {
		return nil, fmt.Errorf("enrollmentexchange: decode operator session: %w", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(encoded, canonical) || value.Schema != operatorSessionSchema || value.Generation == 0 ||
		value.Phase != PhasePendingComparison && value.Phase != PhaseTranscriptConfirmed && value.Phase != PhaseCancelled {
		return nil, errors.New("enrollmentexchange: operator session is noncanonical or unsupported")
	}
	receiptBytes, err := decodeSessionBytes(value.OperatorReceipt, MaxOperatorReceiptSize, "operator receipt")
	if err != nil {
		return nil, err
	}
	encryptedRequest, err := decodeSessionBytes(value.EncryptedRequest, MaxEncryptedRequestSize, "operator encrypted request")
	if err != nil {
		return nil, err
	}
	receipt, err := parseOperatorReceipt(receiptBytes, now)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareOperatorTranscript(receipt.tentative, receipt.operator, encryptedRequest, now)
	if err != nil {
		return nil, err
	}
	if value.TranscriptSHA256 != hex.EncodeToString(prepared.fullSHA256[:]) {
		return nil, errors.New("enrollmentexchange: operator session transcript digest mismatch")
	}
	confirmed, err := decodeOptionalDigest(value.ConfirmedTranscriptSHA256, "operator confirmed transcript")
	if err != nil {
		return nil, err
	}
	return operatorSessionFromPrepared(receipt, prepared, encryptedRequest, value.Generation, value.Phase, confirmed)
}

func (session *OperatorSession) Generation() uint64 {
	if session == nil {
		return 0
	}
	return session.generation
}

func (session *OperatorSession) Phase() SessionPhase {
	if session == nil {
		return ""
	}
	return session.phase
}

func (session *OperatorSession) MailboxAction() (OperatorMailboxAction, error) {
	if session == nil || session.phase == PhaseCancelled {
		return OperatorMailboxAction{}, errors.New("enrollmentexchange: operator mailbox action is unavailable")
	}
	return OperatorMailboxAction{
		Endpoint:                session.receipt.tentative.Invitation.Exchange.Endpoint,
		MailboxID:               session.receipt.operator.MailboxID,
		RequestReadCapability:   session.receipt.operator.RequestReadCapability,
		ResponseWriteCapability: session.receipt.operator.ResponseWriteCapability,
	}, nil
}

// Review returns only the verified public request routing fields and the
// administrator's offline recipient record retained in the private receipt.
func (session *OperatorSession) Review() (OperatorReview, error) {
	if err := session.validateShape(); err != nil {
		return OperatorReview{}, err
	}
	return OperatorReview{
		Role:                     session.prepared.request.Role,
		InstallationID:           session.prepared.request.InstallationID,
		RouteID:                  session.prepared.request.RouteID,
		ConnectorInstallationID:  session.prepared.request.ConnectorInstallationID,
		IntendedRecipient:        session.receipt.payload.IntendedRecipient,
		IdentityContactReference: session.receipt.payload.IdentityContactReference,
	}, nil
}

// SignedRequest returns the exact proof-of-possession-verified request opened
// from this session's ciphertext. The caller must retain it in private offline
// state; it is the only byte representation accepted by route approval.
func (session *OperatorSession) SignedRequest() ([]byte, error) {
	if err := session.validateShape(); err != nil {
		return nil, err
	}
	return append([]byte(nil), session.prepared.requestBytes...), nil
}

// ConfirmTargetWords accepts words spoken by the target. An exact match is the
// only transition that reveals the reverse group. A submitted mismatch is
// terminal and reports no per-position information.
func (session *OperatorSession) ConfirmTargetWords(words [3]string) (ConfirmationOutcome, error) {
	if session == nil || session.phase != PhasePendingComparison {
		return "", errors.New("enrollmentexchange: operator comparison is not pending")
	}
	allEmpty := true
	for _, word := range words {
		allEmpty = allEmpty && strings.TrimSpace(word) == ""
	}
	if allEmpty {
		return OutcomeDeferred, nil
	}
	actual, valid := canonicalComparisonGroup(words)
	expected := strings.Join(session.phrase[:safetyWordsPerDirection], "\x00")
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

// ProvisionerWords implements gated reveal: it is impossible to retrieve the
// reverse group from this API before exact target-first confirmation.
func (session *OperatorSession) ProvisionerWords() ([3]string, error) {
	var words [3]string
	if session == nil || session.phase != PhaseTranscriptConfirmed || session.confirmedTranscriptSHA256 != session.transcriptSHA256 {
		return words, errors.New("enrollmentexchange: reverse words remain hidden until target-first confirmation")
	}
	copy(words[:], session.phrase[safetyWordsPerDirection:])
	return words, nil
}

func (session *OperatorSession) BindResponse(enrollmentResponse []byte, approvedSetSHA256 string, signer ed25519.PrivateKey) ([]byte, error) {
	if session == nil || session.phase != PhaseTranscriptConfirmed || session.confirmedTranscriptSHA256 != session.transcriptSHA256 {
		return nil, errors.New("enrollmentexchange: provisioner-side transcript confirmation is required before issuance")
	}
	public, err := signing.ParsePublic([]byte(session.receipt.tentative.Invitation.DeploymentSignerPublicPEM))
	if err != nil {
		return nil, err
	}
	if len(signer) != ed25519.PrivateKeySize || !bytes.Equal(signer.Public().(ed25519.PublicKey), public) {
		return nil, errors.New("enrollmentexchange: response signer differs from the invitation verifier")
	}
	return BindResponse(
		hex.EncodeToString(session.prepared.invitationSHA256[:]),
		hex.EncodeToString(session.prepared.encryptedRequestSHA256[:]),
		hex.EncodeToString(session.prepared.fullSHA256[:]),
		approvedSetSHA256,
		enrollmentResponse,
		signer,
	)
}

func (session *OperatorSession) validateShape() error {
	if session == nil || session.generation == 0 || len(session.receiptBytes) == 0 || len(session.encryptedRequestBytes) == 0 {
		return errors.New("enrollmentexchange: operator session is incomplete")
	}
	confirmed := session.confirmedTranscriptSHA256 != ([sha256.Size]byte{})
	switch session.phase {
	case PhasePendingComparison, PhaseCancelled:
		if confirmed {
			return errors.New("enrollmentexchange: unconfirmed operator session contains confirmation authority")
		}
	case PhaseTranscriptConfirmed:
		if !confirmed || session.confirmedTranscriptSHA256 != session.transcriptSHA256 {
			return errors.New("enrollmentexchange: operator confirmation does not bind the full transcript")
		}
	default:
		return errors.New("enrollmentexchange: operator session phase is invalid")
	}
	return nil
}
