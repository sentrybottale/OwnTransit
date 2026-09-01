package enrollmentexchange

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
)

// preparedTranscript is the single internal product of invitation parsing,
// request proof-of-possession validation, exact invitation binding, one-time
// request sealing, and full transcript hashing. Keeping this type opaque
// prevents future callers from independently cross-wiring those steps.
type preparedTranscript struct {
	invitationSHA256       [sha256.Size]byte
	requestSHA256          [sha256.Size]byte
	encryptedRequestSHA256 [sha256.Size]byte
	fullSHA256             [sha256.Size]byte
	phrase                 SafetyPhrase
	request                enrollment.RequestPayload
	requestBytes           []byte
	encryptedRequestBytes  []byte
}

func prepareTargetTranscript(tentative tentativeInvitation, requestBytes []byte, now time.Time) (preparedTranscript, error) {
	invitation, err := validateTentativeHandle(tentative, now)
	if err != nil {
		return preparedTranscript{}, err
	}
	request, err := enrollment.ParseRequest(requestBytes, now)
	if err != nil {
		return preparedTranscript{}, err
	}
	if err := bindRequestToInvitation(invitation, request); err != nil {
		return preparedTranscript{}, err
	}
	ciphertext, err := sealRequest(requestBytes, invitation.RequestEncryptionRecipient, now)
	if err != nil {
		return preparedTranscript{}, err
	}
	return buildPreparedTranscript(tentative.Encoded, requestBytes, ciphertext, request)
}

func prepareOperatorTranscript(
	tentative tentativeInvitation,
	operator operatorExchange,
	encryptedRequestBytes []byte,
	now time.Time,
) (preparedTranscript, error) {
	invitation, err := validateTentativeHandle(tentative, now)
	if err != nil {
		return preparedTranscript{}, err
	}
	if err := operator.validateAgainst(invitation.Exchange, invitation.RequestEncryptionRecipient); err != nil {
		return preparedTranscript{}, err
	}
	requestBytes, request, err := openRequest(encryptedRequestBytes, operator.RequestDecryptionIdentity, now)
	if err != nil {
		return preparedTranscript{}, err
	}
	if err := bindRequestToInvitation(invitation, request); err != nil {
		return preparedTranscript{}, err
	}
	return buildPreparedTranscript(tentative.Encoded, requestBytes, encryptedRequestBytes, request)
}

func validateTentativeHandle(tentative tentativeInvitation, now time.Time) (invitation, error) {
	parsed, err := parseTentativeInvitation(tentative.Encoded, now)
	if err != nil {
		return invitation{}, err
	}
	if parsed.Invitation != tentative.Invitation || parsed.SHA256 != tentative.SHA256 || !bytes.Equal(parsed.Encoded, tentative.Encoded) {
		return invitation{}, errors.New("enrollmentexchange: tentative invitation handle does not match its exact bytes")
	}
	return parsed.Invitation, nil
}

func buildPreparedTranscript(
	invitationBytes, requestBytes, encryptedRequestBytes []byte,
	request enrollment.RequestPayload,
) (preparedTranscript, error) {
	fullDigest, err := transcriptDigest(invitationBytes, requestBytes, encryptedRequestBytes)
	if err != nil {
		return preparedTranscript{}, err
	}
	phrase, err := phraseFromTranscriptDigest(fullDigest)
	if err != nil {
		return preparedTranscript{}, err
	}
	return preparedTranscript{
		invitationSHA256:       sha256.Sum256(invitationBytes),
		requestSHA256:          sha256.Sum256(requestBytes),
		encryptedRequestSHA256: sha256.Sum256(encryptedRequestBytes),
		fullSHA256:             fullDigest,
		phrase:                 phrase,
		request:                request,
		requestBytes:           append([]byte(nil), requestBytes...),
		encryptedRequestBytes:  append([]byte(nil), encryptedRequestBytes...),
	}, nil
}
