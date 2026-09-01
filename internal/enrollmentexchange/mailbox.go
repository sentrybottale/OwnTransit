package enrollmentexchange

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

// operatorExchange contains the complementary mailbox capabilities and the
// one-invitation request decryption identity retained offline. It must never be
// included in the recipient invitation or sent to the relay as content.
// It remains unexported so ordinary JSON/logging code cannot accidentally
// serialize the request-decryption identity as a public invitation field.
type operatorExchange struct {
	MailboxID                 string
	RequestReadCapability     string
	ResponseWriteCapability   string
	RequestDecryptionIdentity string
}

// newMailboxExchange creates four independent 256-bit action capabilities, a
// non-secret mailbox identifier, and a dedicated age X25519 request recipient.
// The relay eventually sees capabilities used against it; they are abuse
// controls, never authentication roots.
func newMailboxExchange(endpoint string) (targetExchange, operatorExchange, string, error) {
	mailboxID, err := protocol.NewID()
	if err != nil {
		return targetExchange{}, operatorExchange{}, "", fmt.Errorf("enrollmentexchange: generate mailbox ID: %w", err)
	}
	capabilities := make([]string, 4)
	decoded := make([][]byte, 4)
	for index := range capabilities {
		value := make([]byte, mailboxCapabilitySize)
		if _, err := rand.Read(value); err != nil {
			return targetExchange{}, operatorExchange{}, "", fmt.Errorf("enrollmentexchange: generate mailbox capability: %w", err)
		}
		for prior := 0; prior < index; prior++ {
			if bytes.Equal(value, decoded[prior]) {
				return targetExchange{}, operatorExchange{}, "", errors.New("enrollmentexchange: operating-system randomness repeated a mailbox capability")
			}
		}
		decoded[index] = value
		capabilities[index] = base64.RawURLEncoding.EncodeToString(value)
	}
	requestIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return targetExchange{}, operatorExchange{}, "", fmt.Errorf("enrollmentexchange: generate request encryption identity: %w", err)
	}
	target := targetExchange{
		Endpoint: endpoint, MailboxID: mailboxID.String(),
		RequestWriteCapability: capabilities[0], ResponseReadCapability: capabilities[1],
		RequestReadCapabilityCommitment:   mailboxCapabilityCommitment(mailboxID.String(), "request-read", capabilities[2]),
		ResponseWriteCapabilityCommitment: mailboxCapabilityCommitment(mailboxID.String(), "response-write", capabilities[3]),
	}
	if err := target.validate(); err != nil {
		return targetExchange{}, operatorExchange{}, "", err
	}
	operator := operatorExchange{
		MailboxID: mailboxID.String(), RequestReadCapability: capabilities[2],
		ResponseWriteCapability: capabilities[3], RequestDecryptionIdentity: requestIdentity.String(),
	}
	return target, operator, requestIdentity.Recipient().String(), nil
}

// ValidateAgainst binds an offline operator record to the exact target-side
// exchange without exposing the operator capabilities to the invitation.
func (operator operatorExchange) validateAgainst(target targetExchange, requestRecipient string) error {
	if err := target.validate(); err != nil {
		return err
	}
	if operator.MailboxID != target.MailboxID {
		return errors.New("enrollmentexchange: operator and target mailbox IDs differ")
	}
	requestRead, err := parseMailboxCapability(operator.RequestReadCapability)
	if err != nil {
		return err
	}
	responseWrite, err := parseMailboxCapability(operator.ResponseWriteCapability)
	if err != nil {
		return err
	}
	targetWrite, _ := parseMailboxCapability(target.RequestWriteCapability)
	targetRead, _ := parseMailboxCapability(target.ResponseReadCapability)
	values := [][]byte{targetWrite, targetRead, requestRead, responseWrite}
	for first := range values {
		for second := first + 1; second < len(values); second++ {
			if bytes.Equal(values[first], values[second]) {
				return errors.New("enrollmentexchange: mailbox action capabilities are not independent")
			}
		}
	}
	identity, err := age.ParseX25519Identity(operator.RequestDecryptionIdentity)
	if err != nil || identity.String() != operator.RequestDecryptionIdentity || identity.Recipient().String() != requestRecipient {
		return errors.New("enrollmentexchange: operator request identity does not match invitation recipient")
	}
	if mailboxCapabilityCommitment(operator.MailboxID, "request-read", operator.RequestReadCapability) != target.RequestReadCapabilityCommitment ||
		mailboxCapabilityCommitment(operator.MailboxID, "response-write", operator.ResponseWriteCapability) != target.ResponseWriteCapabilityCommitment {
		return errors.New("enrollmentexchange: operator capabilities do not match invitation commitments")
	}
	return nil
}

func mailboxCapabilityCommitment(mailboxID, action, capability string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("OwnTransit mailbox capability commitment v1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(action))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(mailboxID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(capability))
	return hex.EncodeToString(hash.Sum(nil))
}
