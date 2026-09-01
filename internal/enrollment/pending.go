package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/signing"
)

// ValidatePendingMaterial revalidates one exact generated request together
// with every target-only private component before a privileged lifecycle root
// imports it. It does not issue or authorize a response.
func ValidatePendingMaterial(material PendingMaterial, now time.Time) error {
	if len(material.RequestBytes) == 0 || len(material.RequestBytes) > MaxRequestSize ||
		len(material.OuterPrivateKey) == 0 || len(material.OuterPrivateKey) > 16<<10 ||
		len(material.InnerPrivateKey) == 0 || len(material.InnerPrivateKey) > 16<<10 ||
		len(material.ResponseIdentity) == 0 || len(material.ResponseIdentity) > 4<<10 {
		return errors.New("enrollment: pending material is incomplete or exceeds its bounds")
	}
	payload, err := ParseRequest(material.RequestBytes, now)
	if err != nil || payload != material.Payload {
		return errors.New("enrollment: pending material request does not match its retained payload")
	}
	outerRequest, innerRequest, _, err := requestCSRs(payload)
	if err != nil {
		return err
	}
	outerKey, err := signing.ParsePrivate(material.OuterPrivateKey)
	if err != nil || !bytes.Equal(outerKey.Public().(ed25519.PublicKey), outerRequest.PublicKey.(ed25519.PublicKey)) {
		return errors.New("enrollment: pending outer key does not match its request")
	}
	innerKey, err := signing.ParsePrivate(material.InnerPrivateKey)
	if err != nil || innerRequest == nil || !bytes.Equal(innerKey.Public().(ed25519.PublicKey), innerRequest.PublicKey.(ed25519.PublicKey)) ||
		bytes.Equal(outerKey, innerKey) {
		return errors.New("enrollment: pending inner key does not match or is not independent")
	}
	identity, err := age.ParseX25519Identity(material.ResponseIdentity)
	if err != nil || identity.String() != material.ResponseIdentity || identity.Recipient().String() != payload.ResponseRecipient {
		return errors.New("enrollment: pending response identity does not match its request")
	}
	return nil
}
