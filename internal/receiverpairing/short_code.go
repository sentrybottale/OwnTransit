//go:build darwin || linux

package receiverpairing

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairoffer"
)

var errShortOffer = errors.New("receiverpairing: private code or receiver offer is invalid")

// CreateShortOffer projects a live legacy attempt into a short private code
// and a public-only offer. The original code and its durable hash remain the
// authority used by Claim; no state or existing pairing format changes.
func CreateShortOffer(attempt Attempt, now time.Time) (shortCode []byte, offer []byte, err error) {
	now = now.UTC().Truncate(time.Second)
	ad, _, err := parseAdvertisement(attempt.Advertisement, now)
	if err != nil {
		return nil, nil, errShortOffer
	}
	code, err := parseCode(attempt.Code)
	if err != nil || code.ReceiverID != ad.ReceiverID || code.AttemptID != ad.AttemptID ||
		code.ExpiresUnix != ad.ExpiresUnix || !constantDigestEqual(code.AdvertisementSHA256, digestText(attempt.Advertisement)) ||
		attempt.ReceiverID != ad.ReceiverID || attempt.AttemptID != ad.AttemptID ||
		!attempt.Expires.Equal(time.Unix(ad.ExpiresUnix, 0)) || !now.Before(time.Unix(code.ExpiresUnix, 0)) {
		return nil, nil, errShortOffer
	}
	decoded, err := base64.RawURLEncoding.DecodeString(code.Secret)
	defer clear(decoded)
	if err != nil || len(decoded) != secretSize {
		return nil, nil, errShortOffer
	}
	var secret [secretSize]byte
	defer clear(secret[:])
	copy(secret[:], decoded)
	shortCode, offer, err = pairoffer.New(secret, attempt.Advertisement)
	if err != nil {
		return nil, nil, errShortOffer
	}
	return shortCode, offer, nil
}

// RecoverLegacyCode authenticates an offer before inspecting or using its
// advertised keys, then reconstructs the exact original private code. Its
// caller must keep that code local and use the unchanged pairing exchange.
func RecoverLegacyCode(shortCode, offer []byte, origin string, now time.Time) ([]byte, error) {
	encoded, err := pairoffer.Verify(shortCode, offer)
	if err != nil {
		return nil, errShortOffer
	}
	now = now.UTC().Truncate(time.Second)
	ad, _, err := parseAdvertisement(encoded, now)
	if err != nil || validateRelayOrigin(origin) != nil || ad.RelayOrigin != origin {
		return nil, errShortOffer
	}
	secret, err := pairoffer.Secret(shortCode)
	defer clear(secret[:])
	if err != nil {
		return nil, errShortOffer
	}
	legacy, err := encodeCode(codePayload{
		Schema: codeSchema, ReceiverID: ad.ReceiverID, AttemptID: ad.AttemptID,
		ExpiresUnix: ad.ExpiresUnix, AdvertisementSHA256: digestText(encoded),
		Secret: base64.RawURLEncoding.EncodeToString(secret[:]),
	})
	if err != nil {
		return nil, errShortOffer
	}
	return legacy, nil
}
