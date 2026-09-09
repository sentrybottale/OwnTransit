// Package pairoffer authenticates public receiver advertisements with a
// separately transferred 256-bit, one-use pairing secret. Public offers grant
// no admission or endpoint authority without that secret. No operational key
// is derived from the code.
package pairoffer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	CodePrefix = "otpair2."
	CodeSize   = 56

	MaxAdvertisementBytes = 128 << 10
	MaxOfferBytes         = 192 << 10

	offerSchema    = "owntransit.receiver-offer.v1"
	locatorDomain  = "OwnTransit receiver offer locator v1\x00"
	proofDomain    = "OwnTransit receiver offer proof v1\x00"
	checksumDomain = "OwnTransit receiver short code checksum v1\x00"
)

// ErrInvalid deliberately contains no input or underlying parser error.
var ErrInvalid = errors.New("pairoffer: invalid pairing code or public offer")

// Offer contains only public bytes. Parse establishes syntax, not trust; only
// Verify authenticates Advertisement through the independently obtained code.
type Offer struct {
	Locator       [sha256.Size]byte
	Advertisement []byte
	Proof         [sha256.Size]byte
}

// The v1 encoding is exactly this field order, compact JSON, and one newline.
// Locator is lowercase hex. Advertisement and Proof are unpadded base64url.
type wireOffer struct {
	Schema        string `json:"schema"`
	Locator       string `json:"locator"`
	Advertisement string `json:"advertisement"`
	Proof         string `json:"proof"`
}

// New uses an existing random 32-byte pairing secret. Only encodedOffer may
// be published; code is private and must never be logged or sent to the relay.
func New(secret [sha256.Size]byte, ad []byte) (code []byte, encodedOffer []byte, err error) {
	defer clear(secret[:])
	if len(ad) == 0 || len(ad) > MaxAdvertisementBytes {
		return nil, nil, ErrInvalid
	}
	locator := digest(locatorDomain, secret[:])
	proof := makeProof(secret, ad)
	encoded, err := Encode(Offer{Locator: locator, Advertisement: ad, Proof: proof})
	if err != nil {
		return nil, nil, ErrInvalid
	}
	var payload [sha256.Size + 4]byte
	defer clear(payload[:])
	copy(payload[:sha256.Size], secret[:])
	checksum := digest(checksumDomain, secret[:])
	copy(payload[sha256.Size:], checksum[:4])
	code = make([]byte, CodeSize)
	copy(code, CodePrefix)
	base64.RawURLEncoding.Encode(code[len(CodePrefix):], payload[:])
	return code, encoded, nil
}

// Encode produces the canonical public representation. It checks bounds but
// does not authenticate the offer; the relay never has its private secret.
func Encode(offer Offer) ([]byte, error) {
	if len(offer.Advertisement) == 0 || len(offer.Advertisement) > MaxAdvertisementBytes {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(wireOffer{
		Schema: offerSchema, Locator: hex.EncodeToString(offer.Locator[:]),
		Advertisement: base64.RawURLEncoding.EncodeToString(offer.Advertisement),
		Proof:         base64.RawURLEncoding.EncodeToString(offer.Proof[:]),
	})
	if err != nil || len(encoded)+1 > MaxOfferBytes {
		return nil, ErrInvalid
	}
	return append(encoded, '\n'), nil
}

// Parse strictly decodes a bounded public offer without authenticating it.
func Parse(encoded []byte) (Offer, error) {
	if len(encoded) == 0 || len(encoded) > MaxOfferBytes {
		return Offer{}, ErrInvalid
	}
	var wire wireOffer
	if strictjson.Decode(encoded, &wire) != nil || wire.Schema != offerSchema {
		return Offer{}, ErrInvalid
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(append(canonical, '\n'), encoded) ||
		len(wire.Locator) != sha256.Size*2 || len(wire.Proof) != base64.RawURLEncoding.EncodedLen(sha256.Size) ||
		len(wire.Advertisement) == 0 || len(wire.Advertisement) > base64.RawURLEncoding.EncodedLen(MaxAdvertisementBytes) {
		return Offer{}, ErrInvalid
	}
	locator, err := hex.DecodeString(wire.Locator)
	if err != nil || hex.EncodeToString(locator) != wire.Locator {
		return Offer{}, ErrInvalid
	}
	proof, err := base64.RawURLEncoding.DecodeString(wire.Proof)
	if err != nil || len(proof) != sha256.Size || base64.RawURLEncoding.EncodeToString(proof) != wire.Proof {
		return Offer{}, ErrInvalid
	}
	ad, err := base64.RawURLEncoding.DecodeString(wire.Advertisement)
	if err != nil || len(ad) == 0 || len(ad) > MaxAdvertisementBytes || base64.RawURLEncoding.EncodeToString(ad) != wire.Advertisement {
		return Offer{}, ErrInvalid
	}
	var offer Offer
	copy(offer.Locator[:], locator)
	copy(offer.Proof[:], proof)
	offer.Advertisement = ad
	return offer, nil
}

// ValidateCode checks the exact version, canonical encoding and typo checksum.
// The checksum is not an authority check; Verify remains mandatory.
func ValidateCode(code []byte) error {
	secret, err := Secret(code)
	clear(secret[:])
	return err
}

// Secret explicitly extracts private material for local pairing operations.
// Callers must clear their returned copy after use.
func Secret(code []byte) ([sha256.Size]byte, error) {
	if len(code) != CodeSize || !bytes.HasPrefix(code, []byte(CodePrefix)) {
		return [sha256.Size]byte{}, ErrInvalid
	}
	var payload [sha256.Size + 4]byte
	defer clear(payload[:])
	n, err := base64.RawURLEncoding.Decode(payload[:], code[len(CodePrefix):])
	if err != nil || n != len(payload) {
		return [sha256.Size]byte{}, ErrInvalid
	}
	var canonical [CodeSize - len(CodePrefix)]byte
	defer clear(canonical[:])
	base64.RawURLEncoding.Encode(canonical[:], payload[:])
	checksum := digest(checksumDomain, payload[:sha256.Size])
	if !bytes.Equal(canonical[:], code[len(CodePrefix):]) || subtle.ConstantTimeCompare(checksum[:4], payload[sha256.Size:]) != 1 {
		return [sha256.Size]byte{}, ErrInvalid
	}
	var secret [sha256.Size]byte
	copy(secret[:], payload[:sha256.Size])
	return secret, nil
}

// Locator derives the public lookup value locally. The private code must
// never be substituted for this value in a URL, request, or diagnostic.
func Locator(code []byte) ([sha256.Size]byte, error) {
	secret, err := Secret(code)
	defer clear(secret[:])
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return digest(locatorDomain, secret[:]), nil
}

// Verify returns advertisement bytes only after checking the full MAC and
// exact locator in constant time. Callers must then verify the advertisement's
// existing signed schema, profile, origin and expiry before using its keys.
func Verify(code, encodedOffer []byte) ([]byte, error) {
	secret, err := Secret(code)
	defer clear(secret[:])
	if err != nil {
		return nil, ErrInvalid
	}
	offer, err := Parse(encodedOffer)
	if err != nil {
		return nil, ErrInvalid
	}
	expectedLocator := digest(locatorDomain, secret[:])
	expectedProof := makeProof(secret, offer.Advertisement)
	locatorOK := subtle.ConstantTimeCompare(expectedLocator[:], offer.Locator[:])
	proofOK := subtle.ConstantTimeCompare(expectedProof[:], offer.Proof[:])
	if locatorOK&proofOK != 1 {
		return nil, ErrInvalid
	}
	return offer.Advertisement, nil
}

func digest(domain string, input []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(input)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func makeProof(secret [sha256.Size]byte, ad []byte) [sha256.Size]byte {
	defer clear(secret[:])
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(proofDomain))
	_, _ = mac.Write(ad)
	var proof [sha256.Size]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}
