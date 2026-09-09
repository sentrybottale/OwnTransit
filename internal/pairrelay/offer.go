package pairrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairoffer"
)

// These operations extend OTR2 with an explicitly identified public offer
// profile. Existing kinds, frame version, TLS and WebSocket profiles keep
// their exact meanings. Unsupported peers fail without a fallback operation.
const (
	offerProfile             = "owntransit.receiver-offer.v1\n"
	offerWireVersion         = 1
	maxPublicOfferBytes      = pairoffer.MaxOfferBytes
	maxOfferPublicationBytes = 1 + 2 + 4 + MaxTokenBytes + maxPublicOfferBytes
	offerLocatorBytes        = 1 + sha256.Size
)

func initialOfferPayloadLimit(kind byte) int {
	switch kind {
	case kindCheckOfferSupport:
		return len(offerProfile)
	case kindPublishOffer:
		return maxOfferPublicationBytes
	case kindFetchOffer:
		return offerLocatorBytes
	default:
		return maxWirePayload
	}
}

// CheckOfferSupport checks only transport support for the exact public offer
// profile. A positive result grants no receiver identity or pairing authority.
func (client *PublicClient) CheckOfferSupport(ctx context.Context) error {
	connection, err := client.connect(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindCheckOfferSupport, []byte(offerProfile), len(offerProfile)); err != nil {
		return ErrUnavailable
	}
	frame, err := readWireFrame(connection, len(offerProfile))
	if err != nil || requireKind(frame, kindOfferSupport) != nil || string(frame.data) != offerProfile {
		return ErrUnavailable
	}
	return nil
}

// PublishOffer sends a bounded public advertisement and its opaque MAC proof.
// It never accepts or sends the private pairing code. An optional existing
// token restores only that exact unexpired local-administrator-issued token;
// publication cannot mint or renew relay registration.
func (client *PublicClient) PublishOffer(ctx context.Context, encodedOffer, existingToken []byte) error {
	payload, err := encodeOfferPublication(encodedOffer, existingToken)
	if err != nil {
		return err
	}
	connection, err := client.connect(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindPublishOffer, payload, maxOfferPublicationBytes); err != nil {
		return ErrUnavailable
	}
	frame, err := readWireFrame(connection, 0)
	if err != nil || requireKind(frame, kindOK) != nil {
		return ErrUnavailable
	}
	return nil
}

// FetchOffer returns the public offer for an exact derived locator. The caller
// must authenticate its MAC with the locally retained code before trusting or
// parsing its advertisement as receiver authority.
func (client *PublicClient) FetchOffer(ctx context.Context, locator [32]byte) ([]byte, error) {
	if zeroDigest(locator) {
		return nil, ErrProtocol
	}
	connection, err := client.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	payload := make([]byte, offerLocatorBytes)
	payload[0] = offerWireVersion
	copy(payload[1:], locator[:])
	if err := writeWireFrame(connection, kindFetchOffer, payload, offerLocatorBytes); err != nil {
		return nil, ErrUnavailable
	}
	frame, err := readWireFrame(connection, maxPublicOfferBytes)
	if err != nil || requireKind(frame, kindOffer) != nil {
		return nil, ErrUnavailable
	}
	offer, err := pairoffer.Parse(frame.data)
	if err != nil || offer.Locator != locator {
		return nil, ErrUnavailable
	}
	return frame.data, nil
}

// The publication body is version || u16be(token length) || u32be(offer
// length) || token || offer. Zero token length means advertisement only.
func encodeOfferPublication(encoded, token []byte) ([]byte, error) {
	if len(token) > MaxTokenBytes {
		return nil, ErrProtocol
	}
	if _, err := pairoffer.Parse(encoded); err != nil {
		return nil, ErrProtocol
	}
	payload := make([]byte, 7+len(token)+len(encoded))
	payload[0] = offerWireVersion
	binary.BigEndian.PutUint16(payload[1:3], uint16(len(token)))
	binary.BigEndian.PutUint32(payload[3:7], uint32(len(encoded)))
	copy(payload[7:], token)
	copy(payload[7+len(token):], encoded)
	return payload, nil
}

func decodeOfferPublication(payload []byte) ([]byte, []byte, error) {
	if len(payload) < 8 || len(payload) > maxOfferPublicationBytes || payload[0] != offerWireVersion {
		return nil, nil, ErrProtocol
	}
	tokenSize := int(binary.BigEndian.Uint16(payload[1:3]))
	offerSize := int(binary.BigEndian.Uint32(payload[3:7]))
	if tokenSize > MaxTokenBytes || offerSize <= 0 || offerSize > maxPublicOfferBytes || len(payload)-7 != tokenSize+offerSize {
		return nil, nil, ErrProtocol
	}
	return payload[7+tokenSize:], payload[7 : 7+tokenSize], nil
}

func decodeOfferLocator(payload []byte) ([32]byte, error) {
	var locator [32]byte
	if len(payload) != offerLocatorBytes || payload[0] != offerWireVersion {
		return locator, ErrProtocol
	}
	copy(locator[:], payload[1:])
	if zeroDigest(locator) {
		return [32]byte{}, ErrProtocol
	}
	return locator, nil
}

func (relay *Relay) publishOffer(encoded, token []byte) error {
	offer, err := pairoffer.Parse(encoded)
	if err != nil || zeroDigest(offer.Locator) || len(offer.Advertisement) > relay.limits.AdvertisementBytes || len(token) > MaxTokenBytes {
		return ErrProtocol
	}
	now := relay.now()
	descriptor, err := relay.config.VerifyAdvertisement(append([]byte(nil), offer.Advertisement...), now)
	if err != nil {
		return ErrUnavailable
	}
	_, _, admissionHash, err := parseAdmissionCA(descriptor.AdmissionCAPEM, now)
	if err != nil || zeroID(descriptor.ReceiverID) || zeroRoute(descriptor.RouteID) {
		return ErrUnavailable
	}
	key := routeKey{receiver: descriptor.ReceiverID, route: descriptor.RouteID}
	var restored registrationRecord
	if len(token) != 0 {
		claims, err := VerifyToken(relay.config.TokenKey, token, now)
		if err != nil || claims.ReceiverID != key.receiver || claims.RouteID != key.route || claims.AdmissionRootSHA256 != admissionHash {
			return ErrUnavailable
		}
		restored = registrationRecord{
			token: append([]byte(nil), token...), advertisementSHA256: sha256.Sum256(offer.Advertisement),
			expires: time.Unix(claims.ExpiresUnix, 0),
		}
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return ErrAlreadyClosed
	}
	relay.expireAdvertisementsLocked(now)
	previous, exists := relay.advertisements[key]
	if exists {
		if !bytes.Equal(previous.encoded, offer.Advertisement) || previous.admissionHash != admissionHash ||
			(previous.hasOffer && (previous.offerLocator != offer.Locator || previous.offerProof != offer.Proof)) {
			return ErrUnavailable
		}
	} else if len(relay.advertisements) >= relay.limits.Advertisements {
		return ErrCapacity
	}
	// This scan is bounded by the existing advertisement limit. It introduces
	// no independently growable map, and prevents cross-route locator reuse.
	for otherKey, record := range relay.advertisements {
		if otherKey != key && record.hasOffer && record.offerLocator == offer.Locator {
			return ErrUnavailable
		}
	}
	if len(token) != 0 {
		if current, ok := relay.registrations[key]; ok {
			if !bytes.Equal(current.token, token) || current.advertisementSHA256 != restored.advertisementSHA256 || !current.expires.Equal(restored.expires) {
				return ErrUnavailable
			}
		} else if len(relay.registrations) >= relay.limits.Advertisements {
			return ErrCapacity
		}
	}
	if !exists {
		previous.encoded = offer.Advertisement
		previous.admissionHash = admissionHash
	}
	previous.hasOffer, previous.offerLocator, previous.offerProof = true, offer.Locator, offer.Proof
	previous.expires = now.Add(relay.limits.AdvertisementTTL)
	relay.advertisements[key] = previous
	if len(token) != 0 {
		relay.registrations[key] = restored
	}
	return nil
}

func (relay *Relay) fetchOffer(locator [32]byte) ([]byte, error) {
	if zeroDigest(locator) {
		return nil, ErrProtocol
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return nil, ErrAlreadyClosed
	}
	relay.expireAdvertisementsLocked(relay.now())
	for _, record := range relay.advertisements {
		if record.hasOffer && record.offerLocator == locator {
			return pairoffer.Encode(pairoffer.Offer{
				Locator: record.offerLocator, Advertisement: record.encoded, Proof: record.offerProof,
			})
		}
	}
	return nil, ErrUnavailable
}
