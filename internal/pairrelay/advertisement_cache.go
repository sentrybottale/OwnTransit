package pairrelay

import (
	"bytes"
	"encoding/hex"
	"time"
)

// Public publications can replace only the small pending pool. The protected
// pool is selected by durable local policy, never by an advertisement's own
// claims or a relay token presented over the public connection.
func (relay *Relay) advertisementPools() [3]map[routeKey]advertisementRecord {
	return [3]map[routeKey]advertisementRecord{relay.advertisements, relay.retainedAdvertisements, relay.pendingAdvertisements}
}

func (relay *Relay) advertisementLocked(key routeKey) (advertisementRecord, bool) {
	if record, ok := relay.advertisements[key]; ok {
		return record, true
	}
	if record, ok := relay.retainedAdvertisements[key]; ok {
		return record, true
	}
	record, ok := relay.pendingAdvertisements[key]
	return record, ok
}

func (relay *Relay) protectedAdvertisementLocked(key routeKey, record advertisementRecord) bool {
	policy, ok := relay.admissions[key]
	return ok && (policy.Status == "approved" || policy.Status == "observed") &&
		policy.AdmissionRootSHA256 == hex.EncodeToString(record.admissionHash[:])
}

func (relay *Relay) registrationLimit() int {
	return min(relay.limits.Advertisements, MaxAdmissionRecords)
}

func (relay *Relay) protectedAdvertisementCapacityLocked(key routeKey) bool {
	_, exists := relay.advertisements[key]
	_, retained := relay.retainedAdvertisements[key]
	return exists || retained || len(relay.advertisements)+len(relay.retainedAdvertisements) < relay.registrationLimit()
}

func advertisementExpiry(now, signedExpiry time.Time, ttl time.Duration) time.Time {
	expires := now.Add(ttl)
	if signedExpiry.Before(expires) {
		expires = signedExpiry
	}
	return expires
}

// storePendingAdvertisementLocked is called only after all publication checks.
// Eviction chooses the earliest local expiry and never touches approved routes
// or token-delivery state. The pools retain at most one advertisement per key.
func (relay *Relay) storePendingAdvertisementLocked(key routeKey, record advertisementRecord, now time.Time) {
	if _, exists := relay.pendingAdvertisements[key]; !exists && len(relay.pendingAdvertisements) >= relay.limits.PendingAdvertisements {
		var evictKey routeKey
		var earliest time.Time
		for candidate, pending := range relay.pendingAdvertisements {
			if earliest.IsZero() || pending.expires.Before(earliest) {
				evictKey, earliest = candidate, pending.expires
			}
		}
		delete(relay.pendingAdvertisements, evictKey)
	}
	record.expires = advertisementExpiry(now, record.signedExpires, relay.limits.PendingAdvertisementTTL)
	relay.pendingAdvertisements[key] = record
	delete(relay.advertisements, key)
	delete(relay.retainedAdvertisements, key)
}

// cacheAdvertisementLocked shares allocation, immutability and locator checks
// between the plain-advertisement and offer publication APIs.
func (relay *Relay) cacheAdvertisementLocked(key routeKey, record advertisementRecord, now time.Time) error {
	if policy, exists := relay.admissions[key]; exists && policy.AdmissionRootSHA256 != hex.EncodeToString(record.admissionHash[:]) {
		return ErrUnauthorized
	}
	if _, retained := relay.retainedAdvertisements[key]; retained {
		// This copy exists solely for explicit local reapproval. Public input
		// cannot replace it, extend its expiry, restore an offer or a token.
		return ErrUnauthorized
	}
	previous, exists := relay.advertisementLocked(key)
	if exists && (record.hasOffer || previous.hasOffer) {
		if !bytes.Equal(previous.encoded, record.encoded) || previous.admissionHash != record.admissionHash ||
			(record.hasOffer && previous.hasOffer && (previous.offerLocator != record.offerLocator || previous.offerProof != record.offerProof)) {
			return ErrUnavailable
		}
		if previous.hasOffer && !record.hasOffer {
			record.hasOffer, record.offerLocator, record.offerProof = true, previous.offerLocator, previous.offerProof
		}
	}
	if record.hasOffer {
		for _, pool := range relay.advertisementPools() {
			for otherKey, other := range pool {
				if otherKey != key && other.hasOffer && other.offerLocator == record.offerLocator {
					return ErrUnavailable
				}
			}
		}
	}
	if relay.protectedAdvertisementLocked(key, record) {
		if !relay.protectedAdvertisementCapacityLocked(key) {
			return ErrCapacity
		}
		record.expires = advertisementExpiry(now, record.signedExpires, relay.limits.AdvertisementTTL)
		relay.advertisements[key] = record
		delete(relay.pendingAdvertisements, key)
		delete(relay.retainedAdvertisements, key)
	} else {
		relay.storePendingAdvertisementLocked(key, record, now)
	}
	return nil
}

// Promotion follows successful durable approval or authenticated observation.
// Callers check protected capacity before changing the saved policy.
func (relay *Relay) promoteAdvertisementLocked(key routeKey, now time.Time) {
	record, ok := relay.pendingAdvertisements[key]
	if !ok {
		record, ok = relay.retainedAdvertisements[key]
	}
	if !ok || !relay.protectedAdvertisementLocked(key, record) {
		return
	}
	record.expires = advertisementExpiry(now, record.signedExpires, relay.limits.AdvertisementTTL)
	relay.advertisements[key] = record
	delete(relay.pendingAdvertisements, key)
	delete(relay.retainedAdvertisements, key)
}
