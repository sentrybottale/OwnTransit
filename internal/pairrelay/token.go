package pairrelay

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

const (
	tokenKeySize  = 32
	tokenBodySize = 8 + 32 + 32 + 32 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 4
	tokenSize     = tokenBodySize + sha256.Size
)

var tokenMagic = [8]byte{'O', 'T', 'R', 'T', 'O', 'K', 2, 0}

// IssueToken creates an initial stateless route token. It is intended for the
// root-owned local command, not a network handler. Token bytes contain no
// endpoint or issuer secret; the HMAC key remains relay-local.
func IssueToken(key []byte, claims TokenClaims, now time.Time) ([]byte, error) {
	if len(key) != tokenKeySize || now.IsZero() || claims.Generation == 0 ||
		claims.IssuedUnix != now.UTC().Truncate(time.Second).Unix() {
		return nil, ErrProtocol
	}
	if err := validateTokenClaims(claims, now, false); err != nil {
		return nil, err
	}
	return sealToken(key, claims)
}

// VerifyToken authenticates a currently valid route token. A token authorizes
// admission to this already-untrusted relay only; it conveys no endpoint trust.
func VerifyToken(key, encoded []byte, now time.Time) (TokenClaims, error) {
	return openToken(key, encoded, now, false)
}

// RenewToken reissues only the exact claims authenticated by an existing
// token. authenticated must have been produced after outer TLS verified the
// role certificate under the token-bound CA. Receiver, route, root, and limits
// cannot be supplied by a renewal request or changed here.
func RenewToken(
	key, previous []byte,
	authenticated AuthenticatedPeer,
	now time.Time,
	validity time.Duration,
) ([]byte, error) {
	if now.IsZero() || validity <= 0 || validity > MaxTokenValidity {
		return nil, ErrProtocol
	}
	claims, err := openToken(key, previous, now, true)
	if err != nil {
		return nil, err
	}
	if !sameAuthenticatedRoute(claims, authenticated) || claims.Generation == math.MaxUint64 {
		return nil, ErrUnauthorized
	}
	claims.Generation++
	claims.IssuedUnix = now.UTC().Truncate(time.Second).Unix()
	claims.ExpiresUnix = now.UTC().Truncate(time.Second).Add(validity).Unix()
	if err := validateTokenClaims(claims, now, false); err != nil {
		return nil, err
	}
	return sealToken(key, claims)
}

func sameAuthenticatedRoute(claims TokenClaims, peer AuthenticatedPeer) bool {
	if peer.Role != RoleReceiver && peer.Role != RoleClient {
		return false
	}
	if zeroID(peer.PeerID) || peer.ReceiverID != claims.ReceiverID || peer.RouteID != claims.RouteID ||
		subtle.ConstantTimeCompare(peer.AdmissionRootSHA256[:], claims.AdmissionRootSHA256[:]) != 1 {
		return false
	}
	return peer.Role != RoleReceiver || peer.PeerID == claims.ReceiverID
}

func sealToken(key []byte, claims TokenClaims) ([]byte, error) {
	body := make([]byte, tokenBodySize)
	copy(body[:8], tokenMagic[:])
	offset := 8
	for _, value := range [][]byte{claims.ReceiverID[:], claims.RouteID[:], claims.AdmissionRootSHA256[:]} {
		copy(body[offset:offset+len(value)], value)
		offset += len(value)
	}
	for _, value := range []uint64{claims.Generation, uint64(claims.IssuedUnix), uint64(claims.ExpiresUnix)} {
		binary.BigEndian.PutUint64(body[offset:offset+8], value)
		offset += 8
	}
	seconds := claims.Limits.SessionLifetime / time.Second
	for _, value := range []uint32{
		uint32(claims.Limits.PendingPairings), uint32(claims.Limits.PendingCarriers),
		uint32(claims.Limits.ActiveCarriers), uint32(claims.Limits.PairingBytes), uint32(seconds),
	} {
		binary.BigEndian.PutUint32(body[offset:offset+4], value)
		offset += 4
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("OwnTransit relay route token v2\x00"))
	_, _ = mac.Write(body)
	return append(body, mac.Sum(nil)...), nil
}

func openToken(key, encoded []byte, now time.Time, renewal bool) (TokenClaims, error) {
	if len(key) != tokenKeySize || len(encoded) != tokenSize || len(encoded) > MaxTokenBytes || now.IsZero() {
		return TokenClaims{}, ErrUnauthorized
	}
	body, supplied := encoded[:tokenBodySize], encoded[tokenBodySize:]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("OwnTransit relay route token v2\x00"))
	_, _ = mac.Write(body)
	if subtle.ConstantTimeCompare(supplied, mac.Sum(nil)) != 1 || subtle.ConstantTimeCompare(body[:8], tokenMagic[:]) != 1 {
		return TokenClaims{}, ErrUnauthorized
	}
	offset := 8
	var claims TokenClaims
	copy(claims.ReceiverID[:], body[offset:offset+32])
	offset += 32
	copy(claims.RouteID[:], body[offset:offset+32])
	offset += 32
	copy(claims.AdmissionRootSHA256[:], body[offset:offset+32])
	offset += 32
	claims.Generation = binary.BigEndian.Uint64(body[offset : offset+8])
	offset += 8
	issued := binary.BigEndian.Uint64(body[offset : offset+8])
	offset += 8
	expires := binary.BigEndian.Uint64(body[offset : offset+8])
	offset += 8
	if issued > math.MaxInt64 || expires > math.MaxInt64 {
		return TokenClaims{}, ErrUnauthorized
	}
	claims.IssuedUnix, claims.ExpiresUnix = int64(issued), int64(expires)
	values := make([]uint32, 5)
	for index := range values {
		values[index] = binary.BigEndian.Uint32(body[offset : offset+4])
		offset += 4
	}
	claims.Limits = RouteLimits{
		PendingPairings: int(values[0]), PendingCarriers: int(values[1]),
		ActiveCarriers: int(values[2]), PairingBytes: int(values[3]),
		SessionLifetime: time.Duration(values[4]) * time.Second,
	}
	if err := validateTokenClaims(claims, now, renewal); err != nil {
		if errors.Is(err, ErrExpired) {
			return TokenClaims{}, err
		}
		return TokenClaims{}, ErrUnauthorized
	}
	return claims, nil
}

func validateTokenClaims(claims TokenClaims, now time.Time, renewal bool) error {
	if zeroID(claims.ReceiverID) || zeroRoute(claims.RouteID) || zeroDigest(claims.AdmissionRootSHA256) ||
		claims.Generation == 0 || claims.IssuedUnix <= 0 || claims.ExpiresUnix <= claims.IssuedUnix ||
		claims.ExpiresUnix-claims.IssuedUnix > int64(MaxTokenValidity/time.Second) ||
		validateRouteLimits(claims.Limits) != nil {
		return ErrProtocol
	}
	instant := now.UTC().Truncate(time.Second)
	issued, expires := time.Unix(claims.IssuedUnix, 0).UTC(), time.Unix(claims.ExpiresUnix, 0).UTC()
	if instant.Before(issued.Add(-5 * time.Minute)) {
		return ErrProtocol
	}
	if !instant.Before(expires) {
		if renewal && instant.Sub(expires) <= MaxExpiredRenewalGrace {
			return nil
		}
		return ErrExpired
	}
	return nil
}

func validateRouteLimits(value RouteLimits) error {
	if value.PendingPairings <= 0 || value.PendingPairings > 64 ||
		value.PendingCarriers <= 0 || value.PendingCarriers > 64 ||
		value.ActiveCarriers <= 0 || value.ActiveCarriers > 64 ||
		value.PairingBytes <= 0 || value.PairingBytes > MaxPairingBytes ||
		value.SessionLifetime <= 0 || value.SessionLifetime > MaxTokenValidity ||
		value.SessionLifetime%time.Second != 0 {
		return ErrProtocol
	}
	return nil
}

func zeroID(value [32]byte) bool {
	var zero [32]byte
	return subtle.ConstantTimeCompare(value[:], zero[:]) == 1
}

func zeroRoute(value [32]byte) bool { return zeroID([32]byte(value)) }

func zeroDigest(value [32]byte) bool { return zeroID(value) }
