// Package protocol implements OwnTransit's fixed rendezvous wire format.
package protocol

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"strings"
)

const (
	// IDSize is the binary size of every OwnTransit identifier.
	IDSize = 32
	// EncodedIDSize is the length of a canonical, unpadded base32 identifier.
	EncodedIDSize = 52
)

var (
	// ErrInvalidID means an identifier was not canonical lowercase, unpadded
	// base32 encoding of exactly IDSize bytes.
	ErrInvalidID = errors.New("owntransit protocol: invalid ID")

	base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// ID is the general-purpose, strongly typed representation accepted by
// ParseID and NewID. Protocol frames use the narrower semantic types below.
type ID [IDSize]byte

// RouteID identifies one connector route without carrying a hostname or
// target address.
type RouteID [IDSize]byte

// BootNonce distinguishes one connector process lifetime.
type BootNonce [IDSize]byte

// EpochID identifies one accepted control-connection generation.
type EpochID [IDSize]byte

// SessionID identifies one pending client/data-join pair.
type SessionID [IDSize]byte

// NewID returns a cryptographically random ID.
func NewID() (ID, error) { return randomID[ID]() }

// NewRouteID returns a cryptographically random RouteID.
func NewRouteID() (RouteID, error) { return randomID[RouteID]() }

// NewBootNonce returns a cryptographically random BootNonce.
func NewBootNonce() (BootNonce, error) { return randomID[BootNonce]() }

// NewEpochID returns a cryptographically random EpochID.
func NewEpochID() (EpochID, error) { return randomID[EpochID]() }

// NewSessionID returns a cryptographically random SessionID.
func NewSessionID() (SessionID, error) { return randomID[SessionID]() }

func randomID[T ~[IDSize]byte]() (T, error) {
	var id T
	_, err := io.ReadFull(rand.Reader, id[:])
	return id, err
}

// ParseID parses canonical lowercase, unpadded RFC 4648 base32. It rejects
// aliases such as uppercase text, padding, and nonzero unused trailing bits.
func ParseID(text string) (ID, error) { return parseID[ID](text) }

// ParseRouteID parses a canonical RouteID.
func ParseRouteID(text string) (RouteID, error) { return parseID[RouteID](text) }

// ParseBootNonce parses a canonical BootNonce.
func ParseBootNonce(text string) (BootNonce, error) { return parseID[BootNonce](text) }

// ParseEpochID parses a canonical EpochID.
func ParseEpochID(text string) (EpochID, error) { return parseID[EpochID](text) }

// ParseSessionID parses a canonical SessionID.
func ParseSessionID(text string) (SessionID, error) { return parseID[SessionID](text) }

func parseID[T ~[IDSize]byte](text string) (T, error) {
	var id T
	if len(text) != EncodedIDSize {
		return id, ErrInvalidID
	}
	for i := range text {
		c := text[i]
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return id, ErrInvalidID
		}
	}

	decoded, err := base32NoPadding.DecodeString(strings.ToUpper(text))
	if err != nil || len(decoded) != IDSize {
		return id, ErrInvalidID
	}
	copy(id[:], decoded)

	// Re-encoding rejects alternate encodings with nonzero unused bits.
	if formatID(id[:]) != text {
		var zero T
		return zero, ErrInvalidID
	}
	return id, nil
}

// String returns canonical lowercase, unpadded base32.
func (id ID) String() string { return formatID(id[:]) }

// String returns canonical lowercase, unpadded base32.
func (id RouteID) String() string { return formatID(id[:]) }

// String returns canonical lowercase, unpadded base32.
func (id BootNonce) String() string { return formatID(id[:]) }

// String returns canonical lowercase, unpadded base32.
func (id EpochID) String() string { return formatID(id[:]) }

// String returns canonical lowercase, unpadded base32.
func (id SessionID) String() string { return formatID(id[:]) }

func formatID(id []byte) string {
	return strings.ToLower(base32NoPadding.EncodeToString(id))
}
