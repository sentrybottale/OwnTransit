// Package leasewire carries SSH DATA and bounded authorization controls inside
// an already mutually authenticated TLS stream. It supplies no peer trust,
// pairing, persistence, relay authorization, or SSH target selection.
package leasewire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// ALPN must be explicitly selected and verified by both inner TLS endpoints.
// This framing must never be enabled on a legacy, unframed SSH stream.
const ALPN = "owntransit-paired-lease/1"

const (
	wireVersion   = 1
	headerSize    = 8
	maxData       = 16 << 10
	challengeSize = 80 // directional context, generation, challenge, requested nanoseconds
	grantSize     = 88 // context, issuer/requester generations, challenge, granted nanoseconds
	lockSize      = 40 // directional context, generation
	kindData      = 1
	kindChallenge = 2
	kindGrant     = 3
	kindLock      = 4
)

var (
	ErrProtocol = errors.New("leasewire: invalid frame or authorization binding")
	ErrExpired  = errors.New("leasewire: peer authorization expired")
	ErrLocked   = errors.New("leasewire: locally locked")
	ErrPeerLock = errors.New("leasewire: peer locked")
	ErrPolicy   = errors.New("leasewire: local authorization policy changed or failed")
	ErrClock    = errors.New("leasewire: elapsed-time continuity lost")
)

// Context is supplied only after exact inner TLS peer authorization. IDs are
// bounded canonical ASCII tokens; SessionBinding must be the 32-byte exporter
// output of this fresh TLS connection, using the runtime's fixed exporter label.
type Context struct {
	PairID, LocalID, PeerID string
	SessionBinding          []byte
}

func (value Context) validate() error {
	if !validID(value.PairID) || !validID(value.LocalID) || !validID(value.PeerID) ||
		value.LocalID == value.PeerID || len(value.SessionBinding) != sha256.Size {
		return ErrProtocol
	}
	return nil
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, ch := range []byte(value) {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
			return false
		}
	}
	return true
}

func contextDigest(value Context, outbound bool) [32]byte {
	sender, recipient := value.LocalID, value.PeerID
	if !outbound {
		sender, recipient = recipient, sender
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("OwnTransit lease context v1\x00"))
	for _, item := range []string{ALPN, value.PairID, sender, recipient} {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(item)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(item))
	}
	_, _ = hash.Write(value.SessionBinding)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type frame struct {
	kind byte
	data []byte
}

func validSize(kind byte, size int) bool {
	switch kind {
	case kindData:
		return size > 0 && size <= maxData
	case kindChallenge:
		return size == challengeSize
	case kindGrant:
		return size == grantSize
	case kindLock:
		return size == lockSize
	default:
		return false
	}
}

func readFrame(reader io.Reader) (frame, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return frame{}, err
	}
	size := int(binary.BigEndian.Uint16(header[6:]))
	if string(header[:4]) != "OTLW" || header[4] != wireVersion || !validSize(header[5], size) {
		return frame{}, ErrProtocol
	}
	value := frame{kind: header[5], data: make([]byte, size)}
	_, err := io.ReadFull(reader, value.data)
	return value, err
}

func writeFrame(writer io.Writer, value frame) error {
	if !validSize(value.kind, len(value.data)) {
		return ErrProtocol
	}
	var header [headerSize]byte
	copy(header[:4], "OTLW")
	header[4], header[5] = wireVersion, value.kind
	binary.BigEndian.PutUint16(header[6:], uint16(len(value.data)))
	for _, buffer := range [][]byte{header[:], value.data} {
		for len(buffer) != 0 {
			n, err := writer.Write(buffer)
			if n < 0 || n > len(buffer) {
				return io.ErrShortWrite
			}
			buffer = buffer[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}
