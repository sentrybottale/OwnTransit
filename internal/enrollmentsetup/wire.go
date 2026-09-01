package enrollmentsetup

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

const (
	setupWireVersion byte = 1
	setupHeaderSize       = 12
	MaxFrameSize          = enrollmentexchange.MaxSessionSize
)

var setupMagic = [4]byte{'O', 'T', 'S', 'U'}

// FrameKind identifies one exact private frontend/lifecycle pipe payload.
type FrameKind byte

const (
	FrameInvitation    FrameKind = 1
	FrameReverseWords  FrameKind = 2
	FrameBoundResponse FrameKind = 3
	FrameState         FrameKind = 4
)

// State is the bounded in-memory result returned across the private pipe. Its
// fields stay opaque so generic formatting cannot serialize mailbox caps.
type State struct {
	phase     enrollmentexchange.SessionPhase
	words     [3]string
	action    *enrollmentexchange.TargetMailboxAction
	tombstone *enrollmentexchange.TargetMailboxTombstone
}

func (state State) Phase() enrollmentexchange.SessionPhase { return state.phase }

func (state State) TargetWords() ([3]string, bool) {
	return state.words, state.words != [3]string{}
}

func (state State) MailboxAction() (enrollmentexchange.TargetMailboxAction, bool) {
	if state.action == nil {
		return enrollmentexchange.TargetMailboxAction{}, false
	}
	result := *state.action
	result.EncryptedRequest = append([]byte(nil), state.action.EncryptedRequest...)
	return result, true
}

func (state State) MailboxTombstone() (enrollmentexchange.TargetMailboxTombstone, bool) {
	if state.tombstone == nil {
		return enrollmentexchange.TargetMailboxTombstone{}, false
	}
	return *state.tombstone, true
}

// EncodeFrame creates one exact bounded binary pipe frame.
func EncodeFrame(kind FrameKind, payload []byte) ([]byte, error) {
	if !validFrameKind(kind) || len(payload) > MaxFrameSize {
		return nil, errors.New("enrollmentsetup: invalid frame kind or size")
	}
	encoded := make([]byte, setupHeaderSize+len(payload))
	copy(encoded[:4], setupMagic[:])
	encoded[4], encoded[5] = setupWireVersion, byte(kind)
	binary.BigEndian.PutUint32(encoded[8:12], uint32(len(payload)))
	copy(encoded[setupHeaderSize:], payload)
	return encoded, nil
}

// ReadFrame consumes exactly one frame and rejects trailing bytes.
func ReadFrame(input io.Reader, expected FrameKind, limit int) ([]byte, error) {
	if input == nil || !validFrameKind(expected) || limit < 0 || limit > MaxFrameSize {
		return nil, errors.New("enrollmentsetup: invalid frame reader")
	}
	header := make([]byte, setupHeaderSize)
	if _, err := io.ReadFull(input, header); err != nil {
		return nil, errors.New("enrollmentsetup: incomplete frame")
	}
	if !bytes.Equal(header[:4], setupMagic[:]) || header[4] != setupWireVersion || FrameKind(header[5]) != expected || header[6] != 0 || header[7] != 0 {
		return nil, errors.New("enrollmentsetup: unsupported frame")
	}
	size := int(binary.BigEndian.Uint32(header[8:12]))
	if size < 0 || size > limit {
		return nil, errors.New("enrollmentsetup: frame exceeds its operation bound")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(input, payload); err != nil {
		return nil, errors.New("enrollmentsetup: truncated frame")
	}
	var trailing [1]byte
	if count, err := input.Read(trailing[:]); count != 0 || err == nil {
		return nil, errors.New("enrollmentsetup: trailing frame data")
	} else if !errors.Is(err, io.EOF) {
		return nil, errors.New("enrollmentsetup: inspect frame boundary")
	}
	return payload, nil
}

func EncodeReverseWords(words [3]string) ([]byte, error) {
	payload := make([]byte, 0, 27)
	for _, word := range words {
		if !validWord(word) {
			return nil, errors.New("enrollmentsetup: reverse words are invalid")
		}
		payload = append(payload, byte(len(word)))
		payload = append(payload, word...)
	}
	return EncodeFrame(FrameReverseWords, payload)
}

func DecodeReverseWords(payload []byte) ([3]string, error) {
	var words [3]string
	offset := 0
	for index := range words {
		if offset >= len(payload) {
			return words, errors.New("enrollmentsetup: reverse words are incomplete")
		}
		size := int(payload[offset])
		offset++
		if size < 3 || size > 8 || offset+size > len(payload) {
			return words, errors.New("enrollmentsetup: reverse words are invalid")
		}
		words[index] = string(payload[offset : offset+size])
		if !validWord(words[index]) {
			return [3]string{}, errors.New("enrollmentsetup: reverse words are invalid")
		}
		offset += size
	}
	if offset != len(payload) {
		return [3]string{}, errors.New("enrollmentsetup: reverse words contain trailing data")
	}
	return words, nil
}

func EncodeState(state State) ([]byte, error) {
	if err := validateStateShape(state); err != nil {
		return nil, err
	}
	phase, err := encodePhase(state.phase)
	if err != nil {
		return nil, err
	}
	flags := byte(0)
	payload := []byte{phase, 0, 0, 0}
	if state.words != [3]string{} {
		flags |= 1
		for _, word := range state.words {
			if !validWord(word) {
				return nil, errors.New("enrollmentsetup: state words are invalid")
			}
			payload = append(payload, byte(len(word)))
			payload = append(payload, word...)
		}
	}
	if state.action != nil {
		flags |= 2
		action, err := encodeMailboxAction(*state.action)
		if err != nil {
			return nil, err
		}
		payload = append(payload, action...)
	}
	if state.tombstone != nil {
		flags |= 4
		tombstone, err := encodeMailboxTombstone(*state.tombstone)
		if err != nil {
			return nil, err
		}
		payload = append(payload, tombstone...)
	}
	payload[1] = flags
	return EncodeFrame(FrameState, payload)
}

func DecodeState(payload []byte) (State, error) {
	if len(payload) < 4 || payload[2] != 0 || payload[3] != 0 || payload[1]&^byte(7) != 0 {
		return State{}, errors.New("enrollmentsetup: invalid state payload")
	}
	phase, err := decodePhase(payload[0])
	if err != nil {
		return State{}, err
	}
	state := State{phase: phase}
	offset := 4
	if payload[1]&1 != 0 {
		for index := range state.words {
			if offset >= len(payload) {
				return State{}, errors.New("enrollmentsetup: truncated state words")
			}
			size := int(payload[offset])
			offset++
			if size < 3 || size > 8 || offset+size > len(payload) {
				return State{}, errors.New("enrollmentsetup: invalid state words")
			}
			state.words[index] = string(payload[offset : offset+size])
			if !validWord(state.words[index]) {
				return State{}, errors.New("enrollmentsetup: invalid state words")
			}
			offset += size
		}
	}
	if payload[1]&2 != 0 {
		action, consumed, err := decodeMailboxAction(payload[offset:])
		if err != nil {
			return State{}, err
		}
		state.action = &action
		offset += consumed
	}
	if payload[1]&4 != 0 {
		tombstone, consumed, err := decodeMailboxTombstone(payload[offset:])
		if err != nil {
			return State{}, err
		}
		state.tombstone = &tombstone
		offset += consumed
	}
	if offset != len(payload) {
		return State{}, errors.New("enrollmentsetup: trailing state data")
	}
	if err := validateStateShape(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func validateStateShape(state State) error {
	words := state.words != [3]string{}
	action := state.action != nil
	tombstone := state.tombstone != nil
	valid := false
	switch state.phase {
	case enrollmentexchange.PhasePendingComparison:
		valid = words && action && !tombstone
	case enrollmentexchange.PhaseTranscriptConfirmed:
		valid = !words && action && !tombstone
	case enrollmentexchange.PhaseResponseVerified, enrollmentexchange.PhaseApplied, enrollmentexchange.PhaseCancelled:
		valid = !words && !action && !tombstone
	case enrollmentexchange.PhaseReady:
		valid = !words && !action
	}
	if !valid {
		return errors.New("enrollmentsetup: setup state phase and payload are inconsistent")
	}
	return nil
}

func encodeMailboxAction(action enrollmentexchange.TargetMailboxAction) ([]byte, error) {
	if len(action.Endpoint) == 0 || len(action.Endpoint) > 2048 || len(action.EncryptedRequest) == 0 || len(action.EncryptedRequest) > enrollmentexchange.MaxEncryptedRequestSize {
		return nil, errors.New("enrollmentsetup: mailbox action is invalid")
	}
	id, err := protocol.ParseID(action.MailboxID)
	if err != nil || id == (protocol.ID{}) {
		return nil, errors.New("enrollmentsetup: mailbox identity is invalid")
	}
	writeCap, err := base64.RawURLEncoding.DecodeString(action.RequestWriteCapability)
	if err != nil || len(writeCap) != 32 || base64.RawURLEncoding.EncodeToString(writeCap) != action.RequestWriteCapability {
		return nil, errors.New("enrollmentsetup: request capability is invalid")
	}
	readCap, err := base64.RawURLEncoding.DecodeString(action.ResponseReadCapability)
	if err != nil || len(readCap) != 32 || base64.RawURLEncoding.EncodeToString(readCap) != action.ResponseReadCapability {
		return nil, errors.New("enrollmentsetup: response capability is invalid")
	}
	payload := make([]byte, 2+len(action.Endpoint)+len(id)+len(writeCap)+len(readCap)+4+len(action.EncryptedRequest))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(action.Endpoint)))
	offset := 2
	copy(payload[offset:], action.Endpoint)
	offset += len(action.Endpoint)
	copy(payload[offset:], id[:])
	offset += len(id)
	copy(payload[offset:], writeCap)
	offset += len(writeCap)
	copy(payload[offset:], readCap)
	offset += len(readCap)
	binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(len(action.EncryptedRequest)))
	offset += 4
	copy(payload[offset:], action.EncryptedRequest)
	return payload, nil
}

func decodeMailboxAction(payload []byte) (enrollmentexchange.TargetMailboxAction, int, error) {
	const fixed = 2 + protocol.IDSize + 32 + 32 + 4
	if len(payload) < fixed {
		return enrollmentexchange.TargetMailboxAction{}, 0, errors.New("enrollmentsetup: truncated mailbox action")
	}
	endpointSize := int(binary.BigEndian.Uint16(payload[:2]))
	if endpointSize == 0 || endpointSize > 2048 || len(payload) < fixed+endpointSize {
		return enrollmentexchange.TargetMailboxAction{}, 0, errors.New("enrollmentsetup: mailbox endpoint is invalid")
	}
	offset := 2
	endpoint := string(payload[offset : offset+endpointSize])
	offset += endpointSize
	var id protocol.ID
	copy(id[:], payload[offset:offset+len(id)])
	offset += len(id)
	if id == (protocol.ID{}) {
		return enrollmentexchange.TargetMailboxAction{}, 0, errors.New("enrollmentsetup: mailbox identity is invalid")
	}
	writeCap := base64.RawURLEncoding.EncodeToString(payload[offset : offset+32])
	offset += 32
	readCap := base64.RawURLEncoding.EncodeToString(payload[offset : offset+32])
	offset += 32
	requestSize := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
	offset += 4
	if requestSize <= 0 || requestSize > enrollmentexchange.MaxEncryptedRequestSize || offset+requestSize > len(payload) {
		return enrollmentexchange.TargetMailboxAction{}, 0, errors.New("enrollmentsetup: encrypted request is invalid")
	}
	action := enrollmentexchange.TargetMailboxAction{
		Endpoint: endpoint, MailboxID: id.String(),
		RequestWriteCapability: writeCap, ResponseReadCapability: readCap,
		EncryptedRequest: append([]byte(nil), payload[offset:offset+requestSize]...),
	}
	return action, offset + requestSize, nil
}

func encodeMailboxTombstone(tombstone enrollmentexchange.TargetMailboxTombstone) ([]byte, error) {
	if len(tombstone.Endpoint) == 0 || len(tombstone.Endpoint) > 2048 {
		return nil, errors.New("enrollmentsetup: mailbox tombstone endpoint is invalid")
	}
	id, err := protocol.ParseID(tombstone.MailboxID)
	if err != nil || id == (protocol.ID{}) {
		return nil, errors.New("enrollmentsetup: mailbox tombstone identity is invalid")
	}
	readCap, err := base64.RawURLEncoding.DecodeString(tombstone.ResponseReadCapability)
	if err != nil || len(readCap) != 32 || base64.RawURLEncoding.EncodeToString(readCap) != tombstone.ResponseReadCapability {
		return nil, errors.New("enrollmentsetup: mailbox tombstone capability is invalid")
	}
	payload := make([]byte, 2+len(tombstone.Endpoint)+len(id)+len(readCap))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(tombstone.Endpoint)))
	offset := 2
	copy(payload[offset:], tombstone.Endpoint)
	offset += len(tombstone.Endpoint)
	copy(payload[offset:], id[:])
	offset += len(id)
	copy(payload[offset:], readCap)
	return payload, nil
}

func decodeMailboxTombstone(payload []byte) (enrollmentexchange.TargetMailboxTombstone, int, error) {
	const fixed = 2 + protocol.IDSize + 32
	if len(payload) < fixed {
		return enrollmentexchange.TargetMailboxTombstone{}, 0, errors.New("enrollmentsetup: truncated mailbox tombstone")
	}
	endpointSize := int(binary.BigEndian.Uint16(payload[:2]))
	if endpointSize == 0 || endpointSize > 2048 || len(payload) < fixed+endpointSize {
		return enrollmentexchange.TargetMailboxTombstone{}, 0, errors.New("enrollmentsetup: mailbox tombstone endpoint is invalid")
	}
	offset := 2
	endpoint := string(payload[offset : offset+endpointSize])
	offset += endpointSize
	var id protocol.ID
	copy(id[:], payload[offset:offset+len(id)])
	offset += len(id)
	if id == (protocol.ID{}) {
		return enrollmentexchange.TargetMailboxTombstone{}, 0, errors.New("enrollmentsetup: mailbox tombstone identity is invalid")
	}
	readCap := base64.RawURLEncoding.EncodeToString(payload[offset : offset+32])
	offset += 32
	return enrollmentexchange.TargetMailboxTombstone{
		Endpoint: endpoint, MailboxID: id.String(), ResponseReadCapability: readCap,
	}, offset, nil
}

func encodePhase(phase enrollmentexchange.SessionPhase) (byte, error) {
	switch phase {
	case enrollmentexchange.PhasePendingComparison:
		return 1, nil
	case enrollmentexchange.PhaseTranscriptConfirmed:
		return 2, nil
	case enrollmentexchange.PhaseResponseVerified:
		return 3, nil
	case enrollmentexchange.PhaseApplied:
		return 4, nil
	case enrollmentexchange.PhaseCancelled:
		return 5, nil
	case enrollmentexchange.PhaseReady:
		return 6, nil
	default:
		return 0, errors.New("enrollmentsetup: unsupported setup phase")
	}
}

func decodePhase(value byte) (enrollmentexchange.SessionPhase, error) {
	switch value {
	case 1:
		return enrollmentexchange.PhasePendingComparison, nil
	case 2:
		return enrollmentexchange.PhaseTranscriptConfirmed, nil
	case 3:
		return enrollmentexchange.PhaseResponseVerified, nil
	case 4:
		return enrollmentexchange.PhaseApplied, nil
	case 5:
		return enrollmentexchange.PhaseCancelled, nil
	case 6:
		return enrollmentexchange.PhaseReady, nil
	default:
		return "", errors.New("enrollmentsetup: unknown setup phase")
	}
}

func validFrameKind(kind FrameKind) bool {
	return kind >= FrameInvitation && kind <= FrameState
}

func validWord(word string) bool {
	if len(word) < 3 || len(word) > 8 {
		return false
	}
	for _, value := range []byte(word) {
		if value < 'a' || value > 'z' {
			return false
		}
	}
	return true
}
