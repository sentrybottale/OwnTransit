package pairrelay

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

const (
	wireHeaderSize = 12
	wireVersion    = 2

	kindPublishAdvertisement byte = 1
	kindFetchAdvertisement   byte = 2
	kindPairReceiver         byte = 3
	kindPairClient           byte = 4
	kindRuntime              byte = 5
	kindRenewToken           byte = 6
	kindFetchRegistration    byte = 7
	kindFetchServerInfo      byte = 8

	kindOK            byte = 0x80
	kindAdvertisement byte = 0x81
	kindPairRequest   byte = 0x82
	kindPairResponse  byte = 0x83
	kindRenewedToken  byte = 0x84
	kindReady         byte = 0x85
	kindServerInfo    byte = 0x86
	kindFailure       byte = 0xff
)

const maxWirePayload = MaxPairingBytes + MaxAdmissionCABytes + MaxTokenBytes + 128

type wireFrame struct {
	kind byte
	data []byte
}

func readWireFrame(reader io.Reader, maximum int) (wireFrame, error) {
	if reader == nil || maximum < 0 || maximum > maxWirePayload {
		return wireFrame{}, ErrProtocol
	}
	var header [wireHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return wireFrame{}, err
	}
	if string(header[:4]) != "OTR2" || header[4] != wireVersion || header[6] != 0 || header[7] != 0 {
		return wireFrame{}, ErrProtocol
	}
	size := binary.BigEndian.Uint32(header[8:12])
	if uint64(size) > uint64(maximum) {
		return wireFrame{}, ErrProtocol
	}
	frame := wireFrame{kind: header[5], data: make([]byte, int(size))}
	if _, err := io.ReadFull(reader, frame.data); err != nil {
		return wireFrame{}, err
	}
	return frame, nil
}

func writeWireFrame(writer io.Writer, kind byte, payload []byte, maximum int) error {
	if writer == nil || maximum < 0 || maximum > maxWirePayload || len(payload) > maximum {
		return ErrProtocol
	}
	var header [wireHeaderSize]byte
	copy(header[:4], "OTR2")
	header[4], header[5] = wireVersion, kind
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	for _, part := range [][]byte{header[:], payload} {
		for len(part) != 0 {
			written, err := writer.Write(part)
			if written < 0 || written > len(part) {
				return io.ErrShortWrite
			}
			part = part[written:]
			if err != nil {
				return err
			}
			if written == 0 {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}

type runtimePreface struct {
	token       []byte
	admissionCA []byte
	role        Role
	peerID      protocol.ID
}

func encodeRuntimePreface(value runtimePreface) ([]byte, error) {
	if len(value.token) == 0 || len(value.token) > MaxTokenBytes || len(value.admissionCA) == 0 ||
		len(value.admissionCA) > MaxAdmissionCABytes || (value.role != RoleReceiver && value.role != RoleClient) ||
		zeroID(value.peerID) {
		return nil, ErrProtocol
	}
	encoded := make([]byte, 2+len(value.token)+4+len(value.admissionCA)+1+protocol.IDSize)
	offset := 0
	binary.BigEndian.PutUint16(encoded[offset:offset+2], uint16(len(value.token)))
	offset += 2
	copy(encoded[offset:offset+len(value.token)], value.token)
	offset += len(value.token)
	binary.BigEndian.PutUint32(encoded[offset:offset+4], uint32(len(value.admissionCA)))
	offset += 4
	copy(encoded[offset:offset+len(value.admissionCA)], value.admissionCA)
	offset += len(value.admissionCA)
	encoded[offset] = byte(value.role)
	offset++
	copy(encoded[offset:], value.peerID[:])
	return encoded, nil
}

func decodeRuntimePreface(encoded []byte) (runtimePreface, error) {
	if len(encoded) < 2+1+4+1+protocol.IDSize || len(encoded) > MaxTokenBytes+MaxAdmissionCABytes+64 {
		return runtimePreface{}, ErrProtocol
	}
	offset := 0
	tokenSize := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	if tokenSize <= 0 || tokenSize > MaxTokenBytes || tokenSize > len(encoded)-offset {
		return runtimePreface{}, ErrProtocol
	}
	value := runtimePreface{token: append([]byte(nil), encoded[offset:offset+tokenSize]...)}
	offset += tokenSize
	if len(encoded)-offset < 4 {
		return runtimePreface{}, ErrProtocol
	}
	caSize := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if caSize <= 0 || caSize > MaxAdmissionCABytes || caSize > len(encoded)-offset-1-protocol.IDSize {
		return runtimePreface{}, ErrProtocol
	}
	value.admissionCA = append([]byte(nil), encoded[offset:offset+caSize]...)
	offset += caSize
	value.role = Role(encoded[offset])
	offset++
	if len(encoded)-offset != protocol.IDSize || (value.role != RoleReceiver && value.role != RoleClient) {
		return runtimePreface{}, ErrProtocol
	}
	copy(value.peerID[:], encoded[offset:])
	if zeroID(value.peerID) {
		return runtimePreface{}, ErrProtocol
	}
	return value, nil
}

func encodeTokenAndBlob(token, blob []byte, maximum int) ([]byte, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes || len(blob) == 0 || len(blob) > maximum {
		return nil, ErrProtocol
	}
	encoded := make([]byte, 2+len(token)+4+len(blob))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(token)))
	copy(encoded[2:2+len(token)], token)
	offset := 2 + len(token)
	binary.BigEndian.PutUint32(encoded[offset:offset+4], uint32(len(blob)))
	copy(encoded[offset+4:], blob)
	return encoded, nil
}

func decodeTokenAndBlob(encoded []byte, maximum int) ([]byte, []byte, error) {
	if len(encoded) < 2+1+4+1 || len(encoded) > MaxTokenBytes+maximum+6 {
		return nil, nil, ErrProtocol
	}
	tokenSize := int(binary.BigEndian.Uint16(encoded[:2]))
	if tokenSize <= 0 || tokenSize > MaxTokenBytes || len(encoded) < 2+tokenSize+4 {
		return nil, nil, ErrProtocol
	}
	offset := 2 + tokenSize
	blobSize := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if blobSize <= 0 || blobSize > maximum || len(encoded)-offset != blobSize {
		return nil, nil, ErrProtocol
	}
	return append([]byte(nil), encoded[2:2+tokenSize]...), append([]byte(nil), encoded[offset:]...), nil
}

func requireKind(frame wireFrame, kind byte) error {
	if frame.kind == kind {
		return nil
	}
	if frame.kind == kindFailure {
		return ErrUnavailable
	}
	return errors.New("pairrelay: unexpected response")
}
