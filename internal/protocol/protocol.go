package protocol

import (
	"errors"
	"io"
)

const (
	// HeaderSize is the size of every rendezvous frame header.
	HeaderSize = 8
	// Version is the only supported rendezvous protocol version.
	Version byte = 1

	ControlRegisterSize = HeaderSize + 2*IDSize
	RegisteredSize      = HeaderSize + IDSize
	ClientOpenSize      = HeaderSize + IDSize
	OpenSize            = HeaderSize + 2*IDSize
	DataJoinSize        = HeaderSize + 3*IDSize
	CancelSize          = HeaderSize + 2*IDSize
	PingSize            = HeaderSize
	PongSize            = HeaderSize

	maxFrameSize = DataJoinSize
)

var (
	// ErrInvalidMagic means the frame did not begin with "FGAT".
	ErrInvalidMagic = errors.New("owntransit protocol: invalid magic")
	// ErrUnsupportedVersion means the frame version is not Version.
	ErrUnsupportedVersion = errors.New("owntransit protocol: unsupported version")
	// ErrUnknownType means the frame type byte is not defined by version 1.
	ErrUnknownType = errors.New("owntransit protocol: unknown frame type")
	// ErrNonzeroReserved means one or both reserved header bytes were nonzero.
	ErrNonzeroReserved = errors.New("owntransit protocol: nonzero reserved bytes")
	// ErrUnsupportedFrame means WriteFrame received no supported concrete frame.
	ErrUnsupportedFrame = errors.New("owntransit protocol: unsupported frame")
)

var frameMagic = [4]byte{'F', 'G', 'A', 'T'}

// Type is a version 1 rendezvous frame type.
type Type byte

const (
	TypeControlRegister Type = 0x01
	TypeRegistered      Type = 0x02
	TypeClientOpen      Type = 0x03
	TypeOpen            Type = 0x04
	TypeDataJoin        Type = 0x05
	TypeCancel          Type = 0x06
	TypePing            Type = 0x07
	TypePong            Type = 0x08
)

// Frame is one complete fixed-size version 1 rendezvous frame. The unexported
// method keeps the set closed, so callers cannot introduce variable frames.
type Frame interface {
	Type() Type
	isFrame()
}

type ControlRegister struct {
	Route     RouteID
	BootNonce BootNonce
}

func (ControlRegister) Type() Type { return TypeControlRegister }
func (ControlRegister) isFrame()   {}

type Registered struct {
	Epoch EpochID
}

func (Registered) Type() Type { return TypeRegistered }
func (Registered) isFrame()   {}

type ClientOpen struct {
	Route RouteID
}

func (ClientOpen) Type() Type { return TypeClientOpen }
func (ClientOpen) isFrame()   {}

type Open struct {
	Epoch   EpochID
	Session SessionID
}

func (Open) Type() Type { return TypeOpen }
func (Open) isFrame()   {}

type DataJoin struct {
	Route   RouteID
	Epoch   EpochID
	Session SessionID
}

func (DataJoin) Type() Type { return TypeDataJoin }
func (DataJoin) isFrame()   {}

type Cancel struct {
	Epoch   EpochID
	Session SessionID
}

func (Cancel) Type() Type { return TypeCancel }
func (Cancel) isFrame()   {}

type Ping struct{}

func (Ping) Type() Type { return TypePing }
func (Ping) isFrame()   {}

type Pong struct{}

func (Pong) Type() Type { return TypePong }
func (Pong) isFrame()   {}

// ReadFrame reads exactly one fixed-size frame. It uses io.ReadFull for the
// header and payload and never buffers or reads bytes belonging to a following
// frame or the inner TLS stream.
func ReadFrame(r io.Reader) (Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	frameType, payloadSize, err := parseHeader(header)
	if err != nil {
		return nil, err
	}

	var payload [maxFrameSize - HeaderSize]byte
	if _, err := io.ReadFull(r, payload[:payloadSize]); err != nil {
		return nil, err
	}

	switch frameType {
	case TypeControlRegister:
		var frame ControlRegister
		copy(frame.Route[:], payload[:IDSize])
		copy(frame.BootNonce[:], payload[IDSize:2*IDSize])
		return frame, nil
	case TypeRegistered:
		var frame Registered
		copy(frame.Epoch[:], payload[:IDSize])
		return frame, nil
	case TypeClientOpen:
		var frame ClientOpen
		copy(frame.Route[:], payload[:IDSize])
		return frame, nil
	case TypeOpen:
		var frame Open
		copy(frame.Epoch[:], payload[:IDSize])
		copy(frame.Session[:], payload[IDSize:2*IDSize])
		return frame, nil
	case TypeDataJoin:
		var frame DataJoin
		copy(frame.Route[:], payload[:IDSize])
		copy(frame.Epoch[:], payload[IDSize:2*IDSize])
		copy(frame.Session[:], payload[2*IDSize:3*IDSize])
		return frame, nil
	case TypeCancel:
		var frame Cancel
		copy(frame.Epoch[:], payload[:IDSize])
		copy(frame.Session[:], payload[IDSize:2*IDSize])
		return frame, nil
	case TypePing:
		return Ping{}, nil
	case TypePong:
		return Pong{}, nil
	default:
		// parseHeader makes this unreachable; retain a closed failure mode if a
		// type is added without its decoder.
		return nil, ErrUnknownType
	}
}

func parseHeader(header [HeaderSize]byte) (Type, int, error) {
	if header[0] != frameMagic[0] || header[1] != frameMagic[1] ||
		header[2] != frameMagic[2] || header[3] != frameMagic[3] {
		return 0, 0, ErrInvalidMagic
	}
	if header[4] != Version {
		return 0, 0, ErrUnsupportedVersion
	}
	if header[6] != 0 || header[7] != 0 {
		return 0, 0, ErrNonzeroReserved
	}

	frameType := Type(header[5])
	payloadSize, ok := payloadSize(frameType)
	if !ok {
		return 0, 0, ErrUnknownType
	}
	return frameType, payloadSize, nil
}

func payloadSize(frameType Type) (int, bool) {
	switch frameType {
	case TypeControlRegister:
		return 2 * IDSize, true
	case TypeRegistered, TypeClientOpen:
		return IDSize, true
	case TypeOpen, TypeCancel:
		return 2 * IDSize, true
	case TypeDataJoin:
		return 3 * IDSize, true
	case TypePing, TypePong:
		return 0, true
	default:
		return 0, false
	}
}

// WriteFrame writes exactly one canonical fixed-size frame.
func WriteFrame(w io.Writer, frame Frame) error {
	var encoded [maxFrameSize]byte
	var frameType Type
	var size int

	switch value := frame.(type) {
	case ControlRegister:
		frameType, size = TypeControlRegister, ControlRegisterSize
		copy(encoded[HeaderSize:HeaderSize+IDSize], value.Route[:])
		copy(encoded[HeaderSize+IDSize:size], value.BootNonce[:])
	case *ControlRegister:
		if value == nil {
			return ErrUnsupportedFrame
		}
		return WriteFrame(w, *value)
	case Registered:
		frameType, size = TypeRegistered, RegisteredSize
		copy(encoded[HeaderSize:size], value.Epoch[:])
	case *Registered:
		if value == nil {
			return ErrUnsupportedFrame
		}
		return WriteFrame(w, *value)
	case ClientOpen:
		frameType, size = TypeClientOpen, ClientOpenSize
		copy(encoded[HeaderSize:size], value.Route[:])
	case *ClientOpen:
		if value == nil {
			return ErrUnsupportedFrame
		}
		return WriteFrame(w, *value)
	case Open:
		frameType, size = TypeOpen, OpenSize
		copy(encoded[HeaderSize:HeaderSize+IDSize], value.Epoch[:])
		copy(encoded[HeaderSize+IDSize:size], value.Session[:])
	case *Open:
		if value == nil {
			return ErrUnsupportedFrame
		}
		return WriteFrame(w, *value)
	case DataJoin:
		frameType, size = TypeDataJoin, DataJoinSize
		copy(encoded[HeaderSize:HeaderSize+IDSize], value.Route[:])
		copy(encoded[HeaderSize+IDSize:HeaderSize+2*IDSize], value.Epoch[:])
		copy(encoded[HeaderSize+2*IDSize:size], value.Session[:])
	case *DataJoin:
		if value == nil {
			return ErrUnsupportedFrame
		}
		return WriteFrame(w, *value)
	case Cancel:
		frameType, size = TypeCancel, CancelSize
		copy(encoded[HeaderSize:HeaderSize+IDSize], value.Epoch[:])
		copy(encoded[HeaderSize+IDSize:size], value.Session[:])
	case *Cancel:
		if value == nil {
			return ErrUnsupportedFrame
		}
		return WriteFrame(w, *value)
	case Ping:
		frameType, size = TypePing, PingSize
	case *Ping:
		if value == nil {
			return ErrUnsupportedFrame
		}
		frameType, size = TypePing, PingSize
	case Pong:
		frameType, size = TypePong, PongSize
	case *Pong:
		if value == nil {
			return ErrUnsupportedFrame
		}
		frameType, size = TypePong, PongSize
	default:
		return ErrUnsupportedFrame
	}

	copy(encoded[:4], frameMagic[:])
	encoded[4] = Version
	encoded[5] = byte(frameType)
	// encoded[6:8] remain the canonical zero reserved bytes.
	return writeFull(w, encoded[:size])
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
