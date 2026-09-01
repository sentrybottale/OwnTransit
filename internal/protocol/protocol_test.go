package protocol

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func fixtureIDs() (RouteID, BootNonce, EpochID, SessionID) {
	var route RouteID
	var boot BootNonce
	var epoch EpochID
	var session SessionID
	for i := 0; i < IDSize; i++ {
		route[i] = byte(i)
		boot[i] = byte(i + IDSize)
		epoch[i] = byte(0x80 + i)
		session[i] = byte(0xe0 + i)
	}
	return route, boot, epoch, session
}

func frameFixtures() []struct {
	name    string
	frame   Frame
	typeID  Type
	size    int
	payload []byte
} {
	route, boot, epoch, session := fixtureIDs()
	return []struct {
		name    string
		frame   Frame
		typeID  Type
		size    int
		payload []byte
	}{
		{
			name:    "control register",
			frame:   ControlRegister{Route: route, BootNonce: boot},
			typeID:  TypeControlRegister,
			size:    ControlRegisterSize,
			payload: append(append([]byte(nil), route[:]...), boot[:]...),
		},
		{
			name:    "registered",
			frame:   Registered{Epoch: epoch},
			typeID:  TypeRegistered,
			size:    RegisteredSize,
			payload: append([]byte(nil), epoch[:]...),
		},
		{
			name:    "client open",
			frame:   ClientOpen{Route: route},
			typeID:  TypeClientOpen,
			size:    ClientOpenSize,
			payload: append([]byte(nil), route[:]...),
		},
		{
			name:    "open",
			frame:   Open{Epoch: epoch, Session: session},
			typeID:  TypeOpen,
			size:    OpenSize,
			payload: append(append([]byte(nil), epoch[:]...), session[:]...),
		},
		{
			name:   "data join",
			frame:  DataJoin{Route: route, Epoch: epoch, Session: session},
			typeID: TypeDataJoin,
			size:   DataJoinSize,
			payload: append(
				append(append([]byte(nil), route[:]...), epoch[:]...),
				session[:]...,
			),
		},
		{
			name:    "cancel",
			frame:   Cancel{Epoch: epoch, Session: session},
			typeID:  TypeCancel,
			size:    CancelSize,
			payload: append(append([]byte(nil), epoch[:]...), session[:]...),
		},
		{name: "ping", frame: Ping{}, typeID: TypePing, size: PingSize},
		{name: "pong", frame: Pong{}, typeID: TypePong, size: PongSize},
	}
}

func encodeFrame(t testing.TB, frame Frame) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, frame); err != nil {
		t.Fatalf("WriteFrame(%T): %v", frame, err)
	}
	return encoded.Bytes()
}

func TestFrameWireEncodingAndRoundTrip(t *testing.T) {
	for _, test := range frameFixtures() {
		t.Run(test.name, func(t *testing.T) {
			encoded := encodeFrame(t, test.frame)
			if got := len(encoded); got != test.size {
				t.Fatalf("encoded length = %d, want %d", got, test.size)
			}
			wantHeader := []byte{'F', 'G', 'A', 'T', Version, byte(test.typeID), 0, 0}
			if !bytes.Equal(encoded[:HeaderSize], wantHeader) {
				t.Fatalf("header = %x, want %x", encoded[:HeaderSize], wantHeader)
			}
			if !bytes.Equal(encoded[HeaderSize:], test.payload) {
				t.Fatalf("payload = %x, want %x", encoded[HeaderSize:], test.payload)
			}
			if test.frame.Type() != test.typeID {
				t.Fatalf("Type() = %d, want %d", test.frame.Type(), test.typeID)
			}

			got, err := ReadFrame(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if !reflect.DeepEqual(got, test.frame) {
				t.Fatalf("round trip = %#v, want %#v", got, test.frame)
			}
		})
	}
}

func TestReadFrameDoesNotReadAhead(t *testing.T) {
	suffix := []byte{0xde, 0xad, 0xbe, 0xef}
	for _, test := range frameFixtures() {
		t.Run(test.name, func(t *testing.T) {
			encoded := append(encodeFrame(t, test.frame), suffix...)
			reader := bytes.NewReader(encoded)
			if _, err := ReadFrame(reader); err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("read suffix: %v", err)
			}
			if !bytes.Equal(remaining, suffix) {
				t.Fatalf("remaining bytes = %x, want %x", remaining, suffix)
			}
		})
	}
}

func TestReadFrameRejectsEveryTruncation(t *testing.T) {
	for _, test := range frameFixtures() {
		t.Run(test.name, func(t *testing.T) {
			encoded := encodeFrame(t, test.frame)
			for length := 0; length < len(encoded); length++ {
				if _, err := ReadFrame(bytes.NewReader(encoded[:length])); err == nil {
					t.Fatalf("accepted truncation at %d of %d bytes", length, len(encoded))
				}
			}
		})
	}
}

func TestReadFrameRejectsInvalidHeaders(t *testing.T) {
	valid := encodeFrame(t, Ping{})
	tests := []struct {
		name string
		edit func([]byte)
		want error
	}{
		{name: "magic", edit: func(b []byte) { b[0] ^= 0xff }, want: ErrInvalidMagic},
		{name: "version zero", edit: func(b []byte) { b[4] = 0 }, want: ErrUnsupportedVersion},
		{name: "version two", edit: func(b []byte) { b[4] = 2 }, want: ErrUnsupportedVersion},
		{name: "unknown type zero", edit: func(b []byte) { b[5] = 0 }, want: ErrUnknownType},
		{name: "unknown type high", edit: func(b []byte) { b[5] = 0xff }, want: ErrUnknownType},
		{name: "reserved first", edit: func(b []byte) { b[6] = 1 }, want: ErrNonzeroReserved},
		{name: "reserved second", edit: func(b []byte) { b[7] = 1 }, want: ErrNonzeroReserved},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := append([]byte(nil), valid...)
			test.edit(input)
			_, err := ReadFrame(bytes.NewReader(input))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestWriteFrameAcceptsPointersAndRejectsNil(t *testing.T) {
	want := encodeFrame(t, Ping{})
	var got bytes.Buffer
	if err := WriteFrame(&got, &Ping{}); err != nil {
		t.Fatalf("WriteFrame(pointer): %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("pointer encoding = %x, want %x", got.Bytes(), want)
	}

	var nilPing *Ping
	if err := WriteFrame(io.Discard, nilPing); !errors.Is(err, ErrUnsupportedFrame) {
		t.Fatalf("nil pointer error = %v, want %v", err, ErrUnsupportedFrame)
	}
	if err := WriteFrame(io.Discard, nil); !errors.Is(err, ErrUnsupportedFrame) {
		t.Fatalf("nil interface error = %v, want %v", err, ErrUnsupportedFrame)
	}
}

type chunkWriter struct {
	buf bytes.Buffer
	max int
}

func (w *chunkWriter) Write(data []byte) (int, error) {
	if len(data) > w.max {
		data = data[:w.max]
	}
	return w.buf.Write(data)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	want := encodeFrame(t, DataJoin{})
	writer := &chunkWriter{max: 3}
	if err := WriteFrame(writer, DataJoin{}); err != nil {
		t.Fatalf("WriteFrame(chunk writer): %v", err)
	}
	if !bytes.Equal(writer.buf.Bytes(), want) {
		t.Fatalf("short-write result = %x, want %x", writer.buf.Bytes(), want)
	}

	if err := WriteFrame(zeroWriter{}, Ping{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero writer error = %v, want %v", err, io.ErrShortWrite)
	}
}

func FuzzReadFrame(f *testing.F) {
	for _, fixture := range frameFixtures() {
		f.Add(encodeFrame(f, fixture.frame))
	}
	f.Add([]byte(nil))
	f.Add([]byte("FGAT"))

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bytes.NewReader(data)
		frame, err := ReadFrame(reader)
		if err != nil {
			return
		}

		canonical := encodeFrame(t, frame)
		consumed := len(data) - reader.Len()
		if consumed != len(canonical) {
			t.Fatalf("consumed %d bytes for a %d-byte frame", consumed, len(canonical))
		}
		decoded, err := ReadFrame(bytes.NewReader(canonical))
		if err != nil {
			t.Fatalf("canonical frame failed to decode: %v", err)
		}
		if !reflect.DeepEqual(decoded, frame) {
			t.Fatalf("canonical round trip = %#v, want %#v", decoded, frame)
		}
	})
}
