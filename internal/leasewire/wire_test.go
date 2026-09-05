package leasewire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestStrictVersionedFrameBounds(t *testing.T) {
	for _, value := range []frame{{kindData, []byte("SSH")}, {kindChallenge, make([]byte, challengeSize)}, {kindGrant, make([]byte, grantSize)}, {kindLock, make([]byte, lockSize)}} {
		var wire bytes.Buffer
		if err := writeFrame(&wire, value); err != nil {
			t.Fatal(err)
		}
		decoded, err := readFrame(&wire)
		if err != nil || decoded.kind != value.kind || !bytes.Equal(decoded.data, value.data) {
			t.Fatalf("roundtrip: %+v %v", decoded, err)
		}
	}
	for _, name := range []string{"legacy", "version", "type", "oversize", "empty", "control-size"} {
		t.Run(name, func(t *testing.T) {
			header := []byte{'O', 'T', 'L', 'W', wireVersion, kindData, 0, 1}
			switch name {
			case "legacy":
				copy(header[:4], "FGRD")
			case "version":
				header[4]++
			case "type":
				header[5] = 99
			case "oversize":
				binary.BigEndian.PutUint16(header[6:], maxData+1)
			case "empty":
				header[7] = 0
			case "control-size":
				header[5] = kindGrant
			}
			if _, err := readFrame(bytes.NewReader(header)); !errors.Is(err, ErrProtocol) {
				t.Fatalf("invalid header: %v", err)
			}
		})
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{'O', 'T', 'L', 'W', wireVersion, kindData, 0, 1, 0})
	f.Add([]byte("FGRD\x01\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		value, err := readFrame(bytes.NewReader(wire))
		if err == nil && !validSize(value.kind, len(value.data)) {
			t.Fatal("unbounded decoded frame")
		}
	})
}
