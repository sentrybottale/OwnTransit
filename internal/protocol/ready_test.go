package protocol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadyMarkerRoundTripAndNoReadAhead(t *testing.T) {
	var encoded bytes.Buffer
	if err := WriteReady(&encoded); err != nil {
		t.Fatalf("WriteReady: %v", err)
	}
	want := []byte{'F', 'G', 'R', 'D', ReadyVersion, 0, 0, 0}
	if !bytes.Equal(encoded.Bytes(), want) {
		t.Fatalf("READY marker = %x, want %x", encoded.Bytes(), want)
	}

	sshPrefix := []byte("SSH-2.0-OpenSSH_10.0\r\n")
	reader := bytes.NewReader(append(encoded.Bytes(), sshPrefix...))
	if err := ReadReady(reader); err != nil {
		t.Fatalf("ReadReady: %v", err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read remaining bytes: %v", err)
	}
	if !bytes.Equal(remaining, sshPrefix) {
		t.Fatalf("remaining bytes = %q, want %q", remaining, sshPrefix)
	}
}

func TestReadReadyRejectsTruncationAndMutation(t *testing.T) {
	var encoded bytes.Buffer
	if err := WriteReady(&encoded); err != nil {
		t.Fatalf("WriteReady: %v", err)
	}
	marker := encoded.Bytes()
	for length := 0; length < len(marker); length++ {
		if err := ReadReady(bytes.NewReader(marker[:length])); err == nil {
			t.Fatalf("accepted READY truncation at %d bytes", length)
		}
	}
	for index := range marker {
		mutated := append([]byte(nil), marker...)
		mutated[index] ^= 0xff
		if err := ReadReady(bytes.NewReader(mutated)); !errors.Is(err, ErrInvalidReady) {
			t.Fatalf("mutation at %d error = %v, want %v", index, err, ErrInvalidReady)
		}
	}
}

func TestWriteReadyHandlesShortWrites(t *testing.T) {
	writer := &chunkWriter{max: 1}
	if err := WriteReady(writer); err != nil {
		t.Fatalf("WriteReady(chunk writer): %v", err)
	}
	if got := writer.buf.Len(); got != ReadySize {
		t.Fatalf("wrote %d READY bytes, want %d", got, ReadySize)
	}
	if err := WriteReady(zeroWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero writer error = %v, want %v", err, io.ErrShortWrite)
	}
}
