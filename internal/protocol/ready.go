package protocol

import (
	"errors"
	"io"
)

const (
	// ReadySize is the fixed size of the inner-stream READY marker.
	ReadySize = 8
	// ReadyVersion is the only supported READY marker version.
	ReadyVersion byte = 1
)

var (
	// ErrInvalidReady means the inner stream did not contain the exact READY
	// marker for ReadyVersion.
	ErrInvalidReady = errors.New("owntransit protocol: invalid READY marker")

	// readyMarker is "FGRD", version 1, followed by three fixed zero bytes.
	// It is deliberately distinct from the rendezvous-frame "FGAT" header.
	readyMarker = [ReadySize]byte{'F', 'G', 'R', 'D', ReadyVersion, 0, 0, 0}
)

// WriteReady writes the fixed READY marker. The caller must invoke it only on
// the authenticated inner TLS stream after local SSH has been opened.
func WriteReady(w io.Writer) error {
	return writeFull(w, readyMarker[:])
}

// ReadReady reads and validates exactly one READY marker without reading any
// following SSH bytes. The caller must invoke it only on the authenticated
// inner TLS stream.
func ReadReady(r io.Reader) error {
	var marker [ReadySize]byte
	if _, err := io.ReadFull(r, marker[:]); err != nil {
		return err
	}
	if marker != readyMarker {
		return ErrInvalidReady
	}
	return nil
}
