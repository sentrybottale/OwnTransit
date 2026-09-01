//go:build darwin || linux

package securefs

import (
	"errors"
	"math"
	"testing"

	"golang.org/x/sys/unix"
)

func TestViewWriterNilReceiverFailsClosed(t *testing.T) {
	var root *ViewWriter
	tests := map[string]func() error{
		"sync":  func() error { return root.Sync() },
		"mkdir": func() error { return root.MkdirExclusive("member") },
		"mkdir private": func() error {
			_, err := root.MkdirPrivateExclusive("member")
			return err
		},
		"open private": func() error {
			_, err := root.OpenPrivateDir("member")
			return err
		},
		"expose": func() error { return root.ExposeDir("member", []string{"file"}) },
		"retire": func() error { return root.RetireDir("member", []string{"file"}) },
		"open": func() error {
			_, err := root.OpenDir("member")
			return err
		},
		"create":  func() error { return root.CreateExclusive("member", []byte("value")) },
		"replace": func() error { return root.ReplaceFile("member", []byte("value")) },
		"read": func() error {
			_, err := root.ReadFile("member", 1)
			return err
		},
		"read recoverable": func() error {
			_, err := root.ReadRecoverableFile("member", 1)
			return err
		},
		"exact":  func() error { return root.ValidateExactFiles([]string{"member"}) },
		"unlink": func() error { return root.UnlinkFile("member") },
	}
	for name, invoke := range tests {
		t.Run(name, func(t *testing.T) {
			if err := invoke(); !errors.Is(err, ErrClosed) {
				t.Fatalf("nil ViewWriter = %v, want ErrClosed", err)
			}
		})
	}
}

func TestViewWriterRejectsUint32SentinelReaderGID(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("root is required to reach the publication reader-GID validation")
	}
	if _, err := validateViewWriterCaller(int(uint64(math.MaxUint32))); err == nil {
		t.Fatal("ViewWriter accepted the uint32 sentinel reader GID")
	}
	if _, err := validateViewWriterCaller(int(uint64(math.MaxUint32) - 1)); err != nil {
		t.Fatalf("ViewWriter rejected the highest non-sentinel reader GID: %v", err)
	}
}
