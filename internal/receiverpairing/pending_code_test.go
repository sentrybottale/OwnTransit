//go:build darwin || linux

package receiverpairing

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingCodeRecoveryIsExactPrivateAndReadOnly(t *testing.T) {
	r, path, now := newTestReceiver(t)
	attempt, err := r.CreateAttempt(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(attempt.Code)
	before, err := os.ReadFile(filepath.Join(path, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.PendingCode(now); !errors.Is(err, ErrPendingCodeUnavailable) {
		t.Fatal("legacy state claimed a recoverable code")
	}
	if err := r.RetainPendingCode(attempt.Code, now); err != nil {
		t.Fatal(err)
	}
	if err := r.RetainPendingCode(attempt.Code, now); err != nil {
		t.Fatal("exact retention was not idempotent")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.PendingCode(now.Add(time.Minute))
	defer clear(got.Code)
	if err != nil || !bytes.Equal(got.Code, attempt.Code) || !bytes.Equal(got.Advertisement, attempt.Advertisement) || got.ReceiverID != attempt.ReceiverID || got.AttemptID != attempt.AttemptID || !got.Expires.Equal(attempt.Expires) {
		t.Fatal("recovery changed the pending attempt")
	}
	info, err := os.Stat(filepath.Join(path, pendingCodeFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("code was not private")
	}
	after, err := os.ReadFile(filepath.Join(path, stateFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery mutated authority state")
	}
}

func TestPendingCodeRejectsWrongExpiredCancelledLockedAndConsumed(t *testing.T) {
	for _, action := range []string{"wrong", "expired", "cancelled", "locked", "claimed"} {
		t.Run(action, func(t *testing.T) {
			r, path, now := newTestReceiver(t)
			attempt, err := r.CreateAttempt(now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(attempt.Code)
			if err := r.RetainPendingCode(attempt.Code, now); err != nil {
				t.Fatal(err)
			}
			checkTime := now
			switch action {
			case "wrong":
				other, _, otherNow := newTestReceiver(t)
				otherAttempt, err := other.CreateAttempt(otherNow, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(otherAttempt.Code)
				if err := r.RetainPendingCode(otherAttempt.Code, now); err == nil {
					t.Fatal("foreign code was retained")
				}
				if err := os.WriteFile(filepath.Join(path, pendingCodeFile), otherAttempt.Code, 0600); err != nil {
					t.Fatal(err)
				}
			case "expired":
				checkTime = attempt.Expires
			case "cancelled":
				_, err = r.CancelAttempt()
			case "locked":
				_, err = r.RetireForReplacement("")
			case "claimed":
				request, e := CreateRequest(CreateRequestOptions{Advertisement: attempt.Advertisement, Code: attempt.Code, RelayOrigin: testRelayOrigin, Now: now, Validity: time.Minute})
				if e != nil {
					t.Fatal(e)
				}
				_, err = r.Claim(request.Encrypted, now, func(PeerRequest) ([]byte, error) { return []byte("public fixture authorization"), nil })
			}
			if err != nil {
				t.Fatal(err)
			}
			if action == "cancelled" || action == "locked" || action == "claimed" {
				if _, err := os.Lstat(filepath.Join(path, pendingCodeFile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("retired code file remained")
				}
				// Even a copied-back sidecar cannot resurrect its spent authority.
				if err := os.WriteFile(filepath.Join(path, pendingCodeFile), attempt.Code, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := r.PendingCode(checkTime)
			defer clear(got.Code)
			if err == nil || len(got.Code) != 0 {
				t.Fatal("unusable code was revealed")
			}
		})
	}
}

func TestPendingCodeRejectsUnsafeFilesWithoutExposure(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "permissions", "oversized", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			r, path, now := newTestReceiver(t)
			attempt, err := r.CreateAttempt(now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(attempt.Code)
			if err := r.RetainPendingCode(attempt.Code, now); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, pendingCodeFile)
			switch kind {
			case "symlink":
				if err := os.Rename(file, file+".fixture"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(file+".fixture", file)
			case "hardlink":
				err = os.Link(file, file+".fixture")
			case "permissions":
				err = os.Chmod(file, 0644)
			case "oversized":
				err = os.WriteFile(file, make([]byte, MaxCodeSize+1), 0600)
			case "corrupt":
				err = os.WriteFile(file, []byte("invalid"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.PendingCode(now)
			defer clear(got.Code)
			if err == nil || len(got.Code) != 0 {
				t.Fatal("unsafe code file was revealed")
			}
		})
	}
}
