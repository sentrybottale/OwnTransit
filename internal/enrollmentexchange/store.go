//go:build darwin || linux

package enrollmentexchange

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

const (
	targetSessionFile   = "target-session.json"
	operatorSessionFile = "operator-session.json"
	sessionLockFile     = "exchange.lock"
)

// CreateTargetStore exclusively creates a private 0700 exchange root and one
// 0600 session. The caller chooses a role-scoped installed path; this package
// never guesses or creates a universal state root.
func CreateTargetStore(rootPath string, session *TargetSession) error {
	encoded, err := session.Encode()
	if err != nil {
		return err
	}
	root, err := createOrOpenInterruptedStore(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock(sessionLockFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	return root.EnsureFile(targetSessionFile, encoded, 0o600)
}

// OpenOperatorStore creates the exact initial session or resumes a progressed
// session only when its immutable receipt and encrypted request are identical.
func OpenOperatorStore(rootPath string, operatorReceipt, encryptedRequest []byte, now time.Time) (*OperatorSession, error) {
	candidate, err := NewOperatorSession(operatorReceipt, encryptedRequest, now)
	if err != nil {
		return nil, err
	}
	if err := CreateOperatorStore(rootPath, candidate); err == nil {
		return candidate, nil
	}
	existing, err := LoadOperatorStore(rootPath, now)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(existing.receiptBytes, operatorReceipt) || !bytes.Equal(existing.encryptedRequestBytes, encryptedRequest) {
		return nil, errors.New("enrollmentexchange: existing operator session belongs to another exact exchange")
	}
	return existing, nil
}

func LoadTargetStore(rootPath string, now time.Time) (*TargetSession, error) {
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := root.TryLock(sessionLockFile)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	encoded, err := root.ReadFile(targetSessionFile, MaxSessionSize)
	if err != nil {
		return nil, err
	}
	return ParseTargetSession(encoded, now)
}

// ReplaceTargetStore is a durable generation compare-and-swap. It rejects a
// stale writer and any mutation that skips or repeats a generation.
func ReplaceTargetStore(rootPath string, expectedGeneration uint64, session *TargetSession, now time.Time) error {
	if expectedGeneration == 0 || session == nil || session.Generation() != expectedGeneration+1 {
		return errors.New("enrollmentexchange: target session replacement must advance one expected generation")
	}
	encoded, err := session.Encode()
	if err != nil {
		return err
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock(sessionLockFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	currentBytes, err := root.ReadFile(targetSessionFile, MaxSessionSize)
	if err != nil {
		return err
	}
	current, err := ParseTargetSession(currentBytes, now)
	if err != nil {
		return err
	}
	if current.Generation() != expectedGeneration {
		return fmt.Errorf("enrollmentexchange: stale target session generation %d; current generation is %d", expectedGeneration, current.Generation())
	}
	return root.ReplaceFile(targetSessionFile, encoded, 0o600)
}

// RetireTargetStore destroys one exact applied/READY target session after its
// caller has durably recorded an independently verified READY receipt. This is
// cleanup only: it cannot create, advance, apply, or authorize session state.
// validationTime is the authenticated invitation verification time retained by
// the caller, so an expired enrollment artifact cannot prevent destruction of
// its now-unneeded local capabilities and bound response.
func RetireTargetStore(rootPath string, expectedReadyGeneration uint64, expectedRequestSHA256 string, validationTime time.Time) error {
	if expectedReadyGeneration < 2 || validationTime.IsZero() || len(expectedRequestSHA256) != sha256.Size*2 {
		return errors.New("enrollmentexchange: exact READY session retirement inputs are required")
	}
	decodedDigest, err := hex.DecodeString(expectedRequestSHA256)
	if err != nil || len(decodedDigest) != sha256.Size || hex.EncodeToString(decodedDigest) != expectedRequestSHA256 {
		return errors.New("enrollmentexchange: READY session retirement request digest is invalid")
	}
	root, err := securefs.OpenRoot(rootPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock(sessionLockFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	encoded, err := root.ReadFile(targetSessionFile, MaxSessionSize)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.UnlinkFile(sessionLockFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}
	session, err := ParseTargetSession(encoded, validationTime.UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	generationMatches := session.Phase() == PhaseReady && session.Generation() == expectedReadyGeneration
	if session.Phase() == PhaseApplied && session.Generation() < ^uint64(0) {
		generationMatches = session.Generation()+1 == expectedReadyGeneration
	}
	if !generationMatches || session.RequestSHA256() != expectedRequestSHA256 {
		return errors.New("enrollmentexchange: READY session retirement target is cross-wired")
	}
	if err := root.UnlinkFile(targetSessionFile); err != nil {
		return err
	}
	if err := root.UnlinkFile(sessionLockFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func CreateOperatorStore(rootPath string, session *OperatorSession) error {
	encoded, err := session.Encode()
	if err != nil {
		return err
	}
	root, err := createOrOpenInterruptedStore(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock(sessionLockFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	return root.EnsureFile(operatorSessionFile, encoded, 0o600)
}

// createOrOpenInterruptedStore makes only the initial exact-byte publication
// resumable. An existing root must already satisfy securefs's owner/mode/no-
// symlink policy; EnsureFile then accepts only the identical session bytes.
func createOrOpenInterruptedStore(rootPath string) (*securefs.Root, error) {
	root, err := securefs.CreateRoot(rootPath)
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return securefs.OpenRoot(rootPath)
}

func LoadOperatorStore(rootPath string, now time.Time) (*OperatorSession, error) {
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := root.TryLock(sessionLockFile)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	encoded, err := root.ReadFile(operatorSessionFile, MaxSessionSize)
	if err != nil {
		return nil, err
	}
	return ParseOperatorSession(encoded, now)
}

func ReplaceOperatorStore(rootPath string, expectedGeneration uint64, session *OperatorSession, now time.Time) error {
	if expectedGeneration == 0 || session == nil || session.Generation() != expectedGeneration+1 {
		return errors.New("enrollmentexchange: operator session replacement must advance one expected generation")
	}
	encoded, err := session.Encode()
	if err != nil {
		return err
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock(sessionLockFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	currentBytes, err := root.ReadFile(operatorSessionFile, MaxSessionSize)
	if err != nil {
		return err
	}
	current, err := ParseOperatorSession(currentBytes, now)
	if err != nil {
		return err
	}
	if current.Generation() != expectedGeneration {
		return fmt.Errorf("enrollmentexchange: stale operator session generation %d; current generation is %d", expectedGeneration, current.Generation())
	}
	return root.ReplaceFile(operatorSessionFile, encoded, 0o600)
}
