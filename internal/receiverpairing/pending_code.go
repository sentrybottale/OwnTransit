//go:build darwin || linux

package receiverpairing

import (
	"errors"
	"os"
	"time"
)

const pendingCodeFile = "private-pairing-code.v1"

var ErrPendingCodeUnavailable = errors.New("receiverpairing: no recoverable live pending code")

// RetainPendingCode stores only an exact current attempt in the private local
// authority directory. This is never included in a worker snapshot or RPC.
// It changes no pairing identity, validity, claim or on-wire format.
func (receiver *Receiver) RetainPendingCode(code []byte, now time.Time) error {
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	if _, err := pendingCodeAttempt(state, code, now); err != nil {
		return err
	}
	return root.EnsureFile(pendingCodeFile, code, 0600)
}

// PendingCode reveals the same unspent code only to the authority owner. A
// missing old-version cache, expired attempt, alarm, claim or mismatched file
// cannot regenerate identity or resurrect pairing authority.
func (receiver *Receiver) PendingCode(now time.Time) (Attempt, error) {
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return Attempt{}, err
	}
	defer root.Close()
	defer lock.Close()
	if state.LocalLocked || state.Peer != nil || state.Attempt == nil || now.IsZero() || !now.Before(time.Unix(state.Attempt.ExpiresUnix, 0)) {
		return Attempt{}, ErrPendingCodeUnavailable
	}
	code, err := root.ReadPrivateFile(pendingCodeFile, MaxCodeSize)
	defer clear(code)
	if errors.Is(err, os.ErrNotExist) {
		return Attempt{}, ErrPendingCodeUnavailable
	}
	if err != nil {
		return Attempt{}, err
	}
	attempt, err := pendingCodeAttempt(state, code, now)
	if err != nil {
		return Attempt{}, err
	}
	attempt.Code = append([]byte(nil), code...)
	return attempt, nil
}

func pendingCodeAttempt(state stateRecord, code []byte, now time.Time) (Attempt, error) {
	if state.LocalLocked || state.Peer != nil || state.Attempt == nil || now.IsZero() || !now.Before(time.Unix(state.Attempt.ExpiresUnix, 0)) {
		return Attempt{}, ErrPendingCodeUnavailable
	}
	value, err := parseCode(code)
	if err != nil || !constantDigestEqual(digestText(code), state.Attempt.CodeSHA256) || value.ReceiverID != state.ReceiverID || value.AttemptID != state.Attempt.AttemptID || value.ExpiresUnix != state.Attempt.ExpiresUnix || !constantDigestEqual(value.AdvertisementSHA256, state.Attempt.AdvertisementSHA256) {
		return Attempt{}, ErrPendingCodeUnavailable
	}
	ad, err := decodeBase64(state.Attempt.Advertisement)
	if err != nil {
		return Attempt{}, ErrPendingCodeUnavailable
	}
	info, _, err := parseAdvertisement(ad, now.UTC().Truncate(time.Second))
	if err != nil || info.ReceiverID != state.ReceiverID || info.AttemptID != state.Attempt.AttemptID || info.RelayOrigin != state.RelayOrigin || info.ExpiresUnix != value.ExpiresUnix || !constantDigestEqual(digestText(ad), value.AdvertisementSHA256) {
		return Attempt{}, ErrPendingCodeUnavailable
	}
	return Attempt{ReceiverID: state.ReceiverID, AttemptID: state.Attempt.AttemptID, Advertisement: ad, Expires: time.Unix(value.ExpiresUnix, 0).UTC()}, nil
}
