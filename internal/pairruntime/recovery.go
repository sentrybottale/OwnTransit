//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"path/filepath"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairoffer"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

// ReceiverCode is local authority-owner recovery, never a worker/relay RPC.
// Old releases without a retained code need explicit fresh receiver setup.
func ReceiverCode(path string, now time.Time) (receiverpairing.Attempt, error) {
	p, err := ReadPolicy(path)
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	if p.Locked {
		return receiverpairing.Attempt{}, receiverpairing.ErrPendingCodeUnavailable
	}
	r, err := receiverpairing.Open(filepath.Join(path, "authority"))
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	attempt, err := r.PendingCode(now)
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	defer clear(attempt.Code)
	code, offer, err := receiverpairing.CreateShortOffer(attempt, now)
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	root, err := securefs.OpenRoot(path)
	if err != nil {
		clear(code)
		return receiverpairing.Attempt{}, err
	}
	defer root.Close()
	retained, err := root.ReadFile("pair-offer.json", pairoffer.MaxOfferBytes)
	if err != nil || !bytes.Equal(retained, offer) {
		clear(code)
		return receiverpairing.Attempt{}, ErrReceiverOffer
	}
	p, err = ReadPolicy(path)
	if err != nil || p.Locked {
		clear(code)
		return receiverpairing.Attempt{}, receiverpairing.ErrPendingCodeUnavailable
	}
	attempt.Code = code
	return attempt, nil
}

// Check opens the same authenticated carrier as Proxy. OpenClient returns only
// after inner mTLS, fresh session authorization and the receiver's fixed SSH
// socket dial. It sends no SSH credentials and makes no SSH-login claim.
func Check(ctx context.Context, path string, dial pairrelay.DialFunc) error {
	connection, release, err := OpenClient(ctx, path, dial)
	if err != nil {
		return err
	}
	defer release()
	_ = connection.Close()
	return nil
}
