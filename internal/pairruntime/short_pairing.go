//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairoffer"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
)

var (
	ErrOfferUnavailable = errors.New("pairruntime: receiver offer unavailable; check relay version and receiver startup")
	ErrReceiverOffer    = errors.New("pairruntime: private code does not authenticate this receiver offer and relay URL")
	ErrApprovalMissing  = errors.New("pairruntime: receiver is not approved; run its approval command on the selected VPS")
)

// PairClientShort retrieves only public data using a secret-derived locator.
// The full offer MAC, existing signed advertisement, expiry and selected origin
// are authenticated before any secret-bearing request or client state exists.
// The unchanged PairClient exchange then independently verifies the exact ad.
func PairClientShort(ctx context.Context, path, origin string, code []byte, dial pairrelay.DialFunc) error {
	locator, err := pairoffer.Locator(code)
	if err != nil {
		return ErrReceiverOffer
	}
	public, err := pairrelay.NewPublicClient(origin, dial)
	if err != nil {
		return err
	}
	if err := public.CheckOfferSupport(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrOfferUnavailable
	}
	encoded, err := public.FetchOffer(ctx, locator)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrOfferUnavailable
	}
	legacy, err := receiverpairing.RecoverLegacyCode(code, encoded, origin, time.Now())
	defer clear(legacy)
	if err != nil {
		return ErrReceiverOffer
	}
	offer, err := pairoffer.Parse(encoded)
	if err != nil {
		return ErrReceiverOffer
	}
	ad, err := receiverpairing.VerifyAdvertisement(offer.Advertisement, time.Now())
	if err != nil {
		return ErrReceiverOffer
	}
	receiverID, err := protocol.ParseID(ad.ReceiverID)
	if err != nil {
		return ErrReceiverOffer
	}
	routeID, err := protocol.ParseRouteID(ad.RouteID)
	if err != nil {
		return ErrReceiverOffer
	}
	token, err := public.FetchRegistration(ctx, offer.Advertisement)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrApprovalMissing
	}
	info, err := public.FetchServerInfo(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrOfferUnavailable
	}
	if info.LeafSPKISHA256 != ad.Trust.RelayServerSPKI {
		return ErrReceiverOffer
	}
	return PairClient(ctx, path, origin, legacy, pairrelay.Registration{
		ReceiverID: receiverID, RouteID: routeID, Token: token, ServerInfo: info,
	}, dial)
}
