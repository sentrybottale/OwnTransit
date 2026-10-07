//go:build darwin || linux

package pairrelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairoffer"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
)

type signedPublication struct {
	advertisement []byte
	offer         []byte
	descriptor    Descriptor
}

func verifyCacheAdvertisement(encoded []byte, now time.Time) (Descriptor, error) {
	info, err := receiverpairing.VerifyAdvertisement(encoded, now)
	if err != nil {
		return Descriptor{}, err
	}
	receiver, receiverErr := protocol.ParseID(info.ReceiverID)
	route, routeErr := protocol.ParseRouteID(info.RouteID)
	if receiverErr != nil || routeErr != nil {
		return Descriptor{}, ErrProtocol
	}
	return Descriptor{ReceiverID: receiver, RouteID: route, AdmissionCAPEM: []byte(info.Trust.OuterEndpointCAPEM), Expires: info.Expires}, nil
}

// These are genuine self-signed receiver advertisements and offers, generated
// through the public authority API. Private material stays in test-owned roots
// and the private one-use codes are discarded before publication.
func signedCachePublications(t *testing.T, f relayFixture, count int) []signedPublication {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	result := make([]signedPublication, count)
	for index := range result {
		path := filepath.Join(root, fmt.Sprintf("receiver-%03d", index))
		_, err := receiverpairing.Initialize(receiverpairing.InitializeOptions{
			RootPath: path, RelayOrigin: "wss://relay.example/connects", RelayServerSPKI: f.relayInfo.LeafSPKISHA256, Now: f.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := receiverpairing.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		attempt, err := receiver.CreateAttempt(f.now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		code, offer, err := receiverpairing.CreateShortOffer(attempt, f.now)
		clear(attempt.Code)
		clear(code)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := verifyCacheAdvertisement(attempt.Advertisement, f.now)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = signedPublication{attempt.Advertisement, offer, descriptor}
	}
	return result
}

func TestTokenlessPublicationSaturationPreservesApprovedRoutesAndRestartRestore(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	publications := signedCachePublications(t, f, defaultLimits().Advertisements+2)
	for _, mode := range []string{"advertisement", "offer"} {
		t.Run(mode, func(t *testing.T) {
			config := f.relay.config
			config.VerifyAdvertisement = verifyCacheAdvertisement
			relay, err := NewRelay(config)
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			public, err := NewPublicClient("wss://relay.example/connects", inMemoryDialer(relay))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			publish := func(client *PublicClient, publication signedPublication) {
				t.Helper()
				var err error
				if mode == "advertisement" {
					err = client.PublishAdvertisement(ctx, publication.advertisement)
				} else {
					err = client.PublishOffer(ctx, publication.offer, nil)
				}
				if err != nil {
					t.Fatal("tokenless publication failed", err)
				}
			}
			approved := publications[0]
			// Fill the former 256-slot shared cache before any legitimate
			// Target appears. Its next publication must still be accepted.
			for _, attacker := range publications[1 : len(publications)-1] {
				publish(public, attacker)
			}
			publish(public, approved)
			registration, err := relay.RegisterReceiver(approved.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			// Repeat the flood after approval to check isolation of the exact
			// approved route while a second legitimate Target is introduced.
			for _, attacker := range publications[1 : len(publications)-1] {
				publish(public, attacker)
			}
			fresh := publications[len(publications)-1]
			publish(public, fresh)
			if len(relay.advertisements) != 1 || len(relay.pendingAdvertisements) != relay.limits.PendingAdvertisements || len(relay.registrations) != 1 {
				t.Fatal("tokenless flood changed protected capacity or exceeded pending bound")
			}
			got, err := public.FetchAdvertisement(ctx, registration.Token)
			if err != nil || !bytes.Equal(got, approved.advertisement) {
				t.Fatal("tokenless flood displaced approved route", err)
			}
			if _, err := relay.RegisterReceiver(fresh.descriptor.ReceiverID, offerRouteLimits(), time.Hour); err != nil {
				t.Fatal("flood blocked a new explicit local approval", err)
			}
			if len(relay.advertisements) != 2 || len(relay.pendingAdvertisements) != relay.limits.PendingAdvertisements-1 {
				t.Fatal("approval did not promote exactly one pending advertisement")
			}
			config.Admissions = relay.admissionRecordsLocked()
			restarted, err := NewRelay(config)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			restartedPublic, err := NewPublicClient("wss://relay.example/connects", inMemoryDialer(restarted))
			if err != nil {
				t.Fatal(err)
			}
			for _, attacker := range publications[1 : len(publications)-1] {
				publish(restartedPublic, attacker)
			}
			if err := restartedPublic.PublishOffer(ctx, approved.offer, registration.Token); err != nil {
				t.Fatal("saturated pending pool blocked approved restart restoration", err)
			}
			got, err = restartedPublic.FetchRegistration(ctx, approved.advertisement)
			if err != nil || !bytes.Equal(got, registration.Token) {
				t.Fatal("restart restoration changed exact administrator-issued token", err)
			}
			if len(restarted.advertisements) != 1 || len(restarted.pendingAdvertisements) != restarted.limits.PendingAdvertisements || len(restarted.registrations) != 1 {
				t.Fatal("restart restore shared capacity with tokenless publications")
			}
		})
	}
}

func TestAdvertisementPromotionRequiresDurableApprovalAndUnambiguousReceiver(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	_, encodedOffer := publicOfferFixture(t, f.advertisement)
	if err := f.relay.publishOffer(encodedOffer, nil); err != nil {
		t.Fatal(err)
	}
	f.relay.config.SaveAdmissions = func([]AdmissionRecord) error { return errors.New("disk unavailable") }
	if _, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed save acknowledged approval", err)
	}
	if len(f.relay.advertisements) != 0 || len(f.relay.pendingAdvertisements) != 1 || len(f.relay.admissions) != 0 || len(f.relay.registrations) != 0 {
		t.Fatal("failed approval gained protected cache or token state")
	}
	f.relay.config.SaveAdmissions = nil
	if _, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(f.relay.advertisements) != 1 || len(f.relay.pendingAdvertisements) != 0 {
		t.Fatal("durable approval did not promote pending offer")
	}
	otherAd := []byte("ambiguous-public-receiver-advertisement")
	other := f.descriptor
	other.RouteID = mustRouteID(t)
	f.relay.config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		if bytes.Equal(encoded, f.advertisement) {
			return f.descriptor, nil
		}
		if bytes.Equal(encoded, otherAd) {
			return other, nil
		}
		return Descriptor{}, ErrUnauthorized
	}
	if err := f.relay.publishAdvertisement(otherAd); err != nil {
		t.Fatal(err)
	}
	if _, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour); !errors.Is(err, ErrUnavailable) {
		t.Fatal("receiver ambiguity across protected and pending pools was ignored", err)
	}
	if len(f.relay.advertisements) != 1 || len(f.relay.pendingAdvertisements) != 1 || len(f.relay.admissions) != 1 || len(f.relay.registrations) != 1 {
		t.Fatal("ambiguous registration changed policy or cache")
	}
}

func TestApprovedAdvertisementRequiresExactPersistedAdmissionRoot(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	registration := registerInventoryFixture(t, f)
	config := f.relay.config
	config.Admissions = f.relay.admissionRecordsLocked()
	wrongAd := []byte("self-signed-same-locators-different-admission-root")
	wrong := f.descriptor
	wrong.AdmissionCAPEM = f.relayCA.CertPEM
	config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		if bytes.Equal(encoded, f.advertisement) {
			return f.descriptor, nil
		}
		if bytes.Equal(encoded, wrongAd) {
			return wrong, nil
		}
		return Descriptor{}, ErrUnauthorized
	}
	restarted, err := NewRelay(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	_, wrongOffer := publicOfferFixture(t, wrongAd)
	for _, publish := range []func() error{
		func() error { return restarted.publishAdvertisement(wrongAd) },
		func() error { return restarted.publishOffer(wrongOffer, nil) },
	} {
		if err := publish(); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("public locators granted cache entitlement to another admission root", err)
		}
		if len(restarted.advertisements) != 0 || len(restarted.pendingAdvertisements) != 0 || len(restarted.registrations) != 0 {
			t.Fatal("wrong-root publication consumed approved or pending capacity")
		}
	}
	_, exactOffer := publicOfferFixture(t, f.advertisement)
	if err := restarted.publishOffer(exactOffer, registration.Token); err != nil {
		t.Fatal("exact persisted admission could not restore protected cache", err)
	}
	if len(restarted.advertisements) != 1 || len(restarted.pendingAdvertisements) != 0 {
		t.Fatal("persisted approval did not select protected cache")
	}
}

func TestOfferLocatorCollisionFromProtectedPublicationChecksPendingPool(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	otherAd := []byte("protected-public-advertisement")
	other := f.descriptor
	other.ReceiverID, other.RouteID = mustID(t), mustRouteID(t)
	f.relay.config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		if bytes.Equal(encoded, f.advertisement) {
			return f.descriptor, nil
		}
		if bytes.Equal(encoded, otherAd) {
			return other, nil
		}
		return Descriptor{}, ErrUnauthorized
	}
	pendingOffer, pendingEncoded := publicOfferFixture(t, f.advertisement)
	if err := f.relay.publishOffer(pendingEncoded, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.relay.publishAdvertisement(otherAd); err != nil {
		t.Fatal(err)
	}
	if _, err := f.relay.RegisterReceiver(other.ReceiverID, offerRouteLimits(), time.Hour); err != nil {
		t.Fatal(err)
	}
	collision := pairoffer.Offer{Locator: pendingOffer.Locator, Proof: pendingOffer.Proof, Advertisement: otherAd}
	if err := f.relay.publishOffer(encodePublicOffer(t, collision), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("protected publication reused a pending offer locator", err)
	}
	if len(f.relay.advertisements) != 1 || len(f.relay.pendingAdvertisements) != 1 {
		t.Fatal("locator collision moved or evicted cache state")
	}
	got, err := f.relay.fetchOffer(pendingOffer.Locator)
	if err != nil || !bytes.Equal(got, pendingEncoded) {
		t.Fatal("failed collision replaced pending offer", err)
	}
}

func TestAdvertisementSignedExpiryBoundsPendingAndProtectedRefresh(t *testing.T) {
	for _, protected := range []bool{false, true} {
		for _, mode := range []string{"advertisement", "offer"} {
			t.Run(fmt.Sprintf("%s/protected=%t", mode, protected), func(t *testing.T) {
				f := newRelayFixture(t)
				defer f.relay.Close()
				now := f.now
				f.relay.now = func() time.Time { return now }
				f.descriptor.Expires = now.Add(45 * time.Second)
				f.relay.config.VerifyAdvertisement = func([]byte, time.Time) (Descriptor, error) { return f.descriptor, nil }
				offer, encodedOffer := publicOfferFixture(t, f.advertisement)
				publish := func() error {
					if mode == "advertisement" {
						return f.relay.publishAdvertisement(f.advertisement)
					}
					return f.relay.publishOffer(encodedOffer, nil)
				}
				if err := publish(); err != nil {
					t.Fatal(err)
				}
				var registration Registration
				if protected {
					var err error
					registration, err = f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
					if err != nil {
						t.Fatal(err)
					}
				}
				now = now.Add(30 * time.Second)
				if err := publish(); err != nil {
					t.Fatal("unexpired exact publication failed", err)
				}
				key := routeKey{f.descriptor.ReceiverID, f.descriptor.RouteID}
				record, ok := f.relay.advertisementLocked(key)
				if !ok || !record.expires.Equal(f.descriptor.Expires) {
					t.Fatal("publication refresh exceeded signed expiry")
				}
				now = f.descriptor.Expires
				if mode == "offer" {
					if _, err := f.relay.fetchOffer(offer.Locator); !errors.Is(err, ErrUnavailable) {
						t.Fatal("offer survived its signed expiry", err)
					}
				}
				if protected {
					if _, err := f.relay.fetchAdvertisement(registration.Token); !errors.Is(err, ErrUnavailable) {
						t.Fatal("advertisement survived its signed expiry", err)
					}
				}
				if _, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour); !errors.Is(err, ErrUnavailable) {
					t.Fatal("expired cached advertisement remained locally approvable", err)
				}
				if err := publish(); err == nil {
					t.Fatal("expired descriptor was republished")
				}
				f.descriptor.Expires = time.Time{}
				if err := publish(); err == nil {
					t.Fatal("descriptor without authenticated expiry was published")
				}
				if len(f.relay.advertisements) != 0 || len(f.relay.pendingAdvertisements) != 0 {
					t.Fatal("signed expiry left cached advertisement state")
				}
			})
		}
	}
}

func TestRemovedAdvertisementLosesProtectedCapacityAndRequiresFreshApproval(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.PendingAdvertisements = 1
	now := f.now
	f.relay.now = func() time.Time { return now }
	offer, encodedOffer := publicOfferFixture(t, f.advertisement)
	if err := f.relay.publishOffer(encodedOffer, nil); err != nil {
		t.Fatal(err)
	}
	old, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := routeKey{f.descriptor.ReceiverID, f.descriptor.RouteID}
	originalExpiry := f.relay.advertisements[key].expires
	if err := f.relay.RemoveAdmission(f.descriptor.ReceiverID, f.descriptor.RouteID); err != nil {
		t.Fatal(err)
	}
	if len(f.relay.advertisements) != 0 || len(f.relay.retainedAdvertisements) != 1 || len(f.relay.pendingAdvertisements) != 0 || len(f.relay.registrations) != 0 {
		t.Fatal("removed route retained protected cache or registration delivery")
	}
	if err := f.relay.publishOffer(encodedOffer, nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("removed route reappeared through public offer", err)
	}
	if _, err := f.relay.fetchOffer(offer.Locator); !errors.Is(err, ErrUnavailable) {
		t.Fatal("removed local retention exposed its offer", err)
	}
	if err := f.relay.publishAdvertisement(f.advertisement); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("public publication refreshed removed local retention", err)
	}
	otherAd := []byte("evictable-pending-advertisement")
	other := f.descriptor
	other.ReceiverID, other.RouteID = mustID(t), mustRouteID(t)
	f.relay.config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		if bytes.Equal(encoded, f.advertisement) {
			return f.descriptor, nil
		}
		if bytes.Equal(encoded, otherAd) {
			return other, nil
		}
		return Descriptor{}, ErrUnauthorized
	}
	if err := f.relay.publishAdvertisement(otherAd); err != nil {
		t.Fatal(err)
	}
	// The current Target publishes offers only, and removed offers are denied.
	// Pending expiry or flooding must therefore not erase the local approval
	// input before its original signed/managed expiry.
	now = now.Add(3 * time.Minute)
	if err := f.relay.publishAdvertisement(otherAd); err != nil {
		t.Fatal(err)
	}
	if len(f.relay.retainedAdvertisements) != 1 || !f.relay.retainedAdvertisements[key].expires.Equal(originalExpiry) {
		t.Fatal("pending eviction or expiry changed removed local retention")
	}
	fresh, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil || bytes.Equal(old.Token, fresh.Token) {
		t.Fatal("fresh approval failed or reused removed token", err)
	}
	if len(f.relay.advertisements) != 1 || len(f.relay.retainedAdvertisements) != 0 || len(f.relay.pendingAdvertisements) != 1 {
		t.Fatal("reapproval did not regain protected cache")
	}
	if err := f.relay.publishOffer(encodedOffer, old.Token); err == nil {
		t.Fatal("reapproval accepted removed token restoration")
	}
	if err := f.relay.publishOffer(encodedOffer, fresh.Token); err != nil {
		t.Fatal("fresh approved offer could not be published", err)
	}
	if err := f.relay.RemoveAdmission(f.descriptor.ReceiverID, f.descriptor.RouteID); err != nil {
		t.Fatal(err)
	}
	now = f.descriptor.Expires
	if _, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour); !errors.Is(err, ErrUnavailable) {
		t.Fatal("removed local retention survived signed expiry", err)
	}
	if len(f.relay.retainedAdvertisements) != 0 {
		t.Fatal("signed expiry did not discard removed local retention")
	}
}
