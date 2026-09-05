package pairrelay

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestLongOfflineRecoveryDoesNotAdmitExpiredData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issued := now.Add(-90 * 24 * time.Hour)
	key := bytes.Repeat([]byte{0x29}, 32)
	claims := TokenClaims{ReceiverID: mustID(t), RouteID: mustRouteID(t), AdmissionRootSHA256: sha256.Sum256([]byte("public route root fixture")), Generation: 1, IssuedUnix: issued.Unix(), ExpiresUnix: issued.Add(24 * time.Hour).Unix(), Limits: RouteLimits{PendingPairings: 1, PendingCarriers: 1, ActiveCarriers: 1, PairingBytes: MaxPairingBytes, SessionLifetime: time.Hour}}
	token, err := IssueToken(key, claims, issued)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(key, token, now); !errors.Is(err, ErrExpired) {
		t.Fatal("expired token admitted to data")
	}
	if _, err := openToken(key, token, now, true); err != nil {
		t.Fatalf("long-offline recovery denied: %v", err)
	}
	tooLate := time.Unix(claims.ExpiresUnix, 0).Add(MaxExpiredRenewalGrace + time.Second)
	if _, err := openToken(key, token, tooLate, true); !errors.Is(err, ErrExpired) {
		t.Fatal("recovery bound ignored")
	}
	token[20] ^= 1
	if _, err := openToken(key, token, now, true); err == nil {
		t.Fatal("tampering accepted in recovery")
	}
}
