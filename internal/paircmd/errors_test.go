//go:build darwin || linux

package paircmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
)

func TestFailureMessagesAreActionableAndNeverEchoCauses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.Canceled, "Cancelled"}, {context.DeadlineExceeded, "freshness"},
		{pairrelay.ErrTransport, "Relay connection failed"}, {pairrelay.ErrUnavailable, "No receiver path"},
		{pairrelay.ErrUnauthorized, "Peer authentication"}, {pairruntime.ErrPeerAuthorization, "Peer authentication"},
		{leasewire.ErrLocked, "cannot be unlocked"}, {leasewire.ErrPeerLock, "cannot be unlocked"},
		{leasewire.ErrPolicy, "Local authorization"}, {os.ErrNotExist, "state is missing"},
		{pairruntime.ErrApprovalMissing, "VPS approval command"},
		{pairruntime.ErrReceiverOffer, "private code could not authenticate"},
		{pairruntime.ErrOfferUnavailable, "running relay version"},
	} {
		message := failureMessage("proxy", errors.Join(tc.err, errors.New("private-test-value-never-display")))
		if !strings.Contains(message, tc.want) || strings.Contains(message, "private-test-value") || strings.Contains(message, "otpair1.") {
			t.Fatalf("diagnostic category %q missing or cause leaked", tc.want)
		}
	}
	if !strings.Contains(failureMessage("alarm", context.DeadlineExceeded), "may already be locked") {
		t.Fatal("failed alarm falsely implies unchanged state")
	}
	if strings.Contains(failureMessage("proxy", errors.New("arbitrary-private-value")), "arbitrary") {
		t.Fatal("unknown cause leaked")
	}
}
