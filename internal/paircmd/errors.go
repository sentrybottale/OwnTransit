//go:build darwin || linux

package paircmd

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

// Only fixed local categories reach diagnostics. Never print err.Error(): it
// may contain a path, URL, token, certificate or hostile relay response.
func failureMessage(operation string, err error) string {
	if operation == "alarm" || operation == "lock" || operation == "killswitch" {
		return "Alarm shutdown was not confirmed; the pairing may already be locked. Check status. Do not clear its state."
	}
	if operation == "remove" {
		return "Removal did not finish; the local tunnel may already be detached. Retry remove for the same tunnel to confirm service and worker shutdown. Private state is retained."
	}
	switch {
	case errors.Is(err, pairruntime.ErrRemoved):
		return "This tunnel was removed locally. Use explicit restore to reuse retained identities; terminal alarms cannot be restored."
	case errors.Is(err, context.Canceled):
		return "Cancelled. Completed local steps remain in effect; check status before retrying."
	case errors.Is(err, pairruntime.ErrApprovalMissing):
		return "Target approval is missing. On the Relay, choose Continue tunnel for its existing draft, then retry Client setup with the same private code."
	case errors.Is(err, pairruntime.ErrReceiverOffer):
		return "The private code could not authenticate this target and relay URL. Check the URL and current unexpired target code; never disable verification."
	case errors.Is(err, pairruntime.ErrOfferUnavailable):
		return "One-code setup is unavailable. Check the Target service, Relay URL and running Relay version. Upgrade the Relay for otpair2. codes; older two-code Targets require explicit setup --legacy-codes."
	case errors.Is(err, leasewire.ErrLocked), errors.Is(err, leasewire.ErrPeerLock):
		return "Pairing alarmed. This tunnel cannot be unlocked; recovery requires deliberate fresh pairing."
	case errors.Is(err, securefs.ErrLocked):
		return "Another local OwnTransit operation is running. Retry shortly; do not reset pairing state."
	case errors.Is(err, leasewire.ErrExpired), errors.Is(err, leasewire.ErrClock), errors.Is(err, context.DeadlineExceeded):
		if operation == "proxy" {
			return "Connection timed out or authorization freshness was lost. Check connectivity and the clock, then start a new SSH connection."
		}
		return "Operation timed out or authorization freshness was lost. Check connectivity and the clock, then retry the exact command below. Existing pairing is retained."
	case errors.Is(err, pairrelay.ErrTransport):
		return "Relay connection failed. Check the public URL, HTTPS route and network, then retry. Keep the existing pairing."
	case errors.Is(err, pairrelay.ErrUnavailable), errors.Is(err, pairrelay.ErrCapacity):
		return "No target path is available. Check the relay and target services, then retry. Keep the existing pairing."
	case errors.Is(err, pairrelay.ErrUnauthorized), errors.Is(err, pairruntime.ErrPeerAuthorization), errors.Is(err, leasewire.ErrProtocol):
		return "Peer authentication did not complete. Check both services, versions and pairing; never disable verification."
	case errors.Is(err, leasewire.ErrPolicy):
		return "Local authorization could not be verified. Check status and local state permissions; no trust was reset."
	case errors.Is(err, os.ErrNotExist):
		return "Pairing state is missing. Check the selected --state path; for a new installation, run setup."
	case errors.Is(err, io.EOF) && operation != "proxy":
		return "Input ended. Run setup again when the requested values are ready."
	default:
		if operation == "setup" || operation == "init" || operation == "resume" {
			return "Pairing did not complete. Follow the prompt guidance; use resume for a saved client request. Explicit target replacement may already have retired its old pairing."
		}
		if operation == "proxy" {
			return "Tunnel closed or could not start. Check status and both services, then retry SSH. Keep the existing pairing."
		}
		return "Local operation failed. Check the service status and state permissions; no automatic recovery or trust reset was attempted."
	}
}
