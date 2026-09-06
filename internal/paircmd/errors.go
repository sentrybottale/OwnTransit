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
)

// Only fixed local categories reach diagnostics. Never print err.Error(): it
// may contain a path, URL, token, certificate or hostile relay response.
func failureMessage(operation string, err error) string {
	if operation == "alarm" || operation == "lock" {
		return "Alarm shutdown was not confirmed; the pairing may already be locked. Check pair status. Do not clear its state."
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "Cancelled. Completed local steps remain in effect; check pair status before retrying."
	case errors.Is(err, leasewire.ErrLocked), errors.Is(err, leasewire.ErrPeerLock):
		return "Pairing alarmed. This tunnel cannot be unlocked; recovery requires deliberate fresh pairing."
	case errors.Is(err, leasewire.ErrExpired), errors.Is(err, leasewire.ErrClock), errors.Is(err, context.DeadlineExceeded):
		return "Connection timed out or authorization freshness was lost. Check connectivity and the clock, then start a new SSH connection."
	case errors.Is(err, pairrelay.ErrTransport):
		return "Relay connection failed. Check the public URL, HTTPS route and network, then retry. Keep the existing pairing."
	case errors.Is(err, pairrelay.ErrUnavailable), errors.Is(err, pairrelay.ErrCapacity):
		return "No receiver path is available. Check the relay and receiver services, then retry. Keep the existing pairing."
	case errors.Is(err, pairrelay.ErrUnauthorized), errors.Is(err, pairruntime.ErrPeerAuthorization), errors.Is(err, leasewire.ErrProtocol):
		return "Peer authentication did not complete. Check both services, versions and pairing; never disable verification."
	case errors.Is(err, leasewire.ErrPolicy):
		return "Local authorization could not be verified. Check pair status and local state permissions; no trust was reset."
	case errors.Is(err, os.ErrNotExist):
		return "Pairing state is missing. Check the selected --state path; for a new installation, run pair setup."
	case errors.Is(err, io.EOF) && operation != "proxy":
		return "Input ended. Run setup again when the requested values are ready."
	default:
		if operation == "setup" || operation == "init" || operation == "resume" {
			return "Pairing did not complete. Follow the prompt guidance; use pair resume for a saved client request. Explicit receiver replacement may already have retired its old pairing."
		}
		if operation == "proxy" {
			return "Tunnel closed or could not start. Check pair status and both services, then retry SSH. Keep the existing pairing."
		}
		return "Local operation failed. Check the service status and state permissions; no automatic recovery or trust reset was attempted."
	}
}
