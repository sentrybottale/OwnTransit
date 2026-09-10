//go:build darwin || linux

package paircmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
)

var checkClient = pairruntime.Check
var resumeClient = pairruntime.ResumeClient
var discoverReceiverOffer = discoverOffer

// This selects only a protected, locally installed receiver. The relay's public
// ID is a lookup hint, never permission to read a remote secret or reset trust.
func receiverByID(base, id string) (path, name string, err error) {
	if value, e := protocol.ParseID(id); e != nil || value == (protocol.ID{}) {
		return "", "", pairruntime.ErrState
	}
	names, err := localTunnelNames(base)
	if err != nil {
		return "", "", err
	}
	for _, candidate := range names {
		p, _ := tunnelState(base, candidate)
		r, err := receiverpairing.Open(filepath.Join(p, "authority"))
		if err != nil {
			return "", "", err
		}
		s, err := r.Status()
		if err != nil {
			return "", "", err
		}
		if s.ReceiverID == id {
			if path != "" {
				return "", "", pairruntime.ErrState
			}
			path, name = p, candidate
		}
	}
	if path == "" {
		return "", "", os.ErrNotExist
	}
	return path, name, nil
}

func printNext(out io.Writer, receiver bool, executable, path, selectedState, tunnel, origin string) {
	command := func(operation string) string {
		prefix := ""
		if receiver {
			prefix = "sudo "
		}
		return prefix + pairCommand(executable, operation, selectedState, tunnel)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(out, "UNDER CONSTRUCTION — no local pairing saved.\nNEXT on THIS %s:\n  %s", map[bool]string{true: "TARGET COMPUTER", false: "CLIENT COMPUTER"}[receiver], command("setup"))
		if origin != "" {
			fmt.Fprintf(out, " --relay %s", shellQuote(origin))
		}
		fmt.Fprintln(out)
		if !receiver {
			printMissingCodeHelp(out)
		}
		return
	}
	p, err := pairruntime.ReadRetainedPolicy(path)
	if err != nil {
		fmt.Fprintf(out, "Local state could not be verified; it was not reset. Check the selected path and permissions:\n  ls -ld %s\nThen retry:\n  %s\n", shellQuote(path), command("next"))
		return
	}
	status := tunnelStatus(path, receiver)
	if p.Locked || status == "alarmed" || status == "removed (alarmed)" {
		fmt.Fprintln(out, "SECURITY ALARM — this old pairing cannot be restored or unlocked.")
		if status == "removed (alarmed)" {
			printFreshTunnel(out, receiver, executable, origin)
		} else if receiver {
			fmt.Fprintf(out, "Deliberate rebuild on THIS Target (disconnects the old pairing; asks for confirmation when paired):\n  %s --replace\nThen run sudo owntransit-relay setup for its NEW Target ID.\n", command("setup"))
			printFreshRelayDraftHelp(out)
		} else {
			fmt.Fprintln(out, "Keep this alarmed state. Obtain a fresh code from the Target; never reuse the alarmed pair.")
			printFreshTunnel(out, false, executable, origin)
		}
		return
	}
	if removed, err := pairruntime.IsRemoved(path); err != nil {
		fmt.Fprintln(out, "Local removal state is unavailable; inspect its permissions before retrying.")
		return
	} else if removed {
		fmt.Fprintf(out, "Tunnel removed locally; private state is retained. Complete an interrupted removal with:\n  %s\nThen restore deliberately with:\n  %s\n", command("remove"), command("restore"))
		return
	}
	if receiver {
		r, err := receiverpairing.Open(filepath.Join(path, "authority"))
		if err != nil {
			fmt.Fprintf(out, "Target authority is unreadable; do not delete it. Inspect:\n  %s\n", command("status"))
			return
		}
		s, err := r.Status()
		if err != nil {
			fmt.Fprintln(out, "Target authority is unreadable; do not reset it automatically.")
			return
		}
		fmt.Fprintf(out, "Relay URL: %s\nTarget ID: %s\n", s.RelayOrigin, s.ReceiverID)
		if s.PairedClientID == "" {
			fmt.Fprintf(out, "UNDER CONSTRUCTION — waiting for the Client.\nContinue this Target to retrieve the SAME unexpired code and Relay handoff:\n  %s\n", command("continue"))
		} else {
			fmt.Fprintln(out, "Pairing saved. Continue the matching tunnel on the Client to verify end-to-end transport.")
		}
		if selectedState == "" || tunnel != "" {
			fmt.Fprintf(out, "Continue this Target tunnel:\n  %s\n", command("continue"))
		} else {
			fmt.Fprintf(out, "Start this custom-state target:\n  %s\n", command("serve"))
		}
		return
	}
	saved, pending, _, err := pairruntime.ClientSetupSummary(path)
	if err != nil {
		fmt.Fprintf(out, "Client state is unreadable; do not delete it. Inspect:\n  %s\n", command("status"))
		return
	}
	fmt.Fprintf(out, "Relay URL: %s\n", saved)
	if pending {
		fmt.Fprintf(out, "UNDER CONSTRUCTION — the exact client request is saved. No new code is needed.\nNEXT on THIS CLIENT COMPUTER:\n  %s\nKeep the same target ID and pairing; do not regenerate keys for a network failure.\n", command("resume"))
	} else {
		fmt.Fprintf(out, "Pairing saved; end-to-end reachability is not proved by local state.\nNEXT on THIS CLIENT COMPUTER:\n  %s\n", command("check"))
	}
}

func printMissingCodeHelp(out io.Writer) {
	fmt.Fprintln(out, "Get the private code on the Target: run sudo owntransit-target setup and Continue the matching tunnel. Never send the private code to the Relay.")
}

func printFreshTunnel(out io.Writer, receiver bool, executable, origin string) {
	base, err := defaultState(receiver)
	if err != nil {
		return
	}
	for i := 1; i <= maxListedTunnels; i++ {
		name := fmt.Sprintf("recovery-%d", i)
		path, _ := tunnelState(base, name)
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		prefix := ""
		if receiver {
			prefix = "sudo "
		}
		fmt.Fprintf(out, "For a deliberate fresh pairing instead (old state retained), use this unused local name:\n  %s%s", prefix, pairCommand(executable, "new", "", name))
		if origin != "" {
			fmt.Fprintf(out, " --relay %s", shellQuote(origin))
		}
		fmt.Fprintln(out, "\nThis is not a repair or an unlock of the old pairing.")
		if receiver {
			printFreshRelayDraftHelp(out)
		}
		return
	}
	fmt.Fprintln(out, "No unused recovery name is available; inspect local tunnels before choosing a new name.")
}

func showReceiverCode(out, diagnostics io.Writer, executable, path, selectedState, tunnel string, expectedID ...string) error {
	attempt, err := pairruntime.ReceiverCode(path, time.Now())
	if err != nil {
		printCodeFailure(diagnostics, executable, path, selectedState, tunnel, err)
		return err
	}
	defer clear(attempt.Code)
	if len(expectedID) > 0 && expectedID[0] != "" && attempt.ReceiverID != expectedID[0] {
		fmt.Fprintln(diagnostics, "Target identity changed during lookup; no private code was displayed. Run sudo owntransit-target list on this Target and use its current retrieval command.")
		return pairruntime.ErrState
	}
	info, err := receiverpairing.VerifyAdvertisement(attempt.Advertisement, time.Now())
	if err != nil || info.ReceiverID != attempt.ReceiverID {
		printCodeFailure(diagnostics, executable, path, selectedState, tunnel, receiverpairing.ErrPendingCodeUnavailable)
		return receiverpairing.ErrPendingCodeUnavailable
	}
	if err := printReceiverCode(out, attempt.ReceiverID, attempt.Code, false); err != nil {
		return err
	}
	fmt.Fprintf(out, "This is the SAME pending code; valid until %s. Target ID and approval are unchanged.\n", attempt.Expires.UTC().Format(time.RFC3339))
	printReceiverNext(out, info.RelayOrigin, attempt.ReceiverID, tunnel, false)
	return nil
}

func printCodeFailure(diagnostics io.Writer, executable, path, selectedState, tunnel string, err error) {
	if !errors.Is(err, receiverpairing.ErrPendingCodeUnavailable) {
		fmt.Fprintf(diagnostics, "The local code could not be read safely (the target may be busy or local state needs attention). No identities were changed. Retry on THIS Target:\n  sudo %s\nInspect the local state and next commands:\n  sudo %s\n", pairCommand(executable, "code", selectedState, tunnel), pairCommand(executable, "next", selectedState, tunnel))
		return
	}
	fmt.Fprintf(diagnostics, "No recoverable unused code is available for this target. It may have expired, been consumed, or been created by an older release. No identities were changed.\nInspect its current state:\n  sudo %s\n", pairCommand(executable, "next", selectedState, tunnel))
	if tunnelStatus(path, true) == "awaiting-client" {
		fmt.Fprintf(diagnostics, "For a NEW code, explicitly replace this unfinished pairing on THIS Target:\n  sudo %s --replace\nThis creates a NEW Target ID. After replacement, run sudo owntransit-relay setup.\n", pairCommand(executable, "setup", selectedState, tunnel))
		printFreshRelayDraftHelp(diagnostics)
	}
}

func finishClient(ctx context.Context, out, diagnostics io.Writer, executable, path, selectedState, tunnel string) error {
	fmt.Fprintln(diagnostics, "UNDER CONSTRUCTION — checking the actual end-to-end transport...")
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := checkClient(bounded, path, nil); err != nil {
		fmt.Fprintln(diagnostics, "End-to-end transport was NOT verified. Existing pairing state was not reset; do not repeat enrollment or replace keys for an outage.")
		return err
	}
	printConnect(out, "TUNNEL READY — end-to-end transport verified. SSH login still uses your own keys.", executable, selectedState, tunnel)
	return nil
}
