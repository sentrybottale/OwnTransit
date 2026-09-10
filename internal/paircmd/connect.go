//go:build darwin || linux

package paircmd

import (
	"fmt"
	"io"
	"strings"
)

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-", r))
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func pairCommand(executable, operation, state string, tunnel ...string) string {
	command := shellQuote(executable) + " " + operation
	if len(tunnel) > 0 && tunnel[0] != "" {
		command += " --tunnel " + shellQuote(tunnel[0])
	} else if state != "" {
		command += " --state " + shellQuote(state)
	}
	return command
}

// A receiver knows its paired relay origin, not the VPS administrator's local
// instance label. Registration therefore selects that exact URL locally on the
// VPS; it never discovers or switches a tunnel to another relay.
func relayRegistrationCommand(origin, receiverID string) string {
	return "sudo owntransit-relay register --url " + shellQuote(origin) + " " + shellQuote(receiverID)
}

func relayApprovalCommand(origin, receiverID string) string {
	return "sudo owntransit-relay approve --url " + shellQuote(origin) + " " + shellQuote(receiverID)
}

func printReceiverCode(output io.Writer, receiverID string, code []byte, legacy bool) error {
	if legacy {
		_, err := fmt.Fprintf(output, "Target ID (public; give to relay):\n%s\n\nPrivate one-use pairing code (give only to your client):\n%s\n\nKeep this code private. It expires in 24 hours.\n", receiverID, code)
		return err
	}
	// The public ID is shown separately in the Relay menu handoff below.
	_, err := fmt.Fprintf(output, "Private client code (one use; never give to VPS):\n%s\n\n", code)
	return err
}

func printReceiverNext(output io.Writer, origin, receiverID, tunnel string, legacyCodes bool, replaced ...bool) {
	client := pairCommand("owntransit-client", "setup", "", tunnel)
	if legacyCodes {
		fmt.Fprintf(output, "\nNEXT — on your PUBLIC RELAY VPS:\n  %s\nThen on your CLIENT COMPUTER, as your ordinary user without sudo:\n  %s --legacy-codes\nPaste the relay's code and the private pairing code above when asked.\n", relayRegistrationCommand(origin, receiverID), client)
		return
	}
	if len(replaced) > 0 && replaced[0] {
		fmt.Fprintf(output, "UNDER CONSTRUCTION — this replacement has a NEW Target ID.\nNEXT on the Relay for %s:\n  sudo owntransit-relay setup\n", origin)
		printFreshRelayDraftHelp(output)
		fmt.Fprintf(output, "Enter this public Target ID in the new draft:\n  %s\n", receiverID)
	} else {
		printRelayApprovalStep(output, origin, receiverID)
	}
	fmt.Fprintf(output, "Keep the private code for the Client. Retrieve the SAME unused code on this Target:\n  sudo owntransit-target code --target-id %s\n", shellQuote(receiverID))
}

func printFreshRelayDraftHelp(output io.Writer) {
	fmt.Fprintln(output, "On the Relay, choose New tunnel with a new local name, then Continue that new draft.\nA bound draft cannot accept a different Target ID. Removing the old Relay entry is a separate explicit action.")
}

func printRelayApprovalStep(output io.Writer, origin, receiverID string) {
	fmt.Fprintf(output, "UNDER CONSTRUCTION — relay approval and Client pairing remain.\nNEXT on the Relay for %s:\n  sudo owntransit-relay setup\nChoose Continue tunnel, select its draft, and enter this public Target ID:\n  %s\n", origin, receiverID)
	fmt.Fprintln(output, "If no draft or approved entry matches this ID, choose New tunnel first; do not overwrite another Target's entry.")
}

func printConnect(w io.Writer, status, executable, state string, tunnel ...string) {
	// There are two shells: the user's command line and SSH's ProxyCommand.
	// Escape SSH percent tokens as well; paths are local data, never code.
	proxy := strings.ReplaceAll(pairCommand(executable, "proxy", state, tunnel...), "%", "%%")
	fmt.Fprintf(w, "%s Connect from THIS CLIENT COMPUTER:\n  ssh -o %s USER@SSH_ALIAS\nUse your SSH account, key and verified host identity.\n", status, shellQuote("ProxyCommand="+proxy))
}
