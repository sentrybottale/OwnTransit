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
	command := shellQuote(executable) + " pair " + operation
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
	return "sudo owntransit-relay-preview register --url " + shellQuote(origin) + " " + shellQuote(receiverID)
}

func relayApprovalCommand(origin, receiverID string) string {
	return "sudo owntransit-relay-preview approve --url " + shellQuote(origin) + " " + shellQuote(receiverID)
}

func printReceiverCode(output io.Writer, receiverID string, code []byte, legacy bool) error {
	if legacy {
		_, err := fmt.Fprintf(output, "Receiver ID (public; give to relay):\n%s\n\nPrivate one-use pairing code (give only to your client):\n%s\n\nKeep this code private. It expires in 24 hours.\n", receiverID, code)
		return err
	}
	// The public ID appears only inside the complete approval command below,
	// not as another value the operator must identify and copy separately.
	_, err := fmt.Fprintf(output, "Private client code (one use; never give to VPS):\n%s\n\n", code)
	return err
}

func printReceiverNext(output io.Writer, origin, receiverID, tunnel string, legacyCodes bool) {
	client := pairCommand("owntransit-preview", "setup", "", tunnel)
	if legacyCodes {
		fmt.Fprintf(output, "\nNEXT — on your PUBLIC RELAY VPS:\n  %s\nThen on your CLIENT COMPUTER, as your ordinary user without sudo:\n  %s --legacy-codes\nPaste the relay's code and the private pairing code above when asked.\n", relayRegistrationCommand(origin, receiverID), client)
		return
	}
	linuxClient := pairCommand("/usr/local/bin/owntransit-preview", "setup", "", tunnel)
	macClient := `"$HOME/.local/bin/owntransit-preview"` + strings.TrimPrefix(client, "owntransit-preview")
	fmt.Fprintf(output, "\nUNDER CONSTRUCTION — receiver configured; client pairing and an end-to-end check are still required.\nSave the private code above for your client. You do NOT have to memorise it.\nRetrieve the SAME unused code on THIS receiving machine:\n  sudo owntransit-connector-preview pair code --receiver-id %s\nNEXT — on your PUBLIC RELAY VPS:\n  %s\nAfter Receiver approved, run on your CLIENT COMPUTER without sudo.\nLinux client:\n  %s --relay %s\nMac client:\n  %s --relay %s\nPaste the one private 56-character code when asked. No VPS code to copy.\n", shellQuote(receiverID), relayApprovalCommand(origin, receiverID), linuxClient, shellQuote(origin), macClient, shellQuote(origin))
}

func printConnect(w io.Writer, status, executable, state string, tunnel ...string) {
	// There are two shells: the user's command line and SSH's ProxyCommand.
	// Escape SSH percent tokens as well; paths are local data, never code.
	proxy := strings.ReplaceAll(pairCommand(executable, "proxy", state, tunnel...), "%", "%%")
	fmt.Fprintf(w, "%s Connect from THIS CLIENT COMPUTER:\n  ssh -o %s USER@SSH_ALIAS\nUse your SSH account, key and verified host identity.\n", status, shellQuote("ProxyCommand="+proxy))
}
