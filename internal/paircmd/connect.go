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

func printConnect(w io.Writer, status, executable, state string, tunnel ...string) {
	// There are two shells: the user's command line and SSH's ProxyCommand.
	// Escape SSH percent tokens as well; paths are local data, never code.
	proxy := strings.ReplaceAll(pairCommand(executable, "proxy", state, tunnel...), "%", "%%")
	fmt.Fprintf(w, "%s Connect:\n  ssh -o %s USER@SSH_ALIAS\nUse your SSH account, key and verified host identity.\n", status, shellQuote("ProxyCommand="+proxy))
}
