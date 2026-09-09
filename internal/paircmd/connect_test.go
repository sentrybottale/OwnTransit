//go:build darwin || linux

package paircmd

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestConnectOutputIsShortAndSelectsExactClientAndState(t *testing.T) {
	var out bytes.Buffer
	printConnect(&out, "OwnTransit paired.", "/opt/bin/owntransit-preview", "")
	want := "OwnTransit paired. Connect:\n  ssh -o 'ProxyCommand=/opt/bin/owntransit-preview pair proxy' USER@SSH_ALIAS\nUse your SSH account, key and verified host identity.\n"
	if out.String() != want {
		t.Fatalf("unexpected success text: %q", out.String())
	}
	// Decode both shell layers without opening SSH or executing the path.
	state := "/example/a 'quote' $var $(false); `false` %h"
	out.Reset()
	printConnect(&out, "Already paired; keys unchanged.", "/example/client binary", state)
	line := strings.Split(out.String(), "\n")[1]
	outer := exec.Command("sh", "-c", "set -- "+strings.TrimSpace(line)+"; printf '%s' \"$3\"")
	option, err := outer.Output()
	if err != nil {
		t.Fatal(err)
	}
	proxy := strings.TrimPrefix(string(option), "ProxyCommand=")
	// OpenSSH resolves %% to a literal percent, not another token expansion.
	proxy = strings.ReplaceAll(proxy, "%%", "%")
	inner := exec.Command("sh", "-c", "set -- "+proxy+"; printf '%s\\n' \"$@\"")
	args, err := inner.Output()
	if err != nil || string(args) != "/example/client binary\npair\nproxy\n--state\n"+state+"\n" {
		t.Fatal("connection example did not retain literal arguments")
	}
}

func TestReceiverRegistrationCommandSelectsExactURLAndQuotesArguments(t *testing.T) {
	for _, origin := range []string{"wss://relay.example/connects", "wss://data.example/' $(false); `false` %h"} {
		command := relayRegistrationCommand(origin, "public-receiver-id")
		// Decode the printed command as data; do not execute sudo or the relay.
		parsed, err := exec.Command("sh", "-c", "set -- "+command+"; printf '%s\\n' \"$@\"").Output()
		want := "sudo\nowntransit-relay-preview\nregister\n--url\n" + origin + "\npublic-receiver-id\n"
		if err != nil || string(parsed) != want {
			t.Fatalf("registration arguments changed: %v %q", err, parsed)
		}
	}
}

func TestReceiverApprovalCommandSelectsExactURLAndQuotesArguments(t *testing.T) {
	for _, origin := range []string{"wss://relay.example/connects", "wss://data.example/' $(false); `false` %h"} {
		command := relayApprovalCommand(origin, "public-receiver-id")
		parsed, err := exec.Command("sh", "-c", "set -- "+command+"; printf '%s\\n' \"$@\"").Output()
		want := "sudo\nowntransit-relay-preview\napprove\n--url\n" + origin + "\npublic-receiver-id\n"
		if err != nil || string(parsed) != want {
			t.Fatal("approval arguments changed")
		}
	}
}

func TestReceiverNextStepsSelectExactCodeProfile(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		var output bytes.Buffer
		printReceiverNext(&output, "wss://relay.example/connects", "public-receiver-id", "laptop", legacy)
		text := output.String()
		if !strings.Contains(text, "pair setup --tunnel laptop") {
			t.Fatal("client next step lost the selected tunnel")
		}
		if legacy {
			if !strings.Contains(text, " register --url ") || !strings.Contains(text, "--legacy-codes") || strings.Contains(text, " approve --url ") {
				t.Fatal("legacy receiver selected one-code setup")
			}
		} else if !strings.Contains(text, " approve --url ") || !strings.Contains(text, "private 56-character code") || strings.Contains(text, " register ") || strings.Contains(text, "--legacy-codes") {
			t.Fatal("new receiver selected legacy code instructions")
		}
	}
}

func TestShortReceiverPrintsOnlyOneCodeAndPublicIDOnlyInCommand(t *testing.T) {
	var output bytes.Buffer
	code := []byte("synthetic-private-code")
	if err := printReceiverCode(&output, "public-receiver-id", code, false); err != nil {
		t.Fatal(err)
	}
	printReceiverNext(&output, "wss://relay.example/connects", "public-receiver-id", "", false)
	text := output.String()
	if strings.Count(text, string(code)) != 1 || strings.Count(text, "public-receiver-id") != 1 || strings.Contains(text, "Receiver ID (") || !strings.Contains(text, "pair setup --relay 'wss://relay.example/connects'") {
		t.Fatal("short receiver output duplicated a code or omitted the prefilled relay URL")
	}
	if strings.Count(text, "\n") > 11 {
		t.Fatal("short receiver handoff became a wall of text")
	}
}
