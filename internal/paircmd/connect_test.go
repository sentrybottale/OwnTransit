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
	printConnect(&out, "OwnTransit paired.", "/opt/bin/owntransit-client", "")
	want := "OwnTransit paired. Connect from THIS CLIENT COMPUTER:\n  ssh -o 'ProxyCommand=/opt/bin/owntransit-client proxy' USER@SSH_ALIAS\nUse your SSH account, key and verified host identity.\n"
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
	if err != nil || string(args) != "/example/client binary\nproxy\n--state\n"+state+"\n" {
		t.Fatal("connection example did not retain literal arguments")
	}
}

func TestReceiverRegistrationCommandSelectsExactURLAndQuotesArguments(t *testing.T) {
	for _, origin := range []string{"wss://relay.example/connects", "wss://data.example/' $(false); `false` %h"} {
		command := relayRegistrationCommand(origin, "public-target-id")
		// Decode the printed command as data; do not execute sudo or the relay.
		parsed, err := exec.Command("sh", "-c", "set -- "+command+"; printf '%s\\n' \"$@\"").Output()
		want := "sudo\nowntransit-relay\nregister\n--url\n" + origin + "\npublic-target-id\n"
		if err != nil || string(parsed) != want {
			t.Fatalf("registration arguments changed: %v %q", err, parsed)
		}
	}
}

func TestReceiverApprovalCommandSelectsExactURLAndQuotesArguments(t *testing.T) {
	for _, origin := range []string{"wss://relay.example/connects", "wss://data.example/' $(false); `false` %h"} {
		command := relayApprovalCommand(origin, "public-target-id")
		parsed, err := exec.Command("sh", "-c", "set -- "+command+"; printf '%s\\n' \"$@\"").Output()
		want := "sudo\nowntransit-relay\napprove\n--url\n" + origin + "\npublic-target-id\n"
		if err != nil || string(parsed) != want {
			t.Fatal("approval arguments changed")
		}
	}
}

func TestReceiverNextStepsSelectExactCodeProfile(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		var output bytes.Buffer
		printReceiverNext(&output, "wss://relay.example/connects", "public-target-id", "laptop", legacy)
		text := output.String()
		if legacy {
			if !strings.Contains(text, " register --url ") || !strings.Contains(text, "--legacy-codes") || !strings.Contains(text, "setup --tunnel laptop") || strings.Contains(text, " approve --url ") {
				t.Fatal("legacy target selected one-code setup")
			}
		} else if !strings.Contains(text, "NEXT on the Relay") || !strings.Contains(text, "sudo owntransit-relay setup") || !strings.Contains(text, "Choose Continue tunnel") || !strings.Contains(text, "code --target-id public-target-id") || strings.Contains(text, " register ") || strings.Contains(text, " approve ") || strings.Contains(text, "--legacy-codes") || strings.Contains(text, "Linux client") || strings.Contains(text, "Mac client") {
			t.Fatal("new target selected legacy code instructions")
		}
	}
}

func TestShortReceiverPrintsOnePrivateCodeAndExactPublicHandoff(t *testing.T) {
	var output bytes.Buffer
	code := []byte("synthetic-private-code")
	if err := printReceiverCode(&output, "public-target-id", code, false); err != nil {
		t.Fatal(err)
	}
	printReceiverNext(&output, "wss://relay.example/connects", "public-target-id", "", false)
	text := output.String()
	if strings.Count(text, string(code)) != 1 || strings.Count(text, "public-target-id") != 2 || !strings.Contains(text, "public Target ID:") || !strings.Contains(text, "NEXT on the Relay for wss://relay.example/connects") || !strings.Contains(text, "code --target-id public-target-id") {
		t.Fatal("short target output duplicated a code or omitted the prefilled relay URL")
	}
	if strings.Count(text, "\n") > 18 {
		t.Fatal("short target handoff became a wall of text")
	}
}

func TestReplacementHandoffUsesNewRelayDraftWithoutChangingNormalRetry(t *testing.T) {
	var ordinary, retry, replacement bytes.Buffer
	printReceiverNext(&ordinary, "wss://relay.example/connects", "public-target-id", "target-local-name", false)
	printReceiverNext(&retry, "wss://relay.example/connects", "public-target-id", "target-local-name", false, false)
	if !bytes.Equal(ordinary.Bytes(), retry.Bytes()) || !strings.Contains(retry.String(), "Choose Continue tunnel, select its draft") || strings.Contains(retry.String(), "New tunnel with a new local name") {
		t.Fatal("normal pending retry stopped using the existing Relay draft")
	}
	if !strings.Contains(retry.String(), "If no draft or approved entry matches this ID, choose New tunnel first") {
		t.Fatal("retrieved replacement code has no missing-draft recovery")
	}
	printReceiverNext(&replacement, "wss://relay.example/connects", "new-public-target-id", "target-local-name", false, true)
	for _, want := range []string{"NEW Target ID", "sudo owntransit-relay setup", "New tunnel with a new local name", "Continue that new draft", "public Target ID in the new draft:\n  new-public-target-id", "separate explicit action"} {
		if !strings.Contains(replacement.String(), want) {
			t.Fatalf("replacement handoff omitted %q", want)
		}
	}
	for _, unwanted := range []string{"Choose Continue tunnel, select its draft", "approve --url", "TUNNEL READY", "target-local-name"} {
		if strings.Contains(replacement.String(), unwanted) {
			t.Fatal("replacement reused old approval or inferred a shared tunnel name")
		}
	}
}
