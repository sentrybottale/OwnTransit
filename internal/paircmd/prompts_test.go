//go:build darwin || linux

package paircmd

import (
	"bufio"
	"bytes"
	"context"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"strings"
	"testing"
)

func TestURLPromptExplainsCommandPasteAndReprompts(t *testing.T) {
	in := strings.NewReader("owntransit-client setup\n\nwss://relay.example/connects\n")
	var out bytes.Buffer
	value, err := promptValidated(context.Background(), in, bufio.NewReader(in), &out, "Public relay URL: ", "Enter a URL, not a shell command.", 2048, false, func(v []byte) error { _, e := pairrelay.NewPublicClient(string(v), nil); return e })
	if err != nil || string(value) != "wss://relay.example/connects" || strings.Count(out.String(), "Public relay URL:") != 3 {
		t.Fatal("URL correction failed")
	}
	if !strings.Contains(out.String(), "not a shell command") {
		t.Fatal("missing guidance")
	}
}
func TestWrongCodePromptNeverEchoesInput(t *testing.T) {
	bad := "otpair1.private-input-must-not-be-logged"
	in := strings.NewReader(bad + "\n\n")
	var out bytes.Buffer
	_, err := promptValidated(context.Background(), in, bufio.NewReader(in), &out, "VPS code (hidden): ", "Get the otrelay1. code on your VPS.", 32768, true, func(v []byte) error { _, e := pairrelaycmd.DecodeRegistration(string(v)); return e })
	if err == nil || strings.Contains(out.String(), bad) || !strings.Contains(out.String(), "Get the otrelay1.") {
		t.Fatal("wrong-code guidance or secrecy failed")
	}
}
