package main

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestPairCommandDispatchesExactSurface(t *testing.T) {
	receiverID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	operations := pairOperations{
		init: func(path string) ([]byte, error) {
			calls = append(calls, "init:"+path)
			return []byte("summary\n"), nil
		},
		serve: func(path string, diagnostics io.Writer) error {
			calls = append(calls, "serve:"+path)
			return nil
		},
		register: func(path string, got protocol.ID) (string, error) {
			if got != receiverID {
				t.Fatal("register received another receiver ID")
			}
			calls = append(calls, "register:"+path)
			return "relay-code", nil
		},
	}
	tests := []struct {
		arguments []string
		output    string
		call      string
	}{
		{[]string{"init", "--state", "/private/state"}, "summary\n", "init:/private/state"},
		{[]string{"serve", "--state", "/private/state"}, "", "serve:/private/state"},
		{[]string{"register", "--state", "/private/state", receiverID.String()}, "relay-code\n", "register:/private/state"},
	}
	for _, test := range tests {
		var output, diagnostics bytes.Buffer
		before := len(calls)
		if code := executePairCommand(test.arguments, &output, &diagnostics, operations); code != 0 {
			t.Fatalf("%v code=%d diagnostics=%q", test.arguments, code, diagnostics.String())
		}
		if output.String() != test.output || diagnostics.Len() != 0 || len(calls) != before+1 || calls[before] != test.call {
			t.Fatalf("%v output=%q diagnostics=%q calls=%v", test.arguments, output.String(), diagnostics.String(), calls)
		}
	}
}

func TestRelayDispatchesPairWithoutEnteringLegacyRun(t *testing.T) {
	called := false
	commands := relayCommands{pair: func(arguments []string, output, diagnostics io.Writer) int {
		called = true
		if len(arguments) != 1 || arguments[0] != "help" {
			t.Fatalf("pair arguments=%v", arguments)
		}
		_, _ = io.WriteString(output, "pair-help\n")
		return 0
	}}
	var output, diagnostics bytes.Buffer
	if code := executeRelay([]string{"pair", "help"}, &output, &diagnostics, commands); code != 0 || !called || output.String() != "pair-help\n" || diagnostics.Len() != 0 {
		t.Fatalf("code/output/diagnostics = %q/%q called=%v", output.String(), diagnostics.String(), called)
	}
}

func TestPairCommandFailsClosedAndHidesOperationDetails(t *testing.T) {
	secret := "/private/secret-must-not-leak"
	operations := pairOperations{init: func(string) ([]byte, error) { return nil, errors.New(secret) }}
	var output, diagnostics bytes.Buffer
	code := executePairCommand([]string{"init", "--state", "/private/state"}, &output, &diagnostics, operations)
	if code != 1 || output.Len() != 0 || bytes.Contains(diagnostics.Bytes(), []byte(secret)) || diagnostics.String() != "owntransit-relay pair init: operation failed\n" {
		t.Fatalf("code=%d output=%q diagnostics=%q", code, output.String(), diagnostics.String())
	}
	for _, arguments := range [][]string{
		{}, {"init"}, {"serve", "--state", "/private/state", "extra"},
		{"register", "--state", "/private/state", "not-an-id"}, {"unknown", "--state", "/private/state"},
	} {
		output.Reset()
		diagnostics.Reset()
		if code := executePairCommand(arguments, &output, &diagnostics, pairOperations{}); code != 2 || output.Len() != 0 || diagnostics.Len() == 0 {
			t.Fatalf("%v code=%d output=%q diagnostics=%q", arguments, code, output.String(), diagnostics.String())
		}
	}
}
