package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
)

func TestProvisionVersionIsOfflineAndRoleBound(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	commands := productionProvisionCommands()
	commands.initAuthority = func(initAuthorityOptions) ([]byte, error) {
		return nil, errors.New("unexpected authority initialization")
	}
	commands.approveInitialRoute = func(approveInitialRouteOptions) ([]byte, error) {
		return nil, errors.New("unexpected route approval")
	}
	if code := executeProvision([]string{"version"}, &output, &diagnostics, commands); code != 0 {
		t.Fatalf("executeProvision(version) = %d, diagnostics=%q", code, diagnostics.String())
	}
	var info buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	if info.Role != "provisioner" || info.ConnectorTarget != "" {
		t.Fatalf("unexpected provisioner version: %+v", info)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected diagnostics: %q", diagnostics.String())
	}
}

func TestProvisionInitAuthorityWritesOnlyReturnedPublicSummaryToStdout(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	calledWith := ""
	commands := provisionCommands{
		version: func(io.Writer) error { return errors.New("unexpected version") },
		initAuthority: func(options initAuthorityOptions) ([]byte, error) {
			calledWith = options.outputDir
			return []byte("{\"schema\":\"public\"}\n"), nil
		},
		approveInitialRoute: func(approveInitialRouteOptions) ([]byte, error) {
			return nil, errors.New("unexpected approval")
		},
	}
	code := executeProvision([]string{"init-authority", "--out", "authority"}, &output, &diagnostics, commands)
	if code != 0 || calledWith != "authority" {
		t.Fatalf("executeProvision(init) = %d, out=%q, diagnostics=%q", code, calledWith, diagnostics.String())
	}
	if output.String() != "{\"schema\":\"public\"}\n" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestProvisionApproveRequiresEveryExplicitInput(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	called := false
	commands := provisionCommands{
		version:       func(io.Writer) error { return nil },
		initAuthority: func(initAuthorityOptions) ([]byte, error) { return nil, nil },
		approveInitialRoute: func(approveInitialRouteOptions) ([]byte, error) {
			called = true
			return nil, nil
		},
	}
	code := executeProvision([]string{"approve-initial-route", "--out", "responses"}, &output, &diagnostics, commands)
	if code != 2 || called {
		t.Fatalf("executeProvision(approve) = %d, called=%v", code, called)
	}
	if output.Len() != 0 || !strings.Contains(diagnostics.String(), "-relay-request is required") {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestProvisionLifecycleCommandsDispatchOnlyExplicitFileInputs(t *testing.T) {
	commands := provisionCommands{
		signLifecyclePolicy: func(options signLifecyclePolicyOptions) ([]byte, error) {
			if options.policyPath != "policy.json" || options.signingKey != "signer.pem" || options.outputPath != "policy.signed" {
				t.Fatalf("unexpected lifecycle options: %+v", options)
			}
			return []byte("{\"kind\":\"policy\"}\n"), nil
		},
		signRollbackAuthorization: func(options signRollbackOptions) ([]byte, error) {
			if options.authorizationPath != "rollback.json" || options.signingKey != "signer.pem" || options.outputPath != "rollback.signed" {
				t.Fatalf("unexpected rollback options: %+v", options)
			}
			return []byte("{\"kind\":\"rollback\"}\n"), nil
		},
	}
	for _, test := range []struct {
		arguments []string
		want      string
	}{
		{[]string{"sign-lifecycle-policy", "--policy", "policy.json", "--deployment-signing-key", "signer.pem", "--out", "policy.signed"}, "{\"kind\":\"policy\"}\n"},
		{[]string{"sign-rollback-authorization", "--authorization", "rollback.json", "--deployment-signing-key", "signer.pem", "--out", "rollback.signed"}, "{\"kind\":\"rollback\"}\n"},
	} {
		var output bytes.Buffer
		var diagnostics bytes.Buffer
		if code := executeProvision(test.arguments, &output, &diagnostics, commands); code != 0 {
			t.Fatalf("executeProvision(%v) = %d, diagnostics=%q", test.arguments, code, diagnostics.String())
		}
		if output.String() != test.want || diagnostics.Len() != 0 {
			t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
		}
	}
}

func TestProvisionLifecycleHelpAndMissingInputsFailClosed(t *testing.T) {
	for _, command := range []string{"sign-lifecycle-policy", "sign-rollback-authorization", "approve-route-rotation"} {
		var output bytes.Buffer
		var diagnostics bytes.Buffer
		if code := executeProvision([]string{command, "--help"}, &output, &diagnostics, provisionCommands{}); code != 0 {
			t.Fatalf("%s --help = %d, diagnostics=%q", command, code, diagnostics.String())
		}
		if output.Len() != 0 || diagnostics.Len() == 0 {
			t.Fatalf("%s help streams: stdout=%q stderr=%q", command, output.String(), diagnostics.String())
		}
		output.Reset()
		diagnostics.Reset()
		if code := executeProvision([]string{command}, &output, &diagnostics, provisionCommands{}); code != 2 {
			t.Fatalf("%s missing inputs = %d", command, code)
		}
		if output.Len() != 0 || diagnostics.Len() == 0 {
			t.Fatalf("%s missing-input streams: stdout=%q stderr=%q", command, output.String(), diagnostics.String())
		}
	}
}

func TestProvisionGlobalHelpListsOfflineLifecycleCommands(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	if code := executeProvision([]string{"--help"}, &output, &diagnostics, provisionCommands{}); code != 0 {
		t.Fatalf("global help = %d, diagnostics=%q", code, diagnostics.String())
	}
	for _, command := range []string{"approve-route-rotation", "sign-lifecycle-policy", "sign-rollback-authorization", "issue-invitation", "operator-open", "operator-confirm-target", "operator-bind-response"} {
		if !strings.Contains(output.String(), command) {
			t.Fatalf("global help omits %q: %q", command, output.String())
		}
	}
	if diagnostics.Len() != 0 || strings.Contains(output.String(), "PRIVATE KEY-----") {
		t.Fatalf("unsafe help streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestProvisionExchangeCommandsKeepWordsOffArgvAndDispatchFilesOnly(t *testing.T) {
	commands := provisionCommands{
		issueInvitation: func(options issueInvitationOptions) ([]byte, error) {
			if options.authorityDir != "authority" || options.role != "client" || options.connectorInstallationID != "connector-id" ||
				options.releaseID != "release-id" || options.releaseSequence != 7 || options.artifactSHA256 != strings.Repeat("a", 64) ||
				options.goos != "darwin" || options.goarch != "arm64" || options.exchangeEndpoint != "wss://relay.example.com/connects/enrollment" ||
				options.recipientRecord != "recipient.json" || options.outputDir != "bundle" {
				t.Fatalf("unexpected issue options: %+v", options)
			}
			return []byte("{\"schema\":\"invitation-summary\"}\n"), nil
		},
		operatorOpen: func(options operatorOpenOptions) ([]byte, error) {
			if options.receiptPath != "receipt" || options.requestPath != "request" || options.sessionRoot != "session" {
				t.Fatalf("unexpected open options: %+v", options)
			}
			return []byte("{\"phase\":\"pending-comparison\"}\n"), nil
		},
		operatorConfirm: func(options operatorConfirmOptions) ([]byte, error) {
			if options.sessionRoot != "session" {
				t.Fatalf("unexpected confirm options: %+v", options)
			}
			return []byte("reverse\nwords\nhere\n"), nil
		},
		operatorBindResponse: func(options operatorBindOptions) ([]byte, error) {
			if options.sessionRoot != "session" || options.responsePath != "response" || options.relayRequest != "relay" ||
				options.connectorRequest != "connector" || options.clientRequest != "client" || options.deploymentSignerKey != "signer" || options.outputDir != "bound" {
				t.Fatalf("unexpected bind options: %+v", options)
			}
			return []byte("{\"schema\":\"bound-summary\"}\n"), nil
		},
	}
	tests := []struct {
		arguments []string
		want      string
	}{
		{[]string{"issue-invitation", "--authority", "authority", "--role", "client", "--connector-installation-id", "connector-id", "--release-id", "release-id", "--release-sequence", "7", "--artifact-sha256", strings.Repeat("a", 64), "--os", "darwin", "--arch", "arm64", "--exchange-endpoint", "wss://relay.example.com/connects/enrollment", "--recipient-record", "recipient.json", "--out", "bundle"}, "{\"schema\":\"invitation-summary\"}\n"},
		{[]string{"operator-open", "--receipt", "receipt", "--request", "request", "--session-root", "session"}, "{\"phase\":\"pending-comparison\"}\n"},
		{[]string{"operator-confirm-target", "--session-root", "session"}, "reverse\nwords\nhere\n"},
		{[]string{"operator-bind-response", "--session-root", "session", "--response", "response", "--relay-request", "relay", "--connector-request", "connector", "--client-request", "client", "--deployment-signing-key", "signer", "--out", "bound"}, "{\"schema\":\"bound-summary\"}\n"},
	}
	for _, test := range tests {
		var output, diagnostics bytes.Buffer
		if code := executeProvision(test.arguments, &output, &diagnostics, commands); code != 0 {
			t.Fatalf("%v code=%d stderr=%q", test.arguments, code, diagnostics.String())
		}
		if output.String() != test.want || diagnostics.Len() != 0 {
			t.Fatalf("%v stdout=%q stderr=%q", test.arguments, output.String(), diagnostics.String())
		}
	}

	var output, diagnostics bytes.Buffer
	if code := executeProvision([]string{"operator-confirm-target", "--session-root", "session", "target", "words", "forbidden"}, &output, &diagnostics, commands); code != 2 {
		t.Fatalf("word argv accepted: code=%d stdout=%q stderr=%q", code, output.String(), diagnostics.String())
	}
}

func TestProvisionExchangeFailuresAreGenericAndDoNotEchoPrivatePaths(t *testing.T) {
	secretPath := "/private/recipient-name-must-not-leak"
	commands := provisionCommands{operatorOpen: func(operatorOpenOptions) ([]byte, error) { return nil, errors.New("internal detail " + secretPath) }}
	var output, diagnostics bytes.Buffer
	code := executeProvision([]string{"operator-open", "--receipt", secretPath, "--request", "/private/request", "--session-root", "/private/session"}, &output, &diagnostics, commands)
	if code != 1 || output.Len() != 0 || strings.Contains(diagnostics.String(), secretPath) || !strings.Contains(diagnostics.String(), "operation failed") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, output.String(), diagnostics.String())
	}
}
