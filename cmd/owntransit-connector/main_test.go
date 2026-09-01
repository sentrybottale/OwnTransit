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

func TestConnectorVersionIsOfflineAndIncludesCompiledTarget(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	commands := productionConnectorCommands()
	commands.checkConfig = func(string) error { return errors.New("unexpected config check") }
	commands.run = func(string, io.Writer) error { return errors.New("unexpected run") }

	if code := executeConnector([]string{"version"}, &output, &diagnostics, commands); code != 0 {
		t.Fatalf("executeConnector(version) = %d, diagnostics=%q", code, diagnostics.String())
	}
	var info buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	if info.Role != "connector" || info.ConnectorTarget != compiledConnectorTarget {
		t.Fatalf("unexpected connector version: %+v", info)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected diagnostics: %q", diagnostics.String())
	}
}

func TestConnectorExplicitAndLegacyRunModes(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments []string
	}{
		{name: "explicit", arguments: []string{"run", "-config", "connector.json"}},
		{name: "legacy no subcommand", arguments: []string{"-config", "connector.json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			var diagnostics bytes.Buffer
			runPath := ""
			commands := connectorCommands{
				version:     func(io.Writer) error { return errors.New("unexpected version") },
				checkConfig: func(string) error { return errors.New("unexpected config check") },
				run: func(configPath string, _ io.Writer) error {
					runPath = configPath
					return nil
				},
			}
			if code := executeConnector(test.arguments, &output, &diagnostics, commands); code != 0 {
				t.Fatalf("executeConnector(run) = %d, diagnostics=%q", code, diagnostics.String())
			}
			if runPath != "connector.json" || output.Len() != 0 || diagnostics.Len() != 0 {
				t.Fatalf("runPath=%q stdout=%q stderr=%q", runPath, output.String(), diagnostics.String())
			}
		})
	}
}

func TestConnectorCheckConfigDoesNotRun(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	checkedPath := ""
	commands := connectorCommands{
		version: func(io.Writer) error { return errors.New("unexpected version") },
		checkConfig: func(configPath string) error {
			checkedPath = configPath
			return nil
		},
		run: func(string, io.Writer) error { return errors.New("unexpected run") },
	}
	code := executeConnector([]string{"check-config", "-config", "connector.json"}, &output, &diagnostics, commands)
	if code != 0 || checkedPath != "connector.json" {
		t.Fatalf("executeConnector(check-config) = %d, path=%q, diagnostics=%q", code, checkedPath, diagnostics.String())
	}
	if output.String() != "owntransit-connector: configuration valid\n" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestConnectorRelayURLOverrideIsDirectConfigOnly(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	overridePath := ""
	overrideURL := ""
	runtimeCalled := false
	commands := connectorCommands{
		version:     func(io.Writer) error { return nil },
		checkConfig: func(string) error { return nil },
		run: func(string, io.Writer) error {
			return errors.New("ordinary run called")
		},
		runOverride: func(path, relayURL string, _ io.Writer) error {
			overridePath, overrideURL = path, relayURL
			return nil
		},
		runRuntime: func(string, string, int, io.Writer) error {
			runtimeCalled = true
			return nil
		},
	}
	url := "wss://relay.example.com/carrier"
	code := executeConnector([]string{"run", "-config", "connector.json", "-relay-url", url}, &output, &diagnostics, commands)
	if code != 0 || overridePath != "connector.json" || overrideURL != url {
		t.Fatalf("direct override = %d, path=%q url=%q diagnostics=%q", code, overridePath, overrideURL, diagnostics.String())
	}
	diagnostics.Reset()
	code = executeConnector([]string{
		"run", "-runtime-root", "/runtime", "-anchor-view-root", "/anchor", "-reader-gid", "1234", "-relay-url", url,
	}, &output, &diagnostics, commands)
	if code != 2 || runtimeCalled || !strings.Contains(diagnostics.String(), "direct-config run mode") {
		t.Fatalf("runtime override = %d, runtimeCalled=%v diagnostics=%q", code, runtimeCalled, diagnostics.String())
	}
}

func TestConnectorReadOnlyViewsUseHeldRuntime(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	runRoot, runAnchor := "", ""
	runGID := 0
	commands := connectorCommands{
		run: func(string, io.Writer) error { return errors.New("pathname run must not execute") },
		runRuntime: func(root, anchor string, gid int, _ io.Writer) error {
			runRoot, runAnchor, runGID = root, anchor, gid
			return nil
		},
	}
	code := executeConnector([]string{
		"run", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234",
	}, &output, &diagnostics, commands)
	if code != 0 || runRoot != "/runtime" || runAnchor != "/anchor" || runGID != 1234 {
		t.Fatalf("runtime run = %d, root=%q anchor=%q gid=%d diagnostics=%q", code, runRoot, runAnchor, runGID, diagnostics.String())
	}
	if output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestConnectorRuntimeViewFailureAndConfigConflictNeverUsePathnameRun(t *testing.T) {
	for index, arguments := range [][]string{
		{"run", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234"},
		{"run", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234", "--config", "connector.json"},
	} {
		var output bytes.Buffer
		var diagnostics bytes.Buffer
		runtimeCalls := 0
		pathnameRunCalled := false
		commands := connectorCommands{
			run: func(string, io.Writer) error {
				pathnameRunCalled = true
				return nil
			},
			runRuntime: func(string, string, int, io.Writer) error {
				runtimeCalls++
				return errors.New("invalid active state")
			},
		}
		code := executeConnector(arguments, &output, &diagnostics, commands)
		wantRuntimeCalls := 1 - index
		if code == 0 || pathnameRunCalled || runtimeCalls != wantRuntimeCalls || output.Len() != 0 {
			t.Fatalf("arguments=%v code=%d runtimeCalls=%d pathnameRun=%v stdout=%q stderr=%q", arguments, code, runtimeCalls, pathnameRunCalled, output.String(), diagnostics.String())
		}
	}
}
