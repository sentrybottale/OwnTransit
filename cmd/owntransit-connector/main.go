package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/connector"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmenttarget"
	"github.com/sentrybottale/owntransit/internal/paircmd"
)

const compiledConnectorTarget = "tcp4 " + config.ConnectorSSHTarget

type connectorCommands struct {
	version      func(io.Writer) error
	checkConfig  func(string) error
	checkRuntime func(string, string, int) error
	run          func(string, io.Writer) error
	runOverride  func(string, string, io.Writer) error
	runRuntime   func(string, string, int, io.Writer) error
}

type connectorRuntimeSource struct {
	configPath     string
	runtimeRoot    string
	anchorViewRoot string
	readerGID      int
	relayURL       string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pair" {
		os.Exit(paircmd.Run(true, os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	code := executeConnector(os.Args[1:], os.Stdout, os.Stderr, productionConnectorCommands())
	if code != 0 {
		os.Exit(code)
	}
}

func productionConnectorCommands() connectorCommands {
	return connectorCommands{
		version: func(output io.Writer) error {
			return buildinfo.Write(output, "connector", compiledConnectorTarget)
		},
		checkConfig: func(configPath string) error {
			_, err := config.LoadConnector(configPath)
			return err
		},
		checkRuntime: checkConnectorRuntime,
		run:          runConnector,
		runOverride:  runConnectorOverride,
		runRuntime:   runConnectorRuntime,
	}
}

func executeConnector(arguments []string, output, diagnostics io.Writer, commands connectorCommands) int {
	command := "run"
	commandArguments := arguments
	if len(arguments) > 0 {
		switch arguments[0] {
		case "version", "check-config", "run":
			command = arguments[0]
			commandArguments = arguments[1:]
		}
	}

	switch command {
	case "version":
		if len(commandArguments) != 0 {
			fmt.Fprintln(diagnostics, "owntransit-connector version: unexpected argument")
			return 2
		}
		if err := commands.version(output); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-connector version: %v\n", err)
			return 1
		}
		return 0
	case "check-config":
		source, code, ok := parseConnectorConfigArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if source.runtimeRoot != "" {
			if commands.checkRuntime == nil {
				fmt.Fprintln(diagnostics, "owntransit-connector check-config: runtime-view validation is unavailable")
				return 1
			}
			if err := commands.checkRuntime(source.runtimeRoot, source.anchorViewRoot, source.readerGID); err != nil {
				fmt.Fprintf(diagnostics, "owntransit-connector check-config: %v\n", err)
				return 1
			}
			fmt.Fprintln(output, "owntransit-connector: configuration valid")
			return 0
		}
		if commands.checkConfig == nil {
			fmt.Fprintln(diagnostics, "owntransit-connector check-config: direct-config validation is unavailable")
			return 1
		}
		if err := commands.checkConfig(source.configPath); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-connector check-config: %v\n", err)
			return 1
		}
		fmt.Fprintln(output, "owntransit-connector: configuration valid")
		return 0
	case "run":
		source, code, ok := parseConnectorConfigArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if source.runtimeRoot != "" {
			if commands.runRuntime == nil {
				fmt.Fprintln(diagnostics, "owntransit-connector run: runtime-view carrier is unavailable")
				return 1
			}
			if err := commands.runRuntime(source.runtimeRoot, source.anchorViewRoot, source.readerGID, diagnostics); err != nil {
				fmt.Fprintf(diagnostics, "owntransit-connector run: %v\n", err)
				return 1
			}
			return 0
		}
		if source.relayURL != "" {
			if commands.runOverride == nil {
				fmt.Fprintln(diagnostics, "owntransit-connector run: relay URL override is unavailable")
				return 1
			}
			if err := commands.runOverride(source.configPath, source.relayURL, diagnostics); err != nil {
				fmt.Fprintf(diagnostics, "owntransit-connector run: %v\n", err)
				return 1
			}
			return 0
		}
		if commands.run == nil {
			fmt.Fprintln(diagnostics, "owntransit-connector run: direct-config carrier is unavailable")
			return 1
		}
		if err := commands.run(source.configPath, diagnostics); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-connector run: %v\n", err)
			return 1
		}
		return 0
	default:
		panic("unreachable connector command")
	}
}

func parseConnectorConfigArguments(command string, arguments []string, diagnostics io.Writer) (connectorRuntimeSource, int, bool) {
	flags := flag.NewFlagSet("owntransit-connector "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	configPath := flags.String("config", "", "development-only direct connector configuration file")
	runtimeRoot := flags.String("runtime-root", "", "root-owned read-only runtime view root")
	anchorViewRoot := flags.String("anchor-view-root", "", "root-owned read-only anchor view root")
	readerGID := flags.Int("reader-gid", 0, "exact dedicated runtime reader primary GID")
	relayURL := flags.String("relay-url", "", "direct-config-only local relay URL override")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return connectorRuntimeSource{}, 0, false
		}
		return connectorRuntimeSource{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(diagnostics, "owntransit-connector %s: unexpected positional argument\n", command)
		return connectorRuntimeSource{}, 2, false
	}
	configExplicit := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "config" {
			configExplicit = true
		}
	})
	viewSelected := *runtimeRoot != "" || *anchorViewRoot != "" || *readerGID != 0
	if viewSelected && configExplicit {
		fmt.Fprintf(diagnostics, "owntransit-connector %s: -config and runtime-view arguments are mutually exclusive\n", command)
		return connectorRuntimeSource{}, 2, false
	}
	if viewSelected && (*runtimeRoot == "" || *anchorViewRoot == "" || *readerGID <= 0) {
		fmt.Fprintf(diagnostics, "owntransit-connector %s: -runtime-root, -anchor-view-root and a positive -reader-gid are required together\n", command)
		return connectorRuntimeSource{}, 2, false
	}
	if !viewSelected && !configExplicit {
		fmt.Fprintf(diagnostics, "owntransit-connector %s: select the authenticated runtime views explicitly\n", command)
		return connectorRuntimeSource{}, 2, false
	}
	if *relayURL != "" && (command != "run" || viewSelected) {
		fmt.Fprintf(diagnostics, "owntransit-connector %s: -relay-url is allowed only for direct-config run mode\n", command)
		return connectorRuntimeSource{}, 2, false
	}
	return connectorRuntimeSource{
		configPath: *configPath, runtimeRoot: *runtimeRoot, anchorViewRoot: *anchorViewRoot,
		readerGID: *readerGID, relayURL: *relayURL,
	}, 0, true
}

func runConnector(configPath string, diagnostics io.Writer) error {
	value, err := config.LoadConnector(configPath)
	if err != nil {
		return err
	}
	return runConnectorValue(value, diagnostics)
}

func runConnectorOverride(configPath, relayURL string, diagnostics io.Writer) error {
	value, err := config.LoadConnector(configPath)
	if err != nil {
		return err
	}
	value.RelayURL = relayURL
	if err := value.Validate(); err != nil {
		return fmt.Errorf("relay URL override: %w", err)
	}
	return runConnectorValue(value, diagnostics)
}

func runConnectorValue(value config.Connector, diagnostics io.Writer) error {
	service, err := connector.New(value, connector.WithStateSink(func(state connector.State) {
		fmt.Fprintf(diagnostics, "owntransit-connector: state=%s\n", state)
	}))
	if err != nil {
		return fmt.Errorf("initialize service: %w", err)
	}

	root, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(diagnostics, "owntransit-connector: process started; awaiting authenticated registration")
	return service.Run(root)
}

func checkConnectorRuntime(runtimeRoot, anchorViewRoot string, readerGID int) error {
	handle, _, err := prepareConnectorRuntime(runtimeRoot, anchorViewRoot, readerGID, io.Discard)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.FinalCheck()
}

func runConnectorRuntime(runtimeRoot, anchorViewRoot string, readerGID int, diagnostics io.Writer) error {
	handle, service, err := prepareConnectorRuntime(runtimeRoot, anchorViewRoot, readerGID, diagnostics)
	if err != nil {
		return err
	}
	defer handle.Close()
	root, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(diagnostics, "owntransit-connector: process started; awaiting authenticated registration")
	return service.Run(root)
}

func prepareConnectorRuntime(runtimeRoot, anchorViewRoot string, readerGID int, diagnostics io.Writer) (*enrollmenttarget.RuntimeGenerationHandle, *connector.Service, error) {
	handle, err := enrollmenttarget.OpenRuntimeGeneration(runtimeRoot, anchorViewRoot, readerGID, enrollment.RoleConnector)
	if err != nil {
		return nil, nil, err
	}
	fail := func(value error) (*enrollmenttarget.RuntimeGenerationHandle, *connector.Service, error) {
		_ = handle.Close()
		return nil, nil, value
	}
	value, err := handle.ConnectorConfig()
	if err != nil {
		return fail(err)
	}
	service, err := connector.NewFromMaterial(value, handle.ReadMaterial, handle.FinalCheck, connector.WithStateSink(func(state connector.State) {
		fmt.Fprintf(diagnostics, "owntransit-connector: state=%s\n", state)
	}))
	if err != nil {
		return fail(fmt.Errorf("initialize service: %w", err))
	}
	return handle, service, nil
}
