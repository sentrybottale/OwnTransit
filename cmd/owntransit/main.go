package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/carrier"
	"github.com/sentrybottale/owntransit/internal/client"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/enrollmenttarget"
)

type clientCommands struct {
	authorizeCommand        func(string, []string) error
	version                 func(io.Writer) error
	checkConfig             func(string) error
	checkRuntime            func(string, string, int) error
	verifyReader            func(int) error
	proxy                   func(string, io.Reader, io.Writer) error
	proxyOverride           func(string, string, io.Reader, io.Writer) error
	proxyRuntime            func(string, string, int, io.Reader, io.Writer) error
	doctor                  func(string) error
	doctorRuntime           func(string, string, int) error
	sshConfig               func(string, string, io.Writer) error
	courierCredentialInit   func(string) (string, error)
	courierCredentialRotate func(string) (string, error)
	courierRegister         func(string, string) error
	courierFetchRequest     func(string, string) error
	courierUploadResponse   func(string, string) error
	setup                   func([]string, io.Reader, io.Writer, io.Writer) int
}

type clientRuntimeSource struct {
	configPath     string
	runtimeRoot    string
	anchorViewRoot string
	readerGID      int
	relayURL       string
}

func main() {
	code := executeClient(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, productionClientCommands())
	if code != 0 {
		os.Exit(code)
	}
}

func productionClientCommands() clientCommands {
	return clientCommands{
		authorizeCommand: productionClientCommandAuthorizer(),
		version: func(output io.Writer) error {
			return buildinfo.Write(output, "client", "")
		},
		checkConfig: func(configPath string) error {
			_, err := config.LoadClient(configPath)
			return err
		},
		checkRuntime:  checkClientRuntime,
		verifyReader:  verifyClientReaderGID,
		proxy:         runProxy,
		proxyOverride: runProxyOverride,
		proxyRuntime:  runProxyRuntime,
		doctor:        runDoctor,
		doctorRuntime: runDoctorRuntime,
		sshConfig: func(alias, user string, output io.Writer) error {
			return writeSSHConfigSnippet(output, alias, user, runtime.GOOS)
		},
		courierCredentialInit:   enrollmentexchange.CreateCourierCredentialStore,
		courierCredentialRotate: enrollmentexchange.RotateCourierCredentialStore,
		courierRegister:         registerCourierMailbox,
		courierFetchRequest:     fetchCourierRequest,
		courierUploadResponse:   uploadCourierResponse,
		setup:                   runClientSetupCommand,
	}
}

func productionClientCommandAuthorizer() func(string, []string) error {
	executable, err := os.Executable()
	if err == nil {
		executable, err = filepath.EvalSymlinks(executable)
	}
	if err != nil || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return func(string, []string) error {
			return errors.New("cannot resolve the actual client executable")
		}
	}
	return clientCommandAuthorizer(
		executable, syscall.Getuid(), syscall.Geteuid(), syscall.Getgid(), syscall.Getegid(),
	)
}

func executeClient(
	arguments []string,
	input io.Reader,
	output io.Writer,
	diagnostics io.Writer,
	commands clientCommands,
) int {
	command := "proxy"
	commandArguments := arguments
	if len(arguments) > 0 {
		switch arguments[0] {
		case "version", "check-config", "verify-reader-gid", "proxy", "doctor", "ssh-config", "courier-credential-init", "courier-credential-rotate", "courier-register", "courier-fetch-request", "courier-upload-response", "setup":
			command = arguments[0]
			commandArguments = arguments[1:]
		}
	}
	if commands.authorizeCommand != nil {
		if err := commands.authorizeCommand(command, commandArguments); err != nil {
			fmt.Fprintln(diagnostics, "owntransit: command is unavailable through the privileged proxy entry point")
			return 1
		}
	}

	switch command {
	case "setup":
		if commands.setup == nil {
			fmt.Fprintln(diagnostics, "owntransit setup: installed setup support is unavailable")
			return 1
		}
		return commands.setup(commandArguments, input, output, diagnostics)
	case "version":
		if len(commandArguments) != 0 {
			fmt.Fprintln(diagnostics, "owntransit version: unexpected argument")
			return 2
		}
		if err := commands.version(output); err != nil {
			fmt.Fprintf(diagnostics, "owntransit version: %v\n", err)
			return 1
		}
		return 0
	case "check-config":
		source, code, ok := parseClientConfigArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if source.runtimeRoot != "" {
			if commands.checkRuntime == nil {
				fmt.Fprintln(diagnostics, "owntransit check-config: runtime-view validation is unavailable")
				return 1
			}
			if err := commands.checkRuntime(source.runtimeRoot, source.anchorViewRoot, source.readerGID); err != nil {
				fmt.Fprintf(diagnostics, "owntransit check-config: %v\n", err)
				return 1
			}
			fmt.Fprintln(output, "owntransit: configuration valid")
			return 0
		}
		if commands.checkConfig == nil {
			fmt.Fprintln(diagnostics, "owntransit check-config: direct-config validation is unavailable")
			return 1
		}
		if err := commands.checkConfig(source.configPath); err != nil {
			fmt.Fprintf(diagnostics, "owntransit check-config: %v\n", err)
			return 1
		}
		fmt.Fprintln(output, "owntransit: configuration valid")
		return 0
	case "verify-reader-gid":
		if len(commandArguments) != 1 {
			fmt.Fprintln(diagnostics, "owntransit verify-reader-gid: one positive numeric GID is required")
			return 2
		}
		expected, err := strconv.ParseUint(commandArguments[0], 10, 31)
		if err != nil || expected == 0 {
			fmt.Fprintln(diagnostics, "owntransit verify-reader-gid: one positive numeric GID is required")
			return 2
		}
		if commands.verifyReader == nil {
			fmt.Fprintln(diagnostics, "owntransit verify-reader-gid: runtime principal verification is unavailable")
			return 1
		}
		if err := commands.verifyReader(int(expected)); err != nil {
			fmt.Fprintf(diagnostics, "owntransit verify-reader-gid: %v\n", err)
			return 1
		}
		return 0
	case "ssh-config":
		flags := flag.NewFlagSet("owntransit ssh-config", flag.ContinueOnError)
		flags.SetOutput(diagnostics)
		sshUser := flags.String("user", "", "optional operator-selected OpenSSH user")
		if err := flags.Parse(commandArguments); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if flags.NArg() != 1 {
			fmt.Fprintln(diagnostics, "owntransit ssh-config: one safe OpenSSH alias is required")
			return 2
		}
		if commands.sshConfig == nil {
			fmt.Fprintln(diagnostics, "owntransit ssh-config: snippet generation is unavailable")
			return 1
		}
		if err := commands.sshConfig(flags.Arg(0), *sshUser, output); err != nil {
			fmt.Fprintf(diagnostics, "owntransit ssh-config: %v\n", err)
			return 1
		}
		return 0
	case "courier-credential-init", "courier-credential-rotate":
		flags := flag.NewFlagSet("owntransit "+command, flag.ContinueOnError)
		flags.SetOutput(diagnostics)
		storePath := flags.String("store", "", "private no-symlink online-courier credential root")
		if err := flags.Parse(commandArguments); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if flags.NArg() != 0 || *storePath == "" {
			fmt.Fprintf(diagnostics, "owntransit %s: one -store path is required\n", command)
			return 2
		}
		operation := commands.courierCredentialInit
		if command == "courier-credential-rotate" {
			operation = commands.courierCredentialRotate
		}
		if operation == nil {
			fmt.Fprintf(diagnostics, "owntransit %s: credential operation is unavailable\n", command)
			return 1
		}
		hash, err := operation(*storePath)
		if err != nil {
			fmt.Fprintf(diagnostics, "owntransit %s: %v\n", command, err)
			return 1
		}
		fmt.Fprintln(output, hash)
		return 0
	case "courier-register":
		flags := flag.NewFlagSet("owntransit "+command, flag.ContinueOnError)
		flags.SetOutput(diagnostics)
		registration := flags.String("registration", "", "private signed courier-registration file")
		credentialStore := flags.String("credential-store", "", "private online-courier credential root")
		if err := flags.Parse(commandArguments); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if flags.NArg() != 0 || *registration == "" || *credentialStore == "" {
			fmt.Fprintln(diagnostics, "owntransit courier-register: -registration and -credential-store are required")
			return 2
		}
		if commands.courierRegister == nil || commands.courierRegister(*registration, *credentialStore) != nil {
			fmt.Fprintln(diagnostics, "owntransit courier-register: mailbox operation failed")
			return 1
		}
		fmt.Fprintln(output, "OwnTransit courier mailbox registered.")
		return 0
	case "courier-fetch-request", "courier-upload-response":
		flags := flag.NewFlagSet("owntransit "+command, flag.ContinueOnError)
		flags.SetOutput(diagnostics)
		registration := flags.String("registration", "", "private signed courier-registration file")
		pathName := "out"
		pathDescription := "private request output root"
		if command == "courier-upload-response" {
			pathName, pathDescription = "response", "bound response file"
		}
		pathValue := flags.String(pathName, "", pathDescription)
		if err := flags.Parse(commandArguments); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if flags.NArg() != 0 || *registration == "" || *pathValue == "" {
			fmt.Fprintf(diagnostics, "owntransit %s: -registration and -%s are required\n", command, pathName)
			return 2
		}
		var err error
		if command == "courier-fetch-request" {
			if commands.courierFetchRequest == nil {
				err = errors.New("unavailable")
			} else {
				err = commands.courierFetchRequest(*registration, *pathValue)
			}
		} else if commands.courierUploadResponse == nil {
			err = errors.New("unavailable")
		} else {
			err = commands.courierUploadResponse(*registration, *pathValue)
		}
		if err != nil {
			fmt.Fprintf(diagnostics, "owntransit %s: mailbox operation failed\n", command)
			return 1
		}
		if command == "courier-fetch-request" {
			fmt.Fprintln(output, "OwnTransit encrypted request fetched.")
		} else {
			fmt.Fprintln(output, "OwnTransit bound response uploaded.")
		}
		return 0
	case "doctor":
		source, code, ok := parseClientConfigArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if source.runtimeRoot != "" {
			if commands.doctorRuntime == nil {
				fmt.Fprintln(diagnostics, "owntransit doctor: runtime-view probe is unavailable")
				return 1
			}
			if err := commands.doctorRuntime(source.runtimeRoot, source.anchorViewRoot, source.readerGID); err != nil {
				fmt.Fprintf(diagnostics, "owntransit doctor: %v\n", err)
				return 1
			}
		} else {
			if commands.doctor == nil {
				fmt.Fprintln(diagnostics, "owntransit doctor: direct-config probe is unavailable")
				return 1
			}
			if err := commands.doctor(source.configPath); err != nil {
				fmt.Fprintf(diagnostics, "owntransit doctor: %v\n", err)
				return 1
			}
		}
		fmt.Fprintln(output, "OwnTransit carrier READY; SSH was not attempted.")
		return 0
	case "proxy":
		source, code, ok := parseClientConfigArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if source.runtimeRoot != "" {
			if commands.proxyRuntime == nil {
				fmt.Fprintln(diagnostics, "owntransit proxy: runtime-view carrier is unavailable")
				return 1
			}
			if err := commands.proxyRuntime(source.runtimeRoot, source.anchorViewRoot, source.readerGID, input, output); err != nil {
				fmt.Fprintf(diagnostics, "owntransit proxy: %v\n", err)
				return 1
			}
			return 0
		}
		if source.relayURL != "" {
			if commands.proxyOverride == nil {
				fmt.Fprintln(diagnostics, "owntransit proxy: relay URL override is unavailable")
				return 1
			}
			if err := commands.proxyOverride(source.configPath, source.relayURL, input, output); err != nil {
				fmt.Fprintf(diagnostics, "owntransit proxy: %v\n", err)
				return 1
			}
			return 0
		}
		if commands.proxy == nil {
			fmt.Fprintln(diagnostics, "owntransit proxy: direct-config carrier is unavailable")
			return 1
		}
		if err := commands.proxy(source.configPath, input, output); err != nil {
			// In proxy mode stdout is exclusively the raw SSH byte stream.
			fmt.Fprintf(diagnostics, "owntransit proxy: %v\n", err)
			return 1
		}
		return 0
	default:
		panic("unreachable client command")
	}
}

func verifyClientReaderGID(expected int) error {
	actual := syscall.Getegid()
	if actual != expected {
		return fmt.Errorf("effective GID %d does not match expected reader GID %d", actual, expected)
	}
	return nil
}

// clientCommandAuthorizer keeps the Linux setgid runtime-reader inode a tiny
// carrier-only entry point. Checking both the invoked basename and the real /
// effective IDs prevents argv[0] spoofing from turning that inode into an
// online courier or setup tool. Runtime-bearing commands accept no caller-
// selected paths through this entry point; their no-argument form resolves the
// fixed installed views from the effective reader GID.
func clientCommandAuthorizer(invokedPath string, realUID, effectiveUID, realGID, effectiveGID int) func(string, []string) error {
	privileged := realUID != effectiveUID || realGID != effectiveGID
	entryName := filepath.Base(invokedPath)
	proxyEntry := entryName == "owntransit-proxy"
	frontendEntry := entryName == "owntransit-cli"
	return func(command string, arguments []string) error {
		if frontendEntry {
			switch command {
			case "version", "ssh-config", "courier-credential-init", "courier-credential-rotate", "courier-register", "courier-fetch-request", "courier-upload-response", "setup":
				if !privileged {
					return nil
				}
			}
			return errors.New("installed client frontend command rejected")
		}
		if !privileged && !proxyEntry {
			return nil
		}
		switch command {
		case "version", "proxy", "doctor", "check-config":
			if len(arguments) == 0 {
				return nil
			}
		case "verify-reader-gid":
			if len(arguments) == 1 && arguments[0] == strconv.Itoa(effectiveGID) && effectiveGID > 0 {
				return nil
			}
		}
		return errors.New("privileged proxy command rejected")
	}
}

func parseClientConfigArguments(command string, arguments []string, diagnostics io.Writer) (clientRuntimeSource, int, bool) {
	flags := flag.NewFlagSet("owntransit "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	configPath := flags.String("config", "", "development-only direct client configuration file")
	runtimeRoot := flags.String("runtime-root", "", "root-owned read-only runtime view root")
	anchorViewRoot := flags.String("anchor-view-root", "", "root-owned read-only anchor view root")
	readerGID := flags.Int("reader-gid", 0, "exact dedicated runtime reader primary GID")
	relayURL := flags.String("relay-url", "", "direct-config-only local relay URL override")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return clientRuntimeSource{}, 0, false
		}
		return clientRuntimeSource{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(diagnostics, "owntransit %s: unexpected positional argument\n", command)
		return clientRuntimeSource{}, 2, false
	}
	configExplicit := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "config" {
			configExplicit = true
		}
	})
	viewSelected := *runtimeRoot != "" || *anchorViewRoot != "" || *readerGID != 0
	if viewSelected && configExplicit {
		fmt.Fprintf(diagnostics, "owntransit %s: -config and runtime-view arguments are mutually exclusive\n", command)
		return clientRuntimeSource{}, 2, false
	}
	if viewSelected && (*runtimeRoot == "" || *anchorViewRoot == "" || *readerGID <= 0) {
		fmt.Fprintf(diagnostics, "owntransit %s: -runtime-root, -anchor-view-root and a positive -reader-gid are required together\n", command)
		return clientRuntimeSource{}, 2, false
	}
	if !viewSelected && !configExplicit {
		if len(arguments) == 0 {
			installed, err := installedClientRuntimeSource(runtime.GOOS, syscall.Getegid())
			if err == nil {
				return installed, 0, true
			}
		}
		fmt.Fprintf(diagnostics, "owntransit %s: select the authenticated runtime views explicitly\n", command)
		return clientRuntimeSource{}, 2, false
	}
	if *relayURL != "" && (command != "proxy" || viewSelected) {
		fmt.Fprintf(diagnostics, "owntransit %s: -relay-url is allowed only for direct-config proxy mode\n", command)
		return clientRuntimeSource{}, 2, false
	}
	return clientRuntimeSource{configPath: *configPath, runtimeRoot: *runtimeRoot, anchorViewRoot: *anchorViewRoot, readerGID: *readerGID, relayURL: *relayURL}, 0, true
}

func installedClientRuntimeSource(goos string, effectiveGID int) (clientRuntimeSource, error) {
	if effectiveGID <= 0 {
		return clientRuntimeSource{}, errors.New("no direct installed runtime is available on this platform")
	}
	switch goos {
	case "linux":
		return clientRuntimeSource{
			runtimeRoot: "/var/lib/owntransit/client/runtime", anchorViewRoot: "/var/lib/owntransit/client/anchor-view", readerGID: effectiveGID,
		}, nil
	case "darwin":
		return clientRuntimeSource{
			runtimeRoot: "/Library/OwnTransit/client/runtime", anchorViewRoot: "/Library/OwnTransit/client/anchor-view", readerGID: effectiveGID,
		}, nil
	default:
		return clientRuntimeSource{}, errors.New("no direct installed runtime is available on this platform")
	}
}

func writeSSHConfigSnippet(output io.Writer, alias, user, goos string) error {
	if output == nil || !safeSSHAtom(alias) || user != "" && !safeSSHAtom(user) {
		return errors.New("alias and optional user must use only letters, digits, dot, underscore or hyphen")
	}
	var proxyPath string
	switch goos {
	case "darwin":
		proxyPath = "/Library/OwnTransit/bin/owntransit"
	case "linux":
		proxyPath = "/usr/local/bin/owntransit-proxy"
	default:
		return fmt.Errorf("unsupported client platform %q", goos)
	}
	if _, err := fmt.Fprintf(output, "Host %s\n  HostName %s\n", alias, alias); err != nil {
		return err
	}
	if user != "" {
		if _, err := fmt.Fprintf(output, "  User %s\n", user); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(output, "  ProxyCommand %s\n", proxyPath)
	return err
}

func safeSSHAtom(value string) bool {
	if value == "" || len(value) > 255 || strings.HasPrefix(value, "-") || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func runProxy(configPath string, input io.Reader, output io.Writer) error {
	value, err := config.LoadClient(configPath)
	if err != nil {
		return err
	}
	return runProxyValue(value, input, output)
}

func runProxyOverride(configPath, relayURL string, input io.Reader, output io.Writer) error {
	value, err := config.LoadClient(configPath)
	if err != nil {
		return err
	}
	value.RelayURL = relayURL
	if err := value.Validate(); err != nil {
		return fmt.Errorf("relay URL override: %w", err)
	}
	return runProxyValue(value, input, output)
}

func runProxyValue(value config.Client, input io.Reader, output io.Writer) error {
	carrierDialer, err := carrier.NewDialer(value.RelayURL, value.CarrierCAFile, value.AllowInsecureCarrier, value.ConnectTimeout.Value())
	if err != nil {
		return err
	}
	service, err := client.New(value, carrierDialer)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return service.Proxy(ctx, input, output)
}

func runDoctor(configPath string) error {
	value, err := config.LoadClient(configPath)
	if err != nil {
		return err
	}
	carrierDialer, err := carrier.NewDialer(value.RelayURL, value.CarrierCAFile, value.AllowInsecureCarrier, value.ConnectTimeout.Value())
	if err != nil {
		return err
	}
	service, err := client.New(value, carrierDialer)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return service.Probe(ctx)
}

func checkClientRuntime(runtimeRoot, anchorViewRoot string, readerGID int) error {
	handle, _, err := prepareClientRuntime(runtimeRoot, anchorViewRoot, readerGID)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.FinalCheck()
}

func runProxyRuntime(runtimeRoot, anchorViewRoot string, readerGID int, input io.Reader, output io.Writer) error {
	handle, service, err := prepareClientRuntime(runtimeRoot, anchorViewRoot, readerGID)
	if err != nil {
		return err
	}
	defer handle.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return service.Proxy(ctx, input, output)
}

func runDoctorRuntime(runtimeRoot, anchorViewRoot string, readerGID int) error {
	handle, service, err := prepareClientRuntime(runtimeRoot, anchorViewRoot, readerGID)
	if err != nil {
		return err
	}
	defer handle.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return service.Probe(ctx)
}

func prepareClientRuntime(runtimeRoot, anchorViewRoot string, readerGID int) (*enrollmenttarget.RuntimeGenerationHandle, *client.Service, error) {
	handle, err := enrollmenttarget.OpenRuntimeGeneration(runtimeRoot, anchorViewRoot, readerGID, enrollment.RoleClient)
	if err != nil {
		return nil, nil, err
	}
	fail := func(value error) (*enrollmenttarget.RuntimeGenerationHandle, *client.Service, error) {
		_ = handle.Close()
		return nil, nil, value
	}
	value, err := handle.ClientConfig()
	if err != nil {
		return fail(err)
	}
	var carrierCA []byte
	if value.CarrierCAFile != "" {
		carrierCA, err = handle.ReadMaterial(value.CarrierCAFile)
		if err != nil {
			return fail(err)
		}
	}
	carrierDialer, err := carrier.NewDialerFromMaterial(value.RelayURL, carrierCA, value.AllowInsecureCarrier, value.ConnectTimeout.Value())
	if err != nil {
		return fail(err)
	}
	service, err := client.NewFromMaterial(value, carrierDialer, handle.ReadMaterial, handle.FinalCheck)
	if err != nil {
		return fail(err)
	}
	return handle, service, nil
}
