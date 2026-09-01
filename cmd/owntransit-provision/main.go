// owntransit-provision is the offline-only OwnTransit enrollment authority.
// It has no server mode and never generates endpoint leaf private keys.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
)

type provisionCommands struct {
	version                   func(io.Writer) error
	initAuthority             func(initAuthorityOptions) ([]byte, error)
	approveInitialRoute       func(approveInitialRouteOptions) ([]byte, error)
	approveRouteRotation      func(approveInitialRouteOptions) ([]byte, error)
	signLifecyclePolicy       func(signLifecyclePolicyOptions) ([]byte, error)
	signRollbackAuthorization func(signRollbackOptions) ([]byte, error)
	issueInvitation           func(issueInvitationOptions) ([]byte, error)
	operatorOpen              func(operatorOpenOptions) ([]byte, error)
	operatorConfirm           func(operatorConfirmOptions) ([]byte, error)
	operatorBindResponse      func(operatorBindOptions) ([]byte, error)
}

func main() {
	code := executeProvision(os.Args[1:], os.Stdout, os.Stderr, productionProvisionCommands())
	if code != 0 {
		os.Exit(code)
	}
}

func productionProvisionCommands() provisionCommands {
	return provisionCommands{
		version: func(output io.Writer) error {
			return buildinfo.Write(output, "provisioner", "")
		},
		initAuthority: func(options initAuthorityOptions) ([]byte, error) {
			options.now = time.Now()
			return initAuthority(options)
		},
		approveInitialRoute: func(options approveInitialRouteOptions) ([]byte, error) {
			options.now = time.Now()
			return approveInitialRoute(options)
		},
		approveRouteRotation: func(options approveInitialRouteOptions) ([]byte, error) {
			options.now = time.Now()
			return approveRouteRotation(options)
		},
		signLifecyclePolicy: func(options signLifecyclePolicyOptions) ([]byte, error) {
			options.now = time.Now()
			return signLifecyclePolicy(options)
		},
		signRollbackAuthorization: func(options signRollbackOptions) ([]byte, error) {
			options.now = time.Now()
			return signRollbackAuthorization(options)
		},
		issueInvitation: func(options issueInvitationOptions) ([]byte, error) {
			options.now = time.Now()
			return issueInvitationBundle(options)
		},
		operatorOpen: func(options operatorOpenOptions) ([]byte, error) {
			options.now = time.Now()
			return openOperatorSession(options)
		},
		operatorConfirm: func(options operatorConfirmOptions) ([]byte, error) {
			options.now = time.Now()
			return confirmOperatorSession(options, os.Stdin)
		},
		operatorBindResponse: func(options operatorBindOptions) ([]byte, error) {
			options.now = time.Now()
			return bindOperatorResponse(options)
		},
	}
}

func executeProvision(arguments []string, output, diagnostics io.Writer, commands provisionCommands) int {
	if len(arguments) == 0 {
		fmt.Fprintln(diagnostics, "owntransit-provision: command is required; run owntransit-provision help")
		return 2
	}
	command := arguments[0]
	commandArguments := arguments[1:]
	if command == "help" || command == "-h" || command == "--help" {
		if len(commandArguments) != 0 {
			fmt.Fprintln(diagnostics, "owntransit-provision help: unexpected argument")
			return 2
		}
		if err := writeProvisionHelp(output); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision help: %v\n", err)
			return 1
		}
		return 0
	}

	switch command {
	case "version":
		if len(commandArguments) != 0 {
			fmt.Fprintln(diagnostics, "owntransit-provision version: unexpected argument")
			return 2
		}
		if err := commands.version(output); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision version: %v\n", err)
			return 1
		}
		return 0
	case "init-authority":
		options, code, ok := parseInitAuthorityArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.initAuthority(options)
		if err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision init-authority: %v\n", err)
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision init-authority: write public summary: %v\n", err)
			return 1
		}
		return 0
	case "approve-initial-route":
		options, code, ok := parseApproveInitialRouteArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.approveInitialRoute(options)
		if err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision approve-initial-route: %v\n", err)
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision approve-initial-route: write public summary: %v\n", err)
			return 1
		}
		return 0
	case "approve-route-rotation":
		options, code, ok := parseApproveRouteRotationArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.approveRouteRotation(options)
		if err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision approve-route-rotation: %v\n", err)
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision approve-route-rotation: write public summary: %v\n", err)
			return 1
		}
		return 0
	case "sign-lifecycle-policy":
		options, code, ok := parseSignLifecyclePolicyArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.signLifecyclePolicy(options)
		if err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision sign-lifecycle-policy: %v\n", err)
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision sign-lifecycle-policy: write public summary: %v\n", err)
			return 1
		}
		return 0
	case "sign-rollback-authorization":
		options, code, ok := parseSignRollbackArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.signRollbackAuthorization(options)
		if err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision sign-rollback-authorization: %v\n", err)
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-provision sign-rollback-authorization: write public summary: %v\n", err)
			return 1
		}
		return 0
	case "issue-invitation":
		options, code, ok := parseIssueInvitationArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.issueInvitation(options)
		if err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision issue-invitation: operation failed")
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision issue-invitation: write public summary failed")
			return 1
		}
		return 0
	case "operator-open":
		options, code, ok := parseOperatorOpenArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.operatorOpen(options)
		if err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision operator-open: operation failed")
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision operator-open: write public summary failed")
			return 1
		}
		return 0
	case "operator-confirm-target":
		options, code, ok := parseOperatorConfirmArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		words, err := commands.operatorConfirm(options)
		if err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision operator-confirm-target: comparison failed")
			return 1
		}
		if _, err := output.Write(words); err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision operator-confirm-target: write reverse words failed")
			return 1
		}
		return 0
	case "operator-bind-response":
		options, code, ok := parseOperatorBindArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		summary, err := commands.operatorBindResponse(options)
		if err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision operator-bind-response: operation failed")
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintln(diagnostics, "owntransit-provision operator-bind-response: write public summary failed")
			return 1
		}
		return 0
	default:
		fmt.Fprintf(diagnostics, "owntransit-provision: unknown command %q\n", command)
		return 2
	}
}

func writeProvisionHelp(output io.Writer) error {
	_, err := io.WriteString(output, `OwnTransit offline provisioner

Commands:
  version
  init-authority --out <new-directory>
  approve-initial-route <explicit request, authority, relay, and output flags>
  approve-route-rotation --deployment-sequence <n> <explicit request, authority, relay, and output flags>
  sign-lifecycle-policy --policy <unsigned-json> --deployment-signing-key <private-key-file> --out <new-file>
  sign-rollback-authorization --authorization <unsigned-json> --deployment-signing-key <private-key-file> --out <new-file>
  issue-invitation --authority <private-directory> --role <role> <runtime and recipient flags> --out <new-directory>
  operator-open --receipt <private-file> --request <encrypted-file> --session-root <private-directory>
  operator-confirm-target --session-root <private-directory>  # reads exactly three target words from stdin
  operator-bind-response --session-root <private-directory> --response <private-file> <three approved request files> --deployment-signing-key <private-key-file> --out <new-directory>

This executable is offline-only. Private key material is read from strict
files; it is never accepted as an argument value or environment variable.
`)
	return err
}

func parseIssueInvitationArguments(arguments []string, diagnostics io.Writer) (issueInvitationOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision issue-invitation", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options issueInvitationOptions
	flags.StringVar(&options.authorityDir, "authority", "", "private route-authority directory")
	flags.StringVar(&options.role, "role", "", "exact target role: relay, connector, or client")
	flags.StringVar(&options.connectorInstallationID, "connector-installation-id", "", "client-only approved connector installation ID")
	flags.StringVar(&options.releaseID, "release-id", "", "authenticated release ID")
	flags.Uint64Var(&options.releaseSequence, "release-sequence", 0, "authenticated release sequence")
	flags.StringVar(&options.artifactSHA256, "artifact-sha256", "", "authenticated target artifact SHA-256")
	flags.StringVar(&options.goos, "os", "", "target operating system")
	flags.StringVar(&options.goarch, "arch", "", "target architecture")
	flags.StringVar(&options.exchangeEndpoint, "exchange-endpoint", "", "canonical public wss enrollment mailbox endpoint")
	flags.StringVar(&options.recipientRecord, "recipient-record", "", "private canonical pre-existing recipient record")
	flags.StringVar(&options.outputDir, "out", "", "brand-new invitation bundle directory")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return issueInvitationOptions{}, 0, false
		}
		return issueInvitationOptions{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "owntransit-provision issue-invitation: unexpected positional argument")
		return issueInvitationOptions{}, 2, false
	}
	required := []struct{ name, value string }{
		{"-authority", options.authorityDir}, {"-role", options.role}, {"-release-id", options.releaseID},
		{"-artifact-sha256", options.artifactSHA256}, {"-os", options.goos}, {"-arch", options.goarch},
		{"-exchange-endpoint", options.exchangeEndpoint}, {"-recipient-record", options.recipientRecord}, {"-out", options.outputDir},
	}
	for _, field := range required {
		if field.value == "" {
			fmt.Fprintf(diagnostics, "owntransit-provision issue-invitation: %s is required\n", field.name)
			return issueInvitationOptions{}, 2, false
		}
	}
	if options.releaseSequence == 0 {
		fmt.Fprintln(diagnostics, "owntransit-provision issue-invitation: -release-sequence must be positive")
		return issueInvitationOptions{}, 2, false
	}
	if options.role == "client" && options.connectorInstallationID == "" {
		fmt.Fprintln(diagnostics, "owntransit-provision issue-invitation: -connector-installation-id is required for a client")
		return issueInvitationOptions{}, 2, false
	}
	if options.role != "client" && options.connectorInstallationID != "" {
		fmt.Fprintln(diagnostics, "owntransit-provision issue-invitation: -connector-installation-id is client-only")
		return issueInvitationOptions{}, 2, false
	}
	return options, 0, true
}

func parseOperatorOpenArguments(arguments []string, diagnostics io.Writer) (operatorOpenOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision operator-open", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options operatorOpenOptions
	flags.StringVar(&options.receiptPath, "receipt", "", "private operator receipt")
	flags.StringVar(&options.requestPath, "request", "", "opaque encrypted target request")
	flags.StringVar(&options.sessionRoot, "session-root", "", "new or exact resumable private session directory")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return operatorOpenOptions{}, 0, false
		}
		return operatorOpenOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.receiptPath == "" || options.requestPath == "" || options.sessionRoot == "" {
		fmt.Fprintln(diagnostics, "owntransit-provision operator-open: -receipt, -request, and -session-root are required with no positional arguments")
		return operatorOpenOptions{}, 2, false
	}
	return options, 0, true
}

func parseOperatorConfirmArguments(arguments []string, diagnostics io.Writer) (operatorConfirmOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision operator-confirm-target", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options operatorConfirmOptions
	flags.StringVar(&options.sessionRoot, "session-root", "", "private operator session directory")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return operatorConfirmOptions{}, 0, false
		}
		return operatorConfirmOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.sessionRoot == "" {
		fmt.Fprintln(diagnostics, "owntransit-provision operator-confirm-target: -session-root is required; words are read only from stdin")
		return operatorConfirmOptions{}, 2, false
	}
	return options, 0, true
}

func parseOperatorBindArguments(arguments []string, diagnostics io.Writer) (operatorBindOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision operator-bind-response", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options operatorBindOptions
	flags.StringVar(&options.sessionRoot, "session-root", "", "private confirmed operator session directory")
	flags.StringVar(&options.responsePath, "response", "", "private raw target response")
	flags.StringVar(&options.relayRequest, "relay-request", "", "approved signed relay request")
	flags.StringVar(&options.connectorRequest, "connector-request", "", "approved signed connector request")
	flags.StringVar(&options.clientRequest, "client-request", "", "approved signed client request")
	flags.StringVar(&options.deploymentSignerKey, "deployment-signing-key", "", "offline deployment-signing private-key file")
	flags.StringVar(&options.outputDir, "out", "", "brand-new bound-response output directory")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return operatorBindOptions{}, 0, false
		}
		return operatorBindOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.sessionRoot == "" || options.responsePath == "" || options.relayRequest == "" ||
		options.connectorRequest == "" || options.clientRequest == "" || options.deploymentSignerKey == "" || options.outputDir == "" {
		fmt.Fprintln(diagnostics, "owntransit-provision operator-bind-response: session, response, three request, signing-key, and output file flags are required with no positional arguments")
		return operatorBindOptions{}, 2, false
	}
	return options, 0, true
}

func parseInitAuthorityArguments(arguments []string, diagnostics io.Writer) (initAuthorityOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision init-authority", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options initAuthorityOptions
	flags.StringVar(&options.outputDir, "out", "", "brand-new authority output directory")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return initAuthorityOptions{}, 0, false
		}
		return initAuthorityOptions{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "owntransit-provision init-authority: unexpected positional argument")
		return initAuthorityOptions{}, 2, false
	}
	if options.outputDir == "" {
		fmt.Fprintln(diagnostics, "owntransit-provision init-authority: -out is required")
		return initAuthorityOptions{}, 2, false
	}
	return options, 0, true
}

func parseApproveInitialRouteArguments(arguments []string, diagnostics io.Writer) (approveInitialRouteOptions, int, bool) {
	return parseApproveRouteArguments("approve-initial-route", arguments, diagnostics, false)
}

func parseApproveRouteRotationArguments(arguments []string, diagnostics io.Writer) (approveInitialRouteOptions, int, bool) {
	return parseApproveRouteArguments("approve-route-rotation", arguments, diagnostics, true)
}

func parseApproveRouteArguments(command string, arguments []string, diagnostics io.Writer, rotation bool) (approveInitialRouteOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options approveInitialRouteOptions
	flags.StringVar(&options.relayRequest, "relay-request", "", "signed relay enrollment request")
	flags.StringVar(&options.connectorRequest, "connector-request", "", "signed connector enrollment request")
	flags.StringVar(&options.clientRequest, "client-request", "", "signed client enrollment request")
	flags.StringVar(&options.outerIssuerCert, "outer-ca-cert", "", "route outer-endpoint CA certificate")
	flags.StringVar(&options.outerIssuerKey, "outer-ca-key", "", "route outer-endpoint CA private key")
	flags.StringVar(&options.innerConnectorIssuerCert, "inner-connector-ca-cert", "", "route inner-connector CA certificate")
	flags.StringVar(&options.innerConnectorIssuerKey, "inner-connector-ca-key", "", "route inner-connector CA private key")
	flags.StringVar(&options.innerClientIssuerCert, "inner-client-ca-cert", "", "route inner-client capability CA certificate")
	flags.StringVar(&options.innerClientIssuerKey, "inner-client-ca-key", "", "route inner-client capability CA private key")
	flags.StringVar(&options.deploymentSigningKey, "deployment-signing-key", "", "offline deployment-signing private key")
	flags.StringVar(&options.relayURL, "relay-url", "", "exact public wss:// relay URL")
	flags.StringVar(&options.relayListen, "relay-listen", "", "numeric relay listen address")
	flags.StringVar(&options.enrollmentAllocationCapabilitySHA256, "enrollment-allocation-sha256", "", "relay-visible SHA-256 of the protected online courier allocation credential")
	flags.StringVar(&options.outputDir, "out", "", "brand-new response output directory")
	if rotation {
		flags.Uint64Var(&options.deploymentSequence, "deployment-sequence", 0, "next deployment sequence (>1)")
	}
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return approveInitialRouteOptions{}, 0, false
		}
		return approveInitialRouteOptions{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(diagnostics, "owntransit-provision %s: unexpected positional argument\n", command)
		return approveInitialRouteOptions{}, 2, false
	}
	required := []struct {
		name  string
		value string
	}{
		{"-relay-request", options.relayRequest},
		{"-connector-request", options.connectorRequest},
		{"-client-request", options.clientRequest},
		{"-outer-ca-cert", options.outerIssuerCert},
		{"-outer-ca-key", options.outerIssuerKey},
		{"-inner-connector-ca-cert", options.innerConnectorIssuerCert},
		{"-inner-connector-ca-key", options.innerConnectorIssuerKey},
		{"-inner-client-ca-cert", options.innerClientIssuerCert},
		{"-inner-client-ca-key", options.innerClientIssuerKey},
		{"-deployment-signing-key", options.deploymentSigningKey},
		{"-relay-url", options.relayURL},
		{"-relay-listen", options.relayListen},
		{"-out", options.outputDir},
	}
	if rotation && options.deploymentSequence <= 1 {
		fmt.Fprintf(diagnostics, "owntransit-provision %s: -deployment-sequence greater than one is required\n", command)
		return approveInitialRouteOptions{}, 2, false
	}
	for _, field := range required {
		if field.value == "" {
			fmt.Fprintf(diagnostics, "owntransit-provision %s: %s is required\n", command, field.name)
			return approveInitialRouteOptions{}, 2, false
		}
	}
	return options, 0, true
}

func parseSignLifecyclePolicyArguments(arguments []string, diagnostics io.Writer) (signLifecyclePolicyOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision sign-lifecycle-policy", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options signLifecyclePolicyOptions
	flags.StringVar(&options.policyPath, "policy", "", "strict unsigned lifecycle-policy JSON file")
	flags.StringVar(&options.signingKey, "deployment-signing-key", "", "offline deployment-signing private-key file")
	flags.StringVar(&options.outputPath, "out", "", "new signed lifecycle-policy output file")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return signLifecyclePolicyOptions{}, 0, false
		}
		return signLifecyclePolicyOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.policyPath == "" || options.signingKey == "" || options.outputPath == "" {
		fmt.Fprintln(diagnostics, "owntransit-provision sign-lifecycle-policy: -policy, -deployment-signing-key, and -out are required with no positional arguments")
		return signLifecyclePolicyOptions{}, 2, false
	}
	return options, 0, true
}

func parseSignRollbackArguments(arguments []string, diagnostics io.Writer) (signRollbackOptions, int, bool) {
	flags := flag.NewFlagSet("owntransit-provision sign-rollback-authorization", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options signRollbackOptions
	flags.StringVar(&options.authorizationPath, "authorization", "", "strict unsigned rollback-authorization JSON file")
	flags.StringVar(&options.signingKey, "deployment-signing-key", "", "offline deployment-signing private-key file")
	flags.StringVar(&options.outputPath, "out", "", "new signed rollback-authorization output file")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return signRollbackOptions{}, 0, false
		}
		return signRollbackOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.authorizationPath == "" || options.signingKey == "" || options.outputPath == "" {
		fmt.Fprintln(diagnostics, "owntransit-provision sign-rollback-authorization: -authorization, -deployment-signing-key, and -out are required with no positional arguments")
		return signRollbackOptions{}, 2, false
	}
	return options, 0, true
}
