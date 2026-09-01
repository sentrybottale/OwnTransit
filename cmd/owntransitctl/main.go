// owntransitctl performs target-local OwnTransit lifecycle operations. It has
// no remote orchestration mode and never exports endpoint private material.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/enrollmentsetup"
)

type ctlCommands struct {
	version         func(io.Writer) error
	bootstrap       func(bootstrapOptions) ([]byte, error)
	enrollInit      func(enrollInitOptions) ([]byte, error)
	pending         func(exportPendingOptions) ([]byte, error)
	apply           func(applyOptions) ([]byte, error)
	policyApply     func(signedInputOptions) ([]byte, error)
	rollback        func(signedInputOptions) ([]byte, error)
	recover         func(stateOptions) ([]byte, error)
	verify          func(stateOptions) ([]byte, error)
	cancel          func(stateOptions) ([]byte, error)
	status          func(stateOptions) ([]byte, error)
	packageApply    func(packageApplyOptions) ([]byte, error)
	packageRollback func(packageRollbackOptions) ([]byte, error)
	packageRecover  func(packageStateOptions) ([]byte, error)
	setupStage      func() ([]byte, error)
	setupStatus     func() ([]byte, error)
	setupConfirm    func() ([]byte, error)
	setupAccept     func() ([]byte, error)
	setupResume     func() ([]byte, error)
	setupReady      func() ([]byte, error)
	setupClean      func() ([]byte, error)
	setupCancel     func() ([]byte, error)
}

func main() {
	code := executeCTL(os.Args[1:], os.Stdout, os.Stderr, productionCTLCommands())
	if code != 0 {
		os.Exit(code)
	}
}

func productionCTLCommands() ctlCommands {
	return ctlCommands{
		version: func(output io.Writer) error {
			return buildinfo.Write(output, "lifecycle", "")
		},
		bootstrap: func(options bootstrapOptions) ([]byte, error) {
			options.now = time.Now()
			return bootstrapTarget(options)
		},
		enrollInit: func(options enrollInitOptions) ([]byte, error) {
			options.now = time.Now()
			return initializeEnrollment(options)
		},
		pending: exportPending,
		apply: func(options applyOptions) ([]byte, error) {
			options.now = time.Now()
			return applyResponse(options)
		},
		policyApply: func(options signedInputOptions) ([]byte, error) {
			options.now = time.Now()
			return applyPolicy(options)
		},
		rollback: func(options signedInputOptions) ([]byte, error) {
			options.now = time.Now()
			return rollbackRecord(options)
		},
		recover:         recoverState,
		verify:          verifyState,
		cancel:          cancelPending,
		status:          readStatus,
		packageApply:    applyPackageRelease,
		packageRollback: rollbackPackageRelease,
		packageRecover:  recoverPackageRelease,
		setupStage:      stageClientSetup,
		setupStatus:     statusClientSetup,
		setupConfirm:    confirmClientSetup,
		setupAccept:     acceptClientSetup,
		setupResume:     resumeClientSetup,
		setupReady:      readyClientSetup,
		setupClean:      cleanupClientSetup,
		setupCancel:     cancelClientSetup,
	}
}

func executeCTL(arguments []string, output, diagnostics io.Writer, commands ctlCommands) int {
	if len(arguments) == 0 {
		fmt.Fprintln(diagnostics, "owntransitctl: command is required")
		return 2
	}
	command := arguments[0]
	commandArguments := arguments[1:]

	var result []byte
	var err error
	switch command {
	case "version":
		if len(commandArguments) != 0 {
			fmt.Fprintln(diagnostics, "owntransitctl version: unexpected argument")
			return 2
		}
		if err := commands.version(output); err != nil {
			fmt.Fprintf(diagnostics, "owntransitctl version: %v\n", err)
			return 1
		}
		return 0
	case "bootstrap":
		options, code, ok := parseBootstrapArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		result, err = commands.bootstrap(options)
	case "enroll-init":
		options, code, ok := parseEnrollInitArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		result, err = commands.enrollInit(options)
	case "pending":
		options, code, ok := parseExportPendingArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		result, err = commands.pending(options)
	case "apply":
		options, code, ok := parseApplyArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		result, err = commands.apply(options)
	case "policy-apply", "rollback":
		options, code, ok := parseSignedInputArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if command == "policy-apply" {
			result, err = commands.policyApply(options)
		} else {
			result, err = commands.rollback(options)
		}
	case "cancel", "status", "recover", "verify":
		options, code, ok := parseStateArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if command == "cancel" {
			result, err = commands.cancel(options)
		} else if command == "status" {
			result, err = commands.status(options)
		} else if command == "recover" {
			result, err = commands.recover(options)
		} else {
			result, err = commands.verify(options)
		}
	case "package-apply":
		options, code, ok := parsePackageApplyArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		result, err = commands.packageApply(options)
	case "package-rollback":
		options, code, ok := parsePackageRollbackArguments(commandArguments, diagnostics)
		if !ok {
			return code
		}
		result, err = commands.packageRollback(options)
	case "package-recover":
		options, code, ok := parsePackageStateArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		result, err = commands.packageRecover(options)
	case "setup-stage", "setup-status", "setup-confirm", "setup-accept", "setup-resume", "setup-ready", "setup-clean", "setup-cancel":
		if len(commandArguments) != 0 {
			fmt.Fprintf(diagnostics, "owntransitctl %s: unexpected argument\n", command)
			return 2
		}
		switch command {
		case "setup-stage":
			result, err = commands.setupStage()
		case "setup-status":
			result, err = commands.setupStatus()
		case "setup-confirm":
			result, err = commands.setupConfirm()
		case "setup-accept":
			result, err = commands.setupAccept()
		case "setup-resume":
			result, err = commands.setupResume()
		case "setup-ready":
			result, err = commands.setupReady()
		case "setup-clean":
			result, err = commands.setupClean()
		case "setup-cancel":
			result, err = commands.setupCancel()
		}
	default:
		fmt.Fprintf(diagnostics, "owntransitctl: unknown command %q\n", command)
		return 2
	}
	if err != nil {
		if isSetupCTLCommand(command) {
			if errors.Is(err, enrollmentsetup.ErrResetRequired) {
				fmt.Fprintf(diagnostics, "owntransitctl %s: %s\n", command, enrollmentsetup.ResetSupportCode())
			} else {
				fmt.Fprintf(diagnostics, "owntransitctl %s: setup operation failed\n", command)
			}
			return 1
		}
		fmt.Fprintf(diagnostics, "owntransitctl %s: %v\n", command, err)
		return 1
	}
	if _, err := output.Write(result); err != nil {
		fmt.Fprintf(diagnostics, "owntransitctl %s: write public summary: %v\n", command, err)
		return 1
	}
	return 0
}

func isSetupCTLCommand(command string) bool {
	switch command {
	case "setup-stage", "setup-status", "setup-confirm", "setup-accept", "setup-resume", "setup-ready", "setup-clean", "setup-cancel":
		return true
	default:
		return false
	}
}

func parseBootstrapArguments(arguments []string, diagnostics io.Writer) (bootstrapOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl bootstrap", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options bootstrapOptions
	flags.StringVar(&options.stateRoot, "state-root", "", "brand-new private target state root")
	flags.StringVar(&options.role, "role", "", "target role: client, connector, or relay")
	flags.StringVar(&options.releaseID, "release-id", "", "authenticated release ID")
	flags.Uint64Var(&options.releaseSequence, "release-sequence", 0, "authenticated release sequence")
	flags.StringVar(&options.artifactSHA256, "artifact-sha256", "", "authenticated runtime artifact digest")
	flags.StringVar(&options.goos, "os", "", "runtime operating system")
	flags.StringVar(&options.goarch, "arch", "", "runtime architecture")
	flags.StringVar(&options.outerCA, "outer-ca", "", "outer endpoint CA certificate")
	flags.StringVar(&options.innerConnectorCA, "inner-connector-ca", "", "inner connector CA certificate")
	flags.StringVar(&options.innerClientCA, "inner-client-ca", "", "inner client capability CA certificate")
	flags.StringVar(&options.deploymentSigner, "deployment-signer", "", "deployment signer public key")
	flags.StringVar(&options.rollbackAnchor, "rollback-anchor-root", "", "brand-new external rollback-anchor root")
	flags.StringVar(&options.runtimeRoot, "runtime-root", "", "brand-new root-owned read-only runtime view root")
	flags.StringVar(&options.runtimeConfigRoot, "runtime-config-root", "", "runtime namespace path for the read-only runtime view")
	flags.StringVar(&options.anchorViewRoot, "anchor-view-root", "", "brand-new root-owned read-only anchor view root")
	flags.Uint64Var(&options.readerGID, "reader-gid", 0, "dedicated runtime reader primary GID")
	flags.StringVar(&options.connectorTarget, "connector-target", "", "optional connector target assertion")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return bootstrapOptions{}, 0, false
		}
		return bootstrapOptions{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "owntransitctl bootstrap: unexpected positional argument")
		return bootstrapOptions{}, 2, false
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"-state-root", options.stateRoot},
		{"-role", options.role},
		{"-release-id", options.releaseID},
		{"-artifact-sha256", options.artifactSHA256},
		{"-os", options.goos},
		{"-arch", options.goarch},
		{"-outer-ca", options.outerCA},
		{"-inner-connector-ca", options.innerConnectorCA},
		{"-inner-client-ca", options.innerClientCA},
		{"-deployment-signer", options.deploymentSigner},
		{"-rollback-anchor-root", options.rollbackAnchor},
		{"-runtime-root", options.runtimeRoot},
		{"-runtime-config-root", options.runtimeConfigRoot},
		{"-anchor-view-root", options.anchorViewRoot},
	} {
		if field.value == "" {
			fmt.Fprintf(diagnostics, "owntransitctl bootstrap: %s is required\n", field.name)
			return bootstrapOptions{}, 2, false
		}
	}
	if options.releaseSequence == 0 {
		fmt.Fprintln(diagnostics, "owntransitctl bootstrap: -release-sequence must be positive")
		return bootstrapOptions{}, 2, false
	}
	if options.readerGID == 0 {
		fmt.Fprintln(diagnostics, "owntransitctl bootstrap: -reader-gid must be positive")
		return bootstrapOptions{}, 2, false
	}
	return options, 0, true
}

func parseSignedInputArguments(command string, arguments []string, diagnostics io.Writer) (signedInputOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options signedInputOptions
	flags.StringVar(&options.stateRoot, "state-root", "", "existing private target state root")
	flags.StringVar(&options.inputPath, "authorization", "", "offline-signed lifecycle input")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return signedInputOptions{}, 0, false
		}
		return signedInputOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.stateRoot == "" || options.inputPath == "" {
		fmt.Fprintf(diagnostics, "owntransitctl %s: -state-root and -authorization are required with no positional arguments\n", command)
		return signedInputOptions{}, 2, false
	}
	return options, 0, true
}

func parseEnrollInitArguments(arguments []string, diagnostics io.Writer) (enrollInitOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl enroll-init", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	options := enrollInitOptions{validity: time.Hour}
	flags.StringVar(&options.stateRoot, "state-root", "", "existing private target state root")
	flags.StringVar(&options.routeID, "route", "", "route capability ID for client or connector")
	flags.StringVar(&options.connectorID, "connector-id", "", "connector installation ID for a client capability")
	flags.DurationVar(&options.validity, "validity", time.Hour, "bounded enrollment request validity")
	flags.StringVar(&options.outputPath, "out", "", "brand-new public enrollment request file")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return enrollInitOptions{}, 0, false
		}
		return enrollInitOptions{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "owntransitctl enroll-init: unexpected positional argument")
		return enrollInitOptions{}, 2, false
	}
	if options.stateRoot == "" || options.outputPath == "" {
		fmt.Fprintln(diagnostics, "owntransitctl enroll-init: -state-root and -out are required")
		return enrollInitOptions{}, 2, false
	}
	if options.validity <= 0 {
		fmt.Fprintln(diagnostics, "owntransitctl enroll-init: -validity must be positive")
		return enrollInitOptions{}, 2, false
	}
	return options, 0, true
}

func parseExportPendingArguments(arguments []string, diagnostics io.Writer) (exportPendingOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl pending", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options exportPendingOptions
	flags.StringVar(&options.stateRoot, "state-root", "", "existing private target state root")
	flags.StringVar(&options.outputPath, "out", "", "brand-new public enrollment request file")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exportPendingOptions{}, 0, false
		}
		return exportPendingOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.stateRoot == "" || options.outputPath == "" {
		fmt.Fprintln(diagnostics, "owntransitctl pending: -state-root and -out are required with no positional arguments")
		return exportPendingOptions{}, 2, false
	}
	return options, 0, true
}

func parseApplyArguments(arguments []string, diagnostics io.Writer) (applyOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl apply", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options applyOptions
	flags.StringVar(&options.stateRoot, "state-root", "", "existing private target state root")
	flags.StringVar(&options.responsePath, "response", "", "public encrypted enrollment response envelope")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return applyOptions{}, 0, false
		}
		return applyOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.stateRoot == "" || options.responsePath == "" {
		fmt.Fprintln(diagnostics, "owntransitctl apply: -state-root and -response are required with no positional arguments")
		return applyOptions{}, 2, false
	}
	return options, 0, true
}

func parseStateArguments(command string, arguments []string, diagnostics io.Writer) (stateOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options stateOptions
	flags.StringVar(&options.stateRoot, "state-root", "", "existing private target state root")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return stateOptions{}, 0, false
		}
		return stateOptions{}, 2, false
	}
	if flags.NArg() != 0 || options.stateRoot == "" {
		fmt.Fprintf(diagnostics, "owntransitctl %s: -state-root is required with no positional arguments\n", command)
		return stateOptions{}, 2, false
	}
	return options, 0, true
}
