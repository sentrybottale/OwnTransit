package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/relaysetup"
)

type managedOperations struct {
	prepareSetup func(context.Context, string, string) (relaysetup.SetupPlan, error)
	applySetup   func(context.Context, relaysetup.SetupPlan, bool, io.Writer) (relaysetup.SetupResult, error)
	register     func(context.Context, string, string) (string, error)
	registerURL  func(context.Context, string, string) (string, error)
	cleanup      func(context.Context, string, string, string) error
	uninstall    func(context.Context, string) error
	uninstallAll func(context.Context) error
	list         func(context.Context, io.Writer) error
	lockPackage  func(int) (io.Closer, error)
}

// A selector may occur only once; accepting the last duplicate would hide the
// scope of a privileged operation from an operator reading the command.
type managedStringFlag struct {
	value string
	set   bool
}

func (v *managedStringFlag) String() string { return v.value }
func (v *managedStringFlag) Set(value string) error {
	if v.set {
		return errors.New("option may be specified only once")
	}
	v.value, v.set = value, true
	return nil
}

func runManagedRelay(arguments []string, input io.Reader, output, diagnostics io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return executeManagedRelay(ctx, arguments, input, output, diagnostics, managedOperations{
		prepareSetup: relaysetup.PrepareSetup, applySetup: relaysetup.ApplySetupWithResult,
		register: relaysetup.RegisterInstance, registerURL: relaysetup.RegisterURL,
		cleanup: relaysetup.CleanupInstance, uninstall: relaysetup.UninstallInstance,
		uninstallAll: relaysetup.UninstallAllManaged, list: relaysetup.ListInstances,
		lockPackage: relaysetup.LockPackage,
	})
}

func executeManagedRelay(ctx context.Context, arguments []string, input io.Reader, output, diagnostics io.Writer, operations managedOperations) int {
	usage := func() int {
		fmt.Fprintln(diagnostics, "usage: owntransit-relay setup [--instance NAME] [--url PUBLIC_URL] | approve [--instance NAME | --url PUBLIC_URL] TARGET_ID | register [legacy codes] | list | uninstall-managed [--instance NAME]")
		return 2
	}
	if len(arguments) == 0 {
		return usage()
	}
	action := arguments[0]
	registration := action == "register" || action == "approve"
	switch action {
	case "setup", "register", "approve", "list", "uninstall-managed", "uninstall-all-managed", "cleanup-container":
	default:
		return usage()
	}
	flags := flag.NewFlagSet("owntransit-relay "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	instance := managedStringFlag{value: "default"}
	publicURL, packageFD := managedStringFlag{}, managedStringFlag{}
	if action != "list" && action != "uninstall-all-managed" {
		flags.Var(&instance, "instance", "restrict this operation to one exact local relay instance")
	}
	if action == "setup" || registration {
		flags.Var(&publicURL, "url", "this instance's public URL, for example wss://relay.example/connects")
	}
	if action == "uninstall-managed" || action == "uninstall-all-managed" {
		flags.Var(&packageFD, "package-lock-fd", "internal installer handoff of protected lock descriptor 9")
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := relaysetup.ValidateInstanceName(instance.value); err != nil || (instance.set && instance.value == "") {
		fmt.Fprintln(diagnostics, "Relay instance must be 1..32 lowercase letters, digits or hyphens, starting with a letter; 'all' is reserved.")
		return 2
	}
	if registration && instance.set && publicURL.set {
		fmt.Fprintln(diagnostics, "Select registration by either --instance or --url, not both.")
		return 2
	}
	fd := 0
	if packageFD.set {
		if packageFD.value != "9" {
			return usage()
		}
		fd = 9
	}
	wantArgs := 0
	if registration {
		wantArgs = 1
	} else if action == "cleanup-container" {
		wantArgs = 2
	}
	if flags.NArg() != wantArgs {
		return usage()
	}
	if registration {
		id, err := protocol.ParseID(flags.Arg(0))
		if err != nil || id == (protocol.ID{}) {
			fmt.Fprintln(diagnostics, "Enter the public Target ID. Keep its private pairing code off the Relay.")
			return 2
		}
	}
	// One bounded reader preserves any buffered confirmation after the URL.
	reader := bufio.NewReader(io.LimitReader(input, 8193))
	if action == "setup" {
		if publicURL.value == "" {
			if publicURL.set {
				return usage()
			}
			fmt.Fprintln(output, "Relay VPS — enter the public URL to configure.")
			for attempt := 0; attempt < 3; attempt++ {
				fmt.Fprint(output, "Public relay URL (for example wss://relay.example/connects): ")
				line, err := readManagedLine(ctx, reader, 2048)
				if err != nil {
					fmt.Fprintln(diagnostics, "Setup has not started. Retry on this Relay VPS: sudo owntransit-relay setup")
					return 2
				}
				if canonical, err := relaysetup.PublicURL(line); err == nil {
					publicURL.value = canonical
					break
				}
				fmt.Fprintln(diagnostics, "Enter only your public relay URL, such as wss://relay.example/connects. This prompt does not accept shell commands.")
			}
		}
		canonical, err := relaysetup.PublicURL(publicURL.value)
		if err != nil {
			fmt.Fprintln(diagnostics, "Relay setup needs a URL such as wss://relay.example/connects, not a shell command.")
			return 2
		}
		publicURL.value = canonical
	}
	if registration && publicURL.set {
		canonical, err := relaysetup.PublicURL(publicURL.value)
		if err != nil {
			fmt.Fprintln(diagnostics, "Approval needs the Relay URL shown on the Target.")
			return 2
		}
		publicURL.value = canonical
	}
	// Cleanup is a systemd hook invoked while setup may own the package/global
	// locks. It deliberately uses only exact-instance ownership checks instead
	// of reacquiring those locks and deadlocking the parent operation.
	if action != "cleanup-container" && action != "list" {
		if operations.lockPackage == nil {
			fmt.Fprintln(diagnostics, "Relay package coordination is unavailable.")
			return 1
		}
		lock, err := operations.lockPackage(fd)
		if err != nil {
			fmt.Fprintln(diagnostics, err)
			return 1
		}
		defer lock.Close()
	}
	var err error
	switch action {
	case "setup":
		selected := ""
		if instance.set {
			selected = instance.value
		}
		var plan relaysetup.SetupPlan
		plan, err = operations.prepareSetup(ctx, selected, publicURL.value)
		if err == nil {
			fmt.Fprintf(output, "Selected local relay: %s\nPublic URL: %s\n", plan.Instance, plan.URL)
			if plan.Port != 0 {
				fmt.Fprintf(output, "Loopback port: %d\n", plan.Port)
			}
			if plan.Verification == relaysetup.VerificationLocal403 {
				fmt.Fprintln(output, "Local verification only: HTTP 403 from this VPS leaves public reachability unverified.")
			}
			confirmed := false
			if plan.Kind == "migration" {
				fmt.Fprintf(output, "Adopt the existing relay into local instance %s.\nSource service: %s\nSource container: %s\nRetained relay state: %s\n", plan.Instance, plan.LegacyUnit, plan.LegacyContainer, plan.LegacyState)
				fmt.Fprintln(output, "Setup stops this service, replaces its container, and removes the old service after verification. Relay keys, URL and port are retained. Failed cutover attempts to restore the previous Relay.")
				if plan.Verification == relaysetup.VerificationLocal403 {
					fmt.Fprint(output, "Adopt this Relay with local verification only (public reachability unverified)? Type yes: ")
				} else {
					fmt.Fprint(output, "Adopt this Relay on this VPS? Type yes: ")
				}
				answer, readErr := readManagedLine(ctx, reader, 16)
				if readErr != nil || strings.TrimSpace(answer) != "yes" {
					fmt.Fprintln(diagnostics, "Relay adoption cancelled. Retry with the same setup command to review it again.")
					return 1
				}
				confirmed = true
			}
			var result relaysetup.SetupResult
			result, err = operations.applySetup(ctx, plan, confirmed, output)
			if err == nil {
				err = printRelaySetupHandoff(output, plan.URL, plan.Kind, result.Verification)
			}
		}
	case "register", "approve":
		var code string
		if publicURL.set {
			code, err = operations.registerURL(ctx, publicURL.value, flags.Arg(0))
		} else {
			code, err = operations.register(ctx, instance.value, flags.Arg(0))
		}
		if err == nil {
			if publicURL.set {
				fmt.Fprintf(diagnostics, "Relay URL: %s\n", publicURL.value)
			} else {
				fmt.Fprintf(diagnostics, "Relay instance: %s\n", instance.value)
			}
			if action == "approve" {
				printApprovalHandoff(output, publicURL.value, flags.Arg(0))
			} else {
				fmt.Fprintln(diagnostics, "Legacy Relay registration code for the Client:")
				fmt.Fprintln(output, code)
				fmt.Fprintln(diagnostics, "On the Client:\n  owntransit-client setup --legacy-codes\nEnter the Relay URL, this registration code, and the Target's private otpair1. code. Keep the private code off the Relay.")
			}
		}
	case "uninstall-managed":
		err = operations.uninstall(ctx, instance.value)
		if err == nil {
			fmt.Fprintf(output, "Relay instance %s stopped and disabled. Its keys, admission history, URL/port reservation, unit, website route and shared software are retained.\n", instance.value)
		}
	case "uninstall-all-managed":
		err = operations.uninstallAll(ctx)
		if err == nil {
			fmt.Fprintln(output, "All managed Relay instances stopped and disabled. Keys, admission history, reservations, units, website routes and rollback images are retained.")
		}
	case "cleanup-container":
		err = operations.cleanup(ctx, instance.value, flags.Arg(0), flags.Arg(1))
	case "list":
		err = operations.list(ctx, output)
	}
	if err != nil {
		fmt.Fprintf(diagnostics, "Relay %s: %v\n", action, err)
		switch action {
		case "setup":
			fmt.Fprintln(diagnostics, "On this Relay VPS, inspect instances with sudo owntransit-relay list, resolve the conflict, then retry:")
			fmt.Fprintf(diagnostics, "  sudo owntransit-relay setup")
			if instance.set {
				fmt.Fprintf(diagnostics, " --instance %s", instance.value)
			}
			fmt.Fprintf(diagnostics, " --url %s\n", publicURL.value)
		case "register", "approve":
			fmt.Fprintln(diagnostics, "On this Relay VPS, finish Relay setup, then choose Continue for this tunnel and retry the same public Target ID:")
			if publicURL.set {
				fmt.Fprintf(diagnostics, "  sudo owntransit-relay setup --url %s\n", publicURL.value)
			} else {
				fmt.Fprintf(diagnostics, "  sudo owntransit-relay setup --instance %s\n", instance.value)
			}
		}
		return 1
	}
	return 0
}

// Signal cancellation must exit a guided prompt even when the terminal is
// waiting for Enter. The result channel is buffered so the reader can finish
// independently when the caller leaves the cancelled command.
func readManagedLine(ctx context.Context, reader *bufio.Reader, maximum int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	type result struct {
		line string
		err  error
	}
	ready := make(chan result, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if len(line) > maximum {
			err = errors.New("input exceeds prompt limit")
		}
		ready <- result{line, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-ready:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return value.line, value.err
	}
}

func printRelaySetupHandoff(output io.Writer, publicURL, kind, verification string) error {
	switch verification {
	case relaysetup.VerificationPublic:
		fmt.Fprintf(output, "Relay configured. URL: %s\n", publicURL)
	case relaysetup.VerificationLocal403:
		fmt.Fprintf(output, "Relay configured with local verification only. URL: %s\n", publicURL)
		fmt.Fprintln(output, "HTTP 403 from this VPS: public reachability remains unverified. Continue from a network allowed by this website.")
	default:
		return errors.New("setup returned no recognized verification result; public reachability was not established")
	}
	fmt.Fprintln(output, "New tunnels stay UNDER CONSTRUCTION until the Client's end-to-end check succeeds.")
	if kind == "managed" || kind == "migration" {
		fmt.Fprintln(output, "Existing pairing identities and Relay URL are retained.")
	}
	fmt.Fprintln(output, "Next on the Target computer running SSH:\n  sudo owntransit-target setup\nChoose New tunnel, or Continue for saved setup. Use the Relay URL above. The Target provides its public ID for Relay approval and one private code for the Client.")
	fmt.Fprintf(output, "Then return to this Relay:\n  sudo owntransit-relay setup --url %s\nChoose New tunnel if no plan exists, then Continue to approve the Target ID.\n", publicURL)
	return nil
}

func printApprovalHandoff(output io.Writer, publicURL, receiverID string) {
	fmt.Fprintln(output, "Target approved — UNDER CONSTRUCTION. The Client still needs to check the tunnel.")
	fmt.Fprintln(output, "Next on the Client, without sudo:\n  owntransit-client setup\nChoose New tunnel, or Continue if already started.")
	if publicURL != "" {
		fmt.Fprintf(output, "Relay URL: %s\n", publicURL)
	}
	fmt.Fprintln(output, "Use the Target's private code on the Client. Keep it off the Relay.")
	fmt.Fprintf(output, "Lost the code? On the Target:\n  sudo owntransit-target code --target-id %s\n", receiverID)
}
