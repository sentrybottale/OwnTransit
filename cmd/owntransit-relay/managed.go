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
		fmt.Fprintln(diagnostics, "usage: owntransit-relay setup [--instance NAME] [--url PUBLIC_URL] | approve [--instance NAME | --url PUBLIC_URL] RECEIVER_ID | register [legacy codes] | list | uninstall-managed [--instance NAME]")
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
			fmt.Fprintln(diagnostics, "Give the public receiver ID printed on the receiving SSH machine, not a pairing code.")
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
			fmt.Fprintln(output, "THIS MACHINE: public relay VPS. Enter the URL whose local relay you want to set up or upgrade.")
			for attempt := 0; attempt < 3; attempt++ {
				fmt.Fprint(output, "Public relay URL (for example wss://relay.example/connects): ")
				line, err := readManagedLine(ctx, reader, 2048)
				if err != nil {
					fmt.Fprintln(diagnostics, "Setup has not started. On this VPS, rerun relay setup, enter the public relay URL, then press Enter.")
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
			fmt.Fprintln(diagnostics, "Registration needs the public relay URL printed by your receiving SSH machine.")
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
				fmt.Fprintln(output, "Verification: local relay identity and selected website route only. The public HTTPS route returned HTTP 403 from THIS VPS; public reachability is unverified here.")
			}
			confirmed := false
			if plan.Kind == "migration" {
				fmt.Fprintf(output, "Adopt the existing relay into local instance %s.\nSource service: %s\nSource container: %s\nRetained relay state: %s\n", plan.Instance, plan.LegacyUnit, plan.LegacyContainer, plan.LegacyState)
				fmt.Fprintln(output, "Setup will stop this source service and replace its container while preserving its relay URL, keys and port. Paired endpoints retain their identities. After verification, setup removes the old service and its restart configuration. If cutover fails, setup attempts to restore the old relay and reports any recovery needed.")
				if plan.Verification == relaysetup.VerificationLocal403 {
					fmt.Fprint(output, "Adopt this exact relay using local verification, with public reachability unverified from THIS VPS? Type yes, then press Enter: ")
				} else {
					fmt.Fprint(output, "Adopt this exact relay on THIS VPS? Type yes, then press Enter: ")
				}
				answer, readErr := readManagedLine(ctx, reader, 16)
				if readErr != nil || strings.TrimSpace(answer) != "yes" {
					fmt.Fprintln(diagnostics, "Relay adoption cancelled; no relay was changed. On THIS VPS, rerun the same setup command to review and adopt this relay.")
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
				fmt.Fprintln(diagnostics, "Legacy VPS registration code (give to your client):")
				fmt.Fprintln(output, code)
				fmt.Fprintln(diagnostics, "\nNEXT — on your legacy client:\n  owntransit-preview pair setup --legacy-codes\nEnter this relay's URL, the VPS code above, and the private otpair1. code from your receiving SSH machine. Never give that private code to the relay.")
			}
		}
	case "uninstall-managed":
		err = operations.uninstall(ctx, instance.value)
		if err == nil {
			fmt.Fprintf(output, "Relay instance %s stopped and disabled. Keys, URL/port reservation, unit, website route and shared software retained. Other instances are unchanged.\n", instance.value)
		}
	case "uninstall-all-managed":
		err = operations.uninstallAll(ctx)
		if err == nil {
			fmt.Fprintln(output, "All recognized managed relay instances stopped and disabled. Keys, instance reservations, unit configuration, website routes and rollback images retained.")
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
			fmt.Fprintln(diagnostics, "NEXT — on THIS VPS: inspect local relays with sudo owntransit-relay-preview list, resolve the reported conflict, then rerun setup with this same URL.")
			fmt.Fprintf(diagnostics, "  sudo owntransit-relay-preview setup")
			if instance.set {
				fmt.Fprintf(diagnostics, " --instance %s", instance.value)
			}
			fmt.Fprintf(diagnostics, " --url %s\n", publicURL.value)
		case "register", "approve":
			fmt.Fprintln(diagnostics, "NEXT — on THIS VPS: run sudo owntransit-relay-preview list and finish setup of the relay selected by your receiving SSH machine's approval command, then rerun that exact approval command.")
			if publicURL.set {
				fmt.Fprintf(diagnostics, "  sudo owntransit-relay-preview setup --url %s\n", publicURL.value)
			} else {
				fmt.Fprintf(diagnostics, "  sudo owntransit-relay-preview setup --instance %s\n", instance.value)
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
		fmt.Fprintf(output, "Relay component configured. Relay URL: %s\n", publicURL)
	case relaysetup.VerificationLocal403:
		fmt.Fprintf(output, "Relay component configured with local verification only. Relay URL: %s\n", publicURL)
		fmt.Fprintln(output, "Public reachability is unverified from THIS VPS: the public HTTPS route returned HTTP 403. Complete receiver and client setup from networks allowed by this website; a successful endpoint connection provides the remaining public reachability check.")
	default:
		return errors.New("setup returned no recognized verification result; public reachability was not established")
	}
	fmt.Fprintln(output, "New tunnels remain UNDER CONSTRUCTION until client pairing and an end-to-end check succeed. Relay setup alone does not prove a working tunnel.")
	if kind == "managed" || kind == "migration" {
		fmt.Fprintln(output, "Paired endpoints retain their existing identities and relay URL. For a new connection, continue below.")
	}
	fmt.Fprintln(output, "NEXT — on your RECEIVING SSH MACHINE (the private computer running your SSH server):\n  curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- connector\nThen run on that receiving SSH machine:\n  sudo owntransit-connector-preview pair setup\nRepeated setup retains its existing pairing. For state-specific recovery:\n  sudo owntransit-connector-preview pair next")
	fmt.Fprintf(output, "Enter %s. Receiver setup prints one VPS approval command and one private code for your client computer. Return to THIS VPS only to run that approval command.\n", publicURL)
	return nil
}

func printApprovalHandoff(output io.Writer, publicURL, receiverID string) {
	fmt.Fprintln(output, "Receiver approved. UNDER CONSTRUCTION — client pairing and an end-to-end check are still required. No VPS code to copy.")
	fmt.Fprintf(output, "MISSING THE PRIVATE CODE? Use your receiving machine's console or SSH from your trusted client, NOT an SSH session started on this VPS. Run on that RECEIVING SSH MACHINE:\n  sudo owntransit-connector-preview pair code --receiver-id %s\nThat retrieves the SAME unused code for this receiver. If it expired or came from an older release, that command explains how to replace it explicitly. Do not re-approve unless receiver setup gives you a NEW ID.\n", receiverID)
	fmt.Fprintln(output, "If that command is unavailable, upgrade the connector on THAT receiving machine:\n  curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- connector")
	fmt.Fprintln(output, "NEXT — on your CLIENT COMPUTER, without sudo:")
	for _, client := range []struct{ label, command string }{{"Linux", "/usr/local/bin/owntransit-preview"}, {"Mac", `"$HOME/.local/bin/owntransit-preview"`}} {
		fmt.Fprintf(output, "%s client:\n  %s pair setup", client.label, client.command)
		if publicURL != "" {
			fmt.Fprintf(output, " --relay '%s'", publicURL)
		}
		fmt.Fprintln(output)
	}
	fmt.Fprintln(output, "Paste the private code from the receiving machine. If interrupted, client pair next prints the exact resume/check command. Never paste private codes on this VPS.")
	fmt.Fprintln(output, "Client not installed? Run only the installer for THAT client computer:")
	fmt.Fprintln(output, "Linux client:\n  curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- client\nMac client:\n  curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-macos.sh | sh -s -- client")
}
