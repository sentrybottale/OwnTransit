package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/relaysetup"
)

type managedOperations struct {
	setup        func(context.Context, string, string, io.Writer) error
	register     func(context.Context, string, string) (string, error)
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
		setup: relaysetup.SetupInstance, register: relaysetup.RegisterInstance,
		cleanup: relaysetup.CleanupInstance, uninstall: relaysetup.UninstallInstance,
		uninstallAll: relaysetup.UninstallAllManaged, list: relaysetup.ListInstances,
		lockPackage: relaysetup.LockPackage,
	})
}

func executeManagedRelay(ctx context.Context, arguments []string, input io.Reader, output, diagnostics io.Writer, operations managedOperations) int {
	usage := func() int {
		fmt.Fprintln(diagnostics, "usage: owntransit-relay setup [--instance NAME] [--url PUBLIC_URL] | register [--instance NAME] RECEIVER_ID | list | uninstall-managed [--instance NAME]")
		return 2
	}
	if len(arguments) == 0 {
		return usage()
	}
	action := arguments[0]
	switch action {
	case "setup", "register", "list", "uninstall-managed", "uninstall-all-managed", "cleanup-container":
	default:
		return usage()
	}
	flags := flag.NewFlagSet("owntransit-relay "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	instance := managedStringFlag{value: "default"}
	publicURL, packageFD := managedStringFlag{}, managedStringFlag{}
	if action != "list" && action != "uninstall-all-managed" {
		flags.Var(&instance, "instance", "local managed relay instance (default keeps the existing relay)")
	}
	if action == "setup" {
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
	fd := 0
	if packageFD.set {
		if packageFD.value != "9" {
			return usage()
		}
		fd = 9
	}
	wantArgs := 0
	if action == "register" {
		wantArgs = 1
	} else if action == "cleanup-container" {
		wantArgs = 2
	}
	if flags.NArg() != wantArgs {
		return usage()
	}
	if action == "register" {
		id, err := protocol.ParseID(flags.Arg(0))
		if err != nil || id == (protocol.ID{}) {
			fmt.Fprintln(diagnostics, "Give the public receiver ID printed on the receiving SSH machine, not a pairing code.")
			return 2
		}
	}
	if action == "setup" {
		if publicURL.value == "" {
			if publicURL.set {
				return usage()
			}
			fmt.Fprintf(output, "Relay instance: %s\nPublic relay URL (for example wss://relay.example/connects): ", instance.value)
			reader := bufio.NewReader(io.LimitReader(input, 2049))
			line, err := reader.ReadString('\n')
			if err != nil || len(line) > 2048 {
				fmt.Fprintln(diagnostics, "Enter the public relay URL, then press Enter.")
				return 2
			}
			publicURL.value = line
		}
		canonical, err := relaysetup.PublicURL(publicURL.value)
		if err != nil {
			fmt.Fprintln(diagnostics, "Relay setup needs a URL such as wss://relay.example/connects, not a shell command.")
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
		err = operations.setup(ctx, instance.value, publicURL.value, output)
	case "register":
		var code string
		code, err = operations.register(ctx, instance.value, flags.Arg(0))
		if err == nil {
			fmt.Fprintf(diagnostics, "Relay instance: %s\nVPS registration code (give to your client):\n", instance.value)
			fmt.Fprintln(output, code)
			fmt.Fprintln(diagnostics, "\nNEXT — on your client:\n  owntransit-preview pair setup --tunnel NAME\nChoose your client-local tunnel name. Enter this relay's URL, the VPS code above, and the private code from your receiving SSH machine. Never give that private code to the relay.")
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
		return 1
	}
	return 0
}
