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
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/relaysetup"
)

type pairOperations struct {
	init     func(string) ([]byte, error)
	serve    func(string, io.Writer) error
	register func(string, protocol.ID) (string, error)
}

func runPairCommand(arguments []string, output, diagnostics io.Writer) int {
	if len(arguments) > 0 && arguments[0] == "info" {
		flags := flag.NewFlagSet("pair info", flag.ContinueOnError)
		flags.SetOutput(diagnostics)
		state := flags.String("state", "", "private relay state")
		if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 || *state == "" {
			return 2
		}
		data, err := pairrelaycmd.StateInfo(*state)
		if err != nil {
			fmt.Fprintln(diagnostics, "relay state is unavailable")
			return 1
		}
		_, err = output.Write(append(data, '\n'))
		if err != nil {
			return 1
		}
		return 0
	}
	return executePairCommand(arguments, output, diagnostics, pairOperations{
		init: func(path string) ([]byte, error) { return pairrelaycmd.Init(path, time.Now().UTC()) },
		serve: func(path string, diagnostics io.Writer) error {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return pairrelaycmd.Serve(ctx, path, diagnostics)
		},
		register: func(path string, receiverID protocol.ID) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return pairrelaycmd.Register(ctx, path, receiverID)
		},
	})
}

func runManagedRelay(arguments []string, input io.Reader, output, diagnostics io.Writer) int {
	if len(arguments) == 0 {
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if arguments[0] == "register" {
		if len(arguments) != 2 {
			return 2
		}
		if _, err := protocol.ParseID(arguments[1]); err != nil {
			return 2
		}
		code, err := relaysetup.RegisterManaged(ctx, arguments[1])
		if err != nil {
			fmt.Fprintln(diagnostics, err)
			return 1
		}
		fmt.Fprintln(diagnostics, "Relay code (give to your client):")
		fmt.Fprintln(output, code)
		fmt.Fprintln(diagnostics, "\nNEXT — on your client:\n  owntransit-preview pair setup\nEnter your relay URL, the relay code above, and the receiver's private one-use pairing code. Never give the private receiver code to this relay.")
		return 0
	}
	flags := flag.NewFlagSet("relay setup", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	publicURL := flags.String("url", "", "public URL, for example wss://relay.example/connects")
	if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	if *publicURL == "" {
		fmt.Fprint(output, "Public relay URL (for example wss://your-domain/connects): ")
		reader := bufio.NewReader(io.LimitReader(input, 2049))
		line, err := reader.ReadString('\n')
		if err != nil {
			return 2
		}
		*publicURL = line
	}
	if err := relaysetup.Setup(ctx, *publicURL, output); err != nil {
		fmt.Fprintf(diagnostics, "Relay setup: %v\n", err)
		return 1
	}
	return 0
}

func executePairCommand(arguments []string, output, diagnostics io.Writer, operations pairOperations) int {
	if len(arguments) == 0 {
		fmt.Fprintln(diagnostics, "usage: owntransit-relay pair init|serve|register --state ABSOLUTE_PATH [RECEIVER_ID]")
		return 2
	}
	action := arguments[0]
	if action == "help" || action == "-h" || action == "--help" {
		if len(arguments) != 1 {
			fmt.Fprintln(diagnostics, "owntransit-relay pair help: unexpected argument")
			return 2
		}
		fmt.Fprintln(output, "usage: owntransit-relay pair init|serve|register --state ABSOLUTE_PATH [RECEIVER_ID]")
		return 0
	}
	flags := flag.NewFlagSet("owntransit-relay pair "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	state := flags.String("state", "", "private root-owned relay pairing state")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *state == "" {
		fmt.Fprintf(diagnostics, "owntransit-relay pair %s: -state is required\n", action)
		return 2
	}
	switch action {
	case "init":
		if flags.NArg() != 0 || operations.init == nil {
			fmt.Fprintln(diagnostics, "owntransit-relay pair init: no positional arguments are accepted")
			return 2
		}
		summary, err := operations.init(*state)
		if err != nil {
			fmt.Fprintln(diagnostics, "owntransit-relay pair init: operation failed")
			return 1
		}
		if _, err := output.Write(summary); err != nil {
			fmt.Fprintln(diagnostics, "owntransit-relay pair init: write public summary failed")
			return 1
		}
		return 0
	case "serve":
		if flags.NArg() != 0 || operations.serve == nil {
			fmt.Fprintln(diagnostics, "owntransit-relay pair serve: no positional arguments are accepted")
			return 2
		}
		if err := operations.serve(*state, diagnostics); err != nil {
			fmt.Fprintln(diagnostics, "owntransit-relay pair serve: operation failed")
			return 1
		}
		return 0
	case "register":
		if flags.NArg() != 1 || operations.register == nil {
			fmt.Fprintln(diagnostics, "owntransit-relay pair register: exactly one receiver ID is required")
			return 2
		}
		receiverID, err := protocol.ParseID(flags.Arg(0))
		if err != nil || receiverID == (protocol.ID{}) {
			fmt.Fprintln(diagnostics, "owntransit-relay pair register: receiver ID is invalid")
			return 2
		}
		code, err := operations.register(*state, receiverID)
		if err != nil {
			fmt.Fprintln(diagnostics, "owntransit-relay pair register: operation failed")
			return 1
		}
		fmt.Fprintln(output, code)
		return 0
	default:
		fmt.Fprintf(diagnostics, "owntransit-relay pair: unknown operation %q\n", action)
		return 2
	}
}
