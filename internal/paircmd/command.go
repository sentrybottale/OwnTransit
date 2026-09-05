//go:build darwin || linux

// Package paircmd exposes the receiver-owned profile without changing legacy
// setup semantics or permitting it through a privileged legacy proxy inode.
package paircmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
)

func defaultState(receiver bool) (string, error) {
	if receiver {
		return "/var/lib/owntransit-pair", nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "owntransit-pair"), nil
}

// Run accepts secrets only from input. Diagnostic errors never include user
// input, certificate material, relay responses or private state content.
func Run(receiver bool, args []string, input io.Reader, output, diagnostics io.Writer) int {
	if os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		fmt.Fprintln(diagnostics, "owntransit pair: privileged proxy entry is not supported")
		return 1
	}
	role := "client"
	if receiver {
		role = "connector"
	}
	if len(args) == 0 {
		fmt.Fprintf(diagnostics, "usage: owntransit%s pair %s --state PATH\n", map[bool]string{true: "-connector", false: ""}[receiver], map[bool]string{true: "init|serve|status|lock|unlock", false: "init|resume|proxy|status|lock|unlock"}[receiver])
		return 2
	}
	operation := args[0]
	if operation == "worker" && receiver {
		return runWorker(args[1:], input, output, diagnostics)
	}
	if operation == "discover-worker" && receiver {
		return discoverWorker(args[1:], output)
	}
	if receiver && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
		fmt.Fprintln(diagnostics, "owntransit connector pair: requires Linux root; the network worker drops privileges")
		return 1
	}
	if !receiver && os.Geteuid() == 0 {
		fmt.Fprintln(diagnostics, "owntransit client pair: run as the local SSH client user, not root")
		return 1
	}
	base, err := defaultState(receiver)
	if err != nil {
		return 1
	}
	flags := flag.NewFlagSet("pair "+operation, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	state := flags.String("state", base, "private state directory for this local role")
	origin := flags.String("relay", "", "canonical wss://relay.example/connects URL (init only)")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*state) || filepath.Clean(*state) != *state || (*origin != "" && operation != "init") {
		fmt.Fprintln(diagnostics, "owntransit pair: invalid arguments")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch operation {
	case "init":
		if *origin == "" {
			fmt.Fprintln(diagnostics, "owntransit pair init: --relay wss://relay.example/connects is required")
			return 2
		}
		if _, err := pairrelay.NewPublicClient(*origin, nil); err != nil {
			fmt.Fprintln(diagnostics, "owntransit pair init: invalid relay URL")
			return 2
		}
		if err = os.MkdirAll(filepath.Dir(*state), 0700); err != nil {
			break
		}
		if receiver {
			var info pairrelay.ServerInfo
			info, err = discover(ctx, *origin)
			if err != nil {
				break
			}
			var attempt receiverpairing.Attempt
			attempt, err = pairruntime.InitializeReceiver(*state, *origin, info)
			if err != nil {
				break
			}
			fmt.Fprintf(output, "Receiver ID (give to relay):\n%s\n\nPrivate one-use pairing code (give only to your client):\n%s\n\nKeep this code private. It expires in 24 hours.\nNext: owntransit-connector pair serve --state %s\n", attempt.ReceiverID, attempt.Code, *state)
		} else {
			reader := bufio.NewReaderSize(input, 4096)
			var relayCode, privateCode []byte
			relayCode, err = readLine(input, reader, diagnostics, "Relay code: ", pairrelaycmd.MaxRegistrationCode)
			if err != nil {
				break
			}
			registration, e := pairrelaycmd.DecodeRegistration(string(relayCode))
			if e != nil {
				err = e
				break
			}
			privateCode, err = readLine(input, reader, diagnostics, "Private receiver pairing code: ", receiverpairing.MaxCodeSize)
			if err != nil {
				break
			}
			bounded, c := context.WithTimeout(ctx, time.Minute)
			err = pairruntime.PairClient(bounded, *state, *origin, privateCode, registration, nil)
			c()
			for i := range privateCode {
				privateCode[i] = 0
			}
			if err == nil {
				fmt.Fprintln(output, "Paired. Use your existing SSH identity and host-key policy with:\n  ssh -o 'ProxyCommand=owntransit pair proxy' USER@SSH_ALIAS\nIf you selected --state, include that same path in the ProxyCommand.")
			}
		}
	case "resume":
		if receiver {
			return 2
		}
		bounded, c := context.WithTimeout(ctx, time.Minute)
		err = pairruntime.ResumeClient(bounded, *state, nil)
		c()
		if err == nil {
			fmt.Fprintln(output, "Pairing saved. Ready to open an SSH carrier.")
		}
	case "proxy":
		if receiver {
			return 2
		}
		err = pairruntime.Proxy(ctx, *state, input, output)
	case "serve":
		if !receiver {
			return 2
		}
		err = serveBroker(ctx, *state, diagnostics)
	case "lock", "unlock":
		bounded, c := context.WithTimeout(ctx, 5*time.Second)
		err = pairruntime.SetLocked(bounded, *state, receiver, operation == "lock")
		c()
		if err == nil {
			if operation == "lock" {
				fmt.Fprintln(output, "Locked durably; local workers stopped. Peer cutoff is bounded by its authorization lease.")
			} else {
				fmt.Fprintln(output, "Unlocked locally. A fresh authenticated connection is required.")
			}
		}
	case "status":
		var p pairruntime.Policy
		p, err = pairruntime.ReadPolicy(*state)
		if err == nil {
			fmt.Fprintf(output, "Role: %s\nLocked: %t\nPolicy generation: %d\n", role, p.Locked, p.Generation)
		}
	default:
		return 2
	}
	if err != nil {
		fmt.Fprintln(diagnostics, "owntransit pair: operation failed; no trust was reset. Check the local role state and relay availability. For an interrupted client pairing, use pair resume. A failed lock acknowledgement may still have durably locked the endpoint.")
		return 1
	}
	return 0
}

func readLine(input io.Reader, reader *bufio.Reader, diagnostics io.Writer, prompt string, limit int) ([]byte, error) {
	fmt.Fprint(diagnostics, prompt)
	restore := func() {}
	if f, ok := input.(*os.File); ok {
		var err error
		restore, err = hideEcho(f)
		if err != nil {
			return nil, err
		}
	}
	defer restore()
	defer fmt.Fprintln(diagnostics)
	var out []byte
	for len(out) <= limit {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' {
			out = []byte(strings.TrimSuffix(string(out), "\r"))
			if len(out) == 0 {
				return nil, pairruntime.ErrState
			}
			return out, nil
		}
		out = append(out, b)
	}
	return nil, pairruntime.ErrState
}

func discoverWorker(args []string, output io.Writer) int {
	if os.Geteuid() == 0 || len(args) != 1 {
		return 1
	}
	p, err := pairrelay.NewPublicClient(args[0], nil)
	if err != nil {
		return 1
	}
	ctx, c := context.WithTimeout(context.Background(), 15*time.Second)
	defer c()
	info, err := p.FetchServerInfo(ctx)
	if err != nil {
		return 1
	}
	if json.NewEncoder(output).Encode(info) != nil {
		return 1
	}
	return 0
}
