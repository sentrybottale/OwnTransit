//go:build darwin || linux

// Package paircmd exposes the receiver-owned profile without changing legacy
// setup semantics or permitting it through a privileged legacy proxy inode.
package paircmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/pairoffer"
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
		fmt.Fprintf(diagnostics, "usage: owntransit%s pair %s [--tunnel NAME | --state PATH]\n", map[bool]string{true: "-connector", false: ""}[receiver], map[bool]string{true: "setup|code|next|init|serve|restart|list|status|alarm", false: "setup|next|check|init|resume|proxy|list|status|alarm"}[receiver])
		return 2
	}
	operation := args[0]
	if operation == "worker" && receiver {
		return runWorker(args[1:], input, output, diagnostics)
	}
	if operation == "discover-worker" && receiver {
		return discoverWorker(args[1:], output)
	}
	if operation == "discover-offer-worker" && receiver {
		return discoverWorkerProfile(args[1:], output, true)
	}
	if receiver && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
		fmt.Fprintln(diagnostics, "Receiver commands run with sudo on the RECEIVING SSH MACHINE, the Linux computer running your SSH server. For new setup there, run: sudo owntransit-connector-preview pair setup")
		return 1
	}
	if !receiver && os.Geteuid() == 0 {
		fmt.Fprintln(diagnostics, "Client commands run on your CLIENT COMPUTER, the computer you connect from, as your ordinary user without sudo. On that computer, use the client setup command printed by its installer.\nIf you are currently on the relay VPS, move to your RECEIVING SSH MACHINE first. Run the connector setup command on that receiving machine:\n  sudo owntransit-connector-preview pair setup")
		return 1
	}
	base, err := defaultState(receiver)
	if err != nil {
		return 1
	}
	flags := flag.NewFlagSet("pair "+operation, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	for _, selector := range []string{"tunnel", "state", "receiver-id"} {
		count := 0
		for _, arg := range args[1:] {
			if arg == "--"+selector || arg == "-"+selector || strings.HasPrefix(arg, "--"+selector+"=") || strings.HasPrefix(arg, "-"+selector+"=") {
				count++
			}
		}
		if count > 1 {
			fmt.Fprintln(diagnostics, "Specify each tunnel/state selector only once.")
			return 2
		}
	}
	state := flags.String("state", base, "private state directory for this local role")
	tunnel := flags.String("tunnel", "", "local tunnel name (default keeps the original pairing)")
	origin := flags.String("relay", "", "canonical wss://relay.example/connects URL (init only)")
	receiverID := ""
	if receiver && (operation == "code" || operation == "next") {
		flags.StringVar(&receiverID, "receiver-id", "", "public receiver ID from the VPS; selects only a matching local receiver")
	}
	replace := false
	if receiver && operation == "setup" {
		flags.BoolVar(&replace, "replace", false, "explicitly create fresh identities and a new code; old approval must be replaced")
	}
	legacyCodes := false
	if operation == "init" || operation == "setup" {
		flags.BoolVar(&legacyCodes, "legacy-codes", false, "explicit older two-code setup (otrelay1. and otpair1.)")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	explicitState, explicitTunnel, explicitReceiverID := false, false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "state" {
			explicitState = true
		}
		if f.Name == "tunnel" {
			explicitTunnel = true
		}
		if f.Name == "receiver-id" {
			explicitReceiverID = true
		}
	})
	if explicitTunnel {
		if explicitState || !validTunnelName(*tunnel) {
			fmt.Fprintln(diagnostics, "Use --tunnel NAME or --state PATH, not both. Names start with a lowercase letter and contain at most 32 lowercase letters, digits or hyphens; all is reserved.")
			return 2
		}
		*state, _ = tunnelState(base, *tunnel)
	}
	if explicitReceiverID {
		if receiverID == "" {
			fmt.Fprintln(diagnostics, "A complete public receiver ID is required.")
			return 2
		}
		if explicitState || explicitTunnel {
			fmt.Fprintln(diagnostics, "Select the local receiver by --receiver-id OR --tunnel/--state, not both.")
			return 2
		}
		*state, *tunnel, err = receiverByID(base, receiverID)
		if err != nil {
			fmt.Fprintln(diagnostics, "No unique readable local receiver matches this public ID. You may be on the wrong receiving SSH machine, or its pairing was replaced. No state was changed.\nOn the RECEIVING SSH MACHINE, list current receiver IDs:\n  sudo owntransit-connector-preview pair list")
			return 1
		}
	}
	if operation == "list" && (explicitState || explicitTunnel || *origin != "") {
		fmt.Fprintln(diagnostics, "pair list shows all local tunnels; use pair status to select one.")
		return 2
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*state) || filepath.Clean(*state) != *state || (*origin != "" && operation != "init" && operation != "setup") {
		fmt.Fprintln(diagnostics, "owntransit pair: invalid arguments")
		return 2
	}
	// Validate before any state-aware handoff can repeat this value in a command.
	// A private code accidentally pasted as --relay must never be echoed.
	if *origin != "" {
		if _, err := pairrelay.NewPublicClient(*origin, nil); err != nil {
			fmt.Fprintln(diagnostics, "Invalid relay URL. Use only the public wss:// URL, never a private pairing code.")
			return 2
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if receiver && (operation == "setup" || operation == "restart") {
		guard, err := receiverMaintenanceGuard()
		if err != nil {
			fmt.Fprintln(diagnostics, "Connector package maintenance is active or its lock is unavailable. Retry after maintenance completes.")
			return 1
		}
		defer guard.Close()
	}
	clientCommand := os.Args[0]
	if path, e := exec.LookPath(clientCommand); e == nil {
		if absolute, e := filepath.Abs(path); e == nil {
			clientCommand = absolute
		}
	}
	selectedState := ""
	if *state != base {
		selectedState = *state
	}
	reader := bufio.NewReaderSize(input, 4096)
	replacementPeer := ""
	if operation != "proxy" && operation != "serve" && operation != "list" {
		name := *tunnel
		if name == "" {
			name = defaultTunnel
			if explicitState {
				name = "custom state"
			}
		}
		fmt.Fprintf(diagnostics, "Tunnel: %s\n", name)
	}
	switch operation {
	case "list":
		err = listTunnels(base, receiver, output, clientCommand)
	case "next":
		printNext(output, receiver, clientCommand, *state, selectedState, *tunnel, *origin)
	case "code":
		if !receiver {
			return 2
		}
		err = showReceiverCode(output, diagnostics, clientCommand, *state, selectedState, *tunnel, receiverID)
	case "check":
		if receiver {
			return 2
		}
		err = finishClient(ctx, output, diagnostics, clientCommand, *state, selectedState, *tunnel)
	case "init", "setup":
		if operation == "setup" && !receiver {
			if _, e := os.Lstat(*state); e == nil {
				saved, pending, locked, e := pairruntime.ClientSetupSummary(*state)
				if e != nil {
					fmt.Fprintln(diagnostics, "Existing client state could not be read; it was not replaced.")
					printNext(diagnostics, false, clientCommand, *state, selectedState, *tunnel, *origin)
					return 1
				}
				if locked {
					fmt.Fprintln(diagnostics, "This pairing has a terminal security alarm. Rebuild with fresh endpoint identities; do not reuse or unlock the old state.")
					printNext(diagnostics, false, clientCommand, *state, selectedState, *tunnel, *origin)
					return 1
				}
				if *origin != "" && *origin != saved {
					fmt.Fprintln(diagnostics, "This client state belongs to a different relay. It was not replaced.")
					printFreshTunnel(diagnostics, false, clientCommand, *origin)
					return 1
				}
				if pending {
					fmt.Fprintf(output, "UNDER CONSTRUCTION — pairing pending. Resume (no new codes):\n  %s\n", pairCommand(clientCommand, "resume", selectedState, *tunnel))
				} else {
					err = finishClient(ctx, output, diagnostics, clientCommand, *state, selectedState, *tunnel)
					if err != nil {
						fmt.Fprintln(diagnostics, "owntransit:", failureMessage("check", err))
						printNext(diagnostics, false, clientCommand, *state, selectedState, *tunnel, *origin)
						return 1
					}
				}
				return 0
			} else if !os.IsNotExist(e) {
				return 1
			}
		}
		printSetupBanner(diagnostics, receiver, legacyCodes)
		if operation == "setup" && receiver && *tunnel == "" && *state != "/var/lib/owntransit-pair" {
			fmt.Fprintln(diagnostics, "owntransit pair setup: the installed service uses the default state; custom paths use pair init and pair serve")
			return 2
		}
		if operation == "setup" && receiver {
			if err = prepareInstalledReceiver(ctx, *tunnel); err != nil {
				fmt.Fprintln(diagnostics, "Receiver service is missing or modified. Install the connector package before setup; existing pairing was not replaced.")
				break
			}
		}
		if operation == "setup" && receiver {
			if _, e := os.Lstat(*state); e == nil {
				var r *receiverpairing.Receiver
				r, err = receiverpairing.Open(filepath.Join(*state, "authority"))
				if err != nil {
					break
				}
				var s receiverpairing.ReceiverStatus
				s, err = r.Status()
				if err != nil {
					break
				}
				replacementPeer = s.PairedClientID
				if *origin == "" {
					*origin = s.RelayOrigin
				}
				if s.PairedClientID != "" && !replace {
					fmt.Fprintln(output, "Existing pairing retained. Repeating setup does not replace a paired tunnel; --replace is required for deliberate new identities.")
					printNext(output, true, clientCommand, *state, selectedState, *tunnel, s.RelayOrigin)
					if *origin != s.RelayOrigin {
						fmt.Fprintln(diagnostics, "Requested relay differs from the saved pairing. No origin was changed.")
						return 1
					}
					return 0
				}
				if s.PairedClientID == "" && !replace && legacyCodes {
					fmt.Fprintf(diagnostics, "Existing pending pairing retained. A setup retry cannot change its profile or create new identities.\nTo restart without replacing it:\n  sudo %s\nFor deliberate NEW legacy identities and codes:\n  sudo %s --replace --legacy-codes\n", pairCommand(clientCommand, "restart", selectedState, *tunnel), pairCommand(clientCommand, "setup", selectedState, *tunnel))
					return 1
				}
				if s.PairedClientID == "" && !replace {
					if *origin != s.RelayOrigin {
						fmt.Fprintln(diagnostics, "This pending receiver belongs to a different relay. It was not repointed. Use --replace only for a deliberate fresh pairing.")
						printNext(diagnostics, true, clientCommand, *state, selectedState, *tunnel, s.RelayOrigin)
						return 1
					}
					attempt, e := pairruntime.ReceiverCode(*state, time.Now())
					clear(attempt.Code)
					if e != nil {
						printCodeFailure(diagnostics, clientCommand, *state, selectedState, *tunnel, e)
						return 1
					}
					if err = startInstalledReceiver(ctx, *tunnel); err != nil {
						break
					}
					fmt.Fprintln(output, "Pending pairing retained; receiver restarted without new identities.")
					err = showReceiverCode(output, diagnostics, clientCommand, *state, selectedState, *tunnel)
					break
				}
				if s.PairedClientID != "" {
					fmt.Fprintln(diagnostics, "This replaces the existing tunnel with fresh OwnTransit identities and disconnects its client. Use independent SSH or local-console access; SSH keys are unchanged.")
					var answer []byte
					answer, err = readVisibleLine(ctx, input, reader, diagnostics, "Replace this pairing? [y/N]: ", 8)
					if err != nil {
						break
					}
					if !strings.EqualFold(string(answer), "y") && !strings.EqualFold(string(answer), "yes") {
						fmt.Fprintf(output, "Existing pairing retained. Inspect: sudo %s\n", pairCommand(clientCommand, "status", selectedState, *tunnel))
						return 0
					}
				} else {
					fmt.Fprintln(diagnostics, "Creating a fresh receiver ID and one-use code; the previous uncompleted pairing will be retired.")
				}
			} else if !os.IsNotExist(e) {
				err = e
				break
			}
		}
		if operation == "setup" && *origin == "" {
			var value []byte
			value, err = promptValidated(ctx, input, reader, diagnostics, "Public relay URL: ", "Enter your VPS URL, not a shell command (example only: wss://relay.example/connects).", 2048, false, func(v []byte) error { _, e := pairrelay.NewPublicClient(string(v), nil); return e })
			if err != nil {
				break
			}
			*origin = string(value)
		}
		if *origin == "" {
			fmt.Fprintln(diagnostics, "owntransit pair init: --relay wss://relay.example/connects is required")
			return 2
		}
		if _, err := pairrelay.NewPublicClient(*origin, nil); err != nil {
			fmt.Fprintln(diagnostics, "owntransit pair init: invalid relay URL")
			return 2
		}
		if operation == "setup" {
			fmt.Fprintf(diagnostics, "Relay: %s\n", *origin)
		}
		if *tunnel != "" && *tunnel != defaultTunnel {
			if err = ensureTunnelRoot(base); err != nil {
				break
			}
		}
		if err = os.MkdirAll(filepath.Dir(*state), 0700); err != nil {
			break
		}
		if receiver {
			var info pairrelay.ServerInfo
			if legacyCodes {
				info, err = discover(ctx, *origin)
			} else {
				info, err = discoverReceiverOffer(ctx, *origin)
			}
			if err != nil {
				if ctx.Err() != nil {
					err = ctx.Err()
					break
				}
				if legacyCodes {
					fmt.Fprintln(diagnostics, "Receiver was not initialized: the receiver-owned relay could not be reached. Start the relay and check its HTTPS /connects route.")
				} else {
					fmt.Fprintln(diagnostics, "Receiver was not replaced: this relay is unreachable or does not support one-code setup. Check the URL and upgrade the running relay, then retry. Older installations require explicit --legacy-codes on receiver and client setup.")
				}
				break
			}
			var attempt receiverpairing.Attempt
			if operation == "setup" {
				bounded, c := context.WithTimeout(ctx, 10*time.Second)
				if legacyCodes {
					attempt, _, err = pairruntime.RebuildReceiver(bounded, *state, *origin, info, replacementPeer)
				} else {
					attempt, _, err = pairruntime.RebuildReceiverWithOffer(bounded, *state, *origin, info, replacementPeer)
				}
				c()
			} else {
				if legacyCodes {
					attempt, err = pairruntime.InitializeReceiver(*state, *origin, info)
				} else {
					attempt, err = pairruntime.InitializeReceiverWithOffer(*state, *origin, info)
				}
			}
			if err != nil {
				break
			}
			defer clear(attempt.Code)
			if operation == "setup" {
				err = startInstalledReceiver(ctx, *tunnel)
				if err != nil {
					unit, _ := receiverUnit(*tunnel)
					fmt.Fprintf(diagnostics, "UNDER CONSTRUCTION — receiver setup is saved, but advertisement was not confirmed. Inspect on THIS receiving machine:\n  sudo journalctl -u %s -n 20 --no-pager\nRetry its restart command below; keep the saved identities and code.\n", unit)
					break
				}
			}
			err = printReceiverCode(output, attempt.ReceiverID, attempt.Code, legacyCodes)
			if err != nil {
				break
			}
			fmt.Fprintf(output, "Code expires: %s\n", attempt.Expires.UTC().Format(time.RFC3339))
			if operation == "setup" {
				fmt.Fprintln(output, "Receiver advertising and enabled for reboot.")
			} else {
				fmt.Fprintf(output, "Start this receiver: owntransit-connector pair serve --state %s\n", *state)
			}
			printReceiverNext(output, *origin, attempt.ReceiverID, *tunnel, legacyCodes)
		} else {
			if !legacyCodes {
				var privateCode []byte
				privateCode, err = readShortPairingCode(ctx, input, reader, diagnostics)
				if err != nil {
					break
				}
				bounded, c := context.WithTimeout(ctx, time.Minute)
				err = pairruntime.PairClientShort(bounded, *state, *origin, privateCode, nil)
				c()
				clear(privateCode)
				if err == nil {
					err = finishClient(ctx, output, diagnostics, clientCommand, *state, selectedState, *tunnel)
				}
				break
			}
			var relayCode, privateCode []byte
			relayCode, err = promptValidated(ctx, input, reader, diagnostics, "VPS registration code (otrelay1., hidden): ", "Run the URL-specific relay registration command printed by receiver setup on your VPS; paste its complete otrelay1. code here.", pairrelaycmd.MaxRegistrationCode, true, func(v []byte) error { _, e := pairrelaycmd.DecodeRegistration(string(v)); return e })
			if err != nil {
				break
			}
			registration, e := pairrelaycmd.DecodeRegistration(string(relayCode))
			if e != nil {
				err = e
				break
			}
			privateCode, err = promptValidated(ctx, input, reader, diagnostics, "Private SSH-machine code (otpair1., hidden): ", "Get the complete, unexpired otpair1. code from receiver setup on your SSH machine. Never give it to the VPS.", receiverpairing.MaxCodeSize, true, func(v []byte) error { return receiverpairing.ValidateCodeInput(v, time.Now()) })
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
				err = finishClient(ctx, output, diagnostics, clientCommand, *state, selectedState, *tunnel)
			} else {
				fmt.Fprintln(diagnostics, "Pairing could not complete. Check that the receiver is running and both codes belong to its current pairing. If the request was saved, next run: owntransit-preview pair resume. Do not regenerate keys just because the network failed.")
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
			err = finishClient(ctx, output, diagnostics, clientCommand, *state, selectedState, *tunnel)
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
	case "restart":
		if !receiver || explicitState {
			return 2
		}
		if tunnelStatus(*state, true) == "alarmed" {
			fmt.Fprintln(diagnostics, "This tunnel is alarmed and cannot be restarted. Use explicit receiver setup to rebuild it with fresh identities.")
			printNext(diagnostics, true, clientCommand, *state, selectedState, *tunnel, *origin)
			return 1
		}
		if _, err = pairruntime.ReadPolicy(*state); err == nil {
			err = startInstalledReceiver(ctx, *tunnel)
		}
		if err == nil {
			fmt.Fprintln(output, "Receiver restarted; pairing retained.")
			printNext(output, true, clientCommand, *state, selectedState, *tunnel, *origin)
		}
	case "unlock":
		fmt.Fprintln(diagnostics, "OwnTransit security alarms cannot be cleared. Rebuild and re-pair with fresh OwnTransit identities; do not reuse the alarmed state.")
		printNext(diagnostics, receiver, clientCommand, *state, selectedState, *tunnel, *origin)
		return 2
	case "lock", "alarm":
		bounded, c := context.WithTimeout(ctx, 5*time.Second)
		err = pairruntime.SetLocked(bounded, *state, receiver, true)
		c()
		if err == nil {
			fmt.Fprintln(output, "SECURITY ALARM LATCHED: this pairing is permanently disabled; local workers stopped. Peer cutoff is bounded by its authorization lease. Recovery requires rebuilding and re-pairing the tunnel with fresh OwnTransit identities.")
			printNext(output, receiver, clientCommand, *state, selectedState, *tunnel, *origin)
		}
	case "status":
		var p pairruntime.Policy
		p, err = pairruntime.ReadPolicy(*state)
		if err == nil {
			fmt.Fprintf(output, "Role: %s\nLocked: %t\nPolicy generation: %d\n", role, p.Locked, p.Generation)
			printNext(output, receiver, clientCommand, *state, selectedState, *tunnel, *origin)
		}
	default:
		return 2
	}
	if err != nil {
		fmt.Fprintln(diagnostics, "owntransit:", failureMessage(operation, err))
		var approval *pairruntime.ApprovalRequired
		if errors.As(err, &approval) {
			fmt.Fprintf(diagnostics, "UNDER CONSTRUCTION — run this exact command on the PUBLIC VPS:\n  %s\nThen rerun this client setup with the SAME private code.\n", relayApprovalCommand(approval.Origin, approval.ReceiverID))
		}
		if operation != "proxy" && operation != "serve" && operation != "code" {
			printNext(diagnostics, receiver, clientCommand, *state, selectedState, *tunnel, *origin)
		}
		return 1
	}
	return 0
}

func readLine(ctx context.Context, input io.Reader, reader *bufio.Reader, diagnostics io.Writer, prompt string, limit int) ([]byte, error) {
	return readPrompt(ctx, input, reader, diagnostics, prompt, limit, true)
}

func readVisibleLine(ctx context.Context, input io.Reader, reader *bufio.Reader, diagnostics io.Writer, prompt string, limit int) ([]byte, error) {
	return readPrompt(ctx, input, reader, diagnostics, prompt, limit, false)
}

func readPrompt(ctx context.Context, input io.Reader, reader *bufio.Reader, diagnostics io.Writer, prompt string, limit int, secret bool) (value []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f, ok := input.(*os.File); ok && secret {
		restore, terminal, setupErr := secretTerminal(f)
		if setupErr != nil {
			return nil, setupErr
		}
		if terminal {
			defer func() {
				if e := restore(); e != nil {
					clear(value)
					value, err = nil, e
					fmt.Fprintln(diagnostics, "Could not restore terminal settings; run: stty sane")
				}
				fmt.Fprintln(diagnostics)
			}()
			// Make input safe before announcing that the user can paste.
			if _, err := fmt.Fprint(diagnostics, prompt); err != nil {
				return nil, err
			}
			return readSecretTerminal(ctx, f, reader, limit)
		}
	}
	fmt.Fprint(diagnostics, prompt)
	defer fmt.Fprintln(diagnostics)
	type result struct {
		data []byte
		err  error
	}
	finished := make(chan result, 1)
	go func() {
		var out []byte
		for len(out) <= limit {
			b, err := reader.ReadByte()
			if err != nil {
				finished <- result{nil, err}
				return
			}
			if b == '\n' {
				out = []byte(strings.TrimSuffix(string(out), "\r"))
				finished <- result{out, nil}
				return
			}
			out = append(out, b)
		}
		finished <- result{nil, pairruntime.ErrState}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-finished:
		return result.data, result.err
	}
}

func startInstalledReceiver(ctx context.Context, tunnel string) error {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return pairruntime.ErrState
	}
	if err := prepareInstalledReceiver(ctx, tunnel); err != nil {
		return err
	}
	unit, err := receiverUnit(tunnel)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "enable", unit)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return err
	}
	// Type=notify waits for the dropped-privilege worker's advertisement ACK,
	// not just fork/exec. Restart also selects the freshly rebuilt local state.
	cmd = exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", unit)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
}

func discoverWorker(args []string, output io.Writer) int {
	return discoverWorkerProfile(args, output, false)
}

func discoverWorkerProfile(args []string, output io.Writer, requireOffer bool) int {
	if os.Geteuid() == 0 || len(args) != 1 {
		return 1
	}
	p, err := pairrelay.NewPublicClient(args[0], nil)
	if err != nil {
		return 1
	}
	ctx, c := context.WithTimeout(context.Background(), 15*time.Second)
	defer c()
	info, err := discoverServerInfo(ctx, p, requireOffer)
	if err != nil {
		return 1
	}
	if json.NewEncoder(output).Encode(info) != nil {
		return 1
	}
	return 0
}

type receiverDiscovery interface {
	CheckOfferSupport(context.Context) error
	FetchServerInfo(context.Context) (pairrelay.ServerInfo, error)
}

// Both calls happen in the dropped-privilege worker. A new receiver must not
// replace its current trust until that worker confirms the offer profile.
func discoverServerInfo(ctx context.Context, public receiverDiscovery, requireOffer bool) (pairrelay.ServerInfo, error) {
	if requireOffer {
		if err := public.CheckOfferSupport(ctx); err != nil {
			return pairrelay.ServerInfo{}, err
		}
	}
	return public.FetchServerInfo(ctx)
}

func printSetupBanner(output io.Writer, receiver, legacyCodes bool) {
	role := "client"
	if receiver {
		role = "receiver"
	}
	profile := "one private code (otpair2., 56 characters)"
	if legacyCodes {
		profile = "legacy two-code setup (otrelay1. and otpair1.)"
	}
	fmt.Fprintf(output, "OwnTransit %s %s setup — %s.\n", buildinfo.Version, role, profile)
	if receiver {
		fmt.Fprintln(output, "THIS MACHINE: RECEIVING SSH MACHINE, the private Linux computer running your SSH server. Enter the relay URL printed by setup on your public VPS.")
	} else {
		fmt.Fprintln(output, "THIS MACHINE: CLIENT COMPUTER, the computer you connect from. Use the same relay URL as your receiving SSH machine.")
		fmt.Fprintln(output, "Paste each answer into its prompt, then press Enter. Code input is hidden. Ctrl-C cancels.")
	}
}

func readShortPairingCode(ctx context.Context, input io.Reader, reader *bufio.Reader, diagnostics io.Writer) ([]byte, error) {
	// Read a bounded older code completely so selecting the wrong executable
	// or code type gets useful guidance. Only the exact 56-byte canonical new
	// format can pass validation; no pasted text is extracted or normalized.
	return promptValidated(ctx, input, reader, diagnostics, "Private receiver code (otpair2., 56 characters, hidden): ", "Paste only the complete 56-character otpair2. code from receiver setup, then press Enter. Never give it to the VPS.", pairrelaycmd.MaxRegistrationCode, true, func(value []byte) error {
		if bytes.HasPrefix(value, []byte("otrelay1.")) {
			fmt.Fprintln(diagnostics, "That is an older public VPS code. One-code setup needs the private otpair2. code from your receiving SSH machine.")
		} else if bytes.HasPrefix(value, []byte("otpair1.")) {
			fmt.Fprintln(diagnostics, "That private receiver code belongs to older two-code setup. To use an existing older receiver, cancel and run this client with pair setup --legacy-codes; keep both original codes.")
		}
		return pairoffer.ValidateCode(value)
	})
}
