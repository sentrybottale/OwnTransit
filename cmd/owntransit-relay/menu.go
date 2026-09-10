package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/relaysetup"
)

type relayMenuOperations struct {
	instances func(context.Context) ([]relaysetup.InstanceSummary, error)
	tunnels   func(context.Context, string) ([]relaysetup.MenuTunnel, error)
	newTunnel func(context.Context, string, string) error
	approve   func(context.Context, string, string, string) error
	remove    func(context.Context, string, relaysetup.MenuTunnel) error
	configure func(context.Context, string, string, *bufio.Reader, io.Writer) error
}

func runRelayMenu(arguments []string, input io.Reader, output, diagnostics io.Writer) int {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getuid() != os.Geteuid() {
		fmt.Fprintln(diagnostics, "Run Relay setup with sudo on your Linux VPS.")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return relayMenu(ctx, arguments, input, output, diagnostics, relayMenuOperations{
		instances: relaysetup.MenuInstances, tunnels: relaysetup.MenuTunnels, newTunnel: relaysetup.NewMenuTunnel,
		approve: relaysetup.ApproveMenuTunnel, remove: relaysetup.RemoveMenuTunnel, configure: configureMenuRelay,
	})
}

func relayMenu(ctx context.Context, args []string, input io.Reader, out, diag io.Writer, ops relayMenuOperations) int {
	flags := flag.NewFlagSet("owntransit-relay setup", flag.ContinueOnError)
	flags.SetOutput(diag)
	var selectedName, selectedURL managedStringFlag
	flags.Var(&selectedName, "instance", "select one local relay")
	flags.Var(&selectedURL, "url", "public relay URL")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || (selectedName.set && (selectedName.value == "" || relaysetup.ValidateInstanceName(selectedName.value) != nil)) {
		return 2
	}
	if selectedURL.set {
		u, e := relaysetup.PublicURL(selectedURL.value)
		if e != nil {
			fmt.Fprintln(diag, "Enter a public wss:// URL, not a pairing code.")
			return 2
		}
		selectedURL.value = u
	}
	reader := bufio.NewReader(io.LimitReader(input, 256<<10))
	fmt.Fprintln(out, "OwnTransit · Relay")
	instances, err := ops.instances(ctx)
	if err != nil {
		fmt.Fprintln(diag, "Local relay settings could not be read. No changes were made.")
		return 1
	}
	var chosen relaysetup.InstanceSummary
	for _, item := range instances {
		if selectedName.set && item.Name != selectedName.value {
			continue
		}
		if selectedURL.set && item.URL != selectedURL.value {
			continue
		}
		if selectedName.set || selectedURL.set {
			chosen = item
			break
		}
	}
	if chosen.URL == "" && !selectedName.set && !selectedURL.set && len(instances) > 0 {
		if len(instances) == 1 {
			chosen = instances[0]
		} else {
			fmt.Fprintln(out, "Choose the relay:")
			for i, item := range instances {
				fmt.Fprintf(out, "%d) %s — %s\n", i+1, item.Name, item.URL)
			}
			choice, e := menuChoice(ctx, reader, out, len(instances))
			if e != nil || choice == 0 {
				return 0
			}
			chosen = instances[choice-1]
		}
	}
	if chosen.URL == "" {
		chosen.Name = selectedName.value
		chosen.URL = selectedURL.value
		if chosen.URL == "" {
			fmt.Fprint(out, "Public relay URL: ")
			line, e := readManagedLine(ctx, reader, 2048)
			if e != nil {
				return 0
			}
			chosen.URL, err = relaysetup.PublicURL(strings.TrimSpace(line))
			if err != nil {
				fmt.Fprintln(diag, "Use your public wss:// URL. No relay was changed.")
				return 1
			}
		}
	}
	if !chosen.Configured {
		if err := ops.configure(ctx, chosen.Name, chosen.URL, reader, out); err != nil {
			menuError(diag, "Relay configuration was not confirmed", err)
			return 1
		}
	}
	fmt.Fprintf(out, "Relay: %s\n", chosen.URL)
	for actions := 0; actions < 64; actions++ {
		fmt.Fprintln(out, "\n1) New tunnel\n2) Continue a tunnel\n3) List tunnels\n4) Remove a tunnel\n5) Start or update this relay\n0) Exit")
		choice, e := menuChoice(ctx, reader, out, 5)
		if e != nil || choice == 0 {
			return 0
		}
		switch choice {
		case 5:
			fmt.Fprint(out, "Start/update this relay, preserving its keys and website route? Type yes: ")
			answer, e := readManagedLine(ctx, reader, 16)
			if e != nil {
				return 0
			}
			if strings.TrimSpace(answer) != "yes" {
				fmt.Fprintln(out, "Cancelled.")
				continue
			}
			if e := ops.configure(ctx, chosen.Name, chosen.URL, reader, out); e != nil {
				menuError(diag, "Relay configuration was not confirmed", e)
				return 1
			}
		case 1:
			fmt.Fprint(out, "Tunnel name: ")
			name, e := readManagedLine(ctx, reader, 64)
			if e != nil {
				return 0
			}
			name = strings.TrimSpace(name)
			if name == "" || relaysetup.ValidateInstanceName(name) != nil {
				fmt.Fprintln(out, "Use a short lowercase name, such as office. Nothing changed.")
				continue
			}
			if e = ops.newTunnel(ctx, chosen.URL, name); e != nil {
				fmt.Fprintln(out, "This name could not be created. List tunnels or choose another name.")
				continue
			}
			fmt.Fprintf(out, "\n%s — UNDER CONSTRUCTION\nNext on the TARGET computer:\n  sudo owntransit-target setup\nChoose New tunnel and use relay URL: %s\nReturn here → Continue a tunnel when the Target gives you its public ID.\n", name, chosen.URL)
			return 0
		case 2, 3, 4:
			items, e := ops.tunnels(ctx, chosen.URL)
			if e != nil {
				fmt.Fprintln(out, "Tunnel inventory unavailable. Choose 5 to start/update this relay. Endpoint identities are unchanged.")
				continue
			}
			if len(items) == 0 {
				fmt.Fprintln(out, "No tunnels yet. Choose New tunnel.")
				continue
			}
			printMenuTunnels(out, items)
			if choice == 3 {
				continue
			}
			fmt.Fprintln(out, "Choose a tunnel (0 goes back):")
			n, e := menuChoice(ctx, reader, out, len(items))
			if e != nil {
				return 0
			}
			if n == 0 {
				continue
			}
			item := items[n-1]
			if choice == 4 {
				fmt.Fprintf(out, "Remove %s from THIS relay? Endpoints and SSH stay untouched. Type remove: ", menuTunnelName(item))
				answer, e := readManagedLine(ctx, reader, 16)
				if e != nil {
					return 0
				}
				if strings.TrimSpace(answer) != "remove" {
					fmt.Fprintln(out, "Cancelled. Nothing removed.")
					continue
				}
				if e := ops.remove(ctx, chosen.URL, item); e != nil {
					if errors.Is(e, relaysetup.ErrMenuPlanRemoved) {
						fmt.Fprintln(out, "Removed the local tunnel label only: no matching admission was found. This does not revoke old tokens. Use Remove on the Client or Target to stop that endpoint.")
						continue
					}
					fmt.Fprintln(out, "Removal was not confirmed. List tunnels and retry this exact entry; other tunnels were not selected.")
					return 1
				}
				fmt.Fprintln(out, "Removed from this relay. This is not an endpoint killswitch.")
				continue
			}
			if item.Status == "removed" {
				fmt.Fprintln(out, "This relay admission was removed. Choose New tunnel to build a new path; endpoint alarm state has not been changed.")
				continue
			}
			if item.Status == "unavailable" {
				fmt.Fprintln(out, "No admission record matches this saved tunnel. On the Target, choose Continue to reconnect, then list here again. Remove can clear this stale local label; it does not reset endpoint keys.")
				continue
			}
			if item.ReceiverID == "" {
				fmt.Fprint(out, "Public Target ID (not its private code; Enter goes back): ")
				id, e := readManagedLine(ctx, reader, 128)
				if e != nil {
					return 0
				}
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				parsed, e := protocol.ParseID(id)
				if e != nil || parsed == (protocol.ID{}) {
					fmt.Fprintln(out, "That is not a public Target ID. No approval was changed.")
					continue
				}
				if e := ops.approve(ctx, chosen.URL, item.Name, id); e != nil {
					if errors.Is(e, relaysetup.ErrMenuApprovalSaved) {
						fmt.Fprintln(out, "Approval is saved, but its local display-name update was not confirmed. List tunnels to find the approved Target; do not replace its keys.")
					} else {
						fmt.Fprintln(out, "Approval was not confirmed. On the Target, choose Continue so it reconnects; then check List tunnels before retrying with the same public ID.")
						return 1
					}
				}
				item.ReceiverID = id
				fmt.Fprintln(out, "Target approved. The tunnel is still UNDER CONSTRUCTION.")
			}
			fmt.Fprintf(out, "Next on the CLIENT computer:\n  owntransit-client setup\nChoose New tunnel (or Continue if already started).\nRelay URL: %s\nUse the private code from the Target—not a code from this relay.\n", chosen.URL)
			fmt.Fprintf(out, "Lost it? On the TARGET:\n  sudo owntransit-target code --target-id %s\n", item.ReceiverID)
			return 0
		}
	}
	fmt.Fprintln(out, "Menu paused. Run owntransit-relay setup to continue.")
	return 0
}

func menuError(out io.Writer, prefix string, err error) {
	message := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, err.Error())
	if len(message) > 240 {
		message = message[:240] + "…"
	}
	fmt.Fprintf(out, "%s: %s\nRerun owntransit-relay setup to continue.\n", prefix, message)
}

func menuChoice(ctx context.Context, reader *bufio.Reader, out io.Writer, max int) (int, error) {
	for attempts := 0; attempts < 5; attempts++ {
		fmt.Fprint(out, "> ")
		line, e := readManagedLine(ctx, reader, 8)
		if e != nil {
			return 0, e
		}
		n, e := strconv.Atoi(strings.TrimSpace(line))
		if e == nil && n >= 0 && n <= max {
			return n, nil
		}
		fmt.Fprintf(out, "Choose 0–%d.\n", max)
	}
	return 0, errors.New("too many invalid menu choices")
}
func menuTunnelName(item relaysetup.MenuTunnel) string {
	if item.Name != "" {
		return item.Name
	}
	if len(item.ReceiverID) >= 12 {
		return "Target " + item.ReceiverID[:12]
	}
	return "Target"
}
func printMenuTunnels(out io.Writer, items []relaysetup.MenuTunnel) {
	for i, item := range items {
		status := strings.ToUpper(item.Status)
		if item.Status == "approved" || item.Status == "observed" {
			status = "APPROVED — check on Client"
		}
		fmt.Fprintf(out, "%d) %s · %s\n", i+1, menuTunnelName(item), status)
	}
}

func configureMenuRelay(ctx context.Context, name, url string, reader *bufio.Reader, out io.Writer) error {
	lock, err := relaysetup.LockPackage(0)
	if err != nil {
		return err
	}
	defer lock.Close()
	plan, err := relaysetup.PrepareSetup(ctx, name, url)
	if err != nil {
		return err
	}
	confirmed := false
	if plan.Kind == "migration" {
		fmt.Fprintf(out, "Adopt existing service %s into relay %s at %s? Keys and website route are retained. Type yes: ", plan.LegacyUnit, plan.Instance, plan.URL)
		if plan.Verification == relaysetup.VerificationLocal403 {
			fmt.Fprintln(out, "\nPublic self-check is blocked by HTTP 403; verification will be local only.")
		}
		answer, e := readManagedLine(ctx, reader, 16)
		if e != nil || strings.TrimSpace(answer) != "yes" {
			return errors.New("relay adoption cancelled")
		}
		confirmed = true
	}
	result, err := relaysetup.ApplySetupWithResult(ctx, plan, confirmed, io.Discard)
	if err != nil {
		return err
	}
	if result.Verification == relaysetup.VerificationLocal403 {
		fmt.Fprintln(out, "Relay configured locally; its own HTTPS check is blocked by policy. The Client still checks the real tunnel.")
	} else if result.Verification == relaysetup.VerificationPublic {
		fmt.Fprintln(out, "Relay configured.")
	} else {
		return errors.New("unknown relay verification result")
	}
	return nil
}
