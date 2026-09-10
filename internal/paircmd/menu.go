//go:build darwin || linux

package paircmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairruntime"
)

func runMenu(ctx context.Context, target bool, base string, input io.Reader, reader *bufio.Reader, output, diagnostics io.Writer, execute func([]string) int) int {
	role := "Client"
	if target {
		role = "Target"
	}
	fmt.Fprintf(output, "OwnTransit %s\n", role)
	for step := 0; step < 64; step++ {
		fmt.Fprintln(output, "\n1  New tunnel\n2  Continue tunnel\n3  List tunnels\n4  Remove tunnel\n5  Killswitch\n6  Restore removed tunnel\n0  Exit")
		choice, err := menuNumber(ctx, input, reader, diagnostics, "Choose: ", 6)
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return 0
		}
		if err != nil {
			return 1
		}
		if choice == 0 {
			return 0
		}
		if choice == 1 {
			names, err := localTunnelNames(base)
			if err != nil || len(names) >= maxListedTunnels {
				fmt.Fprintln(diagnostics, "Cannot add another tunnel: inspect the local list and its bounds first.")
				return 1
			}
			name, err := promptValidated(ctx, input, reader, diagnostics, "New tunnel name: ", "Choose an unused name: 1–32 lowercase letters, digits or hyphens, starting with a letter.", 32, false, func(value []byte) error {
				path, e := tunnelState(base, string(value))
				if e != nil {
					return e
				}
				if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
					return pairruntime.ErrState
				}
				return nil
			})
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return 0
			}
			if err != nil {
				return 1
			}
			return execute([]string{"new", "--tunnel", string(name)})
		}
		names, err := localTunnelNames(base)
		if err != nil {
			fmt.Fprintln(diagnostics, "Local tunnel list is unavailable. Check its ownership and permissions.")
			return 1
		}
		if len(names) == 0 {
			fmt.Fprintln(output, "No local tunnels. Choose New tunnel to begin.")
			continue
		}
		for index, name := range names {
			path, _ := tunnelState(base, name)
			fmt.Fprintf(output, "%d  %s  %s\n", index+1, name, tunnelStatus(path, target))
		}
		if choice == 3 {
			fmt.Fprintln(output, "Status is local. Continue a client tunnel to check end-to-end transport.")
			continue
		}
		selected, err := menuNumber(ctx, input, reader, diagnostics, "Select tunnel (0 goes back): ", len(names))
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return 0
		}
		if err != nil {
			return 1
		}
		if selected == 0 {
			continue
		}
		name := names[selected-1]
		operation := map[int]string{2: "continue", 4: "remove", 5: "killswitch", 6: "restore"}[choice]
		if choice == 4 || choice == 5 || choice == 6 {
			message := "Remove only this local tunnel; retain its private pairing state."
			if choice == 5 {
				message = "Permanently alarm this pairing and stop its local carriers. It cannot be unlocked."
			}
			if choice == 6 {
				message = "Restore this local tunnel using retained identities. Terminal alarms cannot be restored."
			}
			fmt.Fprintf(diagnostics, "%s\n", message)
			answer, err := readVisibleLine(ctx, input, reader, diagnostics, "Type the tunnel name to confirm (empty cancels): ", 32)
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return 0
			}
			if err != nil {
				return 1
			}
			if string(answer) != name {
				fmt.Fprintln(output, "Cancelled.")
				continue
			}
		}
		return execute([]string{operation, "--tunnel", name})
	}
	fmt.Fprintln(diagnostics, "Menu closed after 64 steps. Run setup to continue.")
	return 1
}

func menuNumber(ctx context.Context, input io.Reader, reader *bufio.Reader, diagnostics io.Writer, prompt string, maximum int) (int, error) {
	value, err := promptValidated(ctx, input, reader, diagnostics, prompt, "Enter one of the displayed numbers.", 3, false, func(value []byte) error {
		for _, b := range value {
			if b < '0' || b > '9' {
				return pairruntime.ErrState
			}
		}
		n, e := strconv.Atoi(string(value))
		if e != nil || n < 0 || n > maximum {
			return pairruntime.ErrState
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(value))
}

func continueTunnel(ctx context.Context, target bool, path, tunnel, selectedState, executable string, output, diagnostics io.Writer) error {
	status := tunnelStatus(path, target)
	if status != "awaiting-client" && status != "pairing-pending" && status != "paired" {
		return pairruntime.ErrState
	}
	if target {
		if err := startInstalledReceiver(ctx, tunnel); err != nil {
			return err
		}
		if status == "awaiting-client" {
			return showReceiverCode(output, diagnostics, executable, path, selectedState, tunnel)
		}
		fmt.Fprintln(output, "Target restarted with its saved pairing. Continue this tunnel on the Client to check end-to-end transport.")
		return nil
	}
	if status == "pairing-pending" {
		bounded, cancel := context.WithTimeout(ctx, time.Minute)
		err := resumeClient(bounded, path, nil)
		cancel()
		if err != nil {
			return err
		}
	}
	return finishClient(ctx, output, diagnostics, executable, path, selectedState, tunnel)
}
