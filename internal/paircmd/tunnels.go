//go:build darwin || linux

package paircmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

const defaultTunnel = "default"
const maxListedTunnels = 128

func validTunnelName(name string) bool {
	if len(name) < 1 || len(name) > 32 || name == "all" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func tunnelRoot(base string) string { return filepath.Join(filepath.Dir(base), "owntransit-tunnels") }

func tunnelState(base, name string) (string, error) {
	if !validTunnelName(name) {
		return "", pairruntime.ErrState
	}
	if name == defaultTunnel {
		return base, nil
	}
	return filepath.Join(tunnelRoot(base), name), nil
}

func receiverUnit(name string) (string, error) {
	if name == "" || name == defaultTunnel {
		return "owntransit-target.service", nil
	}
	if !validTunnelName(name) {
		return "", pairruntime.ErrState
	}
	return "owntransit-target@" + name + ".service", nil
}

// The named root is private and opened without following symlinks. Individual
// states retain the existing runtime schemas, locks and atomic rebuild rules.
func ensureTunnelRoot(base string) error {
	root, err := securefs.OpenRoot(tunnelRoot(base))
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(filepath.Dir(base), 0700); err != nil {
			return err
		}
		root, err = securefs.CreateRoot(tunnelRoot(base))
		if errors.Is(err, os.ErrExist) {
			root, err = securefs.OpenRoot(tunnelRoot(base))
		}
	}
	if err != nil {
		return err
	}
	return root.Close()
}

func tunnelStatus(path string, receiver bool) string {
	p, err := pairruntime.ReadRetainedPolicy(path)
	if err != nil {
		return "unavailable"
	}
	removed, err := pairruntime.IsRemoved(path)
	if err != nil {
		return "unavailable"
	}
	if removed {
		if p.Locked {
			return "removed (alarmed)"
		}
		return "removed"
	}
	if p.Locked {
		return "alarmed"
	}
	if receiver {
		r, err := receiverpairing.Open(filepath.Join(path, "authority"))
		if err != nil {
			return "unavailable"
		}
		s, err := r.Status()
		if err != nil {
			return "unavailable"
		}
		if s.LocalLocked || s.PeerLocked || s.PeerRevoked {
			return "alarmed"
		}
		if s.PairedClientID == "" {
			return "awaiting-client"
		}
	} else {
		_, pending, _, err := pairruntime.ClientSetupSummary(path)
		if err != nil {
			return "unavailable"
		}
		if pending {
			return "pairing-pending"
		}
	}
	return "paired"
}

func listTunnels(base string, receiver bool, output io.Writer, executable ...string) error {
	program := "owntransit-client"
	if receiver {
		program = "owntransit-target"
	}
	if len(executable) > 0 {
		program = executable[0]
	}
	prefix := ""
	if receiver {
		prefix = "sudo "
	}
	names, err := localTunnelNames(base)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		_, err := fmt.Fprintf(output, "UNDER CONSTRUCTION: no tunnels yet. Start on THIS machine:\n  %s%s\n", prefix, pairCommand(program, "setup", ""))
		return err
	}
	if _, err := fmt.Fprintln(output, "TUNNEL  PAIRING"); err != nil {
		return err
	}
	for _, name := range names {
		path, _ := tunnelState(base, name)
		if _, err := fmt.Fprintf(output, "%s  %s\n", name, tunnelStatus(path, receiver)); err != nil {
			return err
		}
		if receiver {
			r, e := receiverpairing.Open(filepath.Join(path, "authority"))
			if e == nil {
				s, e := r.Status()
				if e == nil {
					fmt.Fprintf(output, "  Target ID: %s\n", s.ReceiverID)
				}
			}
		}
		fmt.Fprintf(output, "  Next commands:\n    %s%s\n", prefix, pairCommand(program, "next", "", name))
		if receiver {
			fmt.Fprintf(output, "  Private code:\n    %s%s\n", prefix, pairCommand(program, "code", "", name))
		}
	}
	_, err = fmt.Fprintln(output, "Pairing status is local; it does not prove the peer is currently reachable. Run the exact Next commands line for your tunnel.")
	return err
}

func localTunnelNames(base string) ([]string, error) {
	names := []string{}
	if _, err := os.Lstat(base); err == nil {
		names = append(names, defaultTunnel)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	root, err := securefs.OpenRoot(tunnelRoot(base))
	if err == nil {
		defer root.Close()
		dir, err := os.Open(tunnelRoot(base))
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		entries, err := dir.ReadDir(maxListedTunnels*2 + 1)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if len(entries) > maxListedTunnels*2 {
			return nil, errors.New("too many local tunnel entries")
		}
		for _, entry := range entries {
			name := entry.Name()
			// Receiver rebuild journals are sibling directories, not tunnels.
			if strings.HasSuffix(name, ".setup") && validTunnelName(strings.TrimSuffix(name, ".setup")) {
				continue
			}
			if !validTunnelName(name) || name == defaultTunnel || !entry.IsDir() {
				return nil, errors.New("unrecognized entry in named tunnel directory")
			}
			names = append(names, name)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(names) > maxListedTunnels {
		return nil, errors.New("too many local tunnels to list")
	}
	sort.Strings(names)
	return names, nil
}
