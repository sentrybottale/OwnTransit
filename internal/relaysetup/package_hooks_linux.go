//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var previousPackageHelper = []byte("/usr/local/bin/owntransit-relay-preview cleanup-container ")
var currentPackageHelper = []byte("/usr/local/bin/owntransit-relay cleanup-container ")

// MigratePackageHooks updates only cleanup executable paths in exact managed
// service units. The caller holds the exclusive package lock until the old
// alias is retired. No service is stopped, started, enabled or reconfigured.
func MigratePackageHooks(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("relay package integration requires root")
	}
	if _, err := os.Lstat(managedRoot); errors.Is(err, os.ErrNotExist) {
		return rejectUnknownPackageHooks(nil)
	}
	root, lock, err := managerRoot(false)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	specs, err := scanInstances(root)
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(specs))
	var selection []uninstallSelection
	for _, s := range specs {
		known[s.unitName] = true
		item, err := s.prepareUninstall(ctx)
		if err != nil {
			return err
		}
		if item.configured {
			selection = append(selection, item)
		}
	}
	if err := rejectUnknownPackageHooks(known); err != nil {
		return err
	}
	// Every instance is validated before any unit changes. Repeating after an
	// interrupted write is safe: both old and rewritten units remain recognized.
	for _, item := range selection {
		if !bytes.Contains(item.unit, previousPackageHelper) {
			continue
		}
		current, mode, err := protectedFile(item.spec.unitPath)
		if err != nil || !bytes.Equal(current, item.unit) {
			return errors.New("relay unit changed during package integration")
		}
		next := bytes.ReplaceAll(current, previousPackageHelper, currentPackageHelper)
		if !item.spec.knownUnit(next, item.config) {
			return errors.New("rewritten relay cleanup hooks are not a known managed unit")
		}
		if err := writeAtomic(item.spec.unitPath, next, mode); err != nil {
			return err
		}
	}
	// Reload even on a retry whose files are already rewritten: a previous
	// process may have stopped after atomic publication and before this command.
	if len(selection) > 0 {
		if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	return nil
}

// A name alone grants no ownership. Unknown local service units and drop-ins
// that still depend on the alias block retirement instead of being rewritten.
func rejectUnknownPackageHooks(known map[string]bool) error {
	names, err := boundedNames("/etc/systemd/system", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, name := range names {
		if known[name] {
			continue
		}
		if strings.HasPrefix(name, managedContainer) && (strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".service.d")) {
			if !known[strings.TrimSuffix(name, ".d")] {
				return errors.New("unbound managed relay unit; package integration refused")
			}
		}
		if strings.HasSuffix(name, ".service") {
			if err := rejectAliasReference("/etc/systemd/system/" + name); err != nil {
				return err
			}
		} else if strings.HasSuffix(name, ".service.d") {
			entries, err := boundedNames("/etc/systemd/system/"+name, 128)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry, ".conf") {
					if err := rejectAliasReference("/etc/systemd/system/" + name + "/" + entry); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func rejectAliasReference(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Inspect an alias's target as a dependency only. It may live outside
		// the manager's directories and can never become a rewrite target.
		resolved, err := filepath.EvalSymlinks(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if resolved == "/dev/null" { // A systemd mask cannot invoke a helper.
			return nil
		}
		path = resolved
		info, err = os.Lstat(path)
		if err != nil {
			return err
		}
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return errors.New("local service configuration cannot be inspected within its bound")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxConfigBytes {
		return errors.New("local service configuration exceeds its bound")
	}
	if bytes.Contains(data, []byte("/usr/local/bin/owntransit-relay-preview")) {
		return errors.New("an unrecognized service still uses the previous relay helper; package integration refused")
	}
	return nil
}
