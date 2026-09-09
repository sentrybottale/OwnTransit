//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
)

// Ownership for the whole selection is checked before any service is stopped.
// Removing shared software is a separate package operation under its lock.
type uninstallSelection struct {
	spec       instanceSpec
	config     savedConfig
	unit       []byte
	configured bool
}

func UninstallManaged(ctx context.Context) error { return UninstallInstance(ctx, "default") }
func UninstallInstance(ctx context.Context, name string) error {
	name, err := normalizedInstanceName(name)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("relay uninstall requires root")
	}
	if _, err := os.Lstat(managedRoot); errors.Is(err, os.ErrNotExist) {
		path := unitPath
		if name != "default" {
			path = "/etc/systemd/system/" + managedContainer + "-" + name + ".service"
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("unmanaged relay unit; uninstall refused")
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	s, err := selectedInstance(root, name)
	if err != nil {
		return err
	}
	selected, err := s.prepareUninstall(ctx)
	if err != nil {
		return err
	}
	return selected.uninstall(ctx)
}
func UninstallAllManaged(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("relay uninstall requires root")
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	specs, err := scanInstances(root)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, s := range specs {
		known[s.unitName] = true
	}
	if !known[managedUnit] {
		specs = append(specs, defaultInstance())
		known[managedUnit] = true
	}
	// An incomplete registry cannot authorize removing shared binaries while
	// an unaccounted service is enabled.
	names, err := boundedNames("/etc/systemd/system", 4096)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, managedContainer+"-") && (strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".service.d")) {
			if !known[strings.TrimSuffix(name, ".d")] {
				return errors.New("unbound managed relay unit; package removal refused")
			}
		}
	}
	var selected []uninstallSelection
	for _, s := range specs {
		item, err := s.prepareUninstall(ctx)
		if err != nil {
			return err
		}
		selected = append(selected, item)
	}
	for _, item := range selected {
		if err := item.uninstall(ctx); err != nil {
			return err
		}
	}
	return nil
}
func (s instanceSpec) prepareUninstall(ctx context.Context) (uninstallSelection, error) {
	item := uninstallSelection{spec: s}
	root, err := s.openRoot()
	if err != nil {
		return item, err
	}
	defer root.Close()
	if err := noPendingOperation(root); err != nil {
		return item, err
	}
	c, err := s.loadConfig()
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(s.unitPath); errors.Is(err, os.ErrNotExist) {
			return item, nil
		}
		return item, errors.New("unmanaged relay unit; uninstall refused")
	}
	if err != nil || !s.validSaved(c) {
		return item, errors.New("invalid saved relay state")
	}
	item.config, item.configured = c, true
	if err := s.validateData(); err != nil {
		return item, err
	}
	data, _, err := protectedFile(s.unitPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return item, err
	}
	if err == nil && !s.knownUnit(data, c) {
		return item, errors.New("modified relay unit; uninstall refused")
	}
	item.unit = data
	if len(data) != 0 {
		drops, err := command(ctx, "/usr/bin/systemctl", "show", s.unitName, "--property=DropInPaths", "--value")
		if err != nil || len(bytes.TrimSpace(drops)) != 0 {
			return item, errors.New("relay service overrides present; uninstall refused")
		}
	}
	if err := s.prevalidateContainer(ctx, c, len(data) != 0); err != nil {
		return item, err
	}
	return item, nil
}
func (item uninstallSelection) uninstall(ctx context.Context) error {
	if !item.configured {
		return nil
	}
	s, c := item.spec, item.config
	if len(item.unit) != 0 {
		if _, err := command(ctx, "/usr/bin/systemctl", "disable", "--now", s.unitName); err != nil {
			return err
		}
	}
	if err := s.cleanupStopped(ctx, c.Engine, []string{c.Image}); err != nil {
		return err
	}
	if len(item.unit) != 0 {
		current, _, err := protectedFile(s.unitPath)
		if err != nil || !bytes.Equal(item.unit, current) {
			return errors.New("relay unit changed during uninstall")
		}
	}
	return nil
}
