//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"errors"
	"os"
)

// UninstallManaged stops only the exact managed relay and disables its unit.
// The disabled unit, website routing, keys and rollback images are retained
// intentionally so explicit reinstall/setup can reuse the exact saved identity.
// Package removal is a separate local-role installer operation.
func UninstallManaged(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("relay uninstall requires root")
	}
	if _, err := os.Lstat(managedRoot); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(unitPath); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("unmanaged relay unit; uninstall refused")
	}
	root, err := stateRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock("setup.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := root.ReadFile("upgrade.json", 8192); !errors.Is(err, os.ErrNotExist) {
		return errors.New("finish or recover the managed upgrade before uninstalling")
	}
	c, err := loadConfig()
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(unitPath); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("unmanaged relay unit; uninstall refused")
	}
	if err != nil || !validSaved(c) {
		return errors.New("invalid saved relay state")
	}
	data, _, err := protectedFile(unitPath)
	if errors.Is(err, os.ErrNotExist) {
		return cleanupStopped(ctx, c.Engine, []string{c.Image})
	}
	if err != nil || !knownUnit(data, c) {
		return errors.New("modified relay unit; uninstall refused")
	}
	drops, err := command(ctx, "/usr/bin/systemctl", "show", managedUnit, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(drops)) != 0 {
		return errors.New("relay service overrides present; uninstall refused")
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "disable", "--now", managedUnit); err != nil {
		return err
	}
	if err := cleanupStopped(ctx, c.Engine, []string{c.Image}); err != nil {
		return err
	}
	current, _, err := protectedFile(unitPath)
	if err != nil || !bytes.Equal(data, current) {
		return errors.New("relay unit changed during uninstall")
	}
	return nil
}
