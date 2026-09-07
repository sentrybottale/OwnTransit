//go:build darwin || linux

package paircmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

const receiverUnits = "/etc/systemd/system"
const originalReceiverState = "/var/lib/owntransit-pair"
const receiverMaintenanceRoot = "/var/lib/owntransit-connector-manager"

// Pairing separate tunnels shares this guard; package mutation takes the
// exclusive side before inspecting or replacing any installed service files.
func receiverMaintenanceGuard() (*securefs.Lock, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil, pairruntime.ErrState
	}
	root, err := securefs.OpenRoot(receiverMaintenanceRoot)
	if errors.Is(err, os.ErrNotExist) {
		root, err = securefs.CreateRoot(receiverMaintenanceRoot)
		if errors.Is(err, os.ErrExist) {
			root, err = securefs.OpenRoot(receiverMaintenanceRoot)
		}
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.TrySharedLock("package.lock")
}

func protectedUnit(path string) ([]byte, error) {
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, pairruntime.ErrState
		}
		if p == path && (!info.Mode().IsRegular() || stat.Nlink != 1 || info.Size() > 16384) {
			return nil, pairruntime.ErrState
		}
		if p != path && !info.IsDir() {
			return nil, pairruntime.ErrState
		}
		if p == "/" {
			break
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(b) > 16384 {
		return nil, pairruntime.ErrState
	}
	return b, nil
}

func namedReceiverUnit(template []byte, name string) ([]byte, error) {
	if !validTunnelName(name) || name == defaultTunnel {
		return nil, pairruntime.ErrState
	}
	if bytes.Count(template, []byte(originalReceiverState)) != 3 {
		return nil, pairruntime.ErrState
	}
	state, _ := tunnelState(originalReceiverState, name)
	return bytes.ReplaceAll(template, []byte(originalReceiverState), []byte(state)), nil
}

// Install a new unit atomically without replacing an existing name. An exact
// rerun is allowed; a different unit is never overwritten by a pairing command.
func publishReceiverUnit(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".owntransit-receiver-unit-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(0644)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	if err = os.Remove(f.Name()); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func prepareInstalledReceiver(parent context.Context, name string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return pairruntime.ErrState
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	template, err := protectedUnit(filepath.Join(filepath.Dir(executable), "service.template"))
	if err != nil {
		return err
	}
	if !bytes.Contains(template, []byte("\nExecStart="+executable+" pair serve --state "+originalReceiverState+"\n")) {
		return pairruntime.ErrState
	}
	unit, err := receiverUnit(name)
	if err != nil {
		return err
	}
	path := filepath.Join(receiverUnits, unit)
	wanted := template
	if name != "" && name != defaultTunnel {
		wanted, err = namedReceiverUnit(template, name)
		if err != nil {
			return err
		}
	}
	current, err := protectedUnit(path)
	if errors.Is(err, os.ErrNotExist) && name != "" && name != defaultTunnel {
		// The installed default unit proves the parent and package binding before
		// any instance is created, even when the default tunnel is unused.
		original, e := protectedUnit(filepath.Join(receiverUnits, "owntransit-connector-pair.service"))
		if e != nil || !bytes.Equal(original, template) {
			return pairruntime.ErrState
		}
		if err = publishReceiverUnit(path, wanted); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		current, err = protectedUnit(path)
	}
	if err != nil || !bytes.Equal(current, wanted) {
		return pairruntime.ErrState
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	// Reload is idempotent and also handles a previous invocation interrupted
	// after its unit was synced but before systemd saw it.
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if err = cmd.Run(); err != nil {
		return err
	}
	cmd = exec.CommandContext(ctx, "/usr/bin/systemctl", "show", unit, "--property=DropInPaths", "--value")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	drops, err := cmd.Output()
	if err != nil || len(strings.TrimSpace(string(drops))) != 0 {
		return pairruntime.ErrState
	}
	return nil
}
