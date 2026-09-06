//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"io"
	"os"
	"time"
)

type upgradeIntent struct {
	Schema   string      `json:"schema"`
	Previous savedConfig `json:"previous"`
	Next     savedConfig `json:"next"`
	Enabled  bool        `json:"enabled"`
	Running  bool        `json:"running"`
}

func validSaved(c savedConfig) bool {
	u, e := PublicURL(c.URL)
	return e == nil && u == c.URL && c.Schema == "owntransit.relay-setup.v1" && validImage(c.Image) && validEngine(c.Engine)
}

func managedIdentity(ctx context.Context, engine, image string) (pairrelay.ServerInfo, error) {
	c, err := inspect(ctx, engine, managedContainer)
	if err != nil || !c.State.Running || c.Image != image || !ownRelay(c) {
		return pairrelay.ServerInfo{}, errors.New("the selected relay image is not running")
	}
	b, err := command(ctx, engine, "exec", managedContainer, "/owntransit-relay", "pair", "info", "--state", "/state/relay")
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	var info pairrelay.ServerInfo
	if strictjson.Decode(b, &info) != nil {
		return info, errors.New("local relay identity could not be verified")
	}
	return info, nil
}

func verifyRunningRelay(ctx context.Context, c savedConfig, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		local, err := managedIdentity(ctx, c.Engine, c.Image)
		if err == nil {
			remote, e := probeServer(ctx, c.URL)
			if e == nil && remote.LeafSPKISHA256 == local.LeafSPKISHA256 && bytes.Equal(remote.CAPEM, local.CAPEM) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("new relay image/public route verification failed")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// The journal contains only protected local software selection and service
// state. Relay identity files are neither rewritten nor restored by upgrades.
func restoreManaged(ctx context.Context, root *securefs.Root, j upgradeIntent) error {
	if !validSaved(j.Previous) || !validSaved(j.Next) || j.Schema != "owntransit.relay-upgrade.v1" || j.Previous.URL != j.Next.URL || j.Previous.Engine != j.Next.Engine {
		return errors.New("invalid relay upgrade journal")
	}
	current, _, err := protectedFile(unitPath)
	if err != nil || (!bytes.Equal(current, unit(j.Previous.Image, j.Previous.Engine)) && !bytes.Equal(current, unit(j.Next.Image, j.Next.Engine))) {
		return errors.New("managed unit changed outside upgrade; rollback refused")
	}
	drops, err := command(ctx, "/usr/bin/systemctl", "show", managedUnit, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(drops)) != 0 {
		return errors.New("managed service overrides changed; rollback refused")
	}
	config, err := loadConfig()
	if err != nil || (config != j.Previous && config != j.Next) {
		return errors.New("setup selection changed outside upgrade; rollback refused")
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "stop", managedUnit); err != nil {
		return err
	}
	if err := writeAtomic(unitPath, unit(j.Previous.Image, j.Previous.Engine), 0644); err != nil {
		return err
	}
	encoded, _ := json.Marshal(j.Previous)
	if err := root.ReplaceFile("setup.json", encoded, 0600); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	action := "disable"
	if j.Enabled {
		action = "enable"
	}
	if _, err := command(ctx, "/usr/bin/systemctl", action, managedUnit); err != nil {
		return err
	}
	if j.Running {
		if _, err := command(ctx, "/usr/bin/systemctl", "start", managedUnit); err != nil {
			return err
		}
		wait, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		for {
			c, e := inspect(wait, j.Previous.Engine, managedContainer)
			if e == nil && c.State.Running && c.Image == j.Previous.Image {
				break
			}
			select {
			case <-wait.Done():
				return errors.New("previous relay did not restart; backup journal retained")
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return root.UnlinkFile("upgrade.json")
}

func recoverManaged(ctx context.Context, root *securefs.Root, output io.Writer) error {
	b, err := root.ReadFile("upgrade.json", 8192)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var j upgradeIntent
	if strictjson.Decode(b, &j) != nil {
		return errors.New("invalid relay upgrade journal")
	}
	fmt.Fprintln(output, "Recovering the previous relay after an interrupted upgrade; keys and website routing are unchanged.")
	return restoreManaged(ctx, root, j)
}

func upgradeManaged(ctx context.Context, root *securefs.Root, previous, next savedConfig, output io.Writer) (returnErr error) {
	if !validSaved(previous) || !validSaved(next) || previous.Engine != next.Engine || previous.URL != next.URL {
		return errors.New("use the existing relay URL and engine for an in-place upgrade")
	}
	original, _, err := protectedFile(unitPath)
	if err != nil || !bytes.Equal(original, unit(previous.Image, previous.Engine)) {
		return errors.New("existing relay unit is not the saved managed configuration; no service was changed")
	}
	drops, err := command(ctx, "/usr/bin/systemctl", "show", managedUnit, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(drops)) != 0 {
		return errors.New("managed relay has custom systemd overrides; refusing an automatic replacement")
	}
	_, activeErr := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", managedUnit)
	_, enabledErr := command(ctx, "/usr/bin/systemctl", "is-enabled", "--quiet", managedUnit)
	if activeErr == nil {
		c, e := inspect(ctx, previous.Engine, managedContainer)
		if e != nil || !c.State.Running || c.Image != previous.Image || !ownRelay(c) {
			return errors.New("running relay does not match saved managed image; no service was changed")
		}
	}
	if previous == next && activeErr == nil {
		if err := verifyRunningRelay(ctx, next, routeProbeTimeout); err != nil {
			return errors.Join(errors.New("existing relay left running; check its public route"), err)
		}
		if enabledErr != nil {
			if _, err := command(ctx, "/usr/bin/systemctl", "enable", managedUnit); err != nil {
				return err
			}
		}
		fmt.Fprintln(output, "This relay version is already running; no container or website configuration was replaced.")
		return nil
	}
	if _, err := command(ctx, previous.Engine, "image", "inspect", "--format", "{{.Id}}", previous.Image); err != nil {
		return errors.New("previous image is unavailable for rollback; relay left unchanged")
	}
	j := upgradeIntent{"owntransit.relay-upgrade.v1", previous, next, enabledErr == nil, activeErr == nil}
	encoded, _ := json.Marshal(j)
	if err := root.CreateExclusive("upgrade.json", encoded, 0600); err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if e := restoreManaged(rollbackCtx, root, j); e != nil {
				returnErr = errors.Join(returnErr, errors.New("rollback needs attention; rerun the same setup command to recover"), e)
			} else {
				fmt.Fprintln(output, "Upgrade failed; previous relay software and service state restored. Retry the same installer command after resolving the reported problem.")
			}
		}
	}()
	fmt.Fprintln(output, "Upgrading the existing relay container. Active tunnels may reconnect; relay keys, pairings and website routing are preserved.")
	if _, err := command(ctx, "/usr/bin/systemctl", "stop", managedUnit); err != nil {
		return err
	}
	if err := writeAtomic(unitPath, unit(next.Image, next.Engine), 0644); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "enable", managedUnit); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "start", managedUnit); err != nil {
		return err
	}
	if err := verifyRunningRelay(ctx, next, routeProbeTimeout); err != nil {
		return err
	}
	config, _ := json.Marshal(next)
	if err := root.ReplaceFile("setup.json", config, 0600); err != nil {
		return err
	}
	if err := root.ReplaceFile("last-upgrade.json", encoded, 0600); err != nil {
		return err
	}
	if err := root.UnlinkFile("upgrade.json"); err != nil {
		return err
	}
	fmt.Fprintln(output, "Relay upgrade verified: the new image is running and reachable. Existing receivers do not need new pairing codes.")
	return nil
}
