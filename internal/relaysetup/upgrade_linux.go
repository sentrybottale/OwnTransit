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
	"strings"
	"time"
)

type upgradeIntent struct {
	Schema       string      `json:"schema"`
	Previous     savedConfig `json:"previous"`
	Next         savedConfig `json:"next"`
	Enabled      bool        `json:"enabled"`
	Running      bool        `json:"running"`
	PreviousUnit []byte      `json:"previous_unit,omitempty"`
}

func validSaved(c savedConfig) bool {
	u, e := PublicURL(c.URL)
	if e != nil || u != c.URL || !validImage(c.Image) || !validEngine(c.Engine) {
		return false
	}
	if c.Schema == "owntransit.relay-setup.v1" {
		return c.Instance == "" && c.Port == 0
	}
	return c.Schema == "owntransit.relay-setup.v2" && ValidateInstanceName(c.Instance) == nil && c.Instance != "" && c.Instance != "default" && c.Port >= firstInstancePort && c.Port <= lastInstancePort
}

func (s instanceSpec) managedIdentity(ctx context.Context, engine, image string) (pairrelay.ServerInfo, error) {
	c, err := inspect(ctx, engine, s.container)
	if err != nil || !c.State.Running || c.Image != image || !s.ownsContainer(c, image) {
		return pairrelay.ServerInfo{}, errors.New("the selected relay image is not running")
	}
	b, err := command(ctx, engine, "exec", s.container, "/owntransit-relay", "pair", "info", "--state", "/state/relay")
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	var info pairrelay.ServerInfo
	if strictjson.Decode(b, &info) != nil {
		return info, errors.New("local relay identity could not be verified")
	}
	return info, nil
}

func (s instanceSpec) verifyRunningRelay(ctx context.Context, c savedConfig, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		local, err := s.managedIdentity(ctx, c.Engine, c.Image)
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
func (s instanceSpec) restoreManaged(ctx context.Context, root *securefs.Root, j upgradeIntent) error {
	if !s.validSaved(j.Previous) || !s.validSaved(j.Next) || !s.validJournalSchema(j.Schema) || j.Previous.URL != j.Next.URL || j.Previous.Engine != j.Next.Engine {
		return errors.New("invalid relay upgrade journal")
	}
	previousUnit := j.PreviousUnit
	if j.Schema == "owntransit.relay-upgrade.v1" {
		if len(previousUnit) != 0 {
			return errors.New("invalid legacy journal")
		}
		previousUnit = s.legacyUnit(j.Previous.Image, j.Previous.Engine)
	}
	if !s.knownUnit(previousUnit, j.Previous) {
		return errors.New("invalid previous unit in upgrade journal")
	}
	current, _, err := protectedFile(s.unitPath)
	if err != nil || (!bytes.Equal(current, previousUnit) && !s.knownUnit(current, j.Next)) {
		return errors.New("managed unit changed outside upgrade; rollback refused")
	}
	drops, err := command(ctx, "/usr/bin/systemctl", "show", s.unitName, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(drops)) != 0 {
		return errors.New("managed service overrides changed; rollback refused")
	}
	config, err := s.loadConfig()
	if err != nil || (config != j.Previous && config != j.Next) {
		return errors.New("setup selection changed outside upgrade; rollback refused")
	}
	if err := s.prevalidateUpgradeContainer(ctx, j); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "stop", s.unitName); err != nil {
		return err
	}
	if err := s.cleanupStopped(ctx, j.Previous.Engine, []string{j.Previous.Image, j.Next.Image}); err != nil {
		return err
	}
	if err := writeAtomic(s.unitPath, previousUnit, 0644); err != nil {
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
	if _, err := command(ctx, "/usr/bin/systemctl", action, s.unitName); err != nil {
		return err
	}
	if j.Running {
		if _, err := command(ctx, "/usr/bin/systemctl", "start", s.unitName); err != nil {
			return err
		}
		wait, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		for {
			c, e := inspect(wait, j.Previous.Engine, s.container)
			if e == nil && c.State.Running && s.ownsContainer(c, j.Previous.Image) {
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

func (s instanceSpec) recoverManaged(ctx context.Context, root *securefs.Root, output io.Writer) error {
	b, err := s.readRecord(root, "upgrade.json", 8192)
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
	return s.restoreManaged(ctx, root, j)
}

func (s instanceSpec) upgradeManaged(ctx context.Context, root *securefs.Root, previous, next savedConfig, output io.Writer) (returnErr error) {
	if !s.validSaved(previous) || !s.validSaved(next) || previous.Engine != next.Engine || previous.URL != next.URL {
		return errors.New("use the existing relay URL and engine for an in-place upgrade")
	}
	original, _, err := protectedFile(s.unitPath)
	if err != nil || !s.knownUnit(original, previous) {
		return errors.New("existing relay unit is not the saved managed configuration; no service was changed")
	}
	drops, err := command(ctx, "/usr/bin/systemctl", "show", s.unitName, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(drops)) != 0 {
		return errors.New("managed relay has custom systemd overrides; refusing an automatic replacement")
	}
	_, activeErr := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", s.unitName)
	_, enabledErr := command(ctx, "/usr/bin/systemctl", "is-enabled", "--quiet", s.unitName)
	if activeErr == nil {
		c, e := inspect(ctx, previous.Engine, s.container)
		if e != nil || !c.State.Running || c.Image != previous.Image || !s.ownsContainer(c, previous.Image) {
			return errors.New("running relay does not match saved managed image; no service was changed")
		}
	}
	if previous == next && activeErr == nil && bytes.Equal(original, s.unit(next.Image, next.Engine)) {
		if err := s.verifyRunningRelay(ctx, next, routeProbeTimeout); err != nil {
			return errors.Join(errors.New("existing relay left running; check its public route"), err)
		}
		if enabledErr != nil {
			if _, err := command(ctx, "/usr/bin/systemctl", "enable", s.unitName); err != nil {
				return err
			}
		}
		fmt.Fprintln(output, "This relay version is already running; no container or website configuration was replaced.")
		return nil
	}
	if err := s.prevalidateUpgradeContainer(ctx, upgradeIntent{Previous: previous, Next: previous}); err != nil {
		return err
	}
	if _, err := command(ctx, previous.Engine, "image", "inspect", "--format", "{{.Id}}", previous.Image); err != nil {
		return errors.New("previous image is unavailable for rollback; relay left unchanged")
	}
	schema := "owntransit.relay-upgrade.v2"
	if s.named() {
		schema = "owntransit.relay-upgrade.v3"
	}
	j := upgradeIntent{schema, previous, next, enabledErr == nil, activeErr == nil, original}
	encoded, _ := json.Marshal(j)
	if err := root.CreateExclusive("upgrade.json", encoded, 0600); err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if e := s.restoreManaged(rollbackCtx, root, j); e != nil {
				returnErr = errors.Join(returnErr, errors.New("rollback needs attention; rerun the same setup command to recover"), e)
			} else {
				fmt.Fprintln(output, "Upgrade failed; previous relay software and service state restored. Retry the same installer command after resolving the reported problem.")
			}
		}
	}()
	fmt.Fprintln(output, "Upgrading the existing relay container. Active tunnels may reconnect; relay keys, pairings and website routing are preserved.")
	if _, err := command(ctx, "/usr/bin/systemctl", "stop", s.unitName); err != nil {
		return err
	}
	if err := s.cleanupStopped(ctx, previous.Engine, []string{previous.Image}); err != nil {
		return err
	}
	if err := writeAtomic(s.unitPath, s.unit(next.Image, next.Engine), 0644); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "enable", s.unitName); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "start", s.unitName); err != nil {
		return err
	}
	if err := s.verifyRunningRelay(ctx, next, routeProbeTimeout); err != nil {
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

func (s instanceSpec) validJournalSchema(schema string) bool {
	if s.named() {
		return schema == "owntransit.relay-upgrade.v3"
	}
	return schema == "owntransit.relay-upgrade.v1" || schema == "owntransit.relay-upgrade.v2"
}
func (s instanceSpec) prevalidateUpgradeContainer(ctx context.Context, j upgradeIntent) error {
	if !s.named() {
		return nil
	}
	c, err := inspect(ctx, j.Previous.Engine, s.container)
	if err != nil {
		// The engine must positively report absence; an inspect failure alone
		// must never authorize stopping an unknown same-name service.
		ids, e := command(ctx, j.Previous.Engine, "ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+s.container)
		if e != nil {
			return e
		}
		for _, id := range strings.Fields(string(ids)) {
			candidate, e := inspect(ctx, j.Previous.Engine, id)
			if e != nil {
				return e
			}
			if strings.TrimPrefix(candidate.Name, "/") == s.container {
				return errors.New("relay inspection failed; service left unchanged")
			}
		}
		return nil
	}
	if !s.ownsContainer(c, j.Previous.Image) && !s.ownsContainer(c, j.Next.Image) {
		return errors.New("relay container ownership changed; service left unchanged")
	}
	return nil
}
func managedIdentity(ctx context.Context, engine, image string) (pairrelay.ServerInfo, error) {
	return defaultInstance().managedIdentity(ctx, engine, image)
}
func verifyRunningRelay(ctx context.Context, c savedConfig, timeout time.Duration) error {
	return defaultInstance().verifyRunningRelay(ctx, c, timeout)
}
func restoreManaged(ctx context.Context, root *securefs.Root, j upgradeIntent) error {
	return defaultInstance().restoreManaged(ctx, root, j)
}
func recoverManaged(ctx context.Context, root *securefs.Root, output io.Writer) error {
	return defaultInstance().recoverManaged(ctx, root, output)
}
func upgradeManaged(ctx context.Context, root *securefs.Root, previous, next savedConfig, output io.Writer) error {
	return defaultInstance().upgradeManaged(ctx, root, previous, next, output)
}
