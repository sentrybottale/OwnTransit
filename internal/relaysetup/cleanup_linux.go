//go:build linux

package relaysetup

import (
	"context"
	"errors"
	"os"
	"strings"
)

// CleanupManaged removes only a stopped container matching this managed name,
// pinned image, executable and state bind. It never forces a running container
// away and never removes images or volumes. Used by systemd pre/post hooks.
func CleanupManaged(ctx context.Context, engine, image string) error {
	return cleanupStopped(ctx, engine, []string{image})
}

func cleanupStopped(ctx context.Context, engine string, images []string) error {
	if os.Geteuid() != 0 || !validEngine(engine) || len(images) == 0 {
		return errors.New("invalid managed cleanup request")
	}
	for _, image := range images {
		if !validImage(image) {
			return errors.New("invalid cleanup image ID")
		}
	}
	ids, err := command(ctx, engine, "ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+managedContainer)
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(ids)) {
		if len(id) != 64 || !validImage("sha256:"+id) {
			return errors.New("invalid cleanup container ID")
		}
		c, err := inspect(ctx, engine, id)
		if err != nil {
			if absent, e := containerAbsent(ctx, engine, id); e == nil && absent {
				continue
			}
			return err
		}
		if strings.TrimPrefix(c.Name, "/") != managedContainer {
			continue
		}
		match := false
		for _, image := range images {
			match = match || c.Image == image
		}
		bind := false
		for _, m := range c.Mounts {
			if m.Type == "bind" && m.Source == managedRoot+"/data" && m.Destination == "/state" {
				bind = true
			}
		}
		if c.ID != id || !match || !ownRelay(c) || !bind {
			return errors.New("container name belongs to an unrecognized instance; cleanup refused")
		}
		if c.State.Running {
			return errors.New("managed container is still running; cleanup refused")
		}
		if _, err := command(ctx, engine, "rm", id); err != nil {
			if absent, e := containerAbsent(ctx, engine, id); e == nil && absent {
				continue
			}
			return err
		}
	}
	return nil
}

func containerAbsent(ctx context.Context, engine, id string) (bool, error) {
	ids, err := command(ctx, engine, "ps", "--all", "--quiet", "--no-trunc")
	if err != nil {
		return false, err
	}
	for _, value := range strings.Fields(string(ids)) {
		if value == id {
			return false, nil
		}
	}
	return true, nil
}
