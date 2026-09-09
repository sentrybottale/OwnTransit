//go:build linux

package relaysetup

import (
	"context"
	"errors"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"os"
	"strings"
)

// CleanupManaged removes only a stopped container matching this managed name,
// pinned image, executable and state bind. It never forces a running container
// away and never removes images or volumes. Used by systemd pre/post hooks.
func CleanupManaged(ctx context.Context, engine, image string) error {
	return CleanupInstance(ctx, "default", engine, image)
}

func (s instanceSpec) cleanupStopped(ctx context.Context, engine string, images []string) error {
	if os.Geteuid() != 0 || !validEngine(engine) || len(images) == 0 {
		return errors.New("invalid managed cleanup request")
	}
	for _, image := range images {
		if !validImage(image) {
			return errors.New("invalid cleanup image ID")
		}
	}
	ids, err := command(ctx, engine, "ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+s.container)
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
		if strings.TrimPrefix(c.Name, "/") != s.container {
			continue
		}
		match := false
		for _, image := range images {
			match = match || c.Image == image
		}
		bind := false
		for _, m := range c.Mounts {
			if m.Type == "bind" && m.Source == s.root+"/data" && m.Destination == "/state" {
				bind = true
			}
		}
		if c.ID != id || !match || !s.ownsContainer(c, c.Image) || !bind {
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

func CleanupInstance(ctx context.Context, name, engine, image string) error {
	name, err := normalizedInstanceName(name)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 || !validEngine(engine) || !validImage(image) {
		return errors.New("invalid managed cleanup request")
	}
	s := defaultInstance()
	if name != "default" {
		root, err := securefs.OpenRoot(managedRoot + "/instances/" + name)
		if err != nil {
			return err
		}
		defer root.Close()
		s, err = readBinding(root, name)
		if err != nil {
			return err
		}
		checked, err := s.openRoot()
		if err != nil {
			return err
		}
		checked.Close()
		if err := s.validateData(); err != nil {
			return err
		}
	}
	return s.cleanupStopped(ctx, engine, []string{image})
}
func cleanupStopped(ctx context.Context, engine string, images []string) error {
	return defaultInstance().cleanupStopped(ctx, engine, images)
}
