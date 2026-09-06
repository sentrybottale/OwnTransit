//go:build linux

package relaysetup

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCleanupOnlyStoppedExactManagedContainer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root fixture")
	}
	if _, err := os.Stat("/owntransit-relay-setup-fixture"); err != nil {
		t.Skip("requires disposable fixture")
	}
	for _, scenario := range []string{"owned", "running", "other-image", "other-mount", "other-name"} {
		t.Run(scenario, func(t *testing.T) {
			old := command
			defer func() { command = old }()
			image := "sha256:" + strings.Repeat("a", 64)
			id := strings.Repeat("b", 64)
			removed := false
			c := containerInfo{ID: id, Name: managedContainer, Image: image}
			c.Config.Entrypoint = []string{"/owntransit-relay"}
			c.Mounts = []struct{ Type, Source, Destination string }{{"bind", managedRoot + "/data", "/state"}}
			switch scenario {
			case "running":
				c.State.Running = true
			case "other-image":
				c.Image = "sha256:" + strings.Repeat("c", 64)
			case "other-mount":
				c.Mounts[0].Source = "/unrelated"
			case "other-name":
				c.Name = "unrelated"
			}
			command = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				switch args[0] {
				case "ps":
					return []byte(id), nil
				case "container":
					return json.Marshal([]containerInfo{c})
				case "rm":
					if len(args) != 2 || args[1] != id {
						t.Fatal("cleanup widened its removal scope")
					}
					removed = true
					return nil, nil
				}
				t.Fatal("unexpected cleanup operation")
				return nil, nil
			}
			err := CleanupManaged(context.Background(), "/usr/bin/podman", image)
			if removed != (scenario == "owned") {
				t.Fatal("incorrect container removed or owned orphan left behind")
			}
			if scenario != "owned" && scenario != "other-name" && err == nil {
				t.Fatal("unsafe removal not rejected")
			}
		})
	}
}
