//go:build linux

package relaysetup

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectionDockerAndPodmanShapes(t *testing.T) {
	for _, engine := range []string{"docker", "podman-4.9.3"} {
		t.Run(engine, func(t *testing.T) {
			entry := any([]string{"/owntransit-relay"})
			image := "sha256:" + strings.Repeat("a", 64)
			if engine != "docker" {
				entry = "/owntransit-relay"
				image = strings.TrimPrefix(image, "sha256:")
			}
			data, _ := json.Marshal([]any{map[string]any{"Id": strings.Repeat("b", 64), "Image": image, "Name": "owntransit-relay-managed", "Config": map[string]any{"Entrypoint": entry, "Cmd": []string{"pair", "serve"}}, "State": map[string]any{"Running": true}}})
			c, err := decodeInspection(data)
			if err != nil || !ownRelay(c) || c.Image != "sha256:"+strings.Repeat("a", 64) {
				t.Fatalf("engine shape rejected: %v", err)
			}
		})
	}
}

func TestInspectionRejectsMalformedFieldsAndShellEntrypoints(t *testing.T) {
	for _, entry := range []string{`42`, `true`, `{}`, `["/owntransit-relay",42]`} {
		data := []byte(`[{"Image":"` + strings.Repeat("a", 64) + `","Config":{"Entrypoint":` + entry + `}}]`)
		if _, err := decodeInspection(data); err == nil {
			t.Fatal("invalid entrypoint type accepted")
		}
	}
	for _, image := range []string{"", "latest", "sha256:abc", strings.Repeat("A", 64), " " + strings.Repeat("a", 64)} {
		b, _ := json.Marshal([]any{map[string]any{"Image": image}})
		if _, err := decodeInspection(b); err == nil {
			t.Fatal("noncanonical image accepted")
		}
	}
	for _, entry := range []string{`"/bin/sh -c /owntransit-relay"`, `""`, `null`, `[]`, `["/bin/sh","-c","/owntransit-relay"]`} {
		data := []byte(`[{"Image":"` + strings.Repeat("a", 64) + `","Name":"owntransit-relay-managed","Config":{"Entrypoint":` + entry + `}}]`)
		c, err := decodeInspection(data)
		if err != nil {
			t.Fatal(err)
		}
		if ownRelay(c) {
			t.Fatal("ambiguous/unrelated executable treated as relay")
		}
	}
	for _, body := range []string{`[]`, `[{},{}]`, `{}`, `null`} {
		if _, err := decodeInspection([]byte(body)); err == nil {
			t.Fatal("invalid inspection cardinality accepted")
		}
	}
}
