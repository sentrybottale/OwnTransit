//go:build linux

package relaysetup

import (
	"bytes"
	"strings"
	"testing"
)

func TestManagedMigrationManualUnitStrict(t *testing.T) {
	s := legacySpec("alpha", "wss://work.example/connects", 9088)
	engine, image := "/usr/bin/podman", "sha256:"+strings.Repeat("a", 64)
	u := s.legacyUnit(image, engine)
	if !knownManualUnit(u, s, engine, image) {
		t.Fatal("supported unit rejected")
	}
	for _, change := range [][2]string{{"--read-only", ""}, {"--cap-drop=all", "--cap-drop=NET_RAW"}, {"127.0.0.1:9088", "0.0.0.0:9088"}, {"--user=65532:65532", "--user=0:0"}, {"/var/lib/owntransit-relay-alpha/data", "/var/lib/owntransit-relay-setup/data"}, {"RestartSec=5s", "RestartSec=1s"}, {"Description=OwnTransit managed relay", "Description=%n"}} {
		bad := bytes.Replace(u, []byte(change[0]), []byte(change[1]), 1)
		if knownManualUnit(bad, s, engine, image) {
			t.Fatalf("accepted altered fixed unit field %q", change[0])
		}
	}
	if knownManualUnit(append(u, []byte("ExecStartPost=/bin/true\n")...), s, engine, image) {
		t.Fatal("unknown unit directive accepted")
	}
}

func TestManagedMigrationPodmanCapabilityProjection(t *testing.T) {
	c := containerInfo{}
	c.HostConfig.CapDrop = []string{"CAP_SYS_CHROOT", "CAP_SETUID", "CAP_SETPCAP", "CAP_SETGID", "CAP_SETFCAP", "CAP_NET_BIND_SERVICE", "CAP_KILL", "CAP_FSETID", "CAP_FOWNER", "CAP_DAC_OVERRIDE", "CAP_CHOWN"}
	if !droppedAllCapabilities(c) {
		t.Fatal("complete expanded Podman drop set rejected")
	}
	c.EffectiveCaps = []string{"CAP_CHOWN"}
	if droppedAllCapabilities(c) {
		t.Fatal("effective capability accepted")
	}
	c.EffectiveCaps = nil
	c.HostConfig.CapDrop = c.HostConfig.CapDrop[:10]
	if droppedAllCapabilities(c) {
		t.Fatal("partial drop set accepted")
	}
	c.HostConfig.CapDrop = []string{"ALL"}
	if !droppedAllCapabilities(c) {
		t.Fatal("Docker ALL projection rejected")
	}
	c.BoundingCaps = []string{"CAP_CHOWN"}
	if droppedAllCapabilities(c) {
		t.Fatal("nonempty bounding set accepted")
	}
}

func TestMigrationBindingCannotAliasDefaultOrSelectPaths(t *testing.T) {
	for _, label := range []string{"", "default", "setup", "managed", "managed-alpha", "pair", "../alpha", "/tmp/alpha", "alpha/data", "all"} {
		b := instanceBinding{Schema: "owntransit.relay-instance.v2", Name: "work", URL: "wss://work.example/connects", Port: 9088, LegacyDataLabel: label}
		if _, err := instanceFromBinding(b); err == nil {
			t.Fatalf("accepted unsupported legacy label %q", label)
		}
	}
	b := instanceBinding{Schema: "owntransit.relay-instance.v2", Name: "default", URL: "wss://work.example/connects", Port: 9087, LegacyDataLabel: "alpha"}
	if _, err := instanceFromBinding(b); err == nil {
		t.Fatal("migration changed default data")
	}
	b.Schema, b.Name, b.Port = "owntransit.relay-instance.v1", "work", 9088
	if _, err := instanceFromBinding(b); err == nil {
		t.Fatal("legacy binding accepted migration authority")
	}
}
