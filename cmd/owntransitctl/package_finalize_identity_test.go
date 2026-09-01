package main

import (
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
)

func TestRenderDarwinLauncherBindingFromAuthenticatedRuntime(t *testing.T) {
	receipt := []byte("schema=owntransit.macos-client-reader.v1\n" +
		"client_user=operator\n" +
		"client_uid=501\n" +
		"client_primary_gid=20\n" +
		"client_uuid=01234567-89AB-CDEF-0123-456789ABCDEF\n" +
		"reader_group=_owntransit\n" +
		"reader_gid=5001\n" +
		"reader_group_uuid=FEDCBA98-7654-3210-FEDC-BA9876543210\n")
	releaseID := strings.Repeat("b", 51) + "a"
	digest := strings.Repeat("c", 64)
	encoded, gid, err := renderDarwinLauncherBinding(receipt, packagetxn.RuntimeIdentity{
		ReleaseID: releaseID, ReleaseSequence: 7, ArtifactSHA256: digest,
		OS: "darwin", Arch: "arm64", Role: "client",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gid != 5001 {
		t.Fatalf("reader GID = %d", gid)
	}
	want := "schema=owntransit.macos-client-launcher.v1\n" +
		"client_uid=501\n" +
		"client_uuid=01234567-89AB-CDEF-0123-456789ABCDEF\n" +
		"reader_gid=5001\n" +
		"release_id=" + releaseID + "\n" +
		"client_sha256=" + digest + "\n"
	if string(encoded) != want {
		t.Fatalf("binding = %q, want %q", encoded, want)
	}
}

func TestRenderDarwinLauncherBindingRejectsUntrustedInputs(t *testing.T) {
	validReceipt := "schema=owntransit.macos-client-reader.v1\n" +
		"client_user=operator\nclient_uid=501\nclient_primary_gid=20\nclient_uuid=01234567-89AB-CDEF-0123-456789ABCDEF\n" +
		"reader_group=_owntransit\nreader_gid=5001\nreader_group_uuid=FEDCBA98-7654-3210-FEDC-BA9876543210\n"
	validRuntime := packagetxn.RuntimeIdentity{
		ReleaseID: strings.Repeat("b", 51) + "a", ReleaseSequence: 1,
		ArtifactSHA256: strings.Repeat("c", 64), OS: "darwin", Arch: "arm64", Role: "client",
	}
	for name, mutate := range map[string]func() ([]byte, packagetxn.RuntimeIdentity){
		"unknown receipt field": func() ([]byte, packagetxn.RuntimeIdentity) {
			return []byte(strings.Replace(validReceipt, "client_user=operator", "other=operator", 1)), validRuntime
		},
		"member-like group": func() ([]byte, packagetxn.RuntimeIdentity) {
			return []byte(strings.Replace(validReceipt, "reader_group=_owntransit", "reader_group=staff", 1)), validRuntime
		},
		"noncanonical uid": func() ([]byte, packagetxn.RuntimeIdentity) {
			return []byte(strings.Replace(validReceipt, "client_uid=501", "client_uid=0501", 1)), validRuntime
		},
		"wrong runtime role": func() ([]byte, packagetxn.RuntimeIdentity) {
			value := validRuntime
			value.Role = "connector"
			return []byte(validReceipt), value
		},
		"noncanonical digest": func() ([]byte, packagetxn.RuntimeIdentity) {
			value := validRuntime
			value.ArtifactSHA256 = strings.Repeat("C", 64)
			return []byte(validReceipt), value
		},
	} {
		t.Run(name, func(t *testing.T) {
			receipt, runtimeIdentity := mutate()
			if _, _, err := renderDarwinLauncherBinding(receipt, runtimeIdentity); err == nil {
				t.Fatal("accepted invalid launcher activation input")
			}
		})
	}
}
