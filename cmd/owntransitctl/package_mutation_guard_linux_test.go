//go:build linux

package main

import "testing"

func TestValidLinuxProtectedHardlinks(t *testing.T) {
	for _, value := range [][]byte{nil, {}, []byte("0\n"), []byte("1"), []byte("1\n\n"), []byte(" 1\n")} {
		if validLinuxProtectedHardlinks(value) {
			t.Fatalf("invalid protected-hardlinks value %q accepted", value)
		}
	}
	if !validLinuxProtectedHardlinks([]byte("1\n")) {
		t.Fatal("exact enabled protected-hardlinks policy rejected")
	}
}

func TestLinuxPackageMutationGuardScopesProtectedHardlinksToProvisioner(t *testing.T) {
	for _, role := range []string{"client", "connector", "relay"} {
		guard, err := acquireNativePackageMutationGuard(role)
		if err != nil {
			t.Fatalf("%s guard: %v", role, err)
		}
		if err := guard.Close(); err != nil {
			t.Fatalf("close %s guard: %v", role, err)
		}
	}
}
