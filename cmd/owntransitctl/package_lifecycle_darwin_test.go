//go:build darwin

package main

import "testing"

func TestDarwinPackageRootsAreCanonicalWithoutVarSymlink(t *testing.T) {
	packageRoot, anchorRoot, err := nativePackageRoots()
	if err != nil {
		t.Fatal(err)
	}
	if packageRoot != "/Library/OwnTransit/roles" {
		t.Fatalf("package root = %q", packageRoot)
	}
	if anchorRoot != "/private/var/db/OwnTransit/package-rollback" {
		t.Fatalf("anchor root = %q", anchorRoot)
	}
}
