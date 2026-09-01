//go:build darwin

package packagetxn

import (
	"os"
	"testing"
)

func TestPackageACLVerifierAcceptsCleanDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "clean")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := verifyPackageACL(int(file.Fd()), false); err != nil {
		t.Fatalf("verify clean package descriptor ACL: %v", err)
	}
}
