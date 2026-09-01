//go:build linux

package packagetxn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxACLVerifierRejectsACLNamedExtendedAttribute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl-probe")
	if err := os.WriteFile(path, []byte("probe"), 0o600); err != nil {
		t.Fatalf("write ACL probe: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open ACL probe: %v", err)
	}
	defer file.Close()
	if err := unix.Setxattr(path, "user.owntransit_acl_probe", []byte("present"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
			t.Skipf("test filesystem cannot create the ACL probe xattr: %v", err)
		}
		t.Fatalf("set ACL probe xattr: %v", err)
	}
	if err := verifyPackageACL(int(file.Fd()), false); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("verifyPackageACL error = %v", err)
	}
}
