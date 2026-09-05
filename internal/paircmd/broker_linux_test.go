//go:build linux

package paircmd

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "pair" && os.Args[2] == "permission-helper" {
		if os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 {
			os.Exit(21)
		}
		groups, e := os.Getgroups()
		if e != nil || len(groups) != 0 {
			os.Exit(22)
		}
		if _, e := os.ReadFile(os.Args[3]); e == nil {
			os.Exit(23)
		}
		if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
			os.Exit(24)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestWorkerDropsIdentityAndCannotReadAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned test executable in a root-owned non-writable directory")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(executable) != "/usr/local/libexec/owntransit-pair-check" {
		t.Skip("run the explicit root-owned broker qualification binary")
	}
	root := t.TempDir()
	secret := filepath.Join(root, "authority-fixture")
	if err := os.WriteFile(secret, []byte("generated disposable authority fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, err := workerCommand(ctx, "permission-helper", secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("unprivileged worker isolation: %v", err)
	}
}
