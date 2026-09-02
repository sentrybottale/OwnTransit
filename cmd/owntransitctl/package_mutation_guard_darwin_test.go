//go:build darwin

package main

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenDarwinMutationLockContendsOnSameCanonicalInode(t *testing.T) {
	stage, err := os.Open(mustCanonicalTempDir(t))
	if err != nil {
		t.Fatalf("open mutation-lock stage: %v", err)
	}
	t.Cleanup(func() {
		if err := stage.Close(); err != nil {
			t.Errorf("close mutation-lock stage: %v", err)
		}
	})

	first, created, err := openDarwinMutationLock(int(stage.Fd()))
	if err != nil {
		t.Fatalf("create mutation lock: %v", err)
	}
	defer unix.Close(first)
	if !created {
		t.Fatal("first mutation-lock open did not create the canonical lock")
	}
	second, created, err := openDarwinMutationLock(int(stage.Fd()))
	if err != nil {
		t.Fatalf("reopen mutation lock: %v", err)
	}
	defer unix.Close(second)
	if created {
		t.Fatal("second mutation-lock open replaced the canonical lock")
	}

	var firstStat, secondStat unix.Stat_t
	if err := unix.Fstat(first, &firstStat); err != nil {
		t.Fatalf("stat first mutation-lock descriptor: %v", err)
	}
	if err := unix.Fstat(second, &secondStat); err != nil {
		t.Fatalf("stat second mutation-lock descriptor: %v", err)
	}
	if firstStat.Dev != secondStat.Dev || firstStat.Ino != secondStat.Ino {
		t.Fatal("mutation-lock opens did not resolve to the same canonical inode")
	}

	if err := unix.Flock(first, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("acquire first mutation lock: %v", err)
	}
	defer unix.Flock(first, unix.LOCK_UN)
	if err := unix.Flock(second, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("contending mutation lock error = %v, want EWOULDBLOCK", err)
	}
	if err := unix.Flock(first, unix.LOCK_UN); err != nil {
		t.Fatalf("release first mutation lock: %v", err)
	}
	if err := unix.Flock(second, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("acquire mutation lock after release: %v", err)
	}
	if err := unix.Flock(second, unix.LOCK_UN); err != nil {
		t.Fatalf("release second mutation lock: %v", err)
	}
}
