//go:build darwin

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestRecoverableDarwinLauncherStageProfiles(t *testing.T) {
	readerGID := uint32(704)
	regular := uint16(unix.S_IFREG)
	tests := []struct {
		name string
		stat unix.Stat_t
		want bool
	}{
		{name: "empty creation", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1}, want: true},
		{name: "partial copy", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: 10}, want: true},
		{name: "ownership transferred", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: readerGID, Nlink: 1, Size: 10}, want: true},
		{name: "activated", stat: unix.Stat_t{Mode: regular | 0o2751, Uid: 0, Gid: readerGID, Nlink: 1, Size: 10}, want: true},
		{name: "empty transferred", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: readerGID, Nlink: 1}},
		{name: "wrong reader", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: readerGID + 1, Nlink: 1, Size: 10}},
		{name: "writable activated", stat: unix.Stat_t{Mode: regular | 0o2771, Uid: 0, Gid: readerGID, Nlink: 1, Size: 10}},
		{name: "hard link", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 2, Size: 10}},
		{name: "symlink", stat: unix.Stat_t{Mode: uint16(unix.S_IFLNK) | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: 10}},
		{name: "oversize", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: maxDarwinClientLauncherBytes + 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := recoverableDarwinLauncherStage(test.stat, readerGID); got != test.want {
				t.Fatalf("recoverableDarwinLauncherStage() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRecoverableDarwinPublicLauncherModes(t *testing.T) {
	for _, mode := range []uint32{0o2751, 0o751} {
		if !recoverableDarwinPublicLauncherMode(mode) {
			t.Fatalf("recoverable public launcher mode %04o rejected", mode)
		}
	}
	for _, mode := range []uint32{0, 0o750, 0o755, 0o4751, 0o2771} {
		if recoverableDarwinPublicLauncherMode(mode) {
			t.Fatalf("unsafe public launcher mode %04o accepted", mode)
		}
	}
}

func TestRecoverableDarwinFrontendStageProfiles(t *testing.T) {
	regular := uint16(unix.S_IFREG)
	tests := []struct {
		name string
		stat unix.Stat_t
		want bool
	}{
		{name: "empty creation", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1}, want: true},
		{name: "partial copy", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: 10}, want: true},
		{name: "activated", stat: unix.Stat_t{Mode: regular | 0o755, Uid: 0, Gid: 0, Nlink: 1, Size: 10}, want: true},
		{name: "empty activated", stat: unix.Stat_t{Mode: regular | 0o755, Uid: 0, Gid: 0, Nlink: 1}},
		{name: "wrong group", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 704, Nlink: 1, Size: 10}},
		{name: "setgid", stat: unix.Stat_t{Mode: regular | 0o2755, Uid: 0, Gid: 0, Nlink: 1, Size: 10}},
		{name: "hard link", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 2, Size: 10}},
		{name: "symlink", stat: unix.Stat_t{Mode: uint16(unix.S_IFLNK) | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: 10}},
		{name: "oversize", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: maxDarwinClientFrontendBytes + 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := recoverableDarwinFrontendStage(test.stat); got != test.want {
				t.Fatalf("recoverableDarwinFrontendStage() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRecoverableDarwinProvisionerStageProfiles(t *testing.T) {
	regular := uint16(unix.S_IFREG)
	tests := []struct {
		name string
		stat unix.Stat_t
		want bool
	}{
		{name: "empty creation", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1}, want: true},
		{name: "partial copy", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: 10}, want: true},
		{name: "activated", stat: unix.Stat_t{Mode: regular | 0o755, Uid: 0, Gid: 0, Nlink: 1, Size: 10}, want: true},
		{name: "hard link", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 2, Size: 10}},
		{name: "wrong mode", stat: unix.Stat_t{Mode: regular | 0o700, Uid: 0, Gid: 0, Nlink: 1, Size: 10}},
		{name: "oversize", stat: unix.Stat_t{Mode: regular | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: maxDarwinProvisionerFrontendBytes + 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := recoverableDarwinProvisionerStage(test.stat); got != test.want {
				t.Fatalf("recoverableDarwinProvisionerStage() = %v, want %v", got, test.want)
			}
		})
	}
}
