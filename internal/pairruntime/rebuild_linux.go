//go:build linux

package pairruntime

import "golang.org/x/sys/unix"

func publishReceiverDirectory(parent int, from, to string, replace bool) error {
	flags := uint(unix.RENAME_NOREPLACE)
	if replace {
		flags = unix.RENAME_EXCHANGE
	}
	return unix.Renameat2(parent, from, parent, to, flags)
}
