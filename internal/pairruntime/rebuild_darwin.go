//go:build darwin

package pairruntime

import "golang.org/x/sys/unix"

func publishReceiverDirectory(parent int, from, to string, replace bool) error {
	flags := uint32(unix.RENAME_EXCL)
	if replace {
		flags = unix.RENAME_SWAP
	}
	return unix.RenameatxNp(parent, from, parent, to, flags)
}
