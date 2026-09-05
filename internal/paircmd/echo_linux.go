//go:build linux

package paircmd

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func hideEcho(f *os.File) (func(), error) {
	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if errors.Is(err, unix.ENOTTY) {
		return func() {}, nil
	}
	if err != nil {
		return nil, err
	}
	old := *t
	t.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, &old) }, nil
}
