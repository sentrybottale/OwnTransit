//go:build darwin

package paircmd

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func hideEcho(f *os.File) (func(), error) {
	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	if errors.Is(err, unix.ENOTTY) {
		return func() {}, nil
	}
	if err != nil {
		return nil, err
	}
	old := *t
	t.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, &old) }, nil
}
