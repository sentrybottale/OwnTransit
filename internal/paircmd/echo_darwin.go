//go:build darwin

package paircmd

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func secretTerminal(f *os.File) (func() error, bool, error) {
	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	if errors.Is(err, unix.ENOTTY) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	old := *t
	configureSecretTerminal(t)
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, t); err != nil {
		return nil, false, err
	}
	return func() error { return unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETAF, &old) }, true, nil
}
