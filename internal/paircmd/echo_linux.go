//go:build linux

package paircmd

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func secretTerminal(f *os.File) (func() error, bool, error) {
	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if errors.Is(err, unix.ENOTTY) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	old := *t
	configureSecretTerminal(t)
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, t); err != nil {
		return nil, false, err
	}
	return func() error { return unix.IoctlSetTermios(int(f.Fd()), unix.TCSETSF, &old) }, true, nil
}
