//go:build darwin

package pairrelaycmd

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func unixPeerUID(connection *net.UnixConn) (uint32, error) {
	if connection == nil {
		return 0, errors.New("pairrelaycmd: missing local connection")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Xucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil || credential == nil {
		if controlErr != nil {
			return 0, controlErr
		}
		return 0, errors.New("pairrelaycmd: local peer credential is absent")
	}
	return credential.Uid, nil
}
