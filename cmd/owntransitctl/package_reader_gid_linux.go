//go:build linux

package main

import (
	"errors"
	"os/user"
	"strconv"
)

func nativePackageReaderGID(role string) (int, error) {
	if role == "provisioner" {
		return 0, nil
	}
	group, err := user.LookupGroup("owntransit-" + role)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(group.Gid, 10, 31)
	if err != nil || value == 0 {
		return 0, errors.New("dedicated runtime reader group has an invalid GID")
	}
	return int(value), nil
}
