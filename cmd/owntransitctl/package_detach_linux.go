//go:build linux

package main

import (
	"errors"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
)

func detachNativePackageRuntime(string, packagetxn.RuntimeIdentity) error {
	return errors.New("native package detach is not implemented on Linux")
}
