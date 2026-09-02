//go:build !darwin && !linux

package main

import (
	"errors"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
)

func detachNativePackageRuntime(string, packagetxn.RuntimeIdentity) error {
	return errors.New("native package detach is unsupported on this operating system")
}
