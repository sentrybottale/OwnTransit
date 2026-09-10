//go:build !linux

package relaysetup

import (
	"context"
	"errors"
)

func MigratePackageHooks(context.Context) error {
	return errors.New("relay package integration requires Linux")
}
