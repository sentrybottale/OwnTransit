//go:build !linux

package relaysetup

import (
	"context"
	"errors"
)

func UninstallManaged(context.Context) error { return errors.New("relay uninstall requires Linux") }
func UninstallInstance(ctx context.Context, name string) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	return UninstallManaged(ctx)
}
func UninstallAllManaged(context.Context) error { return errors.New("relay uninstall requires Linux") }
