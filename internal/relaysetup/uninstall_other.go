//go:build !linux

package relaysetup

import (
	"context"
	"errors"
)

func UninstallManaged(context.Context) error { return errors.New("relay uninstall requires Linux") }
