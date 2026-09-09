//go:build !linux

package relaysetup

import (
	"context"
	"errors"
	"io"
)

func PrepareSetup(context.Context, string, string) (SetupPlan, error) {
	return SetupPlan{}, errors.New("VPS setup runs on Linux")
}
func ApplySetup(context.Context, SetupPlan, bool, io.Writer) error {
	return errors.New("VPS setup runs on Linux")
}
