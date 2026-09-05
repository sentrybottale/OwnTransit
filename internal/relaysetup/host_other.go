//go:build !linux

package relaysetup

import (
	"context"
	"errors"
	"io"
)

func Setup(context.Context, string, io.Writer) error { return errors.New("VPS setup runs on Linux") }
func RegisterManaged(context.Context, string) (string, error) {
	return "", errors.New("VPS registration runs on Linux")
}
