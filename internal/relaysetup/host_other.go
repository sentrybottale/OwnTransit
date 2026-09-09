//go:build !linux

package relaysetup

import (
	"context"
	"errors"
	"io"
)

func Setup(context.Context, string, io.Writer) error { return errors.New("VPS setup runs on Linux") }
func CleanupManaged(context.Context, string, string) error {
	return errors.New("VPS cleanup runs on Linux")
}
func RegisterManaged(context.Context, string) (string, error) {
	return "", errors.New("VPS registration runs on Linux")
}

func SetupInstance(ctx context.Context, name, url string, out io.Writer) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	return Setup(ctx, url, out)
}
func RegisterInstance(ctx context.Context, name, id string) (string, error) {
	if err := ValidateInstanceName(name); err != nil {
		return "", err
	}
	return RegisterManaged(ctx, id)
}
func CleanupInstance(ctx context.Context, name, engine, image string) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	return CleanupManaged(ctx, engine, image)
}
func ListInstances(context.Context, io.Writer) error {
	return errors.New("relay listing requires Linux")
}
