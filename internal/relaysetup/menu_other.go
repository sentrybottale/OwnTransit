//go:build !linux

package relaysetup

import (
	"context"
	"errors"
)

func MenuInstances(context.Context) ([]InstanceSummary, error) {
	return nil, errors.New("relay administration requires Linux")
}
func MenuTunnels(context.Context, string) ([]MenuTunnel, error) {
	return nil, errors.New("relay administration requires Linux")
}
func NewMenuTunnel(context.Context, string, string) error {
	return errors.New("relay administration requires Linux")
}
func ApproveMenuTunnel(context.Context, string, string, string) error {
	return errors.New("relay administration requires Linux")
}
func RemoveMenuTunnel(context.Context, string, MenuTunnel) error {
	return errors.New("relay administration requires Linux")
}
