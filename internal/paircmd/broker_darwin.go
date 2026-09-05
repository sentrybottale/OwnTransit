//go:build darwin

package paircmd

import (
	"context"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"io"
)

func discover(context.Context, string) (pairrelay.ServerInfo, error) {
	return pairrelay.ServerInfo{}, pairruntime.ErrState
}
func serveBroker(context.Context, string, io.Writer) error    { return pairruntime.ErrState }
func runWorker([]string, io.Reader, io.Writer, io.Writer) int { return 1 }
