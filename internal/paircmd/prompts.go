//go:build darwin || linux

package paircmd

import (
	"bufio"
	"context"
	"fmt"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"io"
)

func promptValidated(ctx context.Context, input io.Reader, reader *bufio.Reader, diagnostics io.Writer, prompt, hint string, limit int, secret bool, validate func([]byte) error) ([]byte, error) {
	for attempt := 0; attempt < 5; attempt++ {
		value, err := readPrompt(ctx, input, reader, diagnostics, prompt, limit, secret)
		if err != nil {
			fmt.Fprintln(diagnostics, "Input stopped. Run setup again when ready; values were not logged.")
			return nil, err
		}
		if len(value) > 0 && validate(value) == nil {
			return value, nil
		}
		clear(value)
		fmt.Fprintln(diagnostics, hint)
	}
	fmt.Fprintln(diagnostics, "Setup stopped after five invalid entries. Run the setup command again when you have the requested values.")
	return nil, pairruntime.ErrState
}
