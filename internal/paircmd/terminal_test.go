//go:build darwin || linux

package paircmd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// The Python harness uses isolated PTYs, never the developer's terminal or
// clipboard. All input is synthetic; only length/digest reach helper output.
func TestSecretPromptPTY(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for real terminal regression tests")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "testdata/prompt_pty.py", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("PTY regression: %v\n%s", err, out)
	}
}

func TestPromptPTYHelper(t *testing.T) {
	if os.Getenv("OWNTRANSIT_PROMPT_PTY_HELPER") != "1" {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 8*time.Second)
	defer timeout()
	value, err := readLine(ctx, os.Stdin, bufio.NewReader(os.Stdin), os.Stderr, "HIDDEN: ", 32768)
	status := "ok"
	switch {
	case errors.Is(err, context.Canceled):
		status = "cancel"
	case errors.Is(err, io.EOF):
		status = "eof"
	case err != nil:
		status = "error"
	}
	fmt.Printf("RESULT %s %d %x\n", status, len(value), sha256.Sum256(value))
	clear(value)
}
