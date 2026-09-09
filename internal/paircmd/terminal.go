//go:build darwin || linux

package paircmd

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"golang.org/x/sys/unix"
)

func configureSecretTerminal(t *unix.Termios) {
	// Canonical input can reject a pasted code before our bounded reader sees
	// it (notably on macOS). Handle the few editing keys below ourselves.
	// Disable signal/extended processing too: Ctrl-C cancels locally; Ctrl-Z
	// must not suspend the program with a hidden/noncanonical terminal.
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Iflag &^= unix.IGNCR | unix.INLCR | unix.IXON
	t.Iflag |= unix.ICRNL
	t.Cc[unix.VMIN] = 0
	t.Cc[unix.VTIME] = 1
}

// readSecretTerminal has no background reader left behind on cancellation.
// Polling and bounded termios reads let SIGTERM/context cancellation restore
// the terminal even if no key is pressed. Only local ASCII code input is edited;
// non-terminal input retains its literal, strict parser behavior.
func readSecretTerminal(ctx context.Context, f *os.File, reader *bufio.Reader, limit int) (value []byte, err error) {
	out := make([]byte, 0, min(limit, 4096))
	pasting, pasted := false, false
	defer func() {
		// A paste can still be arriving when Enter, cancellation or a bound
		// ends this read. Keep echo disabled until the bounded quiet drain
		// completes; the caller then restores termios and flushes kernel input.
		drainErr := drainSecretTerminal(f, reader, pasting)
		if err == nil {
			err = ctx.Err()
			if err == nil {
				err = drainErr
			}
		}
		if err != nil {
			clear(out)
			value = nil
		}
	}()
	for {
		b, err := readSecretTerminalByte(ctx, f, reader)
		if err != nil {
			return nil, err
		}
		switch b {
		case '\n', '\r':
			if pasting {
				// A pasted newline must not submit a valid prefix while the
				// rest of a command block remains in the terminal queue.
				return nil, pairruntime.ErrState
			}
			return out, nil
		case 3, 26: // Ctrl-C / Ctrl-Z: cancel, never suspend with echo disabled.
			return nil, context.Canceled
		case 4: // Ctrl-D
			return nil, io.EOF
		case 8, 127: // Backspace / Delete
			if pasting {
				return nil, pairruntime.ErrState
			}
			pasted = false
			if len(out) > 0 {
				out[len(out)-1] = 0
				out = out[:len(out)-1]
			}
		case 21: // Ctrl-U: clear this entry.
			if pasting {
				return nil, pairruntime.ErrState
			}
			pasted = false
			clear(out)
			out = out[:0]
		case 27:
			// Accept only the known bracketed-paste delimiters around one
			// complete bounded payload. No general escape/ANSI stripping.
			if pasted || (!pasting && len(out) != 0) {
				return nil, pairruntime.ErrState
			}
			suffix := "[200~"
			if pasting {
				suffix = "[201~"
			}
			for i := range len(suffix) {
				next, err := readSecretTerminalByte(ctx, f, reader)
				if err != nil {
					return nil, err
				}
				if next == 3 || next == 26 {
					return nil, context.Canceled
				}
				if next == 4 {
					return nil, io.EOF
				}
				if next != suffix[i] {
					return nil, pairruntime.ErrState
				}
			}
			pasting, pasted = !pasting, pasting
		default:
			if b < 32 || b > 126 || pasted || len(out) == limit {
				return nil, pairruntime.ErrState
			}
			out = append(out, b)
		}
	}
}

func readSecretTerminalByte(ctx context.Context, f *os.File, reader *bufio.Reader) (byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if reader.Buffered() > 0 {
			return reader.ReadByte()
		}
		fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return 0, io.EOF
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var one [1]byte
		n, err := unix.Read(int(f.Fd()), one[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || (err == nil && n == 0) {
			continue
		}
		return one[0], err
	}
}

// Drain queued input and ordinary fragmented paste tails without waiting on a
// background reader. The absolute cap also bounds cancellation under continuous
// input. Input arriving after this quiet/capped window is a later terminal event.
func drainSecretTerminal(f *os.File, reader *bufio.Reader, pasting bool) error {
	var result error
	const endPaste = "\x1b[201~"
	endMatched := 0
	discard := func(data []byte) {
		for _, b := range data {
			if pasting {
				if b == endPaste[endMatched] {
					endMatched++
					if endMatched == len(endPaste) {
						pasting = false
					}
				} else if b == endPaste[0] {
					endMatched = 1
				} else {
					endMatched = 0
				}
			}
			if b == 3 || b == 26 {
				result = context.Canceled
			} else if b != '\r' && b != '\n' && result == nil {
				// CRLF is one submit. Any other type-ahead invalidates the
				// entry instead of accepting a prefix of a pasted block.
				result = pairruntime.ErrState
			}
		}
		clear(data)
	}
	buffered, _ := reader.Peek(reader.Buffered())
	discard(buffered)
	reader.Reset(f)
	var scratch [4096]byte
	defer clear(scratch[:])
	deadline := time.Now().Add(750 * time.Millisecond)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return result
		}
		fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, min(75, int(remaining.Milliseconds())+1))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 && pasting {
			// An observed start delimiter identifies the pending paste even
			// across a delivery pause. Drain through its end or the hard cap.
			continue
		}
		if n == 0 || fds[0].Revents&unix.POLLIN == 0 {
			return result
		}
		n, err = unix.Read(int(f.Fd()), scratch[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		discard(scratch[:n])
	}
}
