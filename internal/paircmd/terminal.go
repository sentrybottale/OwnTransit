//go:build darwin || linux

package paircmd

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"

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
	defer func() {
		if err != nil {
			clear(out)
		}
		// Discard buffered type-ahead; restoration also flushes kernel input so
		// an oversized paste cannot become a shell command after we return.
		reader.Reset(f)
	}()
	fd := int(f.Fd())
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var b byte
		if reader.Buffered() > 0 {
			b, err = reader.ReadByte()
		} else {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, err = unix.Poll(fds, 100)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				return nil, io.EOF
			}
			if fds[0].Revents&unix.POLLIN == 0 {
				continue
			}
			var one [1]byte
			var n int
			n, err = unix.Read(fd, one[:])
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || (err == nil && n == 0) {
				continue
			}
			b = one[0]
		}
		if err != nil {
			return nil, err
		}
		switch b {
		case '\n', '\r':
			return out, nil
		case 3, 26: // Ctrl-C / Ctrl-Z: cancel, never suspend with echo disabled.
			return nil, context.Canceled
		case 4: // Ctrl-D
			return nil, io.EOF
		case 8, 127: // Backspace / Delete
			if len(out) > 0 {
				out[len(out)-1] = 0
				out = out[:len(out)-1]
			}
		case 21: // Ctrl-U: clear this entry.
			clear(out)
			out = out[:0]
		default:
			if len(out) == limit {
				return nil, pairruntime.ErrState
			}
			out = append(out, b)
		}
	}
}
