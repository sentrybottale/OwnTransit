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

func TestSecretPastePTY(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for real terminal regression tests")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", secretPastePTY, binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("paste PTY regression: %v\n%s", err, out)
	}
}

func TestPastePTYHelper(t *testing.T) {
	mode := os.Getenv("OWNTRANSIT_PASTE_PTY_HELPER")
	if mode == "" {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 20*time.Second)
	defer timeout()
	limit := 56
	if mode == "legacy" {
		limit = 32768
	}
	reader := bufio.NewReader(os.Stdin)
	value, err := readLine(ctx, os.Stdin, reader, os.Stderr, "HIDDEN: ", limit)
	status := "ok"
	switch {
	case errors.Is(err, context.Canceled):
		status = "cancel"
	case errors.Is(err, io.EOF):
		status = "eof"
	case err != nil:
		status = "error"
	}
	if reader.Buffered() != 0 {
		t.Fatal("terminal left buffered input")
	}
	fmt.Printf("RESULT %s %d %x\n", status, len(value), sha256.Sum256(value))
	clear(value)
}

// This harness runs unchanged on macOS and Linux. Its only code-shaped input
// is synthetic and deliberately not a usable credential; helper output carries
// length and digest only. No clipboard, operator terminal or shell is used.
const secretPastePTY = `
import errno
import hashlib
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import threading
import time

def check(label, chunks, expected=b"", status="ok", mode="short", stop=None, queued=False, pending=False):
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    original[3] |= termios.ICANON | termios.ECHO | termios.ECHONL | termios.ISIG
    termios.tcsetattr(slave, termios.TCSANOW, original)
    original = termios.tcgetattr(slave)
    proc = subprocess.Popen(
        [sys.argv[1], "-test.run=^TestPastePTYHelper$"],
        stdin=slave, stdout=slave, stderr=slave,
        env=dict(os.environ, OWNTRANSIT_PASTE_PTY_HELPER=mode),
        start_new_session=True,
    )
    transcript = bytearray()
    writer_errors = []
    writer = None
    deadline = time.monotonic() + 25

    def read_until(needle):
        while needle not in transcript:
            assert time.monotonic() < deadline, label + ": terminal timeout"
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                transcript.extend(data)

    def write_chunks():
        try:
            for delay, chunk in chunks:
                time.sleep(delay)
                if pending:
                    flags = termios.tcgetattr(slave)[3]
                    assert not flags & (termios.ICANON | termios.ECHO | termios.ECHONL)
                view = memoryview(chunk)
                while view:
                    count = os.write(master, view[:512])
                    view = view[count:]
        except (OSError, AssertionError):
            writer_errors.append(True)

    try:
        read_until(b"HIDDEN: ")
        during = termios.tcgetattr(slave)
        assert not during[3] & (termios.ICANON | termios.ECHO | termios.ECHONL), label
        if queued:
            # Establish that ALL type-ahead is in the kernel queue before the
            # helper sees Enter/cancellation. Input written after those events
            # belongs to a later terminal interaction, not this assertion.
            proc.send_signal(signal.SIGSTOP)
            _, stopped = os.waitpid(proc.pid, os.WUNTRACED)
            assert os.WIFSTOPPED(stopped), label + ": helper did not stop"
        writer = threading.Thread(target=write_chunks, daemon=True)
        writer.start()
        if queued or stop is not None:
            writer.join(timeout=3)
            assert not writer.is_alive() and not writer_errors, label + ": enqueue failed"
        if queued:
            proc.send_signal(signal.SIGCONT)
        if stop is not None:
            proc.send_signal(stop)
        read_until(b"RESULT ")
        read_until(b"\nPASS")
        proc.wait(timeout=2)
        writer.join(timeout=1)
        assert not writer.is_alive() and not writer_errors, label + ": writer failed"
        assert proc.returncode == 0, label + ": helper failed"
        assert termios.tcgetattr(slave) == original, label + ": termios not restored exactly"
        result = ("RESULT %s %d %s" % (status, len(expected), hashlib.sha256(expected).hexdigest())).encode()
        # Exact output proves no echo or pasted control/command text escaped.
        lines = bytes(transcript).replace(b"\r\n", b"\n").splitlines()
        assert lines == [b"HIDDEN: ", result, b"PASS"], label + ": wrong/redacted output"
        # Make incomplete canonical fragments visible to a read as well.
        drained = termios.tcgetattr(slave)
        drained[3] &= ~(termios.ICANON | termios.ECHO | termios.ECHONL)
        drained[6][termios.VMIN] = 0
        drained[6][termios.VTIME] = 0
        termios.tcsetattr(slave, termios.TCSANOW, drained)
        assert os.read(slave, 4096) == b"", label + ": kernel retained pasted input"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=2)
        os.close(slave)
        os.close(master)

code = b"otpair2." + b"x" * 48
start, end = b"\x1b[200~", b"\x1b[201~"
for ending in (b"\r", b"\n", b"\r\n"):
    check("short-plain", [(0, code + ending)], code)
    check("short-framed", [(0, start + code + end + ending)], code)
check("fragmented-framing", [(0.003, bytes([b])) for b in start + code + end + b"\r"], code)
check("legacy-framed", [(0, start + b"x" * 32768 + end + b"\r")], b"x" * 32768, mode="legacy")
check("backspace", [(0, b"discard\x15" + code[:-1] + b"z\x7f" + code[-1:] + b"\n")], code)
check("oversize-drain", [(0, b"x" * 57)] + [(0.02, b"fragment") for _ in range(8)] + [(0, b"\n")], status="error", pending=True)
# Rejection must retain ownership of the unfinished entry across a pause longer
# than both the former 75 ms quiet guess and its 750 ms absolute drain limit.
check("oversize-delayed-submit", [(0, b"x" * 57), (1, b"fragment"), (0, b"\n")], status="error", pending=True)
check("oversize-cancel", [(0, b"x" * 57), (1, b"fragment\x03")], status="cancel", pending=True)
check("framed-oversize", [(0, start + code + b"x" + end + b"\n")], status="error")
for label, payload in (
    ("embedded-newline", start + code + b"\nshell-command\n" + end + b"\n"),
    ("embedded-crlf", start + code + b"\r\nshell-command\r\n" + end + b"\r\n"),
    ("nested-frame", start + start + code + end + end + b"\n"),
    ("stray-end", end + code + b"\n"),
    ("embedded-escape", start + code[:20] + b"\x1b[A" + code[20:] + end + b"\n"),
    ("editing-in-paste", start + b"discard\x15" + code + end + b"\n"),
    ("command-after-frame", start + code + end + b"shell-command\n"),
    ("frame-after-text", b"shell " + start + code + end + b"\n"),
    ("nul", code[:20] + b"\x00" + code[20:] + b"\n"),
    ("tab", code[:20] + b"\t" + code[20:] + b"\n"),
):
    check(label, [(0, payload)], status="error")
check("queued-type-ahead-after-submit", [(0, code + b"\nshell-command\n")], status="error", queued=True)
check("framed-delayed-rejected-tail", [(0, start + code + b"\n"), (1, b"shell-command\n" + end + b"\n")], status="error", pending=True)
check("ctrl-c-drain", [(0, code[:20] + b"\x03fragment\n")], status="cancel", queued=True)
check("ctrl-c-in-frame", [(0, start + code[:20] + b"\x03" + end + b"\n")], status="cancel", queued=True)
check("ctrl-z-drain", [(0, code[:20] + b"\x1afragment\n")], status="cancel", queued=True)
check("ctrl-d-drain", [(0, code[:20] + b"\x04fragment\n")], status="eof", queued=True)
check("sigterm-drain", [(0, code[:20] + b"fragment")], status="cancel", stop=signal.SIGTERM)
check("oversize-sigterm", [(0, b"x" * 57)], status="cancel", stop=signal.SIGTERM)
check("unterminated-frame-sigterm", [(0, start + code)], status="cancel", stop=signal.SIGTERM)
print("PTY: short/legacy framing, exact input, rejection, bounded drain and cancellation passed")
`
