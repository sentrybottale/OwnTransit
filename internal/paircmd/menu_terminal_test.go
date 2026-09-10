//go:build darwin || linux

package paircmd

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMenuTerminalKeepsSecretInputHidden(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for terminal checks")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(python, "-c", menuTerminalFixture, binary).CombinedOutput(); err != nil {
		t.Fatalf("menu terminal check: %v\n%s", err, output)
	}
}

func TestMenuTerminalHelper(t *testing.T) {
	if os.Getenv("OWNTRANSIT_MENU_PTY_HELPER") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	reader := bufio.NewReader(os.Stdin)
	got := runMenu(ctx, false, tunnelFixture(t), os.Stdin, reader, os.Stdout, os.Stderr, func(args []string) int {
		value, err := readLine(ctx, os.Stdin, reader, os.Stderr, "HIDDEN: ", 56)
		defer clear(value)
		if err != nil || len(value) != 40 {
			return 1
		}
		_, err = io.WriteString(os.Stdout, "SECRET ACCEPTED\n")
		if err != nil {
			return 1
		}
		return 0
	})
	if got != 0 {
		t.Fatal("menu secret input failed")
	}
}

const menuTerminalFixture = `
import errno, os, pty, select, subprocess, sys, termios, time
master, slave = pty.openpty()
before = termios.tcgetattr(slave)
proc = subprocess.Popen([sys.argv[1], "-test.run=^TestMenuTerminalHelper$"], stdin=slave, stdout=slave, stderr=slave, env=dict(os.environ, OWNTRANSIT_MENU_PTY_HELPER="1"))
transcript = bytearray()
deadline = time.monotonic() + 10
def until(needle):
    while needle not in transcript:
        assert time.monotonic() < deadline, "menu terminal timeout"
        if select.select([master], [], [], .1)[0]:
            try: data = os.read(master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO: break
                raise
            if not data: break
            transcript.extend(data)
    assert needle in transcript, "menu terminal output missing"
try:
    until(b"Choose: ")
    os.write(master, b"1\n")
    until(b"New tunnel name: ")
    os.write(master, b"fresh\n")
    until(b"HIDDEN: ")
    during = termios.tcgetattr(slave)
    assert not during[3] & (termios.ECHO | termios.ECHONL | termios.ICANON), "secret echo was enabled after menu dispatch"
    secret = b"synthetic-input-" + b"x" * 24
    os.write(master, secret + b"\n")
    until(b"PASS")
    proc.wait(timeout=3)
    assert proc.returncode == 0, "menu helper failed"
    assert secret not in transcript and b"synthetic-input-" not in transcript, "menu echoed private input"
    assert termios.tcgetattr(slave) == before, "menu did not restore terminal"
finally:
    if proc.poll() is None: proc.kill()
    proc.wait(timeout=3)
    os.close(master)
    os.close(slave)
`
