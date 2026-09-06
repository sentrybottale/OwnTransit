"""Real terminal regression; only synthetic input in fresh, isolated PTYs."""

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


def check(binary, label, payload, expected=b"", status="ok", stop=None):
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    original[3] |= termios.ICANON | termios.ECHO | termios.ECHONL | termios.ISIG
    termios.tcsetattr(slave, termios.TCSANOW, original)
    original = termios.tcgetattr(slave)
    env = dict(os.environ, OWNTRANSIT_PROMPT_PTY_HELPER="1")
    proc = subprocess.Popen(
        [binary, "-test.run=^TestPromptPTYHelper$"],
        stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True,
    )
    transcript = bytearray()
    writer = None
    writer_errors = []
    deadline = time.monotonic() + 12

    def read_until(needle):
        while needle not in transcript:
            if time.monotonic() >= deadline:
                raise AssertionError(label + ": terminal timeout")
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

    def write_input():
        try:
            view = memoryview(payload)
            while view:
                count = os.write(master, view[:512])
                view = view[count:]
        except OSError as exc:
            writer_errors.append(exc)

    try:
        read_until(b"HIDDEN: ")
        during = termios.tcgetattr(slave)
        assert not during[3] & (termios.ICANON | termios.ECHO | termios.ECHONL), label
        if stop is not None:
            proc.send_signal(stop)
        else:
            writer = threading.Thread(target=write_input, daemon=True)
            writer.start()
        read_until(b"RESULT ")
        read_until(b"\nPASS")
        proc.wait(timeout=3)
        if writer:
            writer.join(timeout=1)
            assert not writer.is_alive() and not writer_errors, label + ": write failed"
        assert proc.returncode == 0, label + ": helper failed"
        assert termios.tcgetattr(slave) == original, label + ": terminal not restored exactly"
        result = ("RESULT %s %d %s" % (status, len(expected), hashlib.sha256(expected).hexdigest())).encode()
        assert result in transcript, label + ": wrong result (input redacted)"
        assert b"\x07" not in transcript, label + ": terminal rang bell"
        # The complete transcript must contain prompts/results only: no echo,
        # input tail, escape sequences, or edited-away characters.
        lines = bytes(transcript).replace(b"\r\n", b"\n").splitlines()
        assert lines == [b"HIDDEN: ", result, b"PASS"], label + ": unexpected output (redacted)"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=3)
        os.close(slave)
        os.close(master)


binary = sys.argv[1]
for length in (3000, 8192, 32768):
    data = b"x" * length
    check(binary, "long-paste-%d" % length, data + b"\r", data)
check(binary, "empty", b"\n")
check(binary, "backspace", b"abX\x7fY\x08c\n", b"abc")
check(binary, "clear-line", b"discard\x15kept\n", b"kept")
check(binary, "ctrl-c", b"discard\x03", status="cancel")
check(binary, "ctrl-z", b"discard\x1a", status="cancel")
check(binary, "ctrl-d", b"discard\x04", status="eof")
check(binary, "sigterm", b"", status="cancel", stop=signal.SIGTERM)
check(binary, "sigint", b"", status="cancel", stop=signal.SIGINT)
check(binary, "oversize", b"x" * 32769, status="error")
print("PTY: long paste, hidden input, editing, bounds, cancellation and exact restoration passed")
