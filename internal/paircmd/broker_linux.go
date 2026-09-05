//go:build linux

package paircmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

func workerCommand(ctx context.Context, args ...string) (*exec.Cmd, error) {
	if os.Geteuid() != 0 {
		return nil, pairruntime.ErrState
	}
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	// The dropped-privilege child must not execute code writable by that user.
	for checked := path; ; checked = filepath.Dir(checked) {
		info, err := os.Lstat(checked)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, pairruntime.ErrState
		}
		if checked == "/" {
			break
		}
	}
	cmd := exec.CommandContext(ctx, path, append([]string{"pair"}, args...)...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}

func discover(ctx context.Context, origin string) (pairrelay.ServerInfo, error) {
	cmd, err := workerCommand(ctx, "discover-worker", origin)
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	var output bytes.Buffer
	cmd.Stdout = &boundedOutput{buffer: &output, remaining: 128 << 10}
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return pairrelay.ServerInfo{}, err
	}
	var info pairrelay.ServerInfo
	d := json.NewDecoder(&output)
	d.DisallowUnknownFields()
	if err := d.Decode(&info); err != nil {
		return info, err
	}
	return info, nil
}

type boundedOutput struct {
	buffer    *bytes.Buffer
	remaining int
}

func (b *boundedOutput) Write(v []byte) (int, error) {
	if len(v) > b.remaining {
		return 0, pairruntime.ErrState
	}
	b.remaining -= len(v)
	return b.buffer.Write(v)
}

func serveBroker(ctx context.Context, path string, diagnostics io.Writer) error {
	gate, err := pairruntime.Admission(path)
	if err != nil {
		return err
	}
	defer gate.Close()
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	service, err := root.TryLock("service.lock")
	if err != nil {
		return err
	}
	defer service.Close()
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd, err := workerCommand(ctx, "worker")
	if err != nil {
		return err
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer output.Close()
	cmd.Stderr = diagnostics
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(diagnostics, "Receiver worker could not start. The service must retain CAP_SETUID to drop worker privileges; reinstall the current preview connector package.")
		return err
	}
	backend := pairruntime.ReceiverBackend{Path: path, OnReady: func() error {
		if err := notifyReceiverReady(); err != nil {
			return err
		}
		fmt.Fprintln(diagnostics, "Receiver network worker ready; waiting for relay registration or paired client.")
		return nil
	}}
	finished := make(chan error, 1)
	go func() { finished <- pairruntime.ServeAgent(output, input, backend) }()
	// This independent watcher can terminate a wedged worker even if its RPC
	// pipe is blocked. The admission gate is released only after child Wait.
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p, e := pairruntime.ReadPolicy(path)
				if e != nil || p.Locked {
					cancel()
					return
				}
			}
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-finished:
		if err != nil {
			fmt.Fprintln(diagnostics, "Receiver worker or protected-state channel stopped; retrying does not replace identities.")
		}
		cancel()
	}
	input.Close()
	output.Close()
	return cmd.Wait()
}

func notifyReceiverReady() error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil
	} // Explicit foreground pair serve.
	if len(address) > 107 || (address[0] != '/' && address[0] != '@') {
		return pairruntime.ErrState
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = connection.Write([]byte("READY=1\nSTATUS=Receiver network worker ready"))
	return err
}

func runWorker(args []string, input io.Reader, output, diagnostics io.Writer) int {
	if len(args) != 0 || os.Geteuid() != 65534 || os.Getegid() != 65534 {
		return 1
	}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil || unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		return 1
	}
	if err := pairruntime.ServeReceiver(context.Background(), &pairruntime.AgentClient{Input: input, Output: output}, nil); err != nil {
		fmt.Fprintln(diagnostics, "Receiver network worker stopped; no pairing code or private state is included in diagnostics.")
		return 1
	}
	return 0
}
