//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

const darwinClientLauncherPath = "/Library/OwnTransit/bin/owntransit"

const (
	darwinIdentityQueryLimit   = 1024
	darwinIdentityQueryTimeout = 5 * time.Second
)

type boundedDarwinOutput struct {
	data     []byte
	overflow bool
}

func (output *boundedDarwinOutput) Write(value []byte) (int, error) {
	written := len(value)
	remaining := darwinIdentityQueryLimit + 1 - len(output.data)
	if remaining > len(value) {
		remaining = len(value)
	}
	if remaining > 0 {
		output.data = append(output.data, value[:remaining]...)
	}
	if len(output.data) > darwinIdentityQueryLimit || remaining < len(value) {
		output.overflow = true
	}
	return written, nil
}

func loadInstalledSetupClientIdentity() (installedSetupClientIdentity, error) {
	root, err := securefs.OpenRoot(darwinIdentityRoot)
	if err != nil {
		return installedSetupClientIdentity{}, err
	}
	encoded, readErr := root.ReadFile(darwinIdentityReceipt, maxDarwinReaderReceipt)
	closeErr := root.Close()
	if readErr != nil {
		return installedSetupClientIdentity{}, readErr
	}
	if closeErr != nil {
		return installedSetupClientIdentity{}, closeErr
	}
	receipt, err := parseDarwinReaderIdentity(encoded)
	if err != nil {
		return installedSetupClientIdentity{}, err
	}
	uidText := strconv.FormatUint(uint64(receipt.clientUID), 10)
	for _, check := range []struct {
		arguments []string
		want      string
	}{
		{[]string{"-u", receipt.clientUser}, uidText},
		{[]string{"-un", uidText}, receipt.clientUser},
		{[]string{"-g", receipt.clientUser}, strconv.FormatUint(uint64(receipt.clientPrimaryGID), 10)},
	} {
		output, err := runBoundedDarwinID(check.arguments...)
		if err != nil || output != check.want {
			return installedSetupClientIdentity{}, errors.New("installed macOS client identity no longer matches Directory Services")
		}
	}
	groups, err := runBoundedDarwinID("-G", receipt.clientUser)
	if err != nil {
		return installedSetupClientIdentity{}, errors.New("installed macOS client group vector is unavailable")
	}
	readerText := strconv.FormatUint(uint64(receipt.readerGID), 10)
	for _, group := range strings.Fields(groups) {
		if group == readerText {
			return installedSetupClientIdentity{}, errors.New("installed macOS client unexpectedly owns the protected reader GID")
		}
	}
	for _, node := range []string{".", "/Search"} {
		output, err := runBoundedDarwinCommand("/usr/bin/dscl", node, "-read", "/Users/"+receipt.clientUser, "GeneratedUID")
		if err != nil {
			return installedSetupClientIdentity{}, errors.New("installed macOS client GeneratedUID is unavailable")
		}
		liveUUID, err := parseDarwinGeneratedUID(output)
		if err != nil || liveUUID != receipt.clientUUID {
			return installedSetupClientIdentity{}, errors.New("installed macOS client GeneratedUID no longer matches the protected receipt")
		}
	}
	return installedSetupClientIdentity{
		clientUser: receipt.clientUser, clientUID: receipt.clientUID,
		primaryGID: receipt.clientPrimaryGID, readerGID: receipt.readerGID,
	}, nil
}

func runBoundedDarwinID(arguments ...string) (string, error) {
	return runBoundedDarwinCommand("/usr/bin/id", arguments...)
}

func runBoundedDarwinCommand(path string, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), darwinIdentityQueryTimeout)
	defer cancel()
	process := exec.CommandContext(ctx, path, arguments...)
	process.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	process.Dir = "/"
	process.Stdin, process.Stderr = nil, io.Discard
	var output boundedDarwinOutput
	process.Stdout = &output
	if err := process.Run(); err != nil || ctx.Err() != nil || output.overflow || len(output.data) == 0 || bytes.IndexByte(output.data, 0) >= 0 {
		return "", errors.New("bounded Directory Services identity query failed")
	}
	return strings.TrimSuffix(string(output.data), "\n"), nil
}

func parseDarwinGeneratedUID(output string) (string, error) {
	if strings.Count(output, "\n") != 0 {
		return "", errors.New("Directory Services GeneratedUID output is not singular")
	}
	value, ok := strings.CutPrefix(output, "GeneratedUID: ")
	if !ok || !validDarwinUUID(value) {
		return "", errors.New("Directory Services GeneratedUID output is invalid")
	}
	return value, nil
}

func runInstalledClientReadyProbe(ctx context.Context, identity installedSetupClientIdentity) error {
	if ctx == nil || identity.clientUID == 0 || identity.primaryGID == 0 || identity.primaryGID == identity.readerGID {
		return errors.New("installed macOS client READY identity is invalid")
	}
	info, err := os.Stat(darwinClientLauncherPath)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o751 || info.Mode()&os.ModeSetgid == 0 ||
		stat.Uid != 0 || stat.Gid != identity.readerGID || stat.Nlink != 1 {
		return errors.New("installed macOS client launcher boundary is invalid")
	}
	process := exec.CommandContext(ctx, darwinClientLauncherPath, "--doctor")
	process.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	process.Dir = "/"
	process.Stdin, process.Stdout, process.Stderr = nil, io.Discard, io.Discard
	process.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: identity.clientUID, Gid: identity.primaryGID, Groups: []uint32{},
	}}
	return process.Run()
}
