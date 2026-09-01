//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

const (
	linuxClientIdentityRoot = "/var/lib/owntransit/client/identity"
	linuxClientIdentityFile = "client-reader.v1"
	linuxClientProxyPath    = "/usr/local/bin/owntransit-proxy"
)

func loadInstalledSetupClientIdentity() (installedSetupClientIdentity, error) {
	root, err := securefs.OpenRoot(linuxClientIdentityRoot)
	if err != nil {
		return installedSetupClientIdentity{}, err
	}
	encoded, readErr := root.ReadFile(linuxClientIdentityFile, 4096)
	closeErr := root.Close()
	if readErr != nil {
		return installedSetupClientIdentity{}, readErr
	}
	if closeErr != nil {
		return installedSetupClientIdentity{}, closeErr
	}
	identity, err := parseLinuxSetupIdentity(encoded)
	if err != nil {
		return installedSetupClientIdentity{}, err
	}
	if err := validateLinuxLocalIdentity(identity); err != nil {
		return installedSetupClientIdentity{}, err
	}
	return identity, nil
}

func parseLinuxSetupIdentity(encoded []byte) (installedSetupClientIdentity, error) {
	if len(encoded) == 0 || len(encoded) > 4096 || encoded[len(encoded)-1] != '\n' || bytes.IndexByte(encoded, 0) >= 0 {
		return installedSetupClientIdentity{}, errors.New("installed Linux client identity receipt is invalid")
	}
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 8 || lines[7] != "" || lines[0] != "schema=owntransit.linux-client-reader.v1" {
		return installedSetupClientIdentity{}, errors.New("installed Linux client identity receipt has the wrong schema")
	}
	name, ok := strings.CutPrefix(lines[1], "client_user=")
	if !ok || !validLinuxAccountName(name) {
		return installedSetupClientIdentity{}, errors.New("installed Linux client identity has an invalid user")
	}
	uid, err := parseSetupIdentityID(lines[2], "client_uid")
	if err != nil {
		return installedSetupClientIdentity{}, err
	}
	primaryGroup, ok := strings.CutPrefix(lines[3], "primary_group=")
	if !ok || !validLinuxAccountName(primaryGroup) {
		return installedSetupClientIdentity{}, errors.New("installed Linux client identity has an invalid primary group")
	}
	primaryGID, err := parseSetupIdentityID(lines[4], "primary_gid")
	if err != nil {
		return installedSetupClientIdentity{}, err
	}
	if lines[5] != "reader_group=owntransit-client" {
		return installedSetupClientIdentity{}, errors.New("installed Linux client identity has an invalid reader group")
	}
	readerGID, err := parseSetupIdentityID(lines[6], "reader_gid")
	if err != nil {
		return installedSetupClientIdentity{}, err
	}
	return installedSetupClientIdentity{clientUser: name, clientUID: uid, primaryGroup: primaryGroup, primaryGID: primaryGID, readerGID: readerGID}, nil
}

func parseSetupIdentityID(line, key string) (uint32, error) {
	text, ok := strings.CutPrefix(line, key+"=")
	if !ok || text == "" || text[0] == '0' {
		return 0, errors.New("installed client identity contains an invalid numeric ID")
	}
	value, err := strconv.ParseUint(text, 10, 31)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != text {
		return 0, errors.New("installed client identity contains an invalid numeric ID")
	}
	return uint32(value), nil
}

func validLinuxAccountName(value string) bool {
	if value == "" || len(value) > 32 || value[0] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validateLinuxLocalIdentity(identity installedSetupClientIdentity) error {
	passwd, err := readProtectedLinuxDatabase("/etc/passwd")
	if err != nil {
		return err
	}
	group, err := readProtectedLinuxDatabase("/etc/group")
	if err != nil {
		return err
	}
	userMatches, uidMatches := 0, 0
	scanner := bufio.NewScanner(bytes.NewReader(passwd))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 7 {
			continue
		}
		if fields[0] == identity.clientUser {
			userMatches++
			if fields[2] == strconv.FormatUint(uint64(identity.clientUID), 10) && fields[3] == strconv.FormatUint(uint64(identity.primaryGID), 10) {
				uidMatches++
			}
		}
		if fields[2] == strconv.FormatUint(uint64(identity.clientUID), 10) && fields[0] != identity.clientUser {
			uidMatches = -100
		}
	}
	if err := scanner.Err(); err != nil || userMatches != 1 || uidMatches != 1 {
		return errors.New("installed Linux client identity no longer matches /etc/passwd")
	}
	readerMatches, primaryMatches := 0, 0
	scanner = bufio.NewScanner(bytes.NewReader(group))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 4 {
			continue
		}
		if fields[0] == "owntransit-client" && fields[2] == strconv.FormatUint(uint64(identity.readerGID), 10) && fields[3] == identity.clientUser {
			readerMatches++
		}
		if fields[2] == strconv.FormatUint(uint64(identity.readerGID), 10) && fields[0] != "owntransit-client" {
			readerMatches = -100
		}
		if fields[0] == identity.primaryGroup && fields[2] == strconv.FormatUint(uint64(identity.primaryGID), 10) {
			primaryMatches++
		}
		if fields[2] == strconv.FormatUint(uint64(identity.primaryGID), 10) && fields[0] != identity.primaryGroup {
			primaryMatches = -100
		}
	}
	if err := scanner.Err(); err != nil || readerMatches != 1 || primaryMatches != 1 {
		return errors.New("installed Linux reader identity no longer matches /etc/group")
	}
	return nil
}

func readProtectedLinuxDatabase(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("installed Linux account database path is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 || stat.Nlink != 1 || info.Size() < 0 || info.Size() > 4<<20 {
		return nil, errors.New("installed Linux account database is not a protected regular file")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 4<<20+1))
	if err != nil || len(encoded) > 4<<20 {
		return nil, errors.New("installed Linux account database exceeds its bound")
	}
	return encoded, nil
}

func runInstalledClientReadyProbe(ctx context.Context, identity installedSetupClientIdentity) error {
	if ctx == nil {
		return errors.New("installed client READY context is absent")
	}
	info, err := os.Stat(linuxClientProxyPath)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSetgid == 0 ||
		stat.Uid != 0 || stat.Gid != identity.readerGID || stat.Nlink != 1 {
		return errors.New("installed Linux client proxy boundary is invalid")
	}
	process := exec.CommandContext(ctx, linuxClientProxyPath, "doctor")
	process.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	process.Dir = "/"
	process.Stdin, process.Stdout, process.Stderr = nil, io.Discard, io.Discard
	process.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: identity.clientUID, Gid: identity.primaryGID, Groups: []uint32{identity.readerGID},
	}}
	return process.Run()
}
