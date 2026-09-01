// owntransit-launcher is the deliberately tiny macOS setgid boundary. It has
// no network, configuration, enrollment, SSH, update, or lifecycle authority.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const (
	launcherBindingRoot = "/Library/OwnTransit/launcher-auth"
	launcherBindingFile = "client.v1"
	clientRuntimeRoot   = "/Library/OwnTransit/client/runtime"
	clientAnchorRoot    = "/Library/OwnTransit/client/anchor-view"
	clientReleaseRoot   = "/Library/OwnTransit/roles/client/releases/"
	clientRealName      = "owntransit-real"
	qualifyArgument     = "--qualify-reader-gid"
	doctorArgument      = "--doctor"
	maxBindingBytes     = 4096
	maxClientBytes      = 64 << 20
)

type launcherBinding struct {
	clientUID    uint32
	clientUUID   [16]byte
	readerGID    uint32
	releaseID    string
	clientSHA256 [32]byte
}

type launchPlan struct {
	target       string
	arguments    []string
	environment  []string
	clientSHA256 [32]byte
}

type launcherCommands struct {
	uid             func() int
	euid            func() int
	gid             func() int
	egid            func() int
	groups          func() ([]int, error)
	loadBinding     func(int) ([]byte, error)
	liveUUID        func(uint32) ([16]byte, error)
	validateTarget  func(string, [32]byte) error
	closeExtraFDs   func() error
	chdir           func(string) error
	exec            func(string, []string, []string) error
	expectedRelease string
}

func main() {
	unix.Umask(0o077)
	code := executeLauncher(os.Args[1:], os.Stderr, productionLauncherCommands())
	if code != 0 {
		os.Exit(code)
	}
}

func productionLauncherCommands() launcherCommands {
	return launcherCommands{
		uid:             syscall.Getuid,
		euid:            syscall.Geteuid,
		gid:             syscall.Getgid,
		egid:            syscall.Getegid,
		groups:          syscall.Getgroups,
		loadBinding:     readInstalledBinding,
		liveUUID:        liveUserUUID,
		validateTarget:  validateInstalledClient,
		closeExtraFDs:   markExtraFileDescriptorsCloseOnExec,
		chdir:           os.Chdir,
		exec:            syscall.Exec,
		expectedRelease: buildinfo.Release,
	}
}

func executeLauncher(arguments []string, diagnostics io.Writer, commands launcherCommands) int {
	plan, err := prepareLaunch(arguments, commands)
	if err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: %v\n", err)
		return 1
	}
	if err := commands.validateTarget(plan.target, plan.clientSHA256); err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: validate installed client: %v\n", err)
		return 1
	}
	if err := commands.chdir("/"); err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: select fixed working directory: %v\n", err)
		return 1
	}
	if err := commands.closeExtraFDs(); err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: close inherited descriptor authority: %v\n", err)
		return 1
	}
	if err := commands.exec(plan.target, plan.arguments, plan.environment); err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: execute installed client: %v\n", err)
		return 1
	}
	return 0
}

func prepareLaunch(arguments []string, commands launcherCommands) (launchPlan, error) {
	qualify, doctor := false, false
	switch {
	case len(arguments) == 0:
	case len(arguments) == 1 && arguments[0] == qualifyArgument:
		qualify = true
	case len(arguments) == 1 && arguments[0] == doctorArgument:
		doctor = true
	default:
		return launchPlan{}, errors.New("arguments are not accepted by the fixed client launcher")
	}

	ruid, euid := commands.uid(), commands.euid()
	rgid, egid := commands.gid(), commands.egid()
	if ruid <= 0 || euid != ruid {
		return launchPlan{}, errors.New("real/effective UID is not one exact non-root user")
	}
	if egid <= 0 || rgid == egid {
		return launchPlan{}, errors.New("setgid reader boundary is absent")
	}
	groups, err := commands.groups()
	if err != nil {
		return launchPlan{}, fmt.Errorf("read supplementary groups: %w", err)
	}
	for _, group := range groups {
		if group == egid {
			return launchPlan{}, errors.New("reader GID is present in the caller supplementary groups")
		}
	}

	encoded, err := commands.loadBinding(egid)
	if err != nil {
		return launchPlan{}, fmt.Errorf("open protected launcher binding: %w", err)
	}
	binding, err := parseLauncherBinding(encoded)
	if err != nil {
		return launchPlan{}, err
	}
	if binding.clientUID != uint32(ruid) || binding.readerGID != uint32(egid) {
		return launchPlan{}, errors.New("real UID or effective reader GID does not match the protected binding")
	}
	if binding.releaseID != commands.expectedRelease {
		return launchPlan{}, errors.New("launcher build release does not match the protected binding")
	}
	live, err := commands.liveUUID(binding.clientUID)
	if err != nil {
		return launchPlan{}, fmt.Errorf("resolve live user GeneratedUID: %w", err)
	}
	if !bytes.Equal(live[:], binding.clientUUID[:]) {
		return launchPlan{}, errors.New("live user GeneratedUID does not match the protected binding")
	}

	target := clientReleaseRoot + binding.releaseID + "/" + clientRealName
	clientArguments := []string{target}
	if qualify {
		clientArguments = append(clientArguments, "verify-reader-gid", strconv.FormatUint(uint64(binding.readerGID), 10))
	} else {
		// The elevated client accepts only its zero-argument fixed installed
		// runtime form. The effective reader GID selects the exact protected
		// views; no pathname or numeric authority crosses argv.
		clientArguments = append(clientArguments, map[bool]string{false: "proxy", true: "doctor"}[doctor])
	}
	return launchPlan{
		target: target, arguments: clientArguments,
		environment:  []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		clientSHA256: binding.clientSHA256,
	}, nil
}

func parseLauncherBinding(encoded []byte) (launcherBinding, error) {
	if len(encoded) == 0 || len(encoded) > maxBindingBytes || encoded[len(encoded)-1] != '\n' || bytes.IndexByte(encoded, 0) >= 0 {
		return launcherBinding{}, errors.New("protected launcher binding has an invalid size or encoding")
	}
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 7 || lines[6] != "" || lines[0] != "schema=owntransit.macos-client-launcher.v1" {
		return launcherBinding{}, errors.New("protected launcher binding has the wrong schema or field count")
	}
	value := launcherBinding{}
	uid, err := parseCanonicalIDLine(lines[1], "client_uid")
	if err != nil {
		return launcherBinding{}, err
	}
	value.clientUID = uid
	uuidText, ok := strings.CutPrefix(lines[2], "client_uuid=")
	if !ok {
		return launcherBinding{}, errors.New("protected launcher binding has no client_uuid")
	}
	value.clientUUID, err = parseUUID(uuidText)
	if err != nil {
		return launcherBinding{}, fmt.Errorf("protected launcher binding client_uuid: %w", err)
	}
	value.readerGID, err = parseCanonicalIDLine(lines[3], "reader_gid")
	if err != nil {
		return launcherBinding{}, err
	}
	releaseID, ok := strings.CutPrefix(lines[4], "release_id=")
	if !ok || !validReleaseID(releaseID) {
		return launcherBinding{}, errors.New("protected launcher binding has an invalid release_id")
	}
	value.releaseID = releaseID
	digestText, ok := strings.CutPrefix(lines[5], "client_sha256=")
	if !ok || len(digestText) != 64 {
		return launcherBinding{}, errors.New("protected launcher binding has an invalid client_sha256")
	}
	digest, err := hex.DecodeString(digestText)
	if err != nil || hex.EncodeToString(digest) != digestText {
		return launcherBinding{}, errors.New("protected launcher binding client_sha256 is not canonical")
	}
	copy(value.clientSHA256[:], digest)
	return value, nil
}

func parseCanonicalIDLine(line, key string) (uint32, error) {
	text, ok := strings.CutPrefix(line, key+"=")
	if !ok || text == "" || text[0] == '0' {
		return 0, fmt.Errorf("protected launcher binding has an invalid %s", key)
	}
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil || value == 0 || value == uint64(^uint32(0)) || strconv.FormatUint(value, 10) != text {
		return 0, fmt.Errorf("protected launcher binding has an invalid %s", key)
	}
	return uint32(value), nil
}

func parseUUID(text string) ([16]byte, error) {
	var value [16]byte
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return value, errors.New("UUID is not canonical")
	}
	compact := strings.ReplaceAll(text, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != len(value) {
		return value, errors.New("UUID is not hexadecimal")
	}
	copy(value[:], decoded)
	if value == ([16]byte{}) {
		return [16]byte{}, errors.New("UUID is zero")
	}
	return value, nil
}

func validReleaseID(value string) bool {
	if len(value) != 52 || value == strings.Repeat("a", 52) {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '2' || character > '7') {
			return false
		}
	}
	return value[len(value)-1] == 'a' || value[len(value)-1] == 'q'
}

func readInstalledBinding(readerGID int) ([]byte, error) {
	root, err := securefs.OpenReadOnlyRoot(launcherBindingRoot, readerGID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	encoded, err := root.ReadFile(launcherBindingFile, maxBindingBytes)
	if err != nil {
		return nil, err
	}
	if err := root.Recheck(); err != nil {
		return nil, err
	}
	return encoded, nil
}

func validateInstalledClient(path string, expected [32]byte) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("cannot retain installed client descriptor")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != 0 || before.Mode&0o7777 != 0o755 || before.Nlink != 1 || before.Size <= 0 || before.Size > maxClientBytes {
		return errors.New("installed client is not a single-link root:wheel 0755 bounded regular file")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxClientBytes+1))
	if err != nil || written != before.Size {
		return errors.New("installed client could not be measured exactly")
	}
	actual := hash.Sum(nil)
	if !bytes.Equal(actual, expected[:]) {
		return errors.New("installed client digest does not match the protected binding")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink {
		return errors.New("installed client changed while it was measured")
	}
	return nil
}

func markExtraFileDescriptorsCloseOnExec() error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}
	if limit.Cur > 1<<20 {
		return errors.New("open-file limit is too large to close inherited authority safely")
	}
	for fd := 3; uint64(fd) < limit.Cur; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && !errors.Is(err, unix.EBADF) {
			return fmt.Errorf("mark descriptor %d close-on-exec: %w", fd, err)
		}
	}
	return nil
}
