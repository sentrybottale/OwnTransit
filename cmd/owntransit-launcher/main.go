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
	clientRoleRoot      = "/Library/OwnTransit/roles/client"
	clientReleaseRoot   = "/Library/OwnTransit/roles/client/releases/"
	clientCurrentName   = "current"
	clientRealName      = "owntransit-real"
	launcherExecutable  = "/Library/OwnTransit/bin/owntransit"
	qualifyArgument     = "--qualify-reader-gid"
	doctorArgument      = "--doctor"
	maxBindingBytes     = 4096
	maxLauncherBytes    = 16 << 20
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
	releaseID    string
	readerGID    uint32
	clientSHA256 [32]byte
}

type launcherCommands struct {
	uid             func() int
	euid            func() int
	gid             func() int
	egid            func() int
	groups          func() ([]int, error)
	validateSelf    func() error
	loadBinding     func(int) ([]byte, error)
	liveUUID        func(uint32) ([16]byte, error)
	validateCurrent func(string, uint32) error
	validateTarget  func(string, [32]byte, uint32) error
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
		validateSelf:    validateInstalledLauncherSelf,
		loadBinding:     readInstalledBinding,
		liveUUID:        liveUserUUID,
		validateCurrent: validateInstalledCurrentRelease,
		validateTarget:  validateInstalledClient,
		closeExtraFDs:   markExtraFileDescriptorsCloseOnExec,
		chdir:           os.Chdir,
		exec:            syscall.Exec,
		expectedRelease: buildinfo.Release,
	}
}

func executeLauncher(arguments []string, diagnostics io.Writer, commands launcherCommands) int {
	if err := commands.validateSelf(); err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: validate launcher invocation: %v\n", err)
		return 1
	}
	plan, err := prepareLaunch(arguments, commands)
	if err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: %v\n", err)
		return 1
	}
	if err := commands.validateTarget(plan.target, plan.clientSHA256, plan.readerGID); err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: validate installed client: %v\n", err)
		return 1
	}
	// Make the authenticated current selector the launch linearization point.
	// A package mutation that selected another release after the binding was
	// read must fail closed before this process resolves the real client path.
	if err := commands.validateCurrent(plan.releaseID, plan.readerGID); err != nil {
		fmt.Fprintf(diagnostics, "owntransit-launcher: validate current release: %v\n", err)
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

// validateInstalledLauncherSelf rejects retained hard-link aliases before the
// setgid process reads any protected state. The normal client frontend invokes
// this launcher only through the fixed public path; an alias has no authority
// even when another local user managed to retain the root-owned inode.
func validateInstalledLauncherSelf() error {
	executable, err := os.Executable()
	if err := validateLauncherExecutablePath(executable, err); err != nil {
		return err
	}
	selected, err := os.Lstat(launcherExecutable)
	if err != nil || !selected.Mode().IsRegular() {
		return errors.New("fixed public launcher is absent or not regular")
	}
	fd, err := unix.Open(launcherExecutable, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open fixed public launcher: %w", err)
	}
	file := os.NewFile(uintptr(fd), launcherExecutable)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("retain fixed public launcher descriptor")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(selected, opened) {
		return errors.New("fixed public launcher changed during selection")
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return fmt.Errorf("inspect fixed public launcher: %w", err)
	}
	readerGID := uint32(unix.Getegid())
	if !validLauncherSelfStat(before, readerGID) {
		return errors.New("fixed public launcher metadata is invalid")
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("fixed public launcher ACL: %w", err)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino ||
		before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid ||
		before.Nlink != after.Nlink || before.Size != after.Size {
		return errors.New("fixed public launcher changed during authentication")
	}
	return nil
}

func validateLauncherExecutablePath(executable string, executableErr error) error {
	if executableErr != nil {
		return fmt.Errorf("resolve launcher invocation path: %w", executableErr)
	}
	if executable != launcherExecutable {
		return errors.New("launcher was not invoked through its fixed public path")
	}
	return nil
}

func validLauncherSelfStat(stat unix.Stat_t, readerGID uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == 0 && readerGID != 0 && stat.Gid == readerGID &&
		uint32(stat.Mode)&0o7777 == 0o2751 && stat.Nlink >= 1 && stat.Size > 0 && stat.Size <= maxLauncherBytes
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
		environment: []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		releaseID:   binding.releaseID, readerGID: binding.readerGID,
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

func validateInstalledCurrentRelease(expectedRelease string, readerGID uint32) error {
	if !validReleaseID(expectedRelease) || readerGID == 0 || uint32(unix.Getegid()) != readerGID {
		return errors.New("current release validation has an invalid binding")
	}
	roleRoot, err := securefs.OpenReadOnlyRoot(clientRoleRoot, int(readerGID))
	if err != nil {
		return err
	}
	defer roleRoot.Close()
	want := "releases/" + expectedRelease
	target, err := roleRoot.ReadRootSymlink(clientCurrentName, len(want))
	if err != nil || target != want {
		return errors.New("protected binding does not match the authenticated current client selector")
	}
	return roleRoot.Recheck()
}

func validateInstalledClient(path string, expected [32]byte, readerGID uint32) error {
	if uint32(unix.Getegid()) != readerGID {
		return errors.New("installed client validation has the wrong effective reader GID")
	}
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
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != readerGID || before.Mode&0o7777 != 0o750 || before.Nlink != 1 || before.Size <= 0 || before.Size > maxClientBytes {
		return errors.New("installed client is not a single-link root:reader 0750 bounded regular file")
	}
	if err := securefs.VerifyNoExtendedACLFD(fd, false); err != nil {
		return fmt.Errorf("installed client ACL: %w", err)
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
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return fmt.Errorf("enumerate open descriptors: %w", err)
	}
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return fmt.Errorf("enumerate open descriptor names: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close open-descriptor directory: %w", closeErr)
	}
	for _, name := range names {
		fd64, parseErr := strconv.ParseUint(name, 10, 31)
		if parseErr != nil || strconv.FormatUint(fd64, 10) != name {
			return errors.New("open-descriptor enumeration returned a non-canonical entry")
		}
		fd := int(fd64)
		if fd < 3 {
			continue
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && !errors.Is(err, unix.EBADF) {
			return fmt.Errorf("mark descriptor %d close-on-exec: %w", fd, err)
		}
	}
	return nil
}
