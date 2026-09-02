package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const testReleaseID = "aeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testUUID() [16]byte {
	return [16]byte{0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55}
}

func testBinding() []byte {
	digest := strings.Repeat("a", 64)
	return []byte("schema=owntransit.macos-client-launcher.v1\n" +
		"client_uid=501\n" +
		"client_uuid=10111213-2021-3031-4041-505152535455\n" +
		"reader_gid=5000\n" +
		"release_id=" + testReleaseID + "\n" +
		"client_sha256=" + digest + "\n")
}

func validLauncherCommands() launcherCommands {
	return launcherCommands{
		uid:  func() int { return 501 },
		euid: func() int { return 501 },
		gid:  func() int { return 20 },
		egid: func() int { return 5000 },
		groups: func() ([]int, error) {
			return []int{20, 12}, nil
		},
		validateSelf: func() error { return nil },
		loadBinding: func(gid int) ([]byte, error) {
			if gid != 5000 {
				return nil, errors.New("wrong binding GID")
			}
			return testBinding(), nil
		},
		liveUUID: func(uid uint32) ([16]byte, error) {
			if uid != 501 {
				return [16]byte{}, errors.New("wrong UID")
			}
			return testUUID(), nil
		},
		validateCurrent: func(release string, gid uint32) error {
			if release != testReleaseID || gid != 5000 {
				return errors.New("wrong current release binding")
			}
			return nil
		},
		expectedRelease: testReleaseID,
	}
}

func TestExecuteLauncherRejectsNoncanonicalSelfBeforeProtectedState(t *testing.T) {
	commands := validLauncherCommands()
	invocationError := errors.New("retained launcher hard-link alias")
	commands.validateSelf = func() error { return invocationError }
	commands.loadBinding = func(int) ([]byte, error) {
		t.Fatal("invalid launcher invocation reached protected binding")
		return nil, nil
	}
	var diagnostics bytes.Buffer
	if code := executeLauncher(nil, &diagnostics, commands); code != 1 {
		t.Fatalf("execute code=%d, want 1", code)
	}
	if !strings.Contains(diagnostics.String(), invocationError.Error()) {
		t.Fatalf("diagnostics=%q, want invocation failure", diagnostics.String())
	}
}

func TestValidateLauncherExecutablePathIsExact(t *testing.T) {
	if err := validateLauncherExecutablePath(launcherExecutable, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"", "owntransit", "/library/OwnTransit/bin/owntransit",
		"/Library/OwnTransit/bin/../bin/owntransit", "/tmp/retained-launcher",
	} {
		if err := validateLauncherExecutablePath(path, nil); err == nil {
			t.Fatalf("noncanonical launcher invocation %q accepted", path)
		}
	}
	if err := validateLauncherExecutablePath(launcherExecutable, errors.New("lookup failed")); err == nil {
		t.Fatal("launcher executable lookup failure accepted")
	}
}

func TestValidLauncherSelfStatAllowsAliasesButRejectsUnsafeMetadata(t *testing.T) {
	valid := unix.Stat_t{Mode: unix.S_IFREG | 0o2751, Uid: 0, Gid: 5000, Nlink: 2, Size: 4096}
	if !validLauncherSelfStat(valid, 5000) {
		t.Fatal("canonical launcher with a retained hard link was rejected")
	}
	tests := []unix.Stat_t{valid, valid, valid, valid, valid, valid, valid}
	tests[0].Mode = unix.S_IFLNK | 0o2751
	tests[1].Mode = unix.S_IFREG | 0o751
	tests[2].Uid = 501
	tests[3].Gid = 20
	tests[4].Nlink = 0
	tests[5].Size = 0
	tests[6].Size = maxLauncherBytes + 1
	for index, stat := range tests {
		if validLauncherSelfStat(stat, 5000) {
			t.Fatalf("unsafe launcher stat mutation %d accepted", index)
		}
	}
	if validLauncherSelfStat(valid, 0) {
		t.Fatal("zero reader GID accepted")
	}
}

func TestPrepareLaunchFixesTargetConfigEnvironmentAndQualification(t *testing.T) {
	commands := validLauncherCommands()
	plan, err := prepareLaunch(nil, commands)
	if err != nil {
		t.Fatal(err)
	}
	wantTarget := clientReleaseRoot + testReleaseID + "/" + clientRealName
	wantArguments := []string{wantTarget, "proxy"}
	if plan.target != wantTarget || !reflect.DeepEqual(plan.arguments, wantArguments) {
		t.Fatalf("plan target/arguments = %q %#v", plan.target, plan.arguments)
	}
	if plan.releaseID != testReleaseID || plan.readerGID != 5000 {
		t.Fatalf("plan release/reader binding = %q %d", plan.releaseID, plan.readerGID)
	}
	if !reflect.DeepEqual(plan.environment, []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}) {
		t.Fatalf("plan environment = %#v", plan.environment)
	}
	if plan.clientSHA256 != [32]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa} {
		t.Fatal("plan did not retain the authenticated client digest privately")
	}

	qualified, err := prepareLaunch([]string{qualifyArgument}, commands)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(qualified.arguments, []string{wantTarget, "verify-reader-gid", "5000"}) {
		t.Fatalf("qualification argv = %#v", qualified.arguments)
	}
	doctor, err := prepareLaunch([]string{doctorArgument}, commands)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doctor.arguments, []string{wantTarget, "doctor"}) {
		t.Fatalf("doctor argv = %#v", doctor.arguments)
	}
}

func TestPrepareLaunchRejectsAuthorityBeforeClientSelection(t *testing.T) {
	tests := map[string]func(*launcherCommands){
		"root user": func(commands *launcherCommands) {
			commands.uid = func() int { return 0 }
			commands.euid = func() int { return 0 }
		},
		"effective UID changed": func(commands *launcherCommands) { commands.euid = func() int { return 502 } },
		"setgid absent":         func(commands *launcherCommands) { commands.egid = func() int { return 20 } },
		"reader is supplementary": func(commands *launcherCommands) {
			commands.groups = func() ([]int, error) { return []int{20, 5000}, nil }
		},
		"wrong real UID": func(commands *launcherCommands) {
			commands.uid = func() int { return 502 }
			commands.euid = func() int { return 502 }
		},
		"UID reused with new GeneratedUID": func(commands *launcherCommands) {
			commands.liveUUID = func(uint32) ([16]byte, error) { return [16]byte{1}, nil }
		},
		"release substitution": func(commands *launcherCommands) { commands.expectedRelease = strings.Repeat("b", 51) + "a" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			commands := validLauncherCommands()
			mutate(&commands)
			if _, err := prepareLaunch(nil, commands); err == nil {
				t.Fatal("unauthorized launch accepted")
			}
		})
	}
}

func TestPrepareLaunchRejectsAllCallerSelectedArgumentsBeforeBindingRead(t *testing.T) {
	commands := validLauncherCommands()
	loaded := false
	commands.loadBinding = func(int) ([]byte, error) {
		loaded = true
		return testBinding(), nil
	}
	for _, arguments := range [][]string{
		{"proxy"}, {"--config=/tmp/attacker"}, {"--runtime-root=/tmp/attacker"},
		{qualifyArgument, "extra"}, {doctorArgument, "extra"}, {"doctor"},
	} {
		if _, err := prepareLaunch(arguments, commands); err == nil {
			t.Fatalf("arguments %#v accepted", arguments)
		}
	}
	if loaded {
		t.Fatal("rejected caller arguments reached the protected binding")
	}
}

func TestExecuteLauncherValidatesThenClosesAuthorityBeforeFixedExec(t *testing.T) {
	commands := validLauncherCommands()
	order := []string{}
	commands.validateTarget = func(path string, digest [32]byte, gid uint32) error {
		order = append(order, "validate")
		if path != clientReleaseRoot+testReleaseID+"/"+clientRealName || digest[0] != 0xaa || gid != 5000 {
			t.Fatal("target validation received attacker-controlled values")
		}
		return nil
	}
	commands.validateCurrent = func(release string, gid uint32) error {
		order = append(order, "current")
		if release != testReleaseID || gid != 5000 {
			t.Fatal("current validation received attacker-controlled values")
		}
		return nil
	}
	commands.chdir = func(path string) error {
		order = append(order, "chdir")
		if path != "/" {
			t.Fatalf("working directory = %q", path)
		}
		return nil
	}
	commands.closeExtraFDs = func() error {
		order = append(order, "close-fds")
		return nil
	}
	execError := errors.New("test exec return")
	commands.exec = func(path string, arguments, environment []string) error {
		order = append(order, "exec")
		if len(arguments) != 2 || strings.Contains(strings.Join(arguments, " "), strings.Repeat("a", 64)) {
			t.Fatalf("exec arguments leaked authority data: %#v", arguments)
		}
		if !reflect.DeepEqual(environment, []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}) {
			t.Fatalf("exec environment = %#v", environment)
		}
		return execError
	}
	var diagnostics bytes.Buffer
	if code := executeLauncher(nil, &diagnostics, commands); code != 1 || !strings.Contains(diagnostics.String(), execError.Error()) {
		t.Fatalf("execute code=%d diagnostics=%q", code, diagnostics.String())
	}
	if !reflect.DeepEqual(order, []string{"validate", "current", "chdir", "close-fds", "exec"}) {
		t.Fatalf("execution order = %#v", order)
	}
}

func TestExecuteLauncherFailsClosedWhenCurrentSelectorNoLongerMatches(t *testing.T) {
	commands := validLauncherCommands()
	order := []string{}
	commands.validateTarget = func(string, [32]byte, uint32) error {
		order = append(order, "validate")
		return nil
	}
	selectorError := errors.New("authenticated current selector changed")
	commands.validateCurrent = func(release string, gid uint32) error {
		order = append(order, "current")
		if release != testReleaseID || gid != 5000 {
			t.Fatalf("current selector received release=%q gid=%d", release, gid)
		}
		return selectorError
	}
	commands.chdir = func(string) error {
		t.Fatal("selector mismatch reached chdir")
		return nil
	}
	commands.closeExtraFDs = func() error {
		t.Fatal("selector mismatch reached descriptor cleanup")
		return nil
	}
	commands.exec = func(string, []string, []string) error {
		t.Fatal("selector mismatch reached exec")
		return nil
	}
	var diagnostics bytes.Buffer
	if code := executeLauncher(nil, &diagnostics, commands); code != 1 {
		t.Fatalf("execute code=%d, want 1", code)
	}
	if !strings.Contains(diagnostics.String(), selectorError.Error()) {
		t.Fatalf("diagnostics=%q, want selector failure", diagnostics.String())
	}
	if !reflect.DeepEqual(order, []string{"validate", "current"}) {
		t.Fatalf("execution order = %#v", order)
	}
}

func TestParseLauncherBindingRejectsUnknownMissingAndNoncanonicalFields(t *testing.T) {
	if _, err := parseLauncherBinding(testBinding()); err != nil {
		t.Fatal(err)
	}
	mutations := [][]byte{
		bytes.Replace(testBinding(), []byte("client_uid=501"), []byte("client_uid=0501"), 1),
		bytes.Replace(testBinding(), []byte("reader_gid=5000"), []byte("reader_gid=0"), 1),
		bytes.Replace(testBinding(), []byte("client_uuid="), []byte("unknown_uuid="), 1),
		bytes.Replace(testBinding(), []byte("client_sha256="), []byte("unknown_sha256="), 1),
		append(append([]byte(nil), testBinding()...), []byte("extra=value\n")...),
		bytes.TrimSuffix(testBinding(), []byte("\n")),
	}
	for index, encoded := range mutations {
		if _, err := parseLauncherBinding(encoded); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}

func TestValidateInstalledClientRejectsSwapForms(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("positive installed-client ownership test requires root")
	}
	const childMarker = "OWNTRANSIT_LAUNCHER_CLIENT_METADATA_CHILD"
	if os.Getenv(childMarker) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestValidateInstalledClientRejectsSwapForms$", "-test.count=1")
		command.Env = append(os.Environ(), childMarker+"=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated installed-client metadata regression failed: %v\n%s", err, output)
		}
		return
	}

	const readerGID = uint32(60000)
	if err := syscall.Setegid(int(readerGID)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Setegid(0); err != nil {
			t.Errorf("restore effective GID: %v", err)
		}
	}()
	directory := t.TempDir()
	path := filepath.Join(directory, clientRealName)
	contents := []byte("authenticated-client")
	if err := os.WriteFile(path, contents, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if err := validateInstalledClient(path, digest, readerGID); err != nil {
		t.Fatalf("valid installed client rejected: %v", err)
	}

	wrongDigest := digest
	wrongDigest[0] ^= 0xff
	if err := validateInstalledClient(path, wrongDigest, readerGID); err == nil {
		t.Fatal("client with the wrong authenticated digest accepted")
	}
	if err := validateInstalledClient(path, digest, readerGID+1); err == nil {
		t.Fatal("client accepted under a reader GID that was not effective")
	}
	if err := os.Chown(path, 0, int(readerGID+1)); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest, readerGID); err == nil {
		t.Fatal("client owned by the wrong reader group accepted")
	}
	if err := os.Chown(path, 0, int(readerGID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 1, int(readerGID)); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest, readerGID); err == nil {
		t.Fatal("client not owned by root accepted")
	}
	if err := os.Chown(path, 0, int(readerGID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest, readerGID); err == nil {
		t.Fatal("world-executable client accepted")
	}
	if err := os.Chmod(path, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest, readerGID); err == nil {
		t.Fatal("group-writable client accepted")
	}
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest, readerGID); err == nil {
		t.Fatal("multiply linked client accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", path); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest, readerGID); err == nil {
		t.Fatal("symlink client accepted")
	}
}

func TestMarkExtraFileDescriptorsCloseOnExec(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if _, err := unix.FcntlInt(read.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if err := markExtraFileDescriptorsCloseOnExec(); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(read.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("inherited descriptor was not marked close-on-exec")
	}
}

func TestMarkExtraFileDescriptorsFindsDescriptorAboveLoweredLimit(t *testing.T) {
	const childMarker = "OWNTRANSIT_LAUNCHER_HIGH_FD_CHILD"
	if os.Getenv(childMarker) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestMarkExtraFileDescriptorsFindsDescriptorAboveLoweredLimit$", "-test.count=1")
		command.Env = append(os.Environ(), childMarker+"=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated high-descriptor regression failed: %v\n%s", err, output)
		}
		return
	}

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	if original.Cur <= 256 {
		t.Skip("open-file limit is too small for high-descriptor regression")
	}
	high, err := unix.FcntlInt(read.Fd(), unix.F_DUPFD, 256)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(high)
	lowered := original
	lowered.Cur = 32
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lowered); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
			t.Errorf("restore open-file limit: %v", err)
		}
	}()
	if err := markExtraFileDescriptorsCloseOnExec(); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(uintptr(high), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("descriptor %d above lowered soft limit was not marked close-on-exec", high)
	}
}
