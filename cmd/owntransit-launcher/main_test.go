package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
		expectedRelease: testReleaseID,
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
	commands.validateTarget = func(path string, digest [32]byte) error {
		order = append(order, "validate")
		if path != clientReleaseRoot+testReleaseID+"/"+clientRealName || digest[0] != 0xaa {
			t.Fatal("target validation received attacker-controlled values")
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
	if !reflect.DeepEqual(order, []string{"validate", "chdir", "close-fds", "exec"}) {
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
	directory := t.TempDir()
	path := filepath.Join(directory, clientRealName)
	contents := []byte("authenticated-client")
	if err := os.WriteFile(path, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if err := validateInstalledClient(path, digest); err != nil {
		t.Fatalf("valid installed client rejected: %v", err)
	}
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest); err == nil {
		t.Fatal("group-writable client accepted")
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledClient(path, digest); err == nil {
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
	if err := validateInstalledClient(path, digest); err == nil {
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
