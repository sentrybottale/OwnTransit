//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	packageSupervisorRoot   = "/var/lib/owntransit/package-supervisor"
	packageSupervisorSchema = "owntransit.package-supervisor.v1"
	maxSupervisorIntent     = 4096
)

type packageServiceController interface {
	Active(string) (bool, error)
	Stop(string) error
	Start(string) error
}

type packageSupervisorIntent struct {
	Schema        string `json:"schema"`
	Role          string `json:"role"`
	RestartActive bool   `json:"restart_active"`
}

type packageSupervisor struct {
	role       string
	intentRoot string
	service    packageServiceController
	activate   func(packagetxn.Result) error
}

func runSupervisedPackageMutation(role string, preflight func() error, operation func() (packagetxn.Result, error)) (packagetxn.Result, error) {
	if role == "client" || role == "provisioner" {
		if preflight == nil {
			return packagetxn.Result{}, errors.New("package supervisor preflight is required")
		}
		if err := preflight(); err != nil {
			return packagetxn.Result{}, err
		}
		return operation()
	}
	supervisor := packageSupervisor{
		role: role, intentRoot: packageSupervisorRoot, service: systemdPackageController{},
		activate: func(result packagetxn.Result) error {
			if role != "relay" {
				return nil
			}
			return activateRelayImage(result)
		},
	}
	return supervisor.run(preflight, operation)
}

func (supervisor packageSupervisor) run(preflight func() error, operation func() (packagetxn.Result, error)) (packagetxn.Result, error) {
	if supervisor.role != "connector" && supervisor.role != "relay" {
		return packagetxn.Result{}, errors.New("package supervisor supports only connector or relay")
	}
	if preflight == nil || operation == nil || supervisor.service == nil || supervisor.activate == nil {
		return packagetxn.Result{}, errors.New("package supervisor dependencies are incomplete")
	}
	lock, err := acquirePackageSupervisorLock(supervisor.intentRoot, supervisor.role)
	if err != nil {
		return packagetxn.Result{}, err
	}
	defer lock.Close()
	if err := preflight(); err != nil {
		return packagetxn.Result{}, err
	}
	unit := "owntransit-" + supervisor.role + ".service"
	intent, exists, err := readPackageSupervisorIntent(supervisor.intentRoot, supervisor.role)
	if err != nil {
		return packagetxn.Result{}, err
	}
	if !exists {
		active, err := supervisor.service.Active(unit)
		if err != nil {
			return packagetxn.Result{}, err
		}
		intent = packageSupervisorIntent{Schema: packageSupervisorSchema, Role: supervisor.role, RestartActive: active}
		if err := writePackageSupervisorIntent(supervisor.intentRoot, intent); err != nil {
			return packagetxn.Result{}, err
		}
	}
	active, err := supervisor.service.Active(unit)
	if err != nil {
		return packagetxn.Result{}, err
	}
	if active {
		if err := supervisor.service.Stop(unit); err != nil {
			return packagetxn.Result{}, err
		}
	}
	if active, err := supervisor.service.Active(unit); err != nil || active {
		if err != nil {
			return packagetxn.Result{}, err
		}
		return packagetxn.Result{}, errors.New("package supervisor: role runtime remained active after stop")
	}
	result, err := operation()
	if err != nil {
		return packagetxn.Result{}, err
	}
	if err := supervisor.activate(result); err != nil {
		return packagetxn.Result{}, err
	}
	if intent.RestartActive {
		if err := supervisor.service.Start(unit); err != nil {
			return packagetxn.Result{}, err
		}
		active, err := supervisor.service.Active(unit)
		if err != nil || !active {
			if err != nil {
				return packagetxn.Result{}, err
			}
			return packagetxn.Result{}, errors.New("package supervisor: role runtime did not become active after restart")
		}
	}
	if err := removePackageSupervisorIntent(supervisor.intentRoot, supervisor.role); err != nil {
		return packagetxn.Result{}, err
	}
	return result, nil
}

func acquirePackageSupervisorLock(root, role string) (*os.File, error) {
	directory, err := openPackageSupervisorRoot(root)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directory)
	name := role + ".lock"
	fd, err := unix.Openat(directory, name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("package supervisor: open role lock: %w", err)
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return nil, fmt.Errorf("package supervisor: own role lock: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return nil, fmt.Errorf("package supervisor: protect role lock: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || uint32(stat.Mode)&0o7777 != 0o600 || stat.Nlink != 1 {
		return nil, errors.New("package supervisor: role lock metadata is invalid")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("package supervisor: another role package operation is active")
		}
		return nil, fmt.Errorf("package supervisor: lock role package operation: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return nil, errors.New("package supervisor: wrap role lock")
	}
	closeFD = false
	return file, nil
}

type systemdPackageController struct{}

func (systemdPackageController) Active(unit string) (bool, error) {
	output, err := runPackageCommand("/usr/bin/systemctl", "is-active", "--quiet", unit)
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && (exit.ExitCode() == 3 || exit.ExitCode() == 4) {
		return false, nil
	}
	return false, fmt.Errorf("package supervisor: inspect %s: %w: %s", unit, err, output)
}

func (systemdPackageController) Stop(unit string) error {
	output, err := runPackageCommand("/usr/bin/systemctl", "stop", "--no-ask-password", unit)
	if err != nil {
		return fmt.Errorf("package supervisor: stop %s: %w: %s", unit, err, output)
	}
	return nil
}

func (systemdPackageController) Start(unit string) error {
	output, err := runPackageCommand("/usr/bin/systemctl", "start", "--no-ask-password", unit)
	if err != nil {
		return fmt.Errorf("package supervisor: start %s: %w: %s", unit, err, output)
	}
	return nil
}

func runPackageCommand(path string, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/root", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("command timeout: %w", ctx.Err())
	}
	if len(output) > 4096 {
		output = output[:4096]
	}
	return strings.TrimSpace(string(output)), err
}

func readPackageSupervisorIntent(root, role string) (packageSupervisorIntent, bool, error) {
	directory, err := openPackageSupervisorRoot(root)
	if err != nil {
		return packageSupervisorIntent{}, false, err
	}
	defer unix.Close(directory)
	name := role + ".intent"
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return packageSupervisorIntent{}, false, nil
	}
	if err != nil {
		return packageSupervisorIntent{}, false, fmt.Errorf("package supervisor: open intent: %w", err)
	}
	defer unix.Close(fd)
	contents, err := readExactSupervisorFile(fd)
	if err != nil {
		return packageSupervisorIntent{}, false, err
	}
	var intent packageSupervisorIntent
	if err := strictjson.Decode(contents, &intent); err != nil {
		return packageSupervisorIntent{}, false, fmt.Errorf("package supervisor: decode intent: %w", err)
	}
	canonical, _ := json.Marshal(intent)
	canonical = append(canonical, '\n')
	if !bytes.Equal(contents, canonical) || intent.Schema != packageSupervisorSchema || intent.Role != role {
		return packageSupervisorIntent{}, false, errors.New("package supervisor: intent is invalid or noncanonical")
	}
	return intent, true, nil
}

func writePackageSupervisorIntent(root string, intent packageSupervisorIntent) error {
	if intent.Schema != packageSupervisorSchema || (intent.Role != "connector" && intent.Role != "relay") {
		return errors.New("package supervisor: intent is invalid")
	}
	directory, err := openPackageSupervisorRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	contents, _ := json.Marshal(intent)
	contents = append(contents, '\n')
	name := intent.Role + ".intent"
	fd, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("package supervisor: create intent: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("package supervisor: wrap intent")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(directory, name, 0)
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return fmt.Errorf("package supervisor: own intent: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("package supervisor: protect intent: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		return fmt.Errorf("package supervisor: write intent: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("package supervisor: sync intent: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("package supervisor: close intent: %w", err)
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("package supervisor: sync intent root: %w", err)
	}
	remove = false
	return nil
}

func removePackageSupervisorIntent(root, role string) error {
	directory, err := openPackageSupervisorRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	if err := unix.Unlinkat(directory, role+".intent", 0); err != nil {
		return fmt.Errorf("package supervisor: remove completed intent: %w", err)
	}
	return unix.Fsync(directory)
}

func openPackageSupervisorRoot(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, errors.New("package supervisor: intent root is not canonical")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("package supervisor: open intent root: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Gid != 0 || uint32(stat.Mode)&0o7777 != 0o700 {
		_ = unix.Close(fd)
		return -1, errors.New("package supervisor: intent root must be root:root mode 0700")
	}
	return fd, nil
}

func readExactSupervisorFile(fd int) ([]byte, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 ||
		uint32(stat.Mode)&0o7777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxSupervisorIntent {
		return nil, errors.New("package supervisor: intent file metadata is invalid")
	}
	contents := make([]byte, stat.Size)
	offset := 0
	for offset < len(contents) {
		read, err := unix.Read(fd, contents[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || read == 0 {
			return nil, errors.New("package supervisor: read intent file")
		}
		offset += read
	}
	return contents, nil
}

func activateRelayImage(result packagetxn.Result) error {
	if result.Role != "relay" || result.Current == "" {
		return errors.New("package supervisor: relay activation result is invalid")
	}
	packageRoot, _, err := nativePackageRoots()
	if err != nil {
		return err
	}
	archive := filepath.Join(packageRoot, "relay", "current", "owntransit-relay.oci.tar")
	tag := "owntransit-relay:" + result.Current
	expectedImageID, err := expectedRelayImageID(archive, result.Current, result.Runtime.Arch)
	if err != nil {
		return err
	}
	digest, err := bindRelayImage(archive, tag, expectedImageID, runPackageCommand)
	if err != nil {
		return err
	}
	service, err := user.Lookup("owntransit-relay")
	if err != nil {
		return fmt.Errorf("package supervisor: resolve relay service user: %w", err)
	}
	group, err := user.LookupGroup("owntransit-relay")
	if err != nil {
		return fmt.Errorf("package supervisor: resolve relay reader group: %w", err)
	}
	uid, uidErr := strconv.ParseUint(service.Uid, 10, 31)
	gid, gidErr := strconv.ParseUint(group.Gid, 10, 31)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return errors.New("package supervisor: relay service identity is invalid")
	}
	contents := []byte(fmt.Sprintf("OWNTRANSIT_RELAY_IMAGE=sha256:%s\nOWNTRANSIT_RELAY_UID=%d\nOWNTRANSIT_RELAY_READER_GID=%d\n", digest, uid, gid))
	return replaceRelayEnvironment(contents)
}

func replaceRelayEnvironment(contents []byte) error {
	const directoryPath = "/etc/owntransit"
	const target = "relay-container.env"
	const stage = ".relay-container.env.stage"
	directory, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("package supervisor: open relay environment root: %w", err)
	}
	defer unix.Close(directory)
	var stat unix.Stat_t
	if err := unix.Fstat(directory, &stat); err != nil || stat.Uid != 0 || stat.Gid != 0 || uint32(stat.Mode)&0o7777 != 0o755 {
		return errors.New("package supervisor: relay environment root is not root:root mode 0755")
	}
	_ = unix.Unlinkat(directory, stage, 0)
	fd, err := unix.Openat(directory, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("package supervisor: create relay environment stage: %w", err)
	}
	file := os.NewFile(uintptr(fd), stage)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("package supervisor: wrap relay environment stage")
	}
	staged := true
	defer func() {
		_ = file.Close()
		if staged {
			_ = unix.Unlinkat(directory, stage, 0)
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(directory, stage, directory, target); err != nil {
		return fmt.Errorf("package supervisor: publish relay environment: %w", err)
	}
	staged = false
	return unix.Fsync(directory)
}
