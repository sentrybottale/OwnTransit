//go:build linux

package enrollmenttarget

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const runtimeViewHelperEnvironment = "OWNTRANSIT_RUNTIME_VIEW_HELPER"

func TestRuntimeViewReaderHelper(t *testing.T) {
	runtimeRoot := os.Getenv(runtimeViewHelperEnvironment)
	if runtimeRoot == "" {
		return
	}
	anchorRoot := os.Getenv("OWNTRANSIT_RUNTIME_ANCHOR_HELPER")
	readerGID, err := strconv.Atoi(os.Getenv("OWNTRANSIT_RUNTIME_GID_HELPER"))
	if err != nil {
		t.Fatal(err)
	}
	role := enrollment.Role(os.Getenv("OWNTRANSIT_RUNTIME_ROLE_HELPER"))
	handle, err := OpenRuntimeGeneration(runtimeRoot, anchorRoot, readerGID, role)
	if os.Getenv("OWNTRANSIT_RUNTIME_EXPECT_LOCKED") == "1" {
		if !errors.Is(err, securefs.ErrLocked) {
			if err == nil {
				_ = handle.Close()
			}
			t.Fatalf("runtime reader result = %v, want descriptor-bound activation lock", err)
		}
		return
	}
	if os.Getenv("OWNTRANSIT_RUNTIME_EXPECT_FAILURE") == "1" {
		if err == nil {
			_ = handle.Close()
			t.Fatal("runtime reader accepted a deliberately inconsistent publication")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	switch role {
	case enrollment.RoleClient:
		_, err = handle.ClientConfig()
	case enrollment.RoleConnector:
		_, err = handle.ConnectorConfig()
	case enrollment.RoleRelay:
		_, err = handle.RelayConfig()
	default:
		t.Fatalf("invalid helper role %q", role)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.FinalCheck(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OWNTRANSIT_RUNTIME_HOLD_HELPER") == "1" {
		if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
}

func TestRuntimeViewsRejectIndependentRollbackAndRecoveryRepairs(t *testing.T) {
	fixture := newRootRuntimeViewFixture(t)
	role := enrollment.RoleClient
	root := fixture.roots[role]
	binding := fixture.views[role]
	if _, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now); err != nil {
		t.Fatal(err)
	}
	assertRuntimeHelper(t, binding, role, false)

	oldRuntime, err := os.ReadFile(filepath.Join(binding.RuntimeRoot, runtimeViewFile))
	if err != nil {
		t.Fatal(err)
	}
	oldAnchor, err := os.ReadFile(filepath.Join(binding.AnchorViewRoot, anchorViewFile))
	if err != nil {
		t.Fatal(err)
	}
	oldView, err := decodeRuntimeView(oldRuntime)
	if err != nil {
		t.Fatal(err)
	}
	oldGenerationContents := make(map[string][]byte, len(oldView.Files))
	for _, file := range oldView.Files {
		oldGenerationContents[file.Name], err = os.ReadFile(filepath.Join(binding.RuntimeRoot, oldView.Generation, file.Name))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := InitRequest(RequestOptions{
		RootPath: root, RouteID: fixture.route.String(),
		ConnectorInstallationID: fixture.bootstraps[enrollment.RoleConnector].InstallationID,
		Validity:                time.Hour, Now: fixture.now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(binding.RuntimeRoot, oldView.Generation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired runtime generation remains exposed: %v", err)
	}

	// Model a crash after the current generation was exposed but while the old
	// selector/generation was only partly retired. Recovery must use that old
	// selector as the retirement journal, remove the old credential tree, select
	// current, and clear the fail-closed marker in that order.
	restoreInterruptedRetirement(t, binding, oldView, oldRuntime, oldGenerationContents)
	assertRuntimeHelper(t, binding, role, true)
	if _, err := RecoverTransaction(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(binding.RuntimeRoot, oldView.Generation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery left retired credentials group-readable: %v", err)
	}
	assertRuntimeHelper(t, binding, role, false)

	replacePublishedTestFile(t, binding.RuntimeRoot, binding.ReaderGID, runtimeViewFile, oldRuntime)
	assertRuntimeHelper(t, binding, role, true)
	if _, err := RecoverTransaction(root); err != nil {
		t.Fatal(err)
	}
	assertRuntimeHelper(t, binding, role, false)

	replacePublishedTestFile(t, binding.AnchorViewRoot, binding.ReaderGID, anchorViewFile, oldAnchor)
	assertRuntimeHelper(t, binding, role, true)
	if _, err := RecoverTransaction(root); err != nil {
		t.Fatal(err)
	}
	assertRuntimeHelper(t, binding, role, false)

	replacePublishedTestFile(t, binding.RuntimeRoot, binding.ReaderGID, transitionFile, []byte("{}\n"))
	selectorPath := filepath.Join(binding.RuntimeRoot, runtimeViewFile)
	if err := os.Chown(selectorPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(selectorPath, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRuntimeHelper(t, binding, role, true)
	if _, err := RecoverTransaction(root); err != nil {
		t.Fatal(err)
	}
	assertRuntimeHelper(t, binding, role, false)
	assertPublishedTreeMetadataAndContents(t, binding)
}

func TestInterruptedBootstrapIsFailClosedButNotRecoverable(t *testing.T) {
	fixture := newRootRuntimeViewFixture(t)
	releaseID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	privateRoot := filepath.Join(fixture.parent, "interrupted-private")
	authorityRoot := filepath.Join(fixture.parent, "interrupted-authority")
	runtimeRoot := filepath.Join(fixture.parent, "interrupted-runtime")
	anchorViewRoot := filepath.Join(fixture.parent, "interrupted-anchor-view")
	if err := os.Mkdir(anchorViewRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	options := BootstrapOptions{
		RootPath: privateRoot, RollbackAnchorRoot: authorityRoot, Role: enrollment.RoleClient,
		Runtime: enrollment.RuntimeBinding{
			ReleaseID: releaseID.String(), ReleaseSequence: 1,
			ArtifactSHA256: strings.Repeat("a", sha256.Size*2), OS: "linux", Arch: "amd64",
			Role: enrollment.RoleClient, Protocol: enrollment.DeploymentProtocol,
			LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
		},
		Trust: enrollment.Trust{
			RelayAdmissionCA: string(fixture.issuers.RelayAdmission.CertPEM),
			InnerConnectorCA: string(fixture.issuers.InnerConnector.CertPEM),
			InnerClientCA:    string(fixture.issuers.InnerClient.CertPEM),
		},
		DeploymentSignerPublicPEM: fixture.signer.PublicPEM,
		RuntimeViews: RuntimeViewBinding{
			RuntimeRoot: runtimeRoot, RuntimeConfigRoot: runtimeRoot,
			AnchorViewRoot: anchorViewRoot, ReaderGID: 65532,
		},
		Now: fixture.now,
	}
	if _, err := Bootstrap(options); err == nil {
		t.Fatal("bootstrap unexpectedly reused a preexisting anchor-view root")
	}
	for _, partial := range []string{privateRoot, authorityRoot, runtimeRoot} {
		if information, err := os.Stat(partial); err != nil || !information.IsDir() {
			t.Fatalf("expected fail-closed partial root %q: %v", partial, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(privateRoot, stateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted bootstrap selected usable state: %v", err)
	}
	if _, err := Bootstrap(options); err == nil {
		t.Fatal("bootstrap silently reused its partial private root")
	}
	if _, err := RecoverTransaction(privateRoot); err == nil {
		t.Fatal("transaction recovery treated a state-less partial bootstrap as recoverable")
	}
	if _, err := os.Lstat(filepath.Join(runtimeRoot, runtimeViewFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial bootstrap published an active runtime selector: %v", err)
	}
}

func restoreInterruptedRetirement(t *testing.T, binding RuntimeViewBinding, oldView runtimeView, oldRuntime []byte, contents map[string][]byte) {
	t.Helper()
	root, err := securefs.OpenViewRoot(binding.RuntimeRoot, int(binding.ReaderGID))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.ReplaceFile(transitionFile, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	stage, err := root.MkdirPrivateExclusive(oldView.Generation)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range oldView.Files {
		if err := stage.ReplaceFile(file.Name, contents[file.Name], 0o600); err != nil {
			_ = stage.Close()
			t.Fatal(err)
		}
	}
	if err := stage.Sync(); err != nil {
		_ = stage.Close()
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.ExposeDir(oldView.Generation, digestNames(oldView.Files)); err != nil {
		t.Fatal(err)
	}
	if err := root.ReplaceFile(runtimeViewFile, oldRuntime); err != nil {
		t.Fatal(err)
	}
}

func TestSharedRuntimeGateBlocksEveryLifecycleMutationBeforeAnyWrite(t *testing.T) {
	fixture := newRootRuntimeViewFixture(t)
	role := enrollment.RoleClient
	root := fixture.roots[role]
	binding := fixture.views[role]
	if _, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now); err != nil {
		t.Fatal(err)
	}
	command, stdin := startHoldingRuntimeHelper(t, binding, role)
	before := snapshotLifecycleTrees(t, root, binding)
	mutations := map[string]func() error{
		"enrollment request": func() error {
			_, err := InitRequest(RequestOptions{
				RootPath: root, RouteID: fixture.route.String(),
				ConnectorInstallationID: fixture.bootstraps[enrollment.RoleConnector].InstallationID,
				Validity:                time.Hour, Now: fixture.now,
			})
			return err
		},
		"response apply": func() error {
			_, err := ApplyResponse(root, []byte("{}"), fixture.now)
			return err
		},
		"pending cancellation": func() error {
			_, err := CancelPending(root)
			return err
		},
		"lifecycle policy": func() error {
			_, err := ApplyLifecyclePolicy(root, []byte("{}"), fixture.now)
			return err
		},
		"authorized rollback": func() error {
			_, err := Rollback(root, []byte("{}"), fixture.now)
			return err
		},
		"transaction recovery": func() error {
			_, err := RecoverTransaction(root)
			return err
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); !errors.Is(err, securefs.ErrLocked) {
				t.Fatalf("mutation while runtime shared lock held = %v, want ErrLocked", err)
			}
			if after := snapshotLifecycleTrees(t, root, binding); !reflect.DeepEqual(after, before) {
				t.Fatalf("blocked lifecycle operation changed an inode:\n before=%+v\n after=%+v", before, after)
			}
		})
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := InitRequest(RequestOptions{
		RootPath: root, RouteID: fixture.route.String(),
		ConnectorInstallationID: fixture.bootstraps[enrollment.RoleConnector].InstallationID,
		Validity:                time.Hour, Now: fixture.now,
	}); err != nil {
		t.Fatalf("lifecycle mutation remained blocked after runtime exit: %v", err)
	}
}

func TestApplyRetiresOneTimeSecretBeforeExclusiveGateRelease(t *testing.T) {
	fixture := newRootRuntimeViewFixture(t)
	role := enrollment.RoleClient
	root := fixture.roots[role]
	binding := fixture.views[role]
	secret := filepath.Join(root, "record-"+fixture.requests[role].RecordID, responseIdentityFile)
	observed := false
	_, err := applyResponse(root, fixture.responses.ClientEnvelope, fixture.now, func() {
		observed = true
		if _, statErr := os.Lstat(secret); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("one-time response identity was not retired inside the lifecycle boundary: %v", statErr)
		}
		// Publication is complete at this point, so the exclusive lifecycle
		// gate is the only reason a new runtime cannot start.
		assertRuntimeGateLocked(t, binding, role)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("secret-retirement boundary observation did not run")
	}
	assertRuntimeHelper(t, binding, role, false)
}

type lifecycleTreeEntry struct {
	Mode   os.FileMode
	UID    uint32
	GID    uint32
	Inode  uint64
	Links  uint64
	Size   int64
	SHA256 string
}

func snapshotLifecycleTrees(t *testing.T, privateRoot string, binding RuntimeViewBinding) map[string]lifecycleTreeEntry {
	t.Helper()
	result := make(map[string]lifecycleTreeEntry)
	roots := map[string]string{
		"private":     privateRoot,
		"authority":   privateRoot + "-anchor",
		"runtime":     binding.RuntimeRoot,
		"anchor-view": binding.AnchorViewRoot,
	}
	for label, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			information, err := os.Lstat(path)
			if err != nil {
				return err
			}
			stat, ok := information.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("missing syscall metadata for %s", path)
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			value := lifecycleTreeEntry{
				Mode: information.Mode(), UID: stat.Uid, GID: stat.Gid,
				Inode: stat.Ino, Links: uint64(stat.Nlink), Size: information.Size(),
			}
			if information.Mode().IsRegular() {
				contents, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				digest := sha256.Sum256(contents)
				value.SHA256 = fmt.Sprintf("%x", digest[:])
			}
			result[label+"/"+relative] = value
			return nil
		})
		if err != nil {
			t.Fatalf("snapshot %s lifecycle tree: %v", label, err)
		}
	}
	return result
}

func newRootRuntimeViewFixture(t *testing.T) routeTargetFixture {
	t.Helper()
	if unix.Geteuid() != 0 {
		t.Skip("root is required to exercise root-owned publication views")
	}
	parent, err := os.MkdirTemp("/var/lib", "owntransit-runtime-view-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return newRouteTargetFixtureAt(t, parent, 65532)
}

func runtimeHelperCommand(t *testing.T, binding RuntimeViewBinding, role enrollment.Role, expectFailure, expectLocked, hold bool) (*exec.Cmd, io.WriteCloser, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	command := exec.Command("/proc/self/exe", "-test.run=^TestRuntimeViewReaderHelper$")
	command.Env = append(os.Environ(),
		runtimeViewHelperEnvironment+"="+binding.RuntimeRoot,
		"OWNTRANSIT_RUNTIME_ANCHOR_HELPER="+binding.AnchorViewRoot,
		"OWNTRANSIT_RUNTIME_GID_HELPER="+strconv.FormatUint(uint64(binding.ReaderGID), 10),
		"OWNTRANSIT_RUNTIME_ROLE_HELPER="+string(role),
	)
	if expectFailure {
		command.Env = append(command.Env, "OWNTRANSIT_RUNTIME_EXPECT_FAILURE=1")
	}
	if expectLocked {
		command.Env = append(command.Env, "OWNTRANSIT_RUNTIME_EXPECT_LOCKED=1")
	}
	if hold {
		command.Env = append(command.Env, "OWNTRANSIT_RUNTIME_HOLD_HELPER=1")
	}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: 65534, Gid: binding.ReaderGID, Groups: []uint32{binding.ReaderGID},
	}}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	return command, stdin, bufio.NewReader(stdout), &stderr
}

func assertRuntimeHelper(t *testing.T, binding RuntimeViewBinding, role enrollment.Role, expectFailure bool) {
	t.Helper()
	command, stdin, stdout, stderr := runtimeHelperCommand(t, binding, role, expectFailure, false, false)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	output, _ := io.ReadAll(stdout)
	if err := command.Wait(); err != nil {
		t.Fatalf("runtime helper failed: %v stdout=%q stderr=%q", err, output, stderr.String())
	}
}

func assertRuntimeGateLocked(t *testing.T, binding RuntimeViewBinding, role enrollment.Role) {
	t.Helper()
	command, stdin, stdout, stderr := runtimeHelperCommand(t, binding, role, false, true, false)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	output, _ := io.ReadAll(stdout)
	if err := command.Wait(); err != nil {
		t.Fatalf("runtime gate helper failed: %v stdout=%q stderr=%q", err, output, stderr.String())
	}
}

func startHoldingRuntimeHelper(t *testing.T, binding RuntimeViewBinding, role enrollment.Role) (*exec.Cmd, io.WriteCloser) {
	t.Helper()
	command, stdin, stdout, stderr := runtimeHelperCommand(t, binding, role, false, false, true)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := stdout.ReadString('\n')
	if err != nil || line != "ready\n" {
		_ = stdin.Close()
		remainder, _ := io.ReadAll(stdout)
		_ = command.Wait()
		t.Fatalf("holding runtime helper did not start: line=%q remainder=%q err=%v stderr=%q", line, remainder, err, stderr.String())
	}
	return command, stdin
}

func replacePublishedTestFile(t *testing.T, path string, gid uint32, name string, contents []byte) {
	t.Helper()
	root, err := securefs.OpenViewRoot(path, int(gid))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.ReplaceFile(name, contents); err != nil {
		t.Fatal(err)
	}
}

func assertPublishedTreeMetadataAndContents(t *testing.T, binding RuntimeViewBinding) {
	t.Helper()
	for _, rootPath := range []string{binding.RuntimeRoot, binding.AnchorViewRoot} {
		information, err := os.Stat(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		stat := information.Sys().(*syscall.Stat_t)
		if stat.Uid != 0 || stat.Gid != binding.ReaderGID || information.Mode().Perm() != 0o750 {
			t.Fatalf("publication root %q metadata is not root:reader 0750", rootPath)
		}
	}
	entries, err := os.ReadDir(binding.AnchorViewRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != anchorViewFile {
		t.Fatalf("anchor view exposed unexpected entries: %+v", entries)
	}
	viewBytes, err := os.ReadFile(filepath.Join(binding.RuntimeRoot, runtimeViewFile))
	if err != nil {
		t.Fatal(err)
	}
	view, err := decodeRuntimeView(viewBytes)
	if err != nil {
		t.Fatal(err)
	}
	generationEntries, err := os.ReadDir(filepath.Join(binding.RuntimeRoot, view.Generation))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range generationEntries {
		if entry.Name() == requestFile || entry.Name() == deploymentFile ||
			strings.HasPrefix(entry.Name(), "policy-") || entry.Name() == transactionStateFile || entry.Name() == transactionViewFile {
			t.Fatalf("private/future lifecycle material %q was exposed to the runtime", entry.Name())
		}
		information, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		stat := information.Sys().(*syscall.Stat_t)
		if stat.Uid != 0 || stat.Gid != binding.ReaderGID || information.Mode().Perm() != 0o640 {
			t.Fatalf("runtime file %q metadata is not root:reader 0640", entry.Name())
		}
	}
}
