package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/enrollmentsetup"
)

func TestCTLSetupCommandsAcceptNoCallerPathsAndUseGenericErrors(t *testing.T) {
	for _, command := range []string{"setup-stage", "setup-status", "setup-confirm", "setup-accept", "setup-resume", "setup-ready", "setup-clean", "setup-cancel"} {
		t.Run(command, func(t *testing.T) {
			called := false
			operation := func() ([]byte, error) {
				called = true
				return nil, errors.New("secret-looking internal detail")
			}
			commands := ctlCommands{
				setupStage: operation, setupStatus: operation, setupConfirm: operation,
				setupAccept: operation, setupResume: operation, setupReady: operation,
				setupClean: operation, setupCancel: operation,
			}
			var output, diagnostics bytes.Buffer
			if code := executeCTL([]string{command}, &output, &diagnostics, commands); code != 1 || !called || output.Len() != 0 ||
				strings.Contains(diagnostics.String(), "secret-looking") || diagnostics.String() != "owntransitctl "+command+": setup operation failed\n" {
				t.Fatalf("code/output/diagnostics = %q/%q called=%v", output.String(), diagnostics.String(), called)
			}
			called = false
			output.Reset()
			diagnostics.Reset()
			if code := executeCTL([]string{command, "/attacker/path"}, &output, &diagnostics, commands); code != 2 || called {
				t.Fatalf("caller path reached %s operation", command)
			}
		})
	}

	commands := ctlCommands{setupStatus: func() ([]byte, error) { return nil, enrollmentsetup.ErrResetRequired }}
	var output, diagnostics bytes.Buffer
	if code := executeCTL([]string{"setup-status"}, &output, &diagnostics, commands); code != 1 || diagnostics.String() != "owntransitctl setup-status: "+enrollmentsetup.ResetSupportCode()+"\n" {
		t.Fatalf("reset code=%d stderr=%q", code, diagnostics.String())
	}
}

func TestCTLVersionIsOfflineAndLifecycleRoleBound(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	commands := productionCTLCommands()
	commands.bootstrap = func(bootstrapOptions) ([]byte, error) { return nil, errors.New("unexpected bootstrap") }
	commands.enrollInit = func(enrollInitOptions) ([]byte, error) { return nil, errors.New("unexpected init") }
	commands.pending = func(exportPendingOptions) ([]byte, error) { return nil, errors.New("unexpected pending") }
	commands.apply = func(applyOptions) ([]byte, error) { return nil, errors.New("unexpected apply") }
	commands.cancel = func(stateOptions) ([]byte, error) { return nil, errors.New("unexpected cancel") }
	commands.status = func(stateOptions) ([]byte, error) { return nil, errors.New("unexpected status") }
	if code := executeCTL([]string{"version"}, &output, &diagnostics, commands); code != 0 {
		t.Fatalf("executeCTL(version) = %d, diagnostics=%q", code, diagnostics.String())
	}
	var info buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	if info.Role != "lifecycle" || info.ConnectorTarget != "" {
		t.Fatalf("unexpected lifecycle version: %+v", info)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected diagnostics: %q", diagnostics.String())
	}
}

func TestCTLApplyPassesOnlyLocalPathsAndWritesReceipt(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	var got applyOptions
	commands := ctlCommands{
		apply: func(options applyOptions) ([]byte, error) {
			got = options
			return []byte("{\"schema\":\"owntransit.ctl.apply.v1\"}\n"), nil
		},
	}
	code := executeCTL([]string{
		"apply", "--state-root", "target-state", "--response", "response.otre",
	}, &output, &diagnostics, commands)
	if code != 0 || got.stateRoot != "target-state" || got.responsePath != "response.otre" {
		t.Fatalf("executeCTL(apply) = %d, options=%+v, diagnostics=%q", code, got, diagnostics.String())
	}
	if output.String() != "{\"schema\":\"owntransit.ctl.apply.v1\"}\n" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestCTLPackageApplyPassesSignedInputsWithoutCallerSuppliedDigests(t *testing.T) {
	var output, diagnostics bytes.Buffer
	var got packageApplyOptions
	commands := ctlCommands{
		packageApply: func(options packageApplyOptions) ([]byte, error) {
			got = options
			return []byte("{\"schema\":\"owntransit.ctl.package-lifecycle.v1\"}\n"), nil
		},
	}
	code := executeCTL([]string{
		"package-apply", "--role", "provisioner", "--bundle", "/protected/bundle",
		"--manifest", "/trusted/release.json", "--manifest-signature", "/trusted/release.sig",
		"--release-public-key", "/trusted/release.pem", "--policy", "/trusted/policy.json",
		"--policy-signature", "/trusted/policy.sig", "--policy-public-key", "/trusted/policy.pem",
	}, &output, &diagnostics, commands)
	if code != 0 || diagnostics.Len() != 0 || got.role != "provisioner" || got.bundleRoot != "/protected/bundle" ||
		got.releaseKeyPath != "/trusted/release.pem" || got.policyKeyPath != "/trusted/policy.pem" {
		t.Fatalf("package-apply = %d, options=%+v, stderr=%q", code, got, diagnostics.String())
	}
}

func TestCTLPackageRollbackAndRecoveryAreRoleScoped(t *testing.T) {
	var rollbackRole, rollbackRelease, recoveryRole string
	commands := ctlCommands{
		packageRollback: func(options packageRollbackOptions) ([]byte, error) {
			rollbackRole, rollbackRelease = options.role, options.toReleaseID
			return []byte("{}\n"), nil
		},
		packageRecover: func(options packageStateOptions) ([]byte, error) {
			recoveryRole = options.role
			return []byte("{}\n"), nil
		},
	}
	for _, arguments := range [][]string{
		{"package-rollback", "--role", "provisioner", "--to-release", "retained-release"},
		{"package-recover", "--role", "provisioner"},
	} {
		var output, diagnostics bytes.Buffer
		if code := executeCTL(arguments, &output, &diagnostics, commands); code != 0 || diagnostics.Len() != 0 {
			t.Fatalf("executeCTL(%v)=%d stderr=%q", arguments, code, diagnostics.String())
		}
	}
	if rollbackRole != "provisioner" || rollbackRelease != "retained-release" || recoveryRole != "provisioner" {
		t.Fatalf("rollback=(%q,%q), recover=%q", rollbackRole, rollbackRelease, recoveryRole)
	}
}

func TestProvisionerPackageLifecycleHasNoRuntimeReader(t *testing.T) {
	if !validPackageRole("provisioner") {
		t.Fatal("provisioner package role is not accepted")
	}
	if name, err := roleRuntimeName("provisioner"); err != nil || name != "owntransit-provision" {
		t.Fatalf("provisioner runtime name = %q, %v", name, err)
	}
	if gid, err := nativePackageReaderGID("provisioner"); err != nil || gid != 0 {
		t.Fatalf("provisioner package reader GID = %d, %v; want zero", gid, err)
	}
}

func TestCTLSignedLifecycleCommandsPassOnlyLocalPaths(t *testing.T) {
	for _, command := range []string{"policy-apply", "rollback"} {
		t.Run(command, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			var got signedInputOptions
			commands := ctlCommands{}
			callback := func(options signedInputOptions) ([]byte, error) {
				got = options
				return []byte("{\"schema\":\"public\"}\n"), nil
			}
			if command == "policy-apply" {
				commands.policyApply = callback
			} else {
				commands.rollback = callback
			}
			code := executeCTL([]string{command, "--state-root", "target-state", "--authorization", "signed.json"}, &output, &diagnostics, commands)
			if code != 0 || got.stateRoot != "target-state" || got.inputPath != "signed.json" || diagnostics.Len() != 0 {
				t.Fatalf("executeCTL(%s)=%d options=%+v diagnostics=%q", command, code, got, diagnostics.String())
			}
		})
	}
}

func TestCTLStatusWritesOnlyCommandResult(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	gotState := ""
	commands := ctlCommands{
		version:    func(io.Writer) error { return errors.New("unexpected version") },
		bootstrap:  func(bootstrapOptions) ([]byte, error) { return nil, errors.New("unexpected bootstrap") },
		enrollInit: func(enrollInitOptions) ([]byte, error) { return nil, errors.New("unexpected init") },
		pending:    func(exportPendingOptions) ([]byte, error) { return nil, errors.New("unexpected pending") },
		cancel:     func(stateOptions) ([]byte, error) { return nil, errors.New("unexpected cancel") },
		status: func(options stateOptions) ([]byte, error) {
			gotState = options.stateRoot
			return []byte("{\"schema\":\"public\"}\n"), nil
		},
	}
	code := executeCTL([]string{"status", "--state-root", "target-state"}, &output, &diagnostics, commands)
	if code != 0 || gotState != "target-state" {
		t.Fatalf("executeCTL(status) = %d, state=%q, diagnostics=%q", code, gotState, diagnostics.String())
	}
	if output.String() != "{\"schema\":\"public\"}\n" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestCTLBootstrapRequiresExplicitReleaseInputs(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	called := false
	commands := ctlCommands{
		version: func(io.Writer) error { return nil },
		bootstrap: func(bootstrapOptions) ([]byte, error) {
			called = true
			return nil, nil
		},
		enrollInit: func(enrollInitOptions) ([]byte, error) { return nil, nil },
		pending:    func(exportPendingOptions) ([]byte, error) { return nil, nil },
		cancel:     func(stateOptions) ([]byte, error) { return nil, nil },
		status:     func(stateOptions) ([]byte, error) { return nil, nil },
	}
	code := executeCTL([]string{"bootstrap", "--state-root", "target-state"}, &output, &diagnostics, commands)
	if code != 2 || called {
		t.Fatalf("executeCTL(bootstrap) = %d, called=%v", code, called)
	}
	if output.Len() != 0 || !strings.Contains(diagnostics.String(), "-role is required") {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}
