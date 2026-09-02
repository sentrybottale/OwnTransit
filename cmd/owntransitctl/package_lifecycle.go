package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
	"github.com/sentrybottale/owntransit/internal/release"
	"github.com/sentrybottale/owntransit/internal/signing"
)

const packageSignatureLimit int64 = 16 << 10

type packageStateOptions struct {
	role string
}

type packageApplyOptions struct {
	packageStateOptions
	bundleRoot      string
	manifestPath    string
	manifestSigPath string
	releaseKeyPath  string
	policyPath      string
	policySigPath   string
	policyKeyPath   string
}

type packageRollbackOptions struct {
	packageStateOptions
	toReleaseID string
}

type packageLifecycleSummary struct {
	Schema          string `json:"schema"`
	Action          string `json:"action"`
	Role            string `json:"role"`
	Current         string `json:"current_release_id"`
	Previous        string `json:"previous_release_id,omitempty"`
	Generation      uint64 `json:"generation"`
	Installed       bool   `json:"installed"`
	Resumed         bool   `json:"resumed"`
	Idempotent      bool   `json:"idempotent"`
	LifecyclePath   string `json:"lifecycle_path"`
	RoleRuntimePath string `json:"role_runtime_path"`
	LicensePath     string `json:"license_path"`
	ThirdPartyPath  string `json:"third_party_licenses_path"`
}

type packageDetachSummary struct {
	Schema    string `json:"schema"`
	Action    string `json:"action"`
	Role      string `json:"role"`
	ReleaseID string `json:"release_id"`
	Detached  bool   `json:"detached"`
}

type nativePackageMutationGuard interface {
	Close() error
}

type noOpPackageMutationGuard struct{}

func (noOpPackageMutationGuard) Close() error { return nil }

func parsePackageApplyArguments(arguments []string, diagnostics io.Writer) (packageApplyOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl package-apply", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options packageApplyOptions
	flags.StringVar(&options.role, "role", "", "local package role: client, connector, relay, or provisioner")
	flags.StringVar(&options.bundleRoot, "bundle", "", "absolute protected signed release bundle root")
	flags.StringVar(&options.manifestPath, "manifest", "", "signed software release manifest")
	flags.StringVar(&options.manifestSigPath, "manifest-signature", "", "software release manifest signature")
	flags.StringVar(&options.releaseKeyPath, "release-public-key", "", "independently trusted release signer public key")
	flags.StringVar(&options.policyPath, "policy", "", "signed monotonic release policy")
	flags.StringVar(&options.policySigPath, "policy-signature", "", "release policy signature")
	flags.StringVar(&options.policyKeyPath, "policy-public-key", "", "independently trusted policy signer public key")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return packageApplyOptions{}, 0, false
		}
		return packageApplyOptions{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "owntransitctl package-apply: unexpected positional argument")
		return packageApplyOptions{}, 2, false
	}
	for _, required := range []struct{ name, value string }{
		{"-role", options.role}, {"-bundle", options.bundleRoot}, {"-manifest", options.manifestPath},
		{"-manifest-signature", options.manifestSigPath}, {"-release-public-key", options.releaseKeyPath},
		{"-policy", options.policyPath}, {"-policy-signature", options.policySigPath}, {"-policy-public-key", options.policyKeyPath},
	} {
		if required.value == "" {
			fmt.Fprintf(diagnostics, "owntransitctl package-apply: %s is required\n", required.name)
			return packageApplyOptions{}, 2, false
		}
	}
	if !validPackageRole(options.role) {
		fmt.Fprintln(diagnostics, "owntransitctl package-apply: -role must be client, connector, relay, or provisioner")
		return packageApplyOptions{}, 2, false
	}
	return options, 0, true
}

func parsePackageRollbackArguments(arguments []string, diagnostics io.Writer) (packageRollbackOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl package-rollback", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options packageRollbackOptions
	flags.StringVar(&options.role, "role", "", "local package role: client, connector, relay, or provisioner")
	flags.StringVar(&options.toReleaseID, "to-release", "", "exact retained previous release ID")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return packageRollbackOptions{}, 0, false
		}
		return packageRollbackOptions{}, 2, false
	}
	if flags.NArg() != 0 || !validPackageRole(options.role) || options.toReleaseID == "" {
		fmt.Fprintln(diagnostics, "owntransitctl package-rollback: -role and -to-release are required")
		return packageRollbackOptions{}, 2, false
	}
	return options, 0, true
}

func parsePackageStateArguments(command string, arguments []string, diagnostics io.Writer) (packageStateOptions, int, bool) {
	flags := flag.NewFlagSet("owntransitctl "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options packageStateOptions
	flags.StringVar(&options.role, "role", "", "local package role: client, connector, relay, or provisioner")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return packageStateOptions{}, 0, false
		}
		return packageStateOptions{}, 2, false
	}
	if flags.NArg() != 0 || !validPackageRole(options.role) {
		fmt.Fprintf(diagnostics, "owntransitctl %s: -role must be client, connector, relay, or provisioner\n", command)
		return packageStateOptions{}, 2, false
	}
	return options, 0, true
}

func applyPackageRelease(options packageApplyOptions) ([]byte, error) {
	manifest, err := readBoundedPublicFile(options.manifestPath, release.MaxManifestSize)
	if err != nil {
		return nil, err
	}
	manifestSignature, err := readBoundedPublicFile(options.manifestSigPath, packageSignatureLimit)
	if err != nil {
		return nil, err
	}
	releaseKeyPEM, err := readPublicFile(options.releaseKeyPath)
	if err != nil {
		return nil, err
	}
	releaseKey, err := signing.ParsePublic(releaseKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse independently trusted release public key: %w", err)
	}
	policy, err := readBoundedPublicFile(options.policyPath, release.MaxPolicySize)
	if err != nil {
		return nil, err
	}
	policySignature, err := readBoundedPublicFile(options.policySigPath, packageSignatureLimit)
	if err != nil {
		return nil, err
	}
	policyKeyPEM, err := readPublicFile(options.policyKeyPath)
	if err != nil {
		return nil, err
	}
	policyKey, err := signing.ParsePublic(policyKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse independently trusted policy public key: %w", err)
	}
	guard, err := acquireNativePackageMutationGuard(options.role)
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	manager, err := openNativePackageLifecycle(options.role)
	if err != nil {
		return nil, err
	}
	defer manager.Close()
	input := packagetxn.ApplyInput{
		BundleRoot: options.bundleRoot, ManifestBytes: manifest, ManifestSignature: manifestSignature,
		ReleaseKey: releaseKey, PolicyBytes: policy, PolicySignature: policySignature, PolicyKey: policyKey,
	}
	result, err := runSupervisedPackageMutation(options.role,
		func() error { return manager.PreflightApply(input) },
		func() (packagetxn.Result, error) { return manager.Apply(input) })
	if err != nil {
		return nil, err
	}
	if err := finalizeNativePackageMutation(options.role, result); err != nil {
		return nil, fmt.Errorf("finalize selected package runtime: %w", err)
	}
	return encodePackageResult("apply", options.role, result)
}

func rollbackPackageRelease(options packageRollbackOptions) ([]byte, error) {
	guard, err := acquireNativePackageMutationGuard(options.role)
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	manager, err := openNativePackageLifecycle(options.role)
	if err != nil {
		return nil, err
	}
	defer manager.Close()
	input := packagetxn.RollbackInput{ToReleaseID: options.toReleaseID}
	result, err := runSupervisedPackageMutation(options.role,
		func() error { return manager.PreflightRollback(input) },
		func() (packagetxn.Result, error) { return manager.Rollback(input) })
	if err != nil {
		return nil, err
	}
	if err := finalizeNativePackageMutation(options.role, result); err != nil {
		return nil, fmt.Errorf("finalize selected package runtime: %w", err)
	}
	return encodePackageResult("rollback", options.role, result)
}

func recoverPackageRelease(options packageStateOptions) ([]byte, error) {
	guard, err := acquireNativePackageMutationGuard(options.role)
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	manager, err := openNativePackageLifecycle(options.role)
	if err != nil {
		return nil, err
	}
	defer manager.Close()
	result, err := runSupervisedPackageMutation(options.role, manager.PreflightRecover, manager.Recover)
	if err != nil {
		return nil, err
	}
	if err := finalizeNativePackageMutation(options.role, result); err != nil {
		return nil, fmt.Errorf("finalize selected package runtime: %w", err)
	}
	return encodePackageResult("recover", options.role, result)
}

func detachPackageRelease(options packageStateOptions) ([]byte, error) {
	guard, err := acquireNativePackageMutationGuard(options.role)
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	manager, err := openNativePackageLifecycle(options.role)
	if err != nil {
		return nil, err
	}
	defer manager.Close()
	var runtimeIdentity packagetxn.RuntimeIdentity
	err = manager.WithCurrentRuntimeIdentity(func(identity packagetxn.RuntimeIdentity) error {
		if identity.Role != options.role || identity.ReleaseID == "" {
			return errors.New("authenticated current package identity differs from the detach role")
		}
		runtimeIdentity = identity
		return detachNativePackageRuntime(options.role, identity)
	})
	if err != nil {
		return nil, err
	}
	return encodePublic(packageDetachSummary{
		Schema: "owntransit.ctl.package-detach.v1", Action: "detach", Role: options.role,
		ReleaseID: runtimeIdentity.ReleaseID, Detached: true,
	})
}

func openNativePackageLifecycle(role string) (*packagetxn.Manager, error) {
	packageRoot, anchorRoot, err := nativePackageRoots()
	if err != nil {
		return nil, err
	}
	gid, err := nativePackageReaderGID(role)
	if err != nil {
		return nil, err
	}
	return packagetxn.OpenLifecycle(packageRoot, anchorRoot, role, gid)
}

func nativePackageRoots() (string, string, error) {
	switch runtime.GOOS {
	case "linux":
		return "/usr/libexec/owntransit/roles", "/var/lib/owntransit/package-rollback", nil
	case "darwin":
		return "/Library/OwnTransit/roles", "/private/var/db/OwnTransit/package-rollback", nil
	default:
		return "", "", errors.New("package lifecycle is unsupported on this operating system")
	}
}

func encodePackageResult(action, role string, result packagetxn.Result) ([]byte, error) {
	packageRoot, _, err := nativePackageRoots()
	if err != nil {
		return nil, err
	}
	primary, err := roleRuntimeName(role)
	if err != nil {
		return nil, err
	}
	activeRoot := filepath.Join(packageRoot, role, "current")
	return encodePublic(packageLifecycleSummary{
		Schema: "owntransit.ctl.package-lifecycle.v1", Action: action, Role: role,
		Current: result.Current, Previous: result.Previous, Generation: result.Generation,
		Installed: result.Installed, Resumed: result.Resumed, Idempotent: result.Idempotent,
		LifecyclePath: filepath.Join(activeRoot, "owntransitctl"), RoleRuntimePath: filepath.Join(activeRoot, primary),
		LicensePath: filepath.Join(activeRoot, "LICENSE"), ThirdPartyPath: filepath.Join(activeRoot, "THIRD_PARTY_LICENSES.txt"),
	})
}

func roleRuntimeName(role string) (string, error) {
	switch role {
	case "client":
		if runtime.GOOS == "linux" {
			return "owntransit-proxy", nil
		}
		return "owntransit", nil
	case "connector":
		return "owntransit-connector", nil
	case "relay":
		return "owntransit-relay.oci.tar", nil
	case "provisioner":
		return "owntransit-provision", nil
	default:
		return "", errors.New("package role must be client, connector, relay, or provisioner")
	}
}

func validPackageRole(role string) bool {
	return role == "client" || role == "connector" || role == "relay" || role == "provisioner"
}
