//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
)

type fakePackageService struct {
	active        bool
	calls         []string
	intentRoot    string
	startFailures int
}

func (service *fakePackageService) Active(unit string) (bool, error) {
	service.calls = append(service.calls, "active:"+unit)
	return service.active, nil
}

func (service *fakePackageService) Stop(unit string) error {
	service.calls = append(service.calls, "stop:"+unit)
	service.active = false
	return nil
}

func (service *fakePackageService) Start(unit string) error {
	service.calls = append(service.calls, "start:"+unit)
	if service.intentRoot != "" {
		role := strings.TrimSuffix(strings.TrimPrefix(unit, "owntransit-"), ".service")
		if _, err := os.Lstat(filepath.Join(service.intentRoot, role+".intent")); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if _, err := os.Lstat(filepath.Join(service.intentRoot, role+".restart")); err != nil {
			return errors.New("restart obligation was not durable before service start")
		}
	}
	if service.startFailures > 0 {
		service.startFailures--
		return errors.New("injected service start failure")
	}
	service.active = true
	return nil
}

func TestPackageSupervisorStopsMutatesActivatesAndRestarts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	root := newSupervisorRoot(t)
	service := &fakePackageService{active: true, intentRoot: root}
	activated := false
	supervisor := packageSupervisor{
		role: "connector", intentRoot: root, service: service,
		activate: func(result packagetxn.Result) error {
			activated = true
			if service.active || result.Current != "release-b" {
				t.Fatal("activation did not run while the service was stopped")
			}
			return nil
		},
	}
	mutated := false
	result, err := supervisor.run(func() error { return nil }, func() (packagetxn.Result, error) {
		mutated = true
		if service.active {
			t.Fatal("package mutation ran while the service was active")
		}
		return packagetxn.Result{Role: "connector", Current: "release-b"}, nil
	})
	if err != nil || !mutated || !activated || !service.active || result.Current != "release-b" {
		t.Fatalf("supervised mutation = %+v, %v; mutated=%v activated=%v active=%v", result, err, mutated, activated, service.active)
	}
	assertSupervisorRecordsAbsent(t, root, "connector")
	joined := strings.Join(service.calls, ",")
	if !strings.Contains(joined, "stop:owntransit-connector.service") || !strings.Contains(joined, "start:owntransit-connector.service") {
		t.Fatalf("service calls = %q", joined)
	}
}

func TestPackageSupervisorFailureStaysStoppedAndRecoveryRestarts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	root := newSupervisorRoot(t)
	service := &fakePackageService{active: true, intentRoot: root}
	supervisor := packageSupervisor{
		role: "relay", intentRoot: root, service: service,
		activate: func(packagetxn.Result) error { return nil },
	}
	interrupted := errors.New("interrupted package transaction")
	if _, err := supervisor.run(func() error { return nil }, func() (packagetxn.Result, error) {
		return packagetxn.Result{}, interrupted
	}); !errors.Is(err, interrupted) {
		t.Fatalf("interruption error = %v", err)
	}
	if service.active {
		t.Fatal("failed package transaction restarted the relay")
	}
	if _, err := os.Stat(filepath.Join(root, "relay.intent")); err != nil {
		t.Fatalf("durable restart intent absent: %v", err)
	}
	recovered, err := supervisor.run(func() error { return nil }, func() (packagetxn.Result, error) {
		if service.active {
			t.Fatal("recovery ran while relay was active")
		}
		return packagetxn.Result{Role: "relay", Current: "release-c", Resumed: true}, nil
	})
	if err != nil || !recovered.Resumed || !service.active {
		t.Fatalf("recovery = %+v, %v active=%v", recovered, err, service.active)
	}
	assertSupervisorRecordsAbsent(t, root, "relay")
}

func TestPackageSupervisorActivationFailureRetriesExactIdempotentResult(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	root := newSupervisorRoot(t)
	service := &fakePackageService{active: true, intentRoot: root}
	activationFailure := errors.New("relay image activation failed")
	operationAttempts := 0
	activationAttempts := 0
	supervisor := packageSupervisor{
		role: "relay", intentRoot: root, service: service,
		activate: func(result packagetxn.Result) error {
			activationAttempts++
			if service.active {
				t.Fatal("relay activation ran while the service was active")
			}
			if result.Role != "relay" || result.Current != "release-b" {
				t.Fatalf("activation received another package result: %+v", result)
			}
			if activationAttempts == 1 {
				if result.Idempotent {
					t.Fatal("initial package mutation unexpectedly reported an idempotent result")
				}
				return activationFailure
			}
			if !result.Idempotent {
				t.Fatal("activation retry did not receive the exact idempotent package result")
			}
			return nil
		},
	}
	operation := func() (packagetxn.Result, error) {
		operationAttempts++
		if service.active {
			t.Fatal("package retry ran while the relay was active")
		}
		return packagetxn.Result{
			Role: "relay", Current: "release-b", Idempotent: operationAttempts > 1,
		}, nil
	}

	if _, err := supervisor.run(func() error { return nil }, operation); !errors.Is(err, activationFailure) {
		t.Fatalf("activation failure = %v", err)
	}
	if service.active {
		t.Fatal("failed relay activation restarted the service")
	}
	intent, exists, err := readPackageSupervisorIntent(root, "relay")
	if err != nil || !exists || !intent.RestartActive {
		t.Fatalf("activation failure intent = %+v, exists=%v, err=%v", intent, exists, err)
	}

	retried, err := supervisor.run(func() error { return nil }, operation)
	if err != nil || !retried.Idempotent || !service.active {
		t.Fatalf("idempotent activation retry = %+v, %v active=%v", retried, err, service.active)
	}
	if operationAttempts != 2 || activationAttempts != 2 {
		t.Fatalf("retry attempts: operation=%d activation=%d", operationAttempts, activationAttempts)
	}
	assertSupervisorRecordsAbsent(t, root, "relay")
}

func TestPackageSupervisorStartFailureRetainsDurableRestartAndRetries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	for _, role := range []string{"connector", "relay"} {
		t.Run(role, func(t *testing.T) {
			root := newSupervisorRoot(t)
			service := &fakePackageService{active: true, intentRoot: root, startFailures: 1}
			supervisor := packageSupervisor{
				role: role, intentRoot: root, service: service,
				activate: func(packagetxn.Result) error { return nil },
			}
			attempts := 0
			operation := func() (packagetxn.Result, error) {
				attempts++
				return packagetxn.Result{Role: role, Current: "release-b", Idempotent: attempts > 1}, nil
			}

			if _, err := supervisor.run(func() error { return nil }, operation); err == nil || !strings.Contains(err.Error(), "injected service start failure") {
				t.Fatalf("first start error = %v", err)
			}
			if service.active {
				t.Fatal("service became active after injected start failure")
			}
			if _, err := os.Lstat(filepath.Join(root, role+".intent")); !os.IsNotExist(err) {
				t.Fatalf("mutation intent remains after completed operation: %v", err)
			}
			restart, exists, err := readPackageSupervisorRestart(root, role)
			if err != nil || !exists || !restart.RestartActive {
				t.Fatalf("restart record = %+v, exists=%v, err=%v", restart, exists, err)
			}

			result, err := supervisor.run(func() error { return nil }, operation)
			if err != nil || !result.Idempotent || !service.active || attempts != 2 {
				t.Fatalf("restart retry = %+v, %v; active=%v attempts=%d", result, err, service.active, attempts)
			}
			assertSupervisorRecordsAbsent(t, root, role)
		})
	}
}

func TestPackageSupervisorRecoversRestartRecordAfterServiceAutostart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	root := newSupervisorRoot(t)
	intent := packageSupervisorIntent{Schema: packageSupervisorSchema, Role: "connector", RestartActive: true}
	if err := writePackageSupervisorIntent(root, intent); err != nil {
		t.Fatal(err)
	}
	if err := transitionPackageSupervisorRecord(root, "connector", "intent", "restart"); err != nil {
		t.Fatal(err)
	}
	service := &fakePackageService{active: true, intentRoot: root}
	attempts := 0
	supervisor := packageSupervisor{
		role: "connector", intentRoot: root, service: service,
		activate: func(packagetxn.Result) error { return nil },
	}
	result, err := supervisor.run(func() error { return nil }, func() (packagetxn.Result, error) {
		attempts++
		return packagetxn.Result{Role: "connector", Current: "release-b", Idempotent: true}, nil
	})
	if err != nil || !result.Idempotent || !service.active || attempts != 1 {
		t.Fatalf("autostart recovery = %+v, %v; active=%v attempts=%d", result, err, service.active, attempts)
	}
	if joined := strings.Join(service.calls, ","); !strings.Contains(joined, "stop:owntransit-connector.service") || !strings.Contains(joined, "start:owntransit-connector.service") {
		t.Fatalf("autostart recovery service calls = %q", joined)
	}
	assertSupervisorRecordsAbsent(t, root, "connector")
}

func TestPackageSupervisorRejectsInactiveRestartRecord(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	root := newSupervisorRoot(t)
	intent := packageSupervisorIntent{Schema: packageSupervisorSchema, Role: "connector", RestartActive: false}
	if err := writePackageSupervisorIntent(root, intent); err != nil {
		t.Fatal(err)
	}
	if err := transitionPackageSupervisorRecord(root, "connector", "intent", "restart"); err != nil {
		t.Fatal(err)
	}
	mutated := false
	supervisor := packageSupervisor{
		role: "connector", intentRoot: root, service: &fakePackageService{active: false, intentRoot: root},
		activate: func(packagetxn.Result) error { return nil },
	}
	if _, err := supervisor.run(func() error { return nil }, func() (packagetxn.Result, error) {
		mutated = true
		return packagetxn.Result{}, nil
	}); err == nil || !strings.Contains(err.Error(), "restart record cannot preserve an inactive service") {
		t.Fatalf("inactive restart error = %v", err)
	}
	if mutated {
		t.Fatal("inactive restart record reached package mutation")
	}
}

func TestPackageSupervisorRejectsConflictingIntentAndRestartRecords(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	root := newSupervisorRoot(t)
	intent := packageSupervisorIntent{Schema: packageSupervisorSchema, Role: "connector", RestartActive: true}
	if err := writePackageSupervisorIntent(root, intent); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(root, "connector.intent"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "connector.restart"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	mutated := false
	supervisor := packageSupervisor{
		role: "connector", intentRoot: root, service: &fakePackageService{active: true, intentRoot: root},
		activate: func(packagetxn.Result) error { return nil },
	}
	if _, err := supervisor.run(func() error { return nil }, func() (packagetxn.Result, error) {
		mutated = true
		return packagetxn.Result{}, nil
	}); err == nil || !strings.Contains(err.Error(), "conflicting intent and restart records") {
		t.Fatalf("conflicting-record error = %v", err)
	}
	if mutated {
		t.Fatal("conflicting records reached package mutation")
	}
}

func TestPackageSupervisorLeavesPreviouslyInactiveServiceInactive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	service := &fakePackageService{}
	supervisor := packageSupervisor{
		role: "connector", intentRoot: newSupervisorRoot(t), service: service,
		activate: func(packagetxn.Result) error { return nil },
	}
	if _, err := supervisor.run(func() error { return nil }, func() (packagetxn.Result, error) {
		return packagetxn.Result{Role: "connector", Current: "release-a"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if service.active || strings.Contains(strings.Join(service.calls, ","), "start:") {
		t.Fatalf("inactive service was started: active=%v calls=%v", service.active, service.calls)
	}
}

func TestPackageSupervisorRejectsInvalidPreflightBeforeStoppingService(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact supervisor ownership test requires the pinned root build environment")
	}
	root := newSupervisorRoot(t)
	service := &fakePackageService{active: true}
	supervisor := packageSupervisor{
		role: "connector", intentRoot: root, service: service,
		activate: func(packagetxn.Result) error { return nil },
	}
	rejected := errors.New("invalid signed package")
	mutated := false
	if _, err := supervisor.run(func() error { return rejected }, func() (packagetxn.Result, error) {
		mutated = true
		return packagetxn.Result{}, nil
	}); !errors.Is(err, rejected) {
		t.Fatalf("preflight error = %v", err)
	}
	if mutated || !service.active {
		t.Fatalf("invalid package affected live service: mutated=%v active=%v", mutated, service.active)
	}
	if joined := strings.Join(service.calls, ","); strings.Contains(joined, "stop:") {
		t.Fatalf("invalid package stopped service: calls=%q", joined)
	}
	assertSupervisorRecordsAbsent(t, root, "connector")
}

func newSupervisorRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func assertSupervisorRecordsAbsent(t *testing.T, root, role string) {
	t.Helper()
	for _, state := range []string{"intent", "restart"} {
		if _, err := os.Lstat(filepath.Join(root, role+"."+state)); !os.IsNotExist(err) {
			t.Fatalf("completed supervisor %s remains: %v", state, err)
		}
	}
}
