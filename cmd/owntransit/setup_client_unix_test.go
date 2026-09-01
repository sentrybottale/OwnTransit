//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/enrollmentsetup"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

type unavailableSetupCourier struct{}

func (unavailableSetupCourier) PutRequest(context.Context, enrollmentexchange.TargetMailboxAction) error {
	return enrollmentexchange.ErrMailboxUnavailable
}

func (unavailableSetupCourier) ReadResponse(context.Context, enrollmentexchange.TargetMailboxAction) ([]byte, error) {
	return nil, enrollmentexchange.ErrMailboxUnavailable
}

func (unavailableSetupCourier) Consume(context.Context, enrollmentexchange.TargetMailboxTombstone) error {
	return enrollmentexchange.ErrMailboxUnavailable
}

type successfulSetupCourier struct {
	consumed int
}

func (*successfulSetupCourier) PutRequest(context.Context, enrollmentexchange.TargetMailboxAction) error {
	return nil
}

func (*successfulSetupCourier) ReadResponse(context.Context, enrollmentexchange.TargetMailboxAction) ([]byte, error) {
	return []byte("opaque-bound-response"), nil
}

func (courier *successfulSetupCourier) Consume(context.Context, enrollmentexchange.TargetMailboxTombstone) error {
	courier.consumed++
	return nil
}

func TestClientSetupAppliedStateDelegatesDurableReadyProofToControl(t *testing.T) {
	applied, err := enrollmentsetup.DecodeState([]byte{4, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		readyErr   error
		wantOutput string
	}{
		{name: "ready", wantOutput: "OwnTransit carrier READY; SSH was not attempted.\n"},
		{name: "not-ready", readyErr: errors.New("relay unavailable"), wantOutput: "SETUP SAVED — NOT READY\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			code := executeClientSetup(context.Background(), []string{"--resume"}, strings.NewReader(""), &output, &diagnostics, clientSetupDependencies{
				control: func(_ context.Context, command string, _ []byte) (enrollmentsetup.State, error) {
					if command == "setup-status" {
						return applied, nil
					}
					if command == "setup-ready" && test.readyErr != nil {
						return enrollmentsetup.State{}, test.readyErr
					}
					return enrollmentsetup.DecodeState([]byte{6, 0, 0, 0})
				},
				courier:        unavailableSetupCourier{},
				readInvitation: func(string) ([]byte, error) { return nil, errors.New("must not read") },
			})
			if code != 0 || output.String() != test.wantOutput || diagnostics.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, output.String(), diagnostics.String())
			}
		})
	}
}

func TestClientSetupFreshTransitionChainReachesReadyAndCleanup(t *testing.T) {
	pending := decodeSetupTestState(t, 1, true, true)
	confirmed := decodeSetupTestState(t, 2, false, true)
	verified := decodeSetupTestState(t, 3, false, false)
	applied := decodeSetupTestState(t, 4, false, false)
	readyWithCleanup := decodeSetupTestState(t, 6, false, false)
	readyPayload := append([]byte(nil), setupTestMailboxTombstone()...)
	readyPayload[0], readyPayload[1] = 6, 4
	readyWithCleanup, err := enrollmentsetup.DecodeState(readyPayload)
	if err != nil {
		t.Fatal(err)
	}
	ready := decodeSetupTestState(t, 6, false, false)
	states := map[string]enrollmentsetup.State{
		"setup-status": pending, "setup-confirm": confirmed, "setup-accept": verified,
		"setup-resume": applied, "setup-ready": readyWithCleanup, "setup-clean": ready,
	}
	var calls []string
	courier := &successfulSetupCourier{}
	var output, diagnostics bytes.Buffer
	code := executeClientSetup(context.Background(), []string{"--resume"}, strings.NewReader("one two six\n"), &output, &diagnostics, clientSetupDependencies{
		control: func(_ context.Context, command string, _ []byte) (enrollmentsetup.State, error) {
			calls = append(calls, command)
			return states[command], nil
		},
		courier:        courier,
		readInvitation: func(string) ([]byte, error) { return nil, errors.New("must not read") },
	})
	wantCalls := "setup-status,setup-confirm,setup-accept,setup-resume,setup-ready,setup-clean"
	if code != 0 || strings.Join(calls, ",") != wantCalls || courier.consumed != 1 ||
		!strings.HasSuffix(output.String(), "OwnTransit carrier READY; SSH was not attempted.\n") || diagnostics.Len() != 0 {
		t.Fatalf("code=%d calls=%q consumed=%d stdout=%q stderr=%q", code, calls, courier.consumed, output.String(), diagnostics.String())
	}
}

func decodeSetupTestState(t *testing.T, phase byte, words, action bool) enrollmentsetup.State {
	t.Helper()
	payload := []byte{phase, 0, 0, 0}
	if words {
		payload[1] |= 1
		for _, word := range []string{"alpha", "bravo", "cider"} {
			payload = append(payload, byte(len(word)))
			payload = append(payload, word...)
		}
	}
	if action {
		payload[1] |= 2
		payload = append(payload, setupTestMailboxAction()...)
	}
	state, err := enrollmentsetup.DecodeState(payload)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func setupTestMailboxAction() []byte {
	endpoint := []byte("wss://relay.example/connects/enrollment")
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, uint16(len(endpoint)))
	payload = append(payload, endpoint...)
	var id protocol.ID
	id[len(id)-1] = 1
	payload = append(payload, id[:]...)
	payload = append(payload, bytes.Repeat([]byte{3}, 32)...)
	payload = append(payload, bytes.Repeat([]byte{4}, 32)...)
	request := []byte("opaque-encrypted-request")
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(request)))
	payload = append(payload, length...)
	return append(payload, request...)
}

func setupTestMailboxTombstone() []byte {
	endpoint := []byte("wss://relay.example/connects/enrollment")
	payload := []byte{0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(endpoint)))
	payload = append(payload, endpoint...)
	var id protocol.ID
	id[len(id)-1] = 1
	payload = append(payload, id[:]...)
	return append(payload, bytes.Repeat([]byte{4}, 32)...)
}

func TestClientSetupUsesOnlyFixedInstalledBoundaries(t *testing.T) {
	linux, _ := installedSetupPaths("linux")
	if linux.control != "/usr/libexec/owntransit/roles/client/current/owntransitctl" {
		t.Fatalf("linux boundary = %+v", linux)
	}
	darwin, _ := installedSetupPaths("darwin")
	if darwin.control != "/Library/OwnTransit/roles/client/current/owntransitctl" {
		t.Fatalf("darwin boundary = %+v", darwin)
	}
	if _, err := installedSetupPaths("windows"); err == nil {
		t.Fatal("unsupported setup platform accepted")
	}
}

func TestSetupInvitationReaderRejectsAliasesAndLooseFiles(t *testing.T) {
	directory := t.TempDir()
	invitation := filepath.Join(directory, "target.otinvite")
	if err := os.WriteFile(invitation, []byte("bounded invitation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSetupInvitation(invitation); err != nil || string(got) != "bounded invitation\n" {
		t.Fatalf("private invitation = %q, %v", got, err)
	}
	alias := filepath.Join(directory, "alias.otinvite")
	if err := os.Symlink(invitation, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetupInvitation(alias); err == nil {
		t.Fatal("setup followed an invitation symlink")
	}
	if err := os.Chmod(invitation, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetupInvitation(invitation); err == nil {
		t.Fatal("setup accepted a broadly readable invitation capability")
	}
	if _, err := readSetupInvitation(strings.TrimSuffix(invitation, ".otinvite") + ".txt"); err == nil {
		t.Fatal("setup accepted a non-.otinvite path")
	}
}

func TestSetupWordInputIsExactlyBounded(t *testing.T) {
	words, present, err := readSetupWords(strings.NewReader("alpha beta gamma\nignored"))
	if err != nil || !present || words != [3]string{"alpha", "beta", "gamma"} {
		t.Fatalf("words=%v present=%v err=%v", words, present, err)
	}
	if _, present, err := readSetupWords(strings.NewReader("\n")); err != nil || present {
		t.Fatalf("deferred words present=%v err=%v", present, err)
	}
	if _, _, err := readSetupWords(io.LimitReader(strings.NewReader(strings.Repeat("a", maxSetupPromptBytes+2)), maxSetupPromptBytes+2)); err == nil {
		t.Fatal("oversized comparison input accepted")
	}
}
