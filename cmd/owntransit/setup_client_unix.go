//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/enrollmentsetup"
)

const (
	maxSetupPromptBytes = 256
	maxSetupTransitions = 6
)

var errSetupResetRequired = errors.New("owntransit: setup reset required")

type targetSetupCourier interface {
	PutRequest(context.Context, enrollmentexchange.TargetMailboxAction) error
	ReadResponse(context.Context, enrollmentexchange.TargetMailboxAction) ([]byte, error)
	Consume(context.Context, enrollmentexchange.TargetMailboxTombstone) error
}

type clientSetupDependencies struct {
	control        func(context.Context, string, []byte) (enrollmentsetup.State, error)
	courier        targetSetupCourier
	readInvitation func(string) ([]byte, error)
}

func runClientSetupCommand(arguments []string, input io.Reader, output, diagnostics io.Writer) int {
	ctx := context.Background()
	paths, err := installedSetupPaths(runtime.GOOS)
	if err != nil {
		fmt.Fprintln(diagnostics, "owntransit setup: this platform has no installed setup boundary")
		return 1
	}
	dependencies := clientSetupDependencies{
		control: func(ctx context.Context, command string, frame []byte) (enrollmentsetup.State, error) {
			return invokeInstalledSetupControl(ctx, paths.control, command, frame)
		},
		courier:        enrollmentexchange.NewCourier(),
		readInvitation: readSetupInvitation,
	}
	return executeClientSetup(ctx, arguments, input, output, diagnostics, dependencies)
}

type installedSetupBoundary struct {
	control string
}

func installedSetupPaths(goos string) (installedSetupBoundary, error) {
	switch goos {
	case "linux":
		return installedSetupBoundary{
			control: "/usr/libexec/owntransit/roles/client/current/owntransitctl",
		}, nil
	case "darwin":
		return installedSetupBoundary{
			control: "/Library/OwnTransit/roles/client/current/owntransitctl",
		}, nil
	default:
		return installedSetupBoundary{}, errors.New("unsupported platform")
	}
}

func executeClientSetup(
	ctx context.Context,
	arguments []string,
	input io.Reader,
	output, diagnostics io.Writer,
	dependencies clientSetupDependencies,
) int {
	if ctx == nil || input == nil || output == nil || diagnostics == nil || dependencies.control == nil ||
		dependencies.courier == nil || dependencies.readInvitation == nil {
		fmt.Fprintln(diagnostics, "owntransit setup: setup support is unavailable")
		return 1
	}
	var state enrollmentsetup.State
	var err error
	switch {
	case len(arguments) == 1 && arguments[0] == "--resume":
		state, err = dependencies.control(ctx, "setup-status", nil)
	case len(arguments) == 1 && arguments[0] == "--cancel":
		state, err = dependencies.control(ctx, "setup-cancel", nil)
		if err == nil && state.Phase() == enrollmentexchange.PhaseCancelled {
			fmt.Fprintln(output, "OwnTransit setup cancelled. A different invitation may now be staged.")
			return 0
		}
	case len(arguments) == 1 && filepath.Ext(arguments[0]) == ".otinvite":
		invitation, readErr := dependencies.readInvitation(arguments[0])
		if readErr != nil {
			fmt.Fprintln(diagnostics, "owntransit setup: invitation is not a private bounded regular .otinvite file")
			return 1
		}
		frame, frameErr := enrollmentsetup.EncodeFrame(enrollmentsetup.FrameInvitation, invitation)
		if frameErr != nil {
			fmt.Fprintln(diagnostics, "owntransit setup: invitation is invalid")
			return 1
		}
		state, err = dependencies.control(ctx, "setup-stage", frame)
	default:
		fmt.Fprintln(diagnostics, "usage: owntransit setup INVITATION.otinvite | owntransit setup --resume | owntransit setup --cancel")
		return 2
	}
	if err != nil {
		writeSetupControlError(diagnostics, err)
		return 1
	}
	return continueClientSetup(ctx, state, input, output, diagnostics, dependencies)
}

func continueClientSetup(
	ctx context.Context,
	state enrollmentsetup.State,
	input io.Reader,
	output, diagnostics io.Writer,
	dependencies clientSetupDependencies,
) int {
	for transitions := 0; transitions < maxSetupTransitions; transitions++ {
		switch state.Phase() {
		case enrollmentexchange.PhasePendingComparison:
			action, ok := state.MailboxAction()
			words, haveWords := state.TargetWords()
			if !ok || !haveWords {
				fmt.Fprintln(diagnostics, "owntransit setup: saved setup state is incomplete")
				return 1
			}
			if err := dependencies.courier.PutRequest(ctx, action); err != nil {
				fmt.Fprintln(output, "SETUP SAVED — NOT READY")
				return 0
			}
			fmt.Fprintln(output, "Independently authenticate the administrator using your pre-established contact procedure.")
			fmt.Fprintf(output, "Read these target words to the administrator: %s %s %s\n", words[0], words[1], words[2])
			fmt.Fprintln(output, "Only then type the three words the administrator reads back; press Enter to resume later:")
			reverse, present, err := readSetupWords(input)
			if err != nil {
				fmt.Fprintln(diagnostics, "owntransit setup: comparison input is invalid")
				return 2
			}
			if !present {
				fmt.Fprintln(output, "SETUP SAVED — NOT READY")
				return 0
			}
			frame, err := enrollmentsetup.EncodeReverseWords(reverse)
			if err != nil {
				fmt.Fprintln(diagnostics, "owntransit setup: comparison input is invalid")
				return 2
			}
			state, err = dependencies.control(ctx, "setup-confirm", frame)
			if err != nil {
				writeSetupControlError(diagnostics, err)
				return 1
			}
		case enrollmentexchange.PhaseTranscriptConfirmed:
			action, ok := state.MailboxAction()
			if !ok {
				fmt.Fprintln(diagnostics, "owntransit setup: saved setup state is incomplete")
				return 1
			}
			if err := dependencies.courier.PutRequest(ctx, action); err != nil {
				fmt.Fprintln(output, "SETUP SAVED — NOT READY")
				return 0
			}
			response, err := dependencies.courier.ReadResponse(ctx, action)
			if err != nil {
				fmt.Fprintln(output, "SETUP SAVED — NOT READY")
				return 0
			}
			frame, err := enrollmentsetup.EncodeFrame(enrollmentsetup.FrameBoundResponse, response)
			if err != nil {
				fmt.Fprintln(diagnostics, "owntransit setup: mailbox returned an invalid response")
				return 1
			}
			state, err = dependencies.control(ctx, "setup-accept", frame)
			if err != nil {
				writeSetupControlError(diagnostics, err)
				return 1
			}
		case enrollmentexchange.PhaseResponseVerified:
			var err error
			state, err = dependencies.control(ctx, "setup-resume", nil)
			if err != nil {
				writeSetupControlError(diagnostics, err)
				return 1
			}
		case enrollmentexchange.PhaseApplied:
			var controlErr error
			state, controlErr = dependencies.control(ctx, "setup-ready", nil)
			if controlErr != nil {
				fmt.Fprintln(output, "SETUP SAVED — NOT READY")
				return 0
			}
		case enrollmentexchange.PhaseReady:
			tombstone, needsCleanup := state.MailboxTombstone()
			if needsCleanup {
				// Relay consumption is best-effort hygiene only. A malicious or
				// restarted relay cannot veto exact local capability cleanup.
				_ = dependencies.courier.Consume(ctx, tombstone)
				var controlErr error
				state, controlErr = dependencies.control(ctx, "setup-clean", nil)
				if controlErr != nil {
					fmt.Fprintln(output, "OwnTransit carrier READY; local enrollment cleanup is pending.")
					return 0
				}
				if state.Phase() != enrollmentexchange.PhaseReady {
					fmt.Fprintln(diagnostics, "owntransit setup: protected cleanup returned invalid state")
					return 1
				}
				if _, stillRetained := state.MailboxTombstone(); stillRetained {
					fmt.Fprintln(output, "OwnTransit carrier READY; local enrollment cleanup is pending.")
					return 0
				}
			}
			fmt.Fprintln(output, "OwnTransit carrier READY; SSH was not attempted.")
			return 0
		case enrollmentexchange.PhaseCancelled:
			fmt.Fprintln(diagnostics, "owntransit setup: comparison failed; this invitation is cancelled")
			return 1
		default:
			fmt.Fprintln(diagnostics, "owntransit setup: saved setup state is invalid")
			return 1
		}
	}
	fmt.Fprintln(diagnostics, "owntransit setup: setup transition limit exceeded")
	return 1
}

func readSetupInvitation(path string) ([]byte, error) {
	if filepath.Ext(path) != ".otinvite" {
		return nil, errors.New("invalid invitation extension")
	}
	return readCourierFile(path, enrollmentexchange.MaxInvitationSize)
}

func readSetupWords(input io.Reader) ([3]string, bool, error) {
	var result [3]string
	reader := bufio.NewReaderSize(io.LimitReader(input, maxSetupPromptBytes+1), maxSetupPromptBytes+1)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return result, false, err
	}
	if len(line) > maxSetupPromptBytes || strings.ContainsRune(line, 0) {
		return result, false, errors.New("comparison input exceeds its bound")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if strings.TrimSpace(line) == "" {
		return result, false, nil
	}
	fields := strings.Fields(line)
	if len(fields) != len(result) {
		return result, false, errors.New("exactly three words are required")
	}
	copy(result[:], fields)
	return result, true, nil
}

func invokeInstalledSetupControl(ctx context.Context, controlPath, command string, frame []byte) (enrollmentsetup.State, error) {
	if ctx == nil || !filepath.IsAbs(controlPath) || filepath.Clean(controlPath) != controlPath || !isSetupControlCommand(command) {
		return enrollmentsetup.State{}, errors.New("invalid setup control invocation")
	}
	process := exec.CommandContext(ctx, "/usr/bin/sudo", "--", controlPath, command)
	process.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	process.Dir = "/"
	process.Stdin = bytes.NewReader(frame)
	stdout := newSetupBoundedBuffer(enrollmentsetup.MaxFrameSize + 12)
	stderr := newSetupBoundedBuffer(256)
	process.Stdout, process.Stderr = stdout, stderr
	if err := process.Run(); err != nil {
		resetLine := "owntransitctl " + command + ": " + enrollmentsetup.ResetSupportCode() + "\n"
		if !stderr.overflow && stderr.String() == resetLine {
			return enrollmentsetup.State{}, errSetupResetRequired
		}
		return enrollmentsetup.State{}, errors.New("installed setup control failed")
	}
	if stdout.overflow || stderr.overflow || stderr.Len() != 0 {
		return enrollmentsetup.State{}, errors.New("installed setup control returned unexpected output")
	}
	payload, err := enrollmentsetup.ReadFrame(bytes.NewReader(stdout.Bytes()), enrollmentsetup.FrameState, enrollmentsetup.MaxFrameSize)
	if err != nil {
		return enrollmentsetup.State{}, err
	}
	return enrollmentsetup.DecodeState(payload)
}

func isSetupControlCommand(command string) bool {
	switch command {
	case "setup-stage", "setup-status", "setup-confirm", "setup-accept", "setup-resume", "setup-ready", "setup-clean", "setup-cancel":
		return true
	default:
		return false
	}
}

type setupBoundedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func newSetupBoundedBuffer(limit int) *setupBoundedBuffer {
	return &setupBoundedBuffer{limit: limit}
}

func (buffer *setupBoundedBuffer) Write(value []byte) (int, error) {
	if buffer == nil || buffer.limit < 0 {
		return 0, errors.New("invalid bounded output")
	}
	remaining := buffer.limit - buffer.Len()
	if len(value) > remaining {
		if remaining > 0 {
			_, _ = buffer.Buffer.Write(value[:remaining])
		}
		buffer.overflow = true
		return len(value), errors.New("setup subprocess output exceeded its bound")
	}
	return buffer.Buffer.Write(value)
}

func writeSetupControlError(diagnostics io.Writer, err error) {
	if errors.Is(err, errSetupResetRequired) {
		fmt.Fprintf(diagnostics, "owntransit setup: %s\n", enrollmentsetup.ResetSupportCode())
		return
	}
	fmt.Fprintln(diagnostics, "owntransit setup: protected setup operation failed")
}
