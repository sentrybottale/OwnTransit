//go:build darwin || linux

// Package enrollmentsetup coordinates only the client-recipient half of the
// enrollment exchange. Tentative invitation authority and endpoint secrets
// remain in a root-only setup workspace until the reverse comparison is
// durably confirmed. Only then may the exact pending material enter the fixed
// client lifecycle roots.
package enrollmentsetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/enrollmenttarget"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	planSchema        = "owntransit.client-setup-plan.v1"
	selectorSchema    = "owntransit.client-setup-selector.v1"
	pendingSchema     = "owntransit.client-setup-pending.v1"
	cancelledSchema   = "owntransit.client-setup-cancelled.v1"
	readySchema       = "owntransit.client-setup-ready.v1"
	setupLockFile     = "setup.lock"
	selectorFile      = "current.json"
	planFile          = "plan.json"
	pendingFile       = "pending.json"
	cancelledFile     = "cancelled.json"
	readyFile         = "ready.json"
	exchangeDirectory = "exchange"
	maxPlanSize       = 512 << 10
	maxPendingSize    = 1 << 20
	maxReadySize      = 16 << 10
	requestValidity   = time.Hour
	resetSupportCode  = "OT-SETUP-RESET-REQUIRED"
)

// ErrResetRequired means a different invitation cannot replace the selected
// setup without an explicit cancel, or the confirmed immutable bootstrap needs
// a separate authenticated recovery ceremony. No state is silently removed.
var ErrResetRequired = errors.New("enrollmentsetup: " + resetSupportCode)

type clientPaths struct {
	privateRoot    string
	authorityRoot  string
	runtimeRoot    string
	runtimeConfig  string
	anchorViewRoot string
	setupRoot      string
}

// Client is a fixed-path client-recipient coordinator. It has no connector,
// relay, arbitrary-root, or generic bootstrap mode.
type Client struct {
	paths     clientPaths
	runtime   enrollment.RuntimeBinding
	readerGID uint32
}

type currentSetup struct {
	root      *securefs.Root
	workspace *securefs.Root
	lock      *securefs.Lock
	plan      planRecord
	session   *enrollmentexchange.TargetSession
}

func (current *currentSetup) Close() {
	if current == nil {
		return
	}
	if current.workspace != nil {
		_ = current.workspace.Close()
	}
	if current.lock != nil {
		_ = current.lock.Close()
	}
	if current.root != nil {
		_ = current.root.Close()
	}
}

type planRecord struct {
	Schema           string                    `json:"schema"`
	Invitation       string                    `json:"invitation"`
	InvitationSHA256 string                    `json:"invitation_sha256"`
	VerifiedUnix     int64                     `json:"verified_unix"`
	ExpiresUnix      int64                     `json:"expires_unix"`
	InstallationID   string                    `json:"installation_id"`
	Runtime          enrollment.RuntimeBinding `json:"runtime"`
}

type selectorRecord struct {
	Schema           string `json:"schema"`
	InvitationSHA256 string `json:"invitation_sha256"`
	Workspace        string `json:"workspace"`
}

type pendingRecord struct {
	Schema           string `json:"schema"`
	Request          string `json:"request"`
	OuterPrivateKey  string `json:"outer_private_key"`
	InnerPrivateKey  string `json:"inner_private_key"`
	ResponseIdentity string `json:"response_identity"`
}

type cancelledRecord struct {
	Schema           string `json:"schema"`
	InvitationSHA256 string `json:"invitation_sha256"`
}

// readyRecord is the authoritative local READY receipt. Before cleanup it
// retains only the response-read capability needed for best-effort relay
// hygiene. Cleanup atomically replaces it with a redacted receipt after all
// known local enrollment capabilities and the bound response are gone.
type readyRecord struct {
	Schema                 string                    `json:"schema"`
	InvitationSHA256       string                    `json:"invitation_sha256"`
	Workspace              string                    `json:"workspace"`
	InstallationID         string                    `json:"installation_id"`
	RequestSHA256          string                    `json:"request_sha256"`
	ActiveRecordID         string                    `json:"active_record_id"`
	Runtime                enrollment.RuntimeBinding `json:"runtime"`
	ReadySessionGeneration uint64                    `json:"ready_session_generation"`
	ValidationUnix         int64                     `json:"validation_unix"`
	ReadyUnix              int64                     `json:"ready_unix"`
	CleanupComplete        bool                      `json:"cleanup_complete"`
	CleanedUnix            int64                     `json:"cleaned_unix"`
	MailboxEndpoint        string                    `json:"mailbox_endpoint,omitempty"`
	MailboxID              string                    `json:"mailbox_id,omitempty"`
	ResponseReadCapability string                    `json:"response_read_capability,omitempty"`
}

// OpenClient selects only the compiled platform's fixed installed client
// roots. expectedRuntime must come from authenticated package state.
func OpenClient(expectedRuntime enrollment.RuntimeBinding, readerGID int) (*Client, error) {
	if expectedRuntime.Role != enrollment.RoleClient || expectedRuntime.OS != runtime.GOOS || expectedRuntime.Validate(enrollment.RoleClient) != nil ||
		readerGID <= 0 || uint64(readerGID) >= 1<<32 {
		return nil, errors.New("enrollmentsetup: authenticated installed client runtime and reader group are required")
	}
	paths, err := installedClientPaths(runtime.GOOS)
	if err != nil {
		return nil, err
	}
	return &Client{paths: paths, runtime: expectedRuntime, readerGID: uint32(readerGID)}, nil
}

func installedClientPaths(goos string) (clientPaths, error) {
	switch goos {
	case "linux":
		return clientPaths{
			privateRoot: "/var/lib/owntransit/client/private", authorityRoot: "/var/lib/owntransit/client/authority",
			runtimeRoot: "/var/lib/owntransit/client/runtime", runtimeConfig: "/var/lib/owntransit/client/runtime",
			anchorViewRoot: "/var/lib/owntransit/client/anchor-view", setupRoot: "/var/lib/owntransit/client/setup",
		}, nil
	case "darwin":
		return clientPaths{
			privateRoot: "/private/var/db/OwnTransit/client/private", authorityRoot: "/private/var/db/OwnTransit/client/authority",
			runtimeRoot: "/Library/OwnTransit/client/runtime", runtimeConfig: "/Library/OwnTransit/client/runtime",
			anchorViewRoot: "/Library/OwnTransit/client/anchor-view", setupRoot: "/private/var/db/OwnTransit/client/setup",
		}, nil
	default:
		return clientPaths{}, errors.New("enrollmentsetup: client setup is unsupported on this operating system")
	}
}

// Stage creates or resumes one exact tentative request and exchange session.
// It never creates the main client lifecycle roots.
func (client *Client) Stage(invitation []byte, now time.Time) (State, error) {
	if client == nil {
		return State{}, errors.New("enrollmentsetup: client coordinator is unavailable")
	}
	now = now.UTC().Truncate(time.Second)
	bootstrap, err := enrollmentexchange.PrepareClientBootstrap(invitation, client.runtime, now)
	if err != nil {
		return State{}, err
	}
	root, err := client.openSetupRoot(true)
	if err != nil {
		return State{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(setupLockFile)
	if err != nil {
		return State{}, err
	}
	defer lock.Close()
	if _, err := readReady(root); err == nil {
		return State{}, ErrResetRequired
	} else if !errors.Is(err, unix.ENOENT) {
		return State{}, err
	}
	workspace, plan, err := client.selectInvitation(root, invitation, bootstrap, now)
	if err != nil {
		return State{}, err
	}
	defer workspace.Close()
	if cancelled, err := workspaceCancelled(workspace, plan.InvitationSHA256); err != nil {
		return State{}, err
	} else if cancelled {
		return State{}, ErrResetRequired
	}
	material, err := ensurePendingMaterial(workspace, plan, bootstrap, now)
	if err != nil {
		return State{}, err
	}
	plan, bootstrap, err = client.bindPlanValidationToRequest(workspace, plan, bootstrap, material)
	if err != nil {
		return State{}, err
	}
	session, err := client.openOrCreateSession(plan, material.RequestBytes, now)
	if err != nil {
		return State{}, err
	}
	return stateFromSession(session)
}

// Status resumes the currently selected exact setup. If confirmation was
// durably recorded before a crash, it completes the exact pending import.
func (client *Client) Status(now time.Time) (State, error) {
	if ready, found, err := client.readyState(); err != nil {
		return State{}, err
	} else if found {
		return stateFromReady(ready)
	}
	current, err := client.openCurrent(now, true)
	if err != nil {
		current, err = client.openPostApplyCurrent(now)
		if err != nil {
			if ready, found, readyErr := client.readyState(); readyErr != nil {
				return State{}, readyErr
			} else if found {
				return stateFromReady(ready)
			}
			return State{}, err
		}
	}
	defer current.Close()
	if ready, err := readReady(current.root); err == nil {
		if err := client.validateReadyTarget(ready); err != nil {
			return State{}, err
		}
		return stateFromReady(ready)
	} else if !errors.Is(err, unix.ENOENT) && !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	if current.session.Phase() == enrollmentexchange.PhaseReady {
		return State{}, errors.New("enrollmentsetup: READY session lacks its authoritative receipt")
	}
	if current.session.Phase() == enrollmentexchange.PhaseTranscriptConfirmed || current.session.Phase() == enrollmentexchange.PhaseResponseVerified {
		if err := client.commitPending(current.workspace, current.plan, current.session, now); err != nil {
			return State{}, err
		}
	}
	return stateFromSession(current.session)
}

// CompleteReady runs one fixed carrier-only proof supplied by the installed
// lifecycle boundary. It records the proof before advancing the exchange
// session, so a crash can never erase a successful proof. The generation in
// the receipt admits exactly the pre-CAS Applied state or its one-step READY
// successor during cleanup.
func (client *Client) CompleteReady(ctx context.Context, probe func(context.Context) error, now time.Time) (State, error) {
	if client == nil || ctx == nil || probe == nil {
		return State{}, errors.New("enrollmentsetup: installed READY proof is required")
	}
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return State{}, errors.New("enrollmentsetup: current READY time is required")
	}
	if ready, found, err := client.readyState(); err != nil {
		return State{}, err
	} else if found {
		return stateFromReady(ready)
	}
	current, err := client.openCurrent(now, true)
	if err != nil {
		current, err = client.openPostApplyCurrent(now)
		if err != nil {
			if ready, found, readyErr := client.readyState(); readyErr != nil {
				return State{}, readyErr
			} else if found {
				return stateFromReady(ready)
			}
			return State{}, err
		}
	}
	defer current.Close()
	if ready, err := readReady(current.root); err == nil {
		if err := client.validateReadyTarget(ready); err != nil {
			return State{}, err
		}
		return stateFromReady(ready)
	} else if !errors.Is(err, unix.ENOENT) {
		return State{}, err
	}
	if current.session.Phase() != enrollmentexchange.PhaseApplied {
		return State{}, errors.New("enrollmentsetup: applied setup is required before READY")
	}
	var receipt readyRecord
	err = current.session.ReconcileAppliedResponse(func(response []byte) error {
		return enrollmenttarget.WithReconciledAppliedResponse(client.paths.privateRoot, response, current.session.RequestSHA256(), func(result enrollmenttarget.ApplyResult) error {
			if result.Role != enrollment.RoleClient || result.InstallationID != current.plan.InstallationID ||
				result.RequestSHA256 != current.session.RequestSHA256() || result.RecordID == "" || !result.OneTimeSecretRemoved {
				return errors.New("enrollmentsetup: READY proof does not bind the exact applied client response")
			}
			expected := current.session.Generation()
			if err := current.session.CompleteReadyProbe(ctx, probe); err != nil {
				return err
			}
			tombstone, err := current.session.MailboxTombstone()
			if err != nil {
				return err
			}
			receipt = readyRecord{
				Schema: readySchema, InvitationSHA256: current.plan.InvitationSHA256,
				Workspace: workspaceName(current.plan.InvitationSHA256), InstallationID: current.plan.InstallationID,
				RequestSHA256: current.session.RequestSHA256(), ActiveRecordID: result.RecordID,
				Runtime:                current.plan.Runtime,
				ReadySessionGeneration: current.session.Generation(), ValidationUnix: current.plan.VerifiedUnix, ReadyUnix: now.Unix(),
				MailboxEndpoint: tombstone.Endpoint, MailboxID: tombstone.MailboxID,
				ResponseReadCapability: tombstone.ResponseReadCapability,
			}
			encoded, err := encodeReady(receipt)
			if err != nil {
				return err
			}
			if err := current.root.EnsureFile(readyFile, encoded, 0o600); err != nil {
				return err
			}
			validationTime := time.Unix(current.plan.VerifiedUnix, 0).UTC()
			return enrollmentexchange.ReplaceTargetStore(client.exchangePath(current.plan), expected, current.session, validationTime)
		})
	})
	if err != nil {
		return State{}, err
	}
	return stateFromReady(receipt)
}

// CleanupReady removes only the exact setup workspace named by the durable
// receipt. Relay deletion is deliberately not an input: a compromised relay
// cannot prevent local capability and response retirement.
func (client *Client) CleanupReady(now time.Time) (State, error) {
	if client == nil {
		return State{}, errors.New("enrollmentsetup: client coordinator is unavailable")
	}
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return State{}, errors.New("enrollmentsetup: current cleanup time is required")
	}
	root, err := client.openSetupRoot(false)
	if err != nil {
		return State{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(setupLockFile)
	if err != nil {
		return State{}, err
	}
	defer lock.Close()
	receipt, err := readReady(root)
	if err != nil {
		return State{}, err
	}
	if err := client.validateReadyTarget(receipt); err != nil {
		return State{}, err
	}
	if receipt.CleanupComplete {
		return stateFromReady(receipt)
	}
	exchangePath := filepath.Join(client.paths.setupRoot, receipt.Workspace, exchangeDirectory)
	if err := enrollmentexchange.RetireTargetStore(exchangePath, receipt.ReadySessionGeneration, receipt.RequestSHA256, time.Unix(receipt.ValidationUnix, 0).UTC()); err != nil {
		return State{}, err
	}
	workspace, workspaceErr := root.OpenDir(receipt.Workspace)
	if workspaceErr == nil {
		if err := removeOptionalDirectory(workspace, exchangeDirectory); err != nil {
			_ = workspace.Close()
			return State{}, err
		}
		for _, name := range []string{pendingFile, planFile, cancelledFile} {
			if err := unlinkOptional(workspace, name); err != nil {
				_ = workspace.Close()
				return State{}, err
			}
		}
		if err := workspace.Close(); err != nil {
			return State{}, err
		}
		if err := root.RemoveDir(receipt.Workspace); err != nil {
			return State{}, err
		}
	} else if !errors.Is(workspaceErr, unix.ENOENT) {
		return State{}, workspaceErr
	}
	if err := unlinkOptional(root, selectorFile); err != nil {
		return State{}, err
	}
	receipt.CleanupComplete = true
	receipt.CleanedUnix = now.Unix()
	receipt.MailboxEndpoint, receipt.MailboxID, receipt.ResponseReadCapability = "", "", ""
	encoded, err := encodeReady(receipt)
	if err != nil {
		return State{}, err
	}
	if err := root.ReplaceFile(readyFile, encoded, 0o600); err != nil {
		return State{}, err
	}
	return stateFromReady(receipt)
}

// Confirm records the reverse words before importing any tentative bootstrap
// authority. A mismatch is terminal for this invitation.
func (client *Client) Confirm(words [3]string, now time.Time) (State, error) {
	current, err := client.openCurrent(now, true)
	if err != nil {
		return State{}, err
	}
	defer current.Close()
	expected := current.session.Generation()
	outcome, err := current.session.ConfirmProvisionerWords(words)
	if err != nil {
		return State{}, err
	}
	if outcome == enrollmentexchange.OutcomeDeferred {
		return stateFromSession(current.session)
	}
	if err := enrollmentexchange.ReplaceTargetStore(client.exchangePath(current.plan), expected, current.session, now); err != nil {
		return State{}, err
	}
	if outcome == enrollmentexchange.OutcomeCancelled {
		if err := markCancelled(current.workspace, current.plan.InvitationSHA256); err != nil {
			return State{}, err
		}
		if err := unlinkOptional(current.workspace, pendingFile); err != nil {
			return State{}, err
		}
		return stateFromSession(current.session)
	}
	if err := client.commitPending(current.workspace, current.plan, current.session, now); err != nil {
		return State{}, err
	}
	return stateFromSession(current.session)
}

// AcceptAndApply durably verifies one exact bound response, applies only its
// embedded response through the ordinary target lifecycle gate, and records
// applied-not-ready. It never records READY.
func (client *Client) AcceptAndApply(boundResponse []byte, now time.Time) (State, error) {
	current, err := client.openCurrent(now, true)
	if err != nil {
		return State{}, err
	}
	defer current.Close()
	if current.session.Phase() != enrollmentexchange.PhaseTranscriptConfirmed {
		return State{}, errors.New("enrollmentsetup: confirmed setup is required before response verification")
	}
	if err := client.commitPending(current.workspace, current.plan, current.session, now); err != nil {
		return State{}, err
	}
	expected := current.session.Generation()
	if _, err := current.session.AcceptBoundResponse(boundResponse); err != nil {
		return State{}, err
	}
	if err := enrollmentexchange.ReplaceTargetStore(client.exchangePath(current.plan), expected, current.session, now); err != nil {
		return State{}, err
	}
	if err := client.applyVerified(current.plan, current.session, now); err != nil {
		return State{}, err
	}
	return stateFromSession(current.session)
}

// ResumeApply completes a crash after response verification or after the
// lifecycle commit but before the exchange phase advanced.
func (client *Client) ResumeApply(now time.Time) (State, error) {
	current, err := client.openCurrent(now, true)
	if err != nil {
		return State{}, err
	}
	defer current.Close()
	if current.session.Phase() == enrollmentexchange.PhaseApplied {
		return stateFromSession(current.session)
	}
	if current.session.Phase() != enrollmentexchange.PhaseResponseVerified {
		return State{}, errors.New("enrollmentsetup: no verified response is ready to resume")
	}
	if err := client.commitPending(current.workspace, current.plan, current.session, now); err != nil {
		return State{}, err
	}
	if err := client.applyVerified(current.plan, current.session, now); err != nil {
		return State{}, err
	}
	return stateFromSession(current.session)
}

// Cancel tombstones the selected unapplied setup and retires tentative
// secrets even when its normal invitation/session validity window expired.
func (client *Client) Cancel(now time.Time) (State, error) {
	if client == nil {
		return State{}, errors.New("enrollmentsetup: client coordinator is unavailable")
	}
	root, err := client.openSetupRoot(false)
	if err != nil {
		return State{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(setupLockFile)
	if err != nil {
		return State{}, err
	}
	defer lock.Close()
	selector, err := readSelector(root)
	if err != nil {
		return State{}, err
	}
	workspace, err := root.OpenDir(selector.Workspace)
	if err != nil {
		return State{}, err
	}
	defer workspace.Close()
	plan, _, err := readPlan(workspace, false, client.runtime, now)
	if err != nil {
		return State{}, err
	}
	if selector.InvitationSHA256 != plan.InvitationSHA256 || selector.Workspace != workspaceName(plan.InvitationSHA256) {
		return State{}, errors.New("enrollmentsetup: current selector is cross-wired")
	}
	status, statusErr := enrollmenttarget.ReadStatus(client.paths.privateRoot)
	if statusErr == nil && status.State.ActiveRecordID != "" {
		return State{}, errors.New("enrollmentsetup: an applied client setup cannot be cancelled")
	}
	if statusErr != nil && !errors.Is(statusErr, unix.ENOENT) && !errors.Is(statusErr, os.ErrNotExist) {
		return State{}, statusErr
	}
	if err := markCancelled(workspace, plan.InvitationSHA256); err != nil {
		return State{}, err
	}
	if session, loadErr := enrollmentexchange.LoadTargetStore(client.exchangePath(plan), now.UTC().Truncate(time.Second)); loadErr == nil {
		if session.Phase() != enrollmentexchange.PhaseCancelled {
			expected := session.Generation()
			if err := session.Cancel(); err == nil {
				if err := enrollmentexchange.ReplaceTargetStore(client.exchangePath(plan), expected, session, now); err != nil {
					return State{}, err
				}
			}
		}
	}
	if statusErr == nil && status.State.PendingRequest != nil {
		if _, err := enrollmenttarget.CancelPending(client.paths.privateRoot); err != nil {
			return State{}, err
		}
	}
	if err := unlinkOptional(workspace, pendingFile); err != nil {
		return State{}, err
	}
	return State{phase: enrollmentexchange.PhaseCancelled}, nil
}

func (client *Client) openCurrent(now time.Time, requireCurrentRuntime bool) (*currentSetup, error) {
	return client.openCurrentValidated(now, requireCurrentRuntime, false)
}

// openPostApplyCurrent permits only the already-committed Applied tail
// to survive expiry of its one-hour enrollment artifacts. Those artifacts are
// revalidated at the plan's authenticated original verification time, while
// the currently installed runtime binding must still match exactly. No phase
// that can confirm, verify, import, or apply enrollment authority is admitted.
func (client *Client) openPostApplyCurrent(now time.Time) (*currentSetup, error) {
	return client.openCurrentValidated(now, true, true)
}

func (client *Client) openCurrentValidated(now time.Time, requireCurrentRuntime, postApplyOnly bool) (*currentSetup, error) {
	if client == nil {
		return nil, errors.New("enrollmentsetup: client coordinator is unavailable")
	}
	now = now.UTC().Truncate(time.Second)
	root, err := client.openSetupRoot(false)
	if err != nil {
		return nil, err
	}
	current := &currentSetup{root: root}
	fail := func(value error) (*currentSetup, error) { current.Close(); return nil, value }
	lock, err := root.TryLock(setupLockFile)
	if err != nil {
		return fail(err)
	}
	current.lock = lock
	selector, err := readSelector(root)
	if err != nil {
		return fail(err)
	}
	workspace, err := root.OpenDir(selector.Workspace)
	if err != nil {
		return fail(err)
	}
	current.workspace = workspace
	plan, _, err := readPlan(workspace, requireCurrentRuntime && !postApplyOnly, client.runtime, now)
	if err != nil {
		return fail(err)
	}
	validationTime := now
	if postApplyOnly {
		validationTime = time.Unix(plan.VerifiedUnix, 0).UTC()
		if now.Before(validationTime) || plan.Runtime != client.runtime {
			return fail(errors.New("enrollmentsetup: applied setup does not match the current runtime and clock"))
		}
	}
	if selector.InvitationSHA256 != plan.InvitationSHA256 || selector.Workspace != workspaceName(plan.InvitationSHA256) {
		return fail(errors.New("enrollmentsetup: current selector is cross-wired"))
	}
	if cancelled, err := workspaceCancelled(workspace, plan.InvitationSHA256); err != nil {
		return fail(err)
	} else if cancelled {
		return fail(ErrResetRequired)
	}
	session, err := enrollmentexchange.LoadTargetStore(client.exchangePath(plan), validationTime)
	if err != nil {
		return fail(err)
	}
	if session.InvitationSHA256() != plan.InvitationSHA256 {
		return fail(errors.New("enrollmentsetup: exchange session is cross-wired"))
	}
	if postApplyOnly && session.Phase() != enrollmentexchange.PhaseApplied {
		return fail(errors.New("enrollmentsetup: expired setup is not already applied"))
	}
	current.plan, current.session = plan, session
	return current, nil
}

func (client *Client) selectInvitation(root *securefs.Root, invitation []byte, bootstrap enrollmentexchange.ClientBootstrap, now time.Time) (*securefs.Root, planRecord, error) {
	plan := planRecord{
		Schema: planSchema, Invitation: base64.StdEncoding.EncodeToString(invitation), InvitationSHA256: bootstrap.InvitationSHA256,
		VerifiedUnix: now.Unix(), ExpiresUnix: bootstrap.ExpiresUnix,
		InstallationID: deterministicInstallationID(invitation), Runtime: bootstrap.Runtime,
	}
	encodedPlan, err := encodePlan(plan)
	if err != nil {
		return nil, planRecord{}, err
	}
	name := workspaceName(plan.InvitationSHA256)
	selector, selectorErr := readSelector(root)
	if selectorErr == nil && selector.InvitationSHA256 == plan.InvitationSHA256 {
		workspace, err := root.OpenDir(selector.Workspace)
		if err != nil {
			return nil, planRecord{}, err
		}
		existing, _, err := readPlan(workspace, false, client.runtime, now)
		if err != nil || existing.InvitationSHA256 != plan.InvitationSHA256 || existing.Invitation != plan.Invitation || existing.Runtime != plan.Runtime {
			_ = workspace.Close()
			return nil, planRecord{}, ErrResetRequired
		}
		return workspace, existing, nil
	}
	if selectorErr != nil && !errors.Is(selectorErr, unix.ENOENT) {
		return nil, planRecord{}, selectorErr
	}
	if selectorErr == nil {
		current, err := root.OpenDir(selector.Workspace)
		if err != nil {
			return nil, planRecord{}, err
		}
		currentPlan, _, err := readPlan(current, false, client.runtime, now)
		if err != nil {
			_ = current.Close()
			return nil, planRecord{}, err
		}
		cancelled, err := workspaceCancelled(current, currentPlan.InvitationSHA256)
		_ = current.Close()
		if err != nil {
			return nil, planRecord{}, err
		}
		if !cancelled {
			return nil, planRecord{}, ErrResetRequired
		}
		if _, statusErr := enrollmenttarget.ReadStatus(client.paths.privateRoot); statusErr == nil {
			return nil, planRecord{}, ErrResetRequired
		} else if !errors.Is(statusErr, unix.ENOENT) && !errors.Is(statusErr, os.ErrNotExist) {
			return nil, planRecord{}, statusErr
		}
	}
	workspace, err := root.OpenDir(name)
	if err == nil {
		existing, _, planErr := readPlan(workspace, false, client.runtime, now)
		if planErr != nil || existing.InvitationSHA256 != plan.InvitationSHA256 || existing.Invitation != plan.Invitation {
			_ = workspace.Close()
			return nil, planRecord{}, ErrResetRequired
		}
		cancelled, cancelErr := workspaceCancelled(workspace, plan.InvitationSHA256)
		if cancelErr != nil {
			_ = workspace.Close()
			return nil, planRecord{}, cancelErr
		}
		if cancelled {
			_ = workspace.Close()
			return nil, planRecord{}, ErrResetRequired
		}
		plan = existing
		name = workspaceName(plan.InvitationSHA256)
	} else {
		if !errors.Is(err, unix.ENOENT) {
			return nil, planRecord{}, err
		}
		if err := root.MkdirExclusive(name, 0o700); err != nil {
			return nil, planRecord{}, err
		}
		workspace, err = root.OpenDir(name)
		if err != nil {
			return nil, planRecord{}, err
		}
		if err := workspace.EnsureFile(planFile, encodedPlan, 0o600); err != nil {
			_ = workspace.Close()
			return nil, planRecord{}, err
		}
	}
	encodedSelector, err := encodeCanonical(selectorRecord{Schema: selectorSchema, InvitationSHA256: plan.InvitationSHA256, Workspace: name}, 4096)
	if err != nil {
		_ = workspace.Close()
		return nil, planRecord{}, err
	}
	if selectorErr == nil {
		err = root.ReplaceFile(selectorFile, encodedSelector, 0o600)
	} else {
		err = root.EnsureFile(selectorFile, encodedSelector, 0o600)
	}
	if err != nil {
		_ = workspace.Close()
		return nil, planRecord{}, err
	}
	return workspace, plan, nil
}

func (client *Client) commitPending(workspace *securefs.Root, plan planRecord, session *enrollmentexchange.TargetSession, now time.Time) error {
	if session.Phase() != enrollmentexchange.PhaseTranscriptConfirmed && session.Phase() != enrollmentexchange.PhaseResponseVerified {
		return errors.New("enrollmentsetup: transcript confirmation is required before lifecycle import")
	}
	material, err := readPendingMaterial(workspace, now)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		pending, pendingErr := enrollmenttarget.PendingRequest(client.paths.privateRoot)
		if pendingErr == nil && pending.RequestSHA256 == session.RequestSHA256() {
			return nil
		}
		status, statusErr := enrollmenttarget.ReadStatus(client.paths.privateRoot)
		if !mayReconcileCommittedApply(session.Phase(), status, statusErr) {
			return errors.New("enrollmentsetup: confirmed pending material is unavailable")
		}
		return nil
	}
	bootstrap, err := enrollmentexchange.PrepareClientBootstrap(decodeInvitation(plan), client.runtime, now)
	if err != nil {
		return err
	}
	result, err := enrollmenttarget.ImportPendingClient(client.bootstrapOptions(plan, bootstrap, now), material)
	if err != nil {
		return err
	}
	if result.RequestSHA256 != session.RequestSHA256() || !bytes.Equal(result.RequestBytes, material.RequestBytes) {
		return errors.New("enrollmentsetup: imported request differs from the confirmed transcript")
	}
	if err := workspace.UnlinkFile(pendingFile); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func mayReconcileCommittedApply(phase enrollmentexchange.SessionPhase, status enrollmenttarget.Status, err error) bool {
	return phase == enrollmentexchange.PhaseResponseVerified && err == nil && status.State.ActiveRecordID != ""
}

func (client *Client) applyVerified(plan planRecord, session *enrollmentexchange.TargetSession, now time.Time) error {
	if session.Phase() != enrollmentexchange.PhaseResponseVerified {
		return errors.New("enrollmentsetup: verified response is required before apply")
	}
	response, err := session.VerifiedEnrollmentResponse()
	if err != nil {
		return err
	}
	result, applyErr := enrollmenttarget.ApplyResponse(client.paths.privateRoot, response, now)
	if applyErr != nil || !result.OneTimeSecretRemoved {
		result, err = enrollmenttarget.ReconcileAppliedResponse(client.paths.privateRoot, response, session.RequestSHA256())
		if err != nil {
			if applyErr != nil {
				return errors.New("enrollmentsetup: response apply and exact reconciliation both failed")
			}
			return err
		}
	}
	if result.RequestSHA256 != session.RequestSHA256() {
		return errors.New("enrollmentsetup: applied lifecycle record is cross-wired")
	}
	expected := session.Generation()
	if err := session.RecordApplied(); err != nil {
		return err
	}
	return enrollmentexchange.ReplaceTargetStore(client.exchangePath(plan), expected, session, now)
}

func (client *Client) bootstrapOptions(plan planRecord, bootstrap enrollmentexchange.ClientBootstrap, now time.Time) enrollmenttarget.BootstrapOptions {
	views := enrollmenttarget.RuntimeViewBinding{}
	if client.readerGID != 0 {
		views = enrollmenttarget.RuntimeViewBinding{
			RuntimeRoot: client.paths.runtimeRoot, RuntimeConfigRoot: client.paths.runtimeConfig,
			AnchorViewRoot: client.paths.anchorViewRoot, ReaderGID: client.readerGID,
		}
	}
	return enrollmenttarget.BootstrapOptions{
		RootPath: client.paths.privateRoot, Role: enrollment.RoleClient, InstallationID: plan.InstallationID,
		Runtime: bootstrap.Runtime, Trust: bootstrap.Trust, DeploymentSignerPublicPEM: bootstrap.DeploymentSignerPublicPEM,
		RollbackAnchorRoot: client.paths.authorityRoot, RuntimeViews: views, Now: now,
	}
}

func (client *Client) openOrCreateSession(plan planRecord, request []byte, now time.Time) (*enrollmentexchange.TargetSession, error) {
	path := client.exchangePath(plan)
	session, err := enrollmentexchange.LoadTargetStore(path, now)
	if err == nil {
		requestDigest := sha256.Sum256(request)
		if session.InvitationSHA256() != plan.InvitationSHA256 || session.RequestSHA256() != hex.EncodeToString(requestDigest[:]) {
			return nil, errors.New("enrollmentsetup: existing exchange session is cross-wired")
		}
		return session, nil
	}
	if !errors.Is(err, unix.ENOENT) && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	session, err = enrollmentexchange.NewTargetSession(decodeInvitation(plan), request, now)
	if err != nil {
		return nil, err
	}
	if err := enrollmentexchange.CreateTargetStore(path, session); err != nil {
		if existing, loadErr := enrollmentexchange.LoadTargetStore(path, now); loadErr == nil && existing.InvitationSHA256() == session.InvitationSHA256() && existing.RequestSHA256() == session.RequestSHA256() {
			return existing, nil
		}
		return nil, err
	}
	return session, nil
}

func (client *Client) exchangePath(plan planRecord) string {
	return filepath.Join(client.paths.setupRoot, workspaceName(plan.InvitationSHA256), exchangeDirectory)
}

func (client *Client) openSetupRoot(create bool) (*securefs.Root, error) {
	root, err := securefs.OpenRoot(client.paths.setupRoot)
	if err == nil || !create {
		return root, err
	}
	if !errors.Is(err, unix.ENOENT) && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	root, err = securefs.CreateRoot(client.paths.setupRoot)
	if err != nil {
		if existing, openErr := securefs.OpenRoot(client.paths.setupRoot); openErr == nil {
			return existing, nil
		}
	}
	return root, err
}

func ensurePendingMaterial(workspace *securefs.Root, plan planRecord, bootstrap enrollmentexchange.ClientBootstrap, now time.Time) (enrollment.PendingMaterial, error) {
	material, err := readPendingMaterial(workspace, now)
	if err == nil {
		if err := validateMaterialPlan(material, plan); err != nil {
			return enrollment.PendingMaterial{}, err
		}
		return material, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return enrollment.PendingMaterial{}, err
	}
	signer, err := signing.ParsePublic(bootstrap.DeploymentSignerPublicPEM)
	if err != nil || len(signer) != ed25519.PublicKeySize {
		return enrollment.PendingMaterial{}, errors.New("enrollmentsetup: invitation deployment verifier is invalid")
	}
	validity := requestValidity
	if remaining := time.Unix(plan.ExpiresUnix, 0).Sub(now); remaining < validity {
		validity = remaining
	}
	if validity <= 0 {
		return enrollment.PendingMaterial{}, errors.New("enrollmentsetup: invitation expired before request creation")
	}
	material, err = enrollment.NewPendingRequest(enrollment.InitOptions{
		Role: enrollment.RoleClient, InstallationID: plan.InstallationID,
		RouteID: bootstrap.RouteID, ConnectorInstallationID: bootstrap.ConnectorInstallationID,
		Sequence: 1, Now: now, RequestValidity: validity,
		Trust: bootstrap.Trust, DeploymentSigner: signer, Runtime: bootstrap.Runtime,
	})
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	encoded, err := encodePending(material)
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	if err := workspace.EnsureFile(pendingFile, encoded, 0o600); err != nil {
		return enrollment.PendingMaterial{}, err
	}
	return material, nil
}

// bindPlanValidationToRequest makes the signed request creation time the one
// durable historical validation point for every post-apply crash recovery.
// A crash after selecting an invitation but before creating its request may
// otherwise leave those two valid timestamps more than the parser skew apart.
// The validation point may advance exactly once to the request's signed time;
// it is never inferred from an unsigned resume clock and never moves backward.
func (client *Client) bindPlanValidationToRequest(workspace *securefs.Root, plan planRecord, retained enrollmentexchange.ClientBootstrap, material enrollment.PendingMaterial) (planRecord, enrollmentexchange.ClientBootstrap, error) {
	if client == nil || workspace == nil {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, errors.New("enrollmentsetup: setup plan binding is unavailable")
	}
	if err := validateMaterialPlan(material, plan); err != nil {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, err
	}
	createdUnix := material.Payload.CreatedUnix
	if createdUnix < plan.VerifiedUnix || createdUnix >= plan.ExpiresUnix {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, errors.New("enrollmentsetup: signed request time cannot bind the selected invitation")
	}
	requestTime := time.Unix(createdUnix, 0).UTC()
	revalidated, err := enrollmentexchange.PrepareClientBootstrap(decodeInvitation(plan), client.runtime, requestTime)
	if err != nil || !sameClientBootstrap(revalidated, retained) || revalidated.InvitationSHA256 != plan.InvitationSHA256 ||
		revalidated.ExpiresUnix != plan.ExpiresUnix || revalidated.Runtime != plan.Runtime {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, errors.New("enrollmentsetup: signed request time does not revalidate the exact selected invitation")
	}
	if createdUnix == plan.VerifiedUnix {
		return plan, revalidated, nil
	}
	plan.VerifiedUnix = createdUnix
	encoded, err := encodePlan(plan)
	if err != nil {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, err
	}
	if err := workspace.ReplaceFile(planFile, encoded, 0o600); err != nil {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, err
	}
	return plan, revalidated, nil
}

func sameClientBootstrap(left, right enrollmentexchange.ClientBootstrap) bool {
	return left.InvitationSHA256 == right.InvitationSHA256 && left.ExpiresUnix == right.ExpiresUnix &&
		left.Runtime == right.Runtime && left.Trust == right.Trust &&
		bytes.Equal(left.DeploymentSignerPublicPEM, right.DeploymentSignerPublicPEM) &&
		left.RouteID == right.RouteID && left.ConnectorInstallationID == right.ConnectorInstallationID
}

func readPendingMaterial(workspace *securefs.Root, now time.Time) (enrollment.PendingMaterial, error) {
	encoded, err := workspace.ReadFile(pendingFile, maxPendingSize)
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	var record pendingRecord
	if err := strictjson.Decode(encoded, &record); err != nil {
		return enrollment.PendingMaterial{}, err
	}
	canonical, err := encodeCanonical(record, maxPendingSize)
	if err != nil || !bytes.Equal(encoded, canonical) || record.Schema != pendingSchema {
		return enrollment.PendingMaterial{}, errors.New("enrollmentsetup: pending material is noncanonical")
	}
	request, err := decodeBoundedBase64(record.Request, enrollment.MaxRequestSize)
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	outer, err := decodeBoundedBase64(record.OuterPrivateKey, 16<<10)
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	inner, err := decodeBoundedBase64(record.InnerPrivateKey, 16<<10)
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	identity, err := decodeBoundedBase64(record.ResponseIdentity, 4<<10)
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	payload, err := enrollment.ParseRequest(request, now)
	if err != nil {
		return enrollment.PendingMaterial{}, err
	}
	material := enrollment.PendingMaterial{
		RequestBytes: request, Payload: payload, OuterPrivateKey: outer, InnerPrivateKey: inner, ResponseIdentity: string(identity),
	}
	if err := enrollment.ValidatePendingMaterial(material, now); err != nil {
		return enrollment.PendingMaterial{}, err
	}
	return material, nil
}

func encodePending(material enrollment.PendingMaterial) ([]byte, error) {
	record := pendingRecord{
		Schema: pendingSchema, Request: base64.StdEncoding.EncodeToString(material.RequestBytes),
		OuterPrivateKey:  base64.StdEncoding.EncodeToString(material.OuterPrivateKey),
		InnerPrivateKey:  base64.StdEncoding.EncodeToString(material.InnerPrivateKey),
		ResponseIdentity: base64.StdEncoding.EncodeToString([]byte(material.ResponseIdentity)),
	}
	return encodeCanonical(record, maxPendingSize)
}

func validateMaterialPlan(material enrollment.PendingMaterial, plan planRecord) error {
	if material.Payload.Role != enrollment.RoleClient || material.Payload.InstallationID != plan.InstallationID ||
		material.Payload.Runtime != plan.Runtime || material.Payload.Sequence != 1 {
		return errors.New("enrollmentsetup: pending material differs from its exact setup plan")
	}
	return nil
}

func readPlan(workspace *securefs.Root, requireCurrentRuntime bool, expected enrollment.RuntimeBinding, now time.Time) (planRecord, enrollmentexchange.ClientBootstrap, error) {
	encoded, err := workspace.ReadFile(planFile, maxPlanSize)
	if err != nil {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, err
	}
	var plan planRecord
	if err := strictjson.Decode(encoded, &plan); err != nil {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, err
	}
	canonical, err := encodePlan(plan)
	if err != nil || !bytes.Equal(encoded, canonical) || plan.Schema != planSchema || plan.VerifiedUnix <= 0 || plan.ExpiresUnix <= plan.VerifiedUnix ||
		plan.InstallationID != deterministicInstallationID(decodeInvitation(plan)) || plan.InvitationSHA256 != digestBytes(decodeInvitation(plan)) {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, errors.New("enrollmentsetup: setup plan is noncanonical or cross-wired")
	}
	bootstrap, err := enrollmentexchange.PrepareClientBootstrap(decodeInvitation(plan), plan.Runtime, time.Unix(plan.VerifiedUnix, 0).UTC())
	if err != nil || bootstrap.InvitationSHA256 != plan.InvitationSHA256 || bootstrap.ExpiresUnix != plan.ExpiresUnix || bootstrap.Runtime != plan.Runtime {
		return planRecord{}, enrollmentexchange.ClientBootstrap{}, errors.New("enrollmentsetup: retained invitation no longer verifies")
	}
	if requireCurrentRuntime {
		if plan.Runtime != expected {
			return planRecord{}, enrollmentexchange.ClientBootstrap{}, errors.New("enrollmentsetup: installed runtime changed during enrollment")
		}
		bootstrap, err = enrollmentexchange.PrepareClientBootstrap(decodeInvitation(plan), expected, now)
		if err != nil {
			return planRecord{}, enrollmentexchange.ClientBootstrap{}, err
		}
	}
	return plan, bootstrap, nil
}

func encodePlan(plan planRecord) ([]byte, error) {
	if plan.Schema != planSchema || plan.InvitationSHA256 == "" || plan.InstallationID == "" || plan.VerifiedUnix <= 0 || plan.ExpiresUnix <= plan.VerifiedUnix {
		return nil, errors.New("enrollmentsetup: setup plan is incomplete")
	}
	return encodeCanonical(plan, maxPlanSize)
}

func readSelector(root *securefs.Root) (selectorRecord, error) {
	encoded, err := root.ReadFile(selectorFile, 4096)
	if err != nil {
		return selectorRecord{}, err
	}
	var selector selectorRecord
	if err := strictjson.Decode(encoded, &selector); err != nil {
		return selectorRecord{}, err
	}
	canonical, err := encodeCanonical(selector, 4096)
	if err != nil || !bytes.Equal(encoded, canonical) || selector.Schema != selectorSchema || selector.Workspace != workspaceName(selector.InvitationSHA256) {
		return selectorRecord{}, errors.New("enrollmentsetup: current selector is invalid")
	}
	return selector, nil
}

func (client *Client) readyState() (readyRecord, bool, error) {
	if client == nil {
		return readyRecord{}, false, errors.New("enrollmentsetup: client coordinator is unavailable")
	}
	root, err := client.openSetupRoot(false)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return readyRecord{}, false, nil
	}
	if err != nil {
		return readyRecord{}, false, err
	}
	defer root.Close()
	lock, err := root.TryLock(setupLockFile)
	if err != nil {
		return readyRecord{}, false, err
	}
	defer lock.Close()
	receipt, err := readReady(root)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return readyRecord{}, false, nil
	}
	if err != nil {
		return readyRecord{}, false, err
	}
	if err := client.validateReadyTarget(receipt); err != nil {
		return readyRecord{}, false, err
	}
	return receipt, true, nil
}

func (client *Client) validateReadyTarget(receipt readyRecord) error {
	if receipt.Runtime != client.runtime {
		return errors.New("enrollmentsetup: READY receipt belongs to another installed client runtime")
	}
	status, err := enrollmenttarget.ReadStatus(client.paths.privateRoot)
	if err != nil {
		return err
	}
	if status.State.Role != "client" || status.State.InstallationID != receipt.InstallationID ||
		status.State.ActiveRecordID != receipt.ActiveRecordID ||
		!containsExact(status.State.ConsumedRequestSHA256, receipt.RequestSHA256) {
		return errors.New("enrollmentsetup: READY receipt differs from the installed client state")
	}
	return nil
}

func readReady(root *securefs.Root) (readyRecord, error) {
	encoded, err := root.ReadFile(readyFile, maxReadySize)
	if err != nil {
		return readyRecord{}, err
	}
	var receipt readyRecord
	if err := strictjson.Decode(encoded, &receipt); err != nil {
		return readyRecord{}, err
	}
	canonical, err := encodeReady(receipt)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return readyRecord{}, errors.New("enrollmentsetup: READY receipt is noncanonical")
	}
	return receipt, nil
}

func encodeReady(receipt readyRecord) ([]byte, error) {
	if receipt.Schema != readySchema || !validDigest(receipt.InvitationSHA256) || !validDigest(receipt.RequestSHA256) ||
		receipt.Workspace != workspaceName(receipt.InvitationSHA256) || receipt.ReadySessionGeneration < 2 ||
		receipt.ValidationUnix <= 0 || receipt.ReadyUnix < receipt.ValidationUnix || receipt.Runtime.Validate(enrollment.RoleClient) != nil {
		return nil, errors.New("enrollmentsetup: READY receipt is incomplete")
	}
	installationID, installErr := protocol.ParseID(receipt.InstallationID)
	activeID, activeErr := protocol.ParseID(receipt.ActiveRecordID)
	if installErr != nil || activeErr != nil || installationID == (protocol.ID{}) || activeID == (protocol.ID{}) {
		return nil, errors.New("enrollmentsetup: READY receipt identities are invalid")
	}
	if receipt.CleanupComplete {
		if receipt.CleanedUnix < receipt.ReadyUnix || receipt.MailboxEndpoint != "" || receipt.MailboxID != "" || receipt.ResponseReadCapability != "" {
			return nil, errors.New("enrollmentsetup: cleaned READY receipt retains mailbox authority")
		}
	} else {
		if receipt.CleanedUnix != 0 {
			return nil, errors.New("enrollmentsetup: incomplete READY cleanup has a completion time")
		}
		tombstone := enrollmentexchange.TargetMailboxTombstone{
			Endpoint: receipt.MailboxEndpoint, MailboxID: receipt.MailboxID,
			ResponseReadCapability: receipt.ResponseReadCapability,
		}
		if _, err := encodeMailboxTombstone(tombstone); err != nil {
			return nil, err
		}
	}
	return encodeCanonical(receipt, maxReadySize)
}

func stateFromReady(receipt readyRecord) (State, error) {
	if _, err := encodeReady(receipt); err != nil {
		return State{}, err
	}
	state := State{phase: enrollmentexchange.PhaseReady}
	if !receipt.CleanupComplete {
		tombstone := enrollmentexchange.TargetMailboxTombstone{
			Endpoint: receipt.MailboxEndpoint, MailboxID: receipt.MailboxID,
			ResponseReadCapability: receipt.ResponseReadCapability,
		}
		state.tombstone = &tombstone
	}
	return state, nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func containsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func markCancelled(workspace *securefs.Root, digest string) error {
	encoded, err := encodeCanonical(cancelledRecord{Schema: cancelledSchema, InvitationSHA256: digest}, 4096)
	if err != nil {
		return err
	}
	return workspace.EnsureFile(cancelledFile, encoded, 0o600)
}

func workspaceCancelled(workspace *securefs.Root, digest string) (bool, error) {
	encoded, err := workspace.ReadFile(cancelledFile, 4096)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var record cancelledRecord
	if err := strictjson.Decode(encoded, &record); err != nil {
		return false, err
	}
	canonical, err := encodeCanonical(record, 4096)
	if err != nil || !bytes.Equal(encoded, canonical) || record.Schema != cancelledSchema || record.InvitationSHA256 != digest {
		return false, errors.New("enrollmentsetup: cancellation tombstone is invalid")
	}
	return true, nil
}

func stateFromSession(session *enrollmentexchange.TargetSession) (State, error) {
	if session == nil {
		return State{}, errors.New("enrollmentsetup: exchange session is absent")
	}
	state := State{phase: session.Phase()}
	switch session.Phase() {
	case enrollmentexchange.PhasePendingComparison:
		words, err := session.TargetWords()
		if err != nil {
			return State{}, err
		}
		action, err := session.MailboxAction()
		if err != nil {
			return State{}, err
		}
		state.words, state.action = words, &action
	case enrollmentexchange.PhaseTranscriptConfirmed:
		action, err := session.MailboxAction()
		if err != nil {
			return State{}, err
		}
		state.action = &action
	case enrollmentexchange.PhaseReady:
		tombstone, err := session.MailboxTombstone()
		if err != nil {
			return State{}, err
		}
		state.tombstone = &tombstone
	case enrollmentexchange.PhaseResponseVerified, enrollmentexchange.PhaseApplied, enrollmentexchange.PhaseCancelled:
	default:
		return State{}, errors.New("enrollmentsetup: unsupported target session phase")
	}
	return state, nil
}

func encodeCanonical(value any, limit int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) == 0 || len(encoded) > limit {
		return nil, errors.New("enrollmentsetup: canonical state exceeds its bound")
	}
	return encoded, nil
}

func decodeBoundedBase64(value string, limit int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > limit || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("enrollmentsetup: protected material is not bounded canonical base64")
	}
	return decoded, nil
}

func decodeInvitation(plan planRecord) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(plan.Invitation)
	return decoded
}

func deterministicInstallationID(invitation []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("OwnTransit client setup installation v1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(invitation)
	sum := hash.Sum(nil)
	var id protocol.ID
	copy(id[:], sum)
	if id == (protocol.ID{}) {
		id[len(id)-1] = 1
	}
	return id.String()
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func workspaceName(digest string) string {
	if len(digest) != sha256.Size*2 {
		return "invalid"
	}
	return "session-" + digest
}

func unlinkOptional(root *securefs.Root, name string) error {
	err := root.UnlinkFile(name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func removeOptionalDirectory(root *securefs.Root, name string) error {
	err := root.RemoveDir(name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// ResetSupportCode returns the stable non-secret recovery code safe for CLI
// diagnostics. It conveys no invitation, word, or mailbox material.
func ResetSupportCode() string { return resetSupportCode }
