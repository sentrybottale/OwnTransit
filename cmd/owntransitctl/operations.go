package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmenttarget"
	"github.com/sentrybottale/owntransit/internal/localstate"
)

const compiledConnectorTarget = "tcp4/" + config.ConnectorSSHTarget

type bootstrapOptions struct {
	stateRoot         string
	role              string
	releaseID         string
	releaseSequence   uint64
	artifactSHA256    string
	goos              string
	goarch            string
	outerCA           string
	innerConnectorCA  string
	innerClientCA     string
	deploymentSigner  string
	rollbackAnchor    string
	runtimeRoot       string
	runtimeConfigRoot string
	anchorViewRoot    string
	readerGID         uint64
	connectorTarget   string
	now               time.Time
}

type enrollInitOptions struct {
	stateRoot   string
	routeID     string
	connectorID string
	validity    time.Duration
	outputPath  string
	now         time.Time
}

type exportPendingOptions struct {
	stateRoot  string
	outputPath string
}

type applyOptions struct {
	stateRoot    string
	responsePath string
	now          time.Time
}

type stateOptions struct {
	stateRoot string
}

type signedInputOptions struct {
	stateRoot string
	inputPath string
	now       time.Time
}

type bootstrapSummary struct {
	Schema          string          `json:"schema"`
	Role            enrollment.Role `json:"role"`
	InstallationID  string          `json:"installation_id"`
	StateGeneration uint64          `json:"state_generation"`
	ReleaseSequence uint64          `json:"release_sequence"`
}

type requestSummary struct {
	Schema        string `json:"schema"`
	Action        string `json:"action"`
	RequestSHA256 string `json:"request_sha256"`
	Sequence      uint64 `json:"sequence"`
}

type cancelSummary struct {
	Schema                   string `json:"schema"`
	Canceled                 bool   `json:"canceled"`
	StateGeneration          uint64 `json:"state_generation"`
	RequestSequenceHighWater uint64 `json:"request_sequence_high_water"`
}

type applySummary struct {
	Schema               string          `json:"schema"`
	Role                 enrollment.Role `json:"role"`
	InstallationID       string          `json:"installation_id"`
	RecordID             string          `json:"record_id"`
	DeploymentSequence   uint64          `json:"deployment_sequence"`
	CredentialEpoch      uint64          `json:"credential_epoch"`
	RequestSHA256        string          `json:"request_sha256"`
	StateGeneration      uint64          `json:"state_generation"`
	OneTimeSecretRemoved bool            `json:"one_time_secret_removed"`
}

type statusSummary struct {
	Schema                    string                             `json:"schema"`
	Role                      localstate.Role                    `json:"role"`
	InstallationID            string                             `json:"installation_id"`
	StateGeneration           uint64                             `json:"state_generation"`
	StateSHA256               string                             `json:"state_sha256"`
	RequestSequenceHighWater  uint64                             `json:"request_sequence_high_water"`
	HighestDeploymentSequence uint64                             `json:"highest_deployment_sequence"`
	HighestReleaseSequence    uint64                             `json:"highest_release_sequence"`
	HighestCredentialSequence uint64                             `json:"highest_credential_sequence"`
	PolicySequence            uint64                             `json:"policy_sequence"`
	TombstoneSequence         uint64                             `json:"tombstone_sequence"`
	RecoverySequence          uint64                             `json:"recovery_sequence"`
	Active                    bool                               `json:"active"`
	ActiveRecordID            string                             `json:"active_record_id,omitempty"`
	ActiveRecordSHA256        string                             `json:"active_record_sha256,omitempty"`
	ActiveDeploymentSequence  uint64                             `json:"active_deployment_sequence,omitempty"`
	ActiveCredentialSequence  uint64                             `json:"active_credential_sequence,omitempty"`
	ActiveReleaseSequence     uint64                             `json:"active_release_sequence"`
	RollbackFloors            localstate.RollbackFloors          `json:"rollback_floors"`
	Pending                   *localstate.PendingRequestMetadata `json:"pending_request"`
}

type policySummary struct {
	Schema            string `json:"schema"`
	RecordID          string `json:"record_id"`
	PolicySequence    uint64 `json:"policy_sequence"`
	TombstoneSequence uint64 `json:"tombstone_sequence"`
	StateGeneration   uint64 `json:"state_generation"`
}

type rollbackSummary struct {
	Schema             string `json:"schema"`
	SourceRecordID     string `json:"source_record_id"`
	ActivatedRecordID  string `json:"activated_record_id"`
	DeploymentSequence uint64 `json:"deployment_sequence"`
	CredentialSequence uint64 `json:"credential_sequence"`
	ReleaseSequence    uint64 `json:"release_sequence"`
	RecoverySequence   uint64 `json:"recovery_sequence"`
	StateGeneration    uint64 `json:"state_generation"`
}

type recoverySummary struct {
	Schema          string `json:"schema"`
	Recovered       bool   `json:"recovered"`
	StateGeneration uint64 `json:"state_generation"`
	StateSHA256     string `json:"state_sha256"`
}

type verifySummary struct {
	Schema          string          `json:"schema"`
	Role            localstate.Role `json:"role"`
	StateGeneration uint64          `json:"state_generation"`
	StateSHA256     string          `json:"state_sha256"`
	RecordID        string          `json:"record_id"`
}

func bootstrapTarget(options bootstrapOptions) ([]byte, error) {
	now := options.now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return nil, errors.New("current time is required")
	}
	viewConfigured := options.runtimeRoot != "" || options.runtimeConfigRoot != "" || options.anchorViewRoot != "" || options.readerGID != 0
	if viewConfigured && (options.runtimeRoot == "" || options.runtimeConfigRoot == "" || options.anchorViewRoot == "" ||
		options.readerGID == 0 || options.readerGID >= math.MaxUint32) {
		return nil, errors.New("runtime-view binding must include three roots and a non-root reader GID")
	}
	role, err := parseTargetRole(options.role)
	if err != nil {
		return nil, err
	}
	connectorTarget := options.connectorTarget
	if role == enrollment.RoleConnector {
		if connectorTarget == "" {
			connectorTarget = compiledConnectorTarget
		}
		if connectorTarget != compiledConnectorTarget {
			return nil, fmt.Errorf("connector target must be exactly %q", compiledConnectorTarget)
		}
	} else if connectorTarget != "" {
		return nil, errors.New("connector target is accepted only for the connector role")
	}
	stateRoot, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	outerCA, err := readPublicFile(options.outerCA)
	if err != nil {
		return nil, fmt.Errorf("outer CA: %w", err)
	}
	innerConnectorCA, err := readPublicFile(options.innerConnectorCA)
	if err != nil {
		return nil, fmt.Errorf("inner connector CA: %w", err)
	}
	innerClientCA, err := readPublicFile(options.innerClientCA)
	if err != nil {
		return nil, fmt.Errorf("inner client CA: %w", err)
	}
	deploymentSigner, err := readPublicFile(options.deploymentSigner)
	if err != nil {
		return nil, fmt.Errorf("deployment signer: %w", err)
	}
	result, err := enrollmenttarget.Bootstrap(enrollmenttarget.BootstrapOptions{
		RootPath: stateRoot, Role: role, InstallationID: "",
		Runtime: enrollment.RuntimeBinding{
			ReleaseID: options.releaseID, ReleaseSequence: options.releaseSequence,
			ArtifactSHA256: options.artifactSHA256, OS: options.goos, Arch: options.goarch,
			Role: role, Protocol: enrollment.DeploymentProtocol,
			LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
			ConnectorTarget:     connectorTarget,
		},
		Trust: enrollment.Trust{
			RelayAdmissionCA: string(outerCA), InnerConnectorCA: string(innerConnectorCA),
			InnerClientCA: string(innerClientCA),
		},
		DeploymentSignerPublicPEM: deploymentSigner,
		RollbackAnchorRoot:        options.rollbackAnchor,
		RuntimeViews: enrollmenttarget.RuntimeViewBinding{
			RuntimeRoot: options.runtimeRoot, RuntimeConfigRoot: options.runtimeConfigRoot,
			AnchorViewRoot: options.anchorViewRoot, ReaderGID: uint32(options.readerGID),
		},
		Now: now,
	})
	if err != nil {
		return nil, err
	}
	return encodePublic(bootstrapSummary{
		Schema: "owntransit.ctl.bootstrap.v1", Role: role,
		InstallationID: result.InstallationID, StateGeneration: result.State.StateGeneration,
		ReleaseSequence: result.State.HighestReleaseSequence,
	})
}

func applyPolicy(options signedInputOptions) ([]byte, error) {
	root, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	encoded, err := readBoundedPublicFile(options.inputPath, enrollment.MaxLifecyclePolicySize)
	if err != nil {
		return nil, fmt.Errorf("lifecycle policy: %w", err)
	}
	result, err := enrollmenttarget.ApplyLifecyclePolicy(root, encoded, options.now)
	if err != nil {
		return nil, err
	}
	return encodePublic(policySummary{Schema: "owntransit.ctl.policy-apply.v1", RecordID: result.RecordID, PolicySequence: result.PolicySequence, TombstoneSequence: result.TombstoneSequence, StateGeneration: result.StateGeneration})
}

func rollbackRecord(options signedInputOptions) ([]byte, error) {
	root, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	encoded, err := readBoundedPublicFile(options.inputPath, enrollment.MaxRollbackAuthorization)
	if err != nil {
		return nil, fmt.Errorf("rollback authorization: %w", err)
	}
	result, err := enrollmenttarget.Rollback(root, encoded, options.now)
	if err != nil {
		return nil, err
	}
	return encodePublic(rollbackSummary{Schema: "owntransit.ctl.rollback.v1", SourceRecordID: result.SourceRecordID, ActivatedRecordID: result.ActivatedRecordID, DeploymentSequence: result.DeploymentSequence, CredentialSequence: result.CredentialSequence, ReleaseSequence: result.ReleaseSequence, RecoverySequence: result.RecoverySequence, StateGeneration: result.StateGeneration})
}

func recoverState(options stateOptions) ([]byte, error) {
	root, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	result, err := enrollmenttarget.RecoverTransaction(root)
	if err != nil {
		return nil, err
	}
	return encodePublic(recoverySummary{Schema: "owntransit.ctl.recover.v1", Recovered: result.Recovered, StateGeneration: result.StateGeneration, StateSHA256: result.StateSHA256})
}

func verifyState(options stateOptions) ([]byte, error) {
	root, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	status, err := enrollmenttarget.ReadStatus(root)
	if err != nil {
		return nil, err
	}
	role, err := enrollmentRoleForLocal(status.State.Role)
	if err != nil {
		return nil, err
	}
	handle, err := enrollmenttarget.OpenActiveGeneration(root, role)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if err := handle.FinalCheck(); err != nil {
		return nil, err
	}
	return encodePublic(verifySummary{
		Schema: "owntransit.ctl.verify.v1", Role: status.State.Role,
		StateGeneration: status.State.StateGeneration, StateSHA256: status.StateSHA256,
		RecordID: status.State.ActiveRecordID,
	})
}

func enrollmentRoleForLocal(role localstate.Role) (enrollment.Role, error) {
	switch role {
	case localstate.RoleClient:
		return enrollment.RoleClient, nil
	case localstate.RoleConnector:
		return enrollment.RoleConnector, nil
	case localstate.RoleRelay:
		return enrollment.RoleRelay, nil
	default:
		return "", errors.New("durable role is invalid")
	}
}

func initializeEnrollment(options enrollInitOptions) ([]byte, error) {
	stateRoot, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	output, err := preparePublicOutput(options.outputPath)
	if err != nil {
		return nil, err
	}
	defer output.Close()
	result, err := enrollmenttarget.InitRequest(enrollmenttarget.RequestOptions{
		RootPath: stateRoot, RouteID: options.routeID,
		ConnectorInstallationID: options.connectorID,
		Validity:                options.validity, Now: options.now,
	})
	if err != nil {
		return nil, err
	}
	if err := output.Write(result.RequestBytes); err != nil {
		return nil, fmt.Errorf("export request; pending request remains available through 'pending': %w", err)
	}
	if err := output.Close(); err != nil {
		return nil, err
	}
	return encodePublic(requestSummary{
		Schema: "owntransit.ctl.request.v1", Action: "initialized",
		RequestSHA256: result.RequestSHA256, Sequence: result.Sequence,
	})
}

func exportPending(options exportPendingOptions) ([]byte, error) {
	stateRoot, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	output, err := preparePublicOutput(options.outputPath)
	if err != nil {
		return nil, err
	}
	defer output.Close()
	result, err := enrollmenttarget.PendingRequest(stateRoot)
	if err != nil {
		return nil, err
	}
	if err := output.Write(result.RequestBytes); err != nil {
		return nil, err
	}
	if err := output.Close(); err != nil {
		return nil, err
	}
	return encodePublic(requestSummary{
		Schema: "owntransit.ctl.request.v1", Action: "exported",
		RequestSHA256: result.RequestSHA256, Sequence: result.Sequence,
	})
}

func applyResponse(options applyOptions) ([]byte, error) {
	now := options.now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return nil, errors.New("current time is required")
	}
	stateRoot, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	envelope, err := readBoundedPublicFile(options.responsePath, enrollment.MaxEnvelopeSize)
	if err != nil {
		return nil, fmt.Errorf("response envelope: %w", err)
	}
	result, err := enrollmenttarget.ApplyResponse(stateRoot, envelope, now)
	if err != nil {
		return nil, err
	}
	return encodePublic(applySummary{
		Schema: "owntransit.ctl.apply.v1", Role: result.Role,
		InstallationID: result.InstallationID, RecordID: result.RecordID,
		DeploymentSequence: result.DeploymentSequence, CredentialEpoch: result.CredentialEpoch,
		RequestSHA256: result.RequestSHA256, StateGeneration: result.StateGeneration,
		OneTimeSecretRemoved: result.OneTimeSecretRemoved,
	})
}

func cancelPending(options stateOptions) ([]byte, error) {
	stateRoot, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	state, err := enrollmenttarget.CancelPending(stateRoot)
	if err != nil {
		return nil, err
	}
	return encodePublic(cancelSummary{
		Schema: "owntransit.ctl.cancel.v1", Canceled: true,
		StateGeneration:          state.StateGeneration,
		RequestSequenceHighWater: state.RequestSequenceHighWater,
	})
}

func readStatus(options stateOptions) ([]byte, error) {
	stateRoot, err := resolveStateRoot(options.stateRoot)
	if err != nil {
		return nil, err
	}
	status, err := enrollmenttarget.ReadStatus(stateRoot)
	if err != nil {
		return nil, err
	}
	state := status.State
	return encodePublic(statusSummary{
		Schema: "owntransit.ctl.status.v1", Role: state.Role,
		InstallationID: state.InstallationID, StateGeneration: state.StateGeneration,
		StateSHA256:               status.StateSHA256,
		RequestSequenceHighWater:  state.RequestSequenceHighWater,
		HighestDeploymentSequence: state.HighestDeploymentSequence,
		HighestReleaseSequence:    state.HighestReleaseSequence,
		HighestCredentialSequence: state.HighestCredentialSequence,
		PolicySequence:            state.PolicySequence, TombstoneSequence: state.TombstoneSequence,
		RecoverySequence: state.RecoverySequence, Active: state.ActiveRecordID != "",
		ActiveRecordID: state.ActiveRecordID, ActiveRecordSHA256: state.ActiveRecordSHA256,
		ActiveDeploymentSequence: state.ActiveDeploymentSequence, ActiveCredentialSequence: state.ActiveCredentialSequence,
		ActiveReleaseSequence: state.ActiveReleaseSequence, RollbackFloors: state.RollbackFloors,
		Pending: state.PendingRequest,
	})
}

func parseTargetRole(value string) (enrollment.Role, error) {
	switch enrollment.Role(value) {
	case enrollment.RoleClient, enrollment.RoleConnector, enrollment.RoleRelay:
		return enrollment.Role(value), nil
	default:
		return "", errors.New("role must be exactly client, connector, or relay")
	}
}

func encodePublic(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode public result: %w", err)
	}
	return append(encoded, '\n'), nil
}
