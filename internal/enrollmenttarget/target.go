//go:build darwin || linux

// Package enrollmenttarget owns the target-local half of OwnTransit
// enrollment. Public requests may leave the target; endpoint private keys,
// response identities, rollback floors and activation state never do.
package enrollmenttarget

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/localstate"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	bootstrapSchema = "owntransit.target-bootstrap.v1"
	bootstrapFile   = "bootstrap.json"
	stateFile       = "state.json"
	lockFile        = "lifecycle.lock"

	requestFile          = "request.json"
	outerPrivateKeyFile  = "outer-key.pem"
	innerPrivateKeyFile  = "inner-key.pem"
	responseIdentityFile = "response.age-identity"

	maxBootstrapSize  = 256 << 10
	maxPrivateKeySize = 16 << 10
	maxAgeIdentity    = 4 << 10
)

type bootstrapRecord struct {
	Schema                    string                    `json:"schema"`
	Role                      enrollment.Role           `json:"role"`
	InstallationID            string                    `json:"installation_id"`
	Runtime                   enrollment.RuntimeBinding `json:"runtime"`
	Trust                     enrollment.Trust          `json:"trust"`
	DeploymentSignerPublicPEM string                    `json:"deployment_signer_public_key_pem"`
	RollbackAnchorRoot        string                    `json:"rollback_anchor_root"`
	RuntimeViews              RuntimeViewBinding        `json:"runtime_views"`
	BootstrapUnix             int64                     `json:"bootstrap_unix"`
}

// RuntimeViewBinding is local privileged activation state, not a wire or
// deployment-policy input. RuntimeRoot and AnchorViewRoot name the host
// publication trees mutated only by root. RuntimeConfigRoot is the absolute
// path embedded in rendered configuration and may differ only to describe a
// fixed container namespace such as /runtime.
type RuntimeViewBinding struct {
	RuntimeRoot       string `json:"runtime_root"`
	RuntimeConfigRoot string `json:"runtime_config_root"`
	AnchorViewRoot    string `json:"anchor_view_root"`
	ReaderGID         uint32 `json:"reader_gid"`
}

// BootstrapOptions are authenticated software-install inputs. Trust contains
// public route roots only. The deployment signer is a public verification key;
// no authority private key is ever accepted by this package.
type BootstrapOptions struct {
	RootPath                  string
	Role                      enrollment.Role
	InstallationID            string
	Runtime                   enrollment.RuntimeBinding
	Trust                     enrollment.Trust
	DeploymentSignerPublicPEM []byte
	RollbackAnchorRoot        string
	RuntimeViews              RuntimeViewBinding
	Now                       time.Time
}

// BootstrapResult identifies the exclusively created target root. It contains
// no secret material.
type BootstrapResult struct {
	InstallationID string
	State          localstate.State
}

// RequestOptions select only capability scope and request lifetime. Issuers,
// deployment signer, runtime identity, role and installation identity all come
// from the immutable target bootstrap record.
type RequestOptions struct {
	RootPath                string
	RouteID                 string
	ConnectorInstallationID string
	Validity                time.Duration
	Now                     time.Time
}

// RequestResult may be exported to the offline provisioner.
type RequestResult struct {
	RequestBytes  []byte
	RequestSHA256 string
	Sequence      uint64
	RecordID      string
}

// Status is safe for local diagnostics. It deliberately omits bootstrap roots,
// private keys and response identities.
type Status struct {
	State       localstate.State
	StateSHA256 string
}

// Bootstrap exclusively creates a private state root. It writes the complete
// public bootstrap record first and state.json last, so a partial failure can
// never be mistaken for a usable target.
func Bootstrap(options BootstrapOptions) (BootstrapResult, error) {
	now := options.Now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return BootstrapResult{}, errors.New("enrollmenttarget: bootstrap time is required")
	}
	installationID := options.InstallationID
	if installationID == "" {
		generated, err := protocol.NewID()
		if err != nil {
			return BootstrapResult{}, fmt.Errorf("enrollmenttarget: generate installation ID: %w", err)
		}
		installationID = generated.String()
	}
	if err := validateNonzeroID(installationID); err != nil {
		return BootstrapResult{}, fmt.Errorf("enrollmenttarget: installation ID: %w", err)
	}
	if err := options.Runtime.Validate(options.Role); err != nil {
		return BootstrapResult{}, err
	}
	if _, err := enrollment.IssuerPinsFromTrust(options.Trust, now); err != nil {
		return BootstrapResult{}, err
	}
	deploymentSigner, err := signing.ParsePublic(options.DeploymentSignerPublicPEM)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("enrollmenttarget: deployment verifier: %w", err)
	}
	if len(deploymentSigner) != ed25519.PublicKeySize {
		return BootstrapResult{}, errors.New("enrollmenttarget: deployment verifier is not Ed25519")
	}
	record := bootstrapRecord{
		Schema: bootstrapSchema, Role: options.Role, InstallationID: installationID,
		Runtime: options.Runtime, Trust: options.Trust,
		DeploymentSignerPublicPEM: string(options.DeploymentSignerPublicPEM),
		RollbackAnchorRoot:        options.RollbackAnchorRoot,
		RuntimeViews:              options.RuntimeViews,
		BootstrapUnix:             now.Unix(),
	}
	if err := record.validate(now); err != nil {
		return BootstrapResult{}, err
	}
	if err := validateAllActivationRoots(options.RootPath, record.RollbackAnchorRoot, record.RuntimeViews); err != nil {
		return BootstrapResult{}, err
	}
	encodedBootstrap, err := encodeBootstrap(record)
	if err != nil {
		return BootstrapResult{}, err
	}
	role, err := localRole(options.Role)
	if err != nil {
		return BootstrapResult{}, err
	}
	state := localstate.State{
		Schema: localstate.Schema, Role: role, InstallationID: installationID,
		StateGeneration: 1, HighestReleaseSequence: options.Runtime.ReleaseSequence,
		ActiveReleaseSequence:        options.Runtime.ReleaseSequence,
		RollbackFloors:               localstate.RollbackFloors{ReleaseSequence: options.Runtime.ReleaseSequence},
		ConsumedRequestSHA256:        []string{},
		RevokedClientInstallationIDs: []string{},
		CredentialTombstoneSPKIPins:  []string{},
	}
	encodedState, err := localstate.Encode(state)
	if err != nil {
		return BootstrapResult{}, err
	}
	root, err := securefs.CreateRoot(options.RootPath)
	if err != nil {
		return BootstrapResult{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return BootstrapResult{}, err
	}
	defer lock.Close()
	if err := root.CreateExclusive(bootstrapFile, encodedBootstrap, 0o600); err != nil {
		return BootstrapResult{}, err
	}
	anchorRoot, err := createRollbackAnchor(options.RootPath, record.RollbackAnchorRoot, state)
	if err != nil {
		return BootstrapResult{}, err
	}
	defer anchorRoot.Close()
	runtimeViewRoot, anchorViewRoot, err := initializeRuntimeViews(options.RootPath, record, state, encodedState)
	if err != nil {
		return BootstrapResult{}, err
	}
	defer runtimeViewRoot.Close()
	defer anchorViewRoot.Close()
	if err := root.CreateExclusive(stateFile, encodedState, 0o600); err != nil {
		return BootstrapResult{}, err
	}
	return BootstrapResult{InstallationID: installationID, State: state}, nil
}

// BootstrapOrVerify creates a new target bootstrap or verifies that an
// already completed bootstrap is byte-for-byte equivalent to the supplied
// authenticated inputs. It never repairs or guesses through partial residue.
func BootstrapOrVerify(options BootstrapOptions) (BootstrapResult, error) {
	result, err := Bootstrap(options)
	if err == nil {
		return result, nil
	}
	root, openErr := securefs.OpenRoot(options.RootPath)
	if openErr != nil {
		return BootstrapResult{}, err
	}
	defer root.Close()
	lock, lockErr := root.TryLock(lockFile)
	if lockErr != nil {
		return BootstrapResult{}, lockErr
	}
	defer lock.Close()
	state, _, readErr := readAnchoredState(root)
	if readErr != nil {
		return BootstrapResult{}, errors.New("enrollmenttarget: incomplete bootstrap residue requires explicit recovery")
	}
	record, readErr := readBootstrapRecord(root)
	if readErr != nil {
		return BootstrapResult{}, readErr
	}
	if validateErr := record.validate(time.Unix(record.BootstrapUnix, 0).UTC()); validateErr != nil {
		return BootstrapResult{}, validateErr
	}
	expected := bootstrapRecord{
		Schema: bootstrapSchema, Role: options.Role, InstallationID: options.InstallationID,
		Runtime: options.Runtime, Trust: options.Trust,
		DeploymentSignerPublicPEM: string(options.DeploymentSignerPublicPEM),
		RollbackAnchorRoot:        options.RollbackAnchorRoot, RuntimeViews: options.RuntimeViews,
		BootstrapUnix: record.BootstrapUnix,
	}
	if !reflect.DeepEqual(record, expected) {
		return BootstrapResult{}, errors.New("enrollmenttarget: existing bootstrap differs from the exact authenticated inputs")
	}
	role, roleErr := localRole(options.Role)
	if roleErr != nil || state.Role != role || state.InstallationID != options.InstallationID || state.HighestReleaseSequence != options.Runtime.ReleaseSequence {
		return BootstrapResult{}, errors.New("enrollmenttarget: existing bootstrap state differs from the exact authenticated inputs")
	}
	return BootstrapResult{InstallationID: state.InstallationID, State: state}, nil
}

// ImportPendingClient bootstraps the fixed client lifecycle only after the
// caller has durably completed its separate transcript ceremony, then imports
// the exact already-generated pending material. Existing exact state is
// idempotent; different or partial state fails closed.
func ImportPendingClient(options BootstrapOptions, material enrollment.PendingMaterial) (RequestResult, error) {
	if options.Role != enrollment.RoleClient || options.InstallationID == "" {
		return RequestResult{}, errors.New("enrollmenttarget: exact client bootstrap identity is required")
	}
	if err := enrollment.ValidatePendingMaterial(material, options.Now); err != nil {
		return RequestResult{}, err
	}
	payload := material.Payload
	deploymentSigner, err := signing.ParsePublic(options.DeploymentSignerPublicPEM)
	if err != nil {
		return RequestResult{}, errors.New("enrollmenttarget: bootstrap deployment verifier is invalid")
	}
	if payload.Role != options.Role || payload.InstallationID != options.InstallationID || payload.Sequence != 1 ||
		payload.Runtime != options.Runtime || payload.DeploymentSignerKeyID != signing.KeyID(deploymentSigner) {
		return RequestResult{}, errors.New("enrollmenttarget: pending material differs from bootstrap identity or runtime")
	}
	pins, err := enrollment.IssuerPinsFromTrust(options.Trust, options.Now.UTC().Truncate(time.Second))
	if err != nil || payload.IssuerPins != pins {
		return RequestResult{}, errors.New("enrollmenttarget: pending material differs from bootstrap trust")
	}
	if _, err := BootstrapOrVerify(options); err != nil {
		return RequestResult{}, err
	}

	root, err := securefs.OpenRoot(options.RootPath)
	if err != nil {
		return RequestResult{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return RequestResult{}, err
	}
	defer lock.Close()
	boundary, err := acquireLifecycleBoundary(root)
	if err != nil {
		return RequestResult{}, err
	}
	defer boundary.Close()
	state, err := readState(root)
	if err != nil {
		return RequestResult{}, err
	}
	digest := sha256.Sum256(material.RequestBytes)
	digestText := hex.EncodeToString(digest[:])
	if state.PendingRequest != nil {
		if state.PendingRequest.Sequence != 1 || state.PendingRequest.Nonce != payload.Nonce || state.PendingRequest.RequestSHA256 != digestText {
			return RequestResult{}, errors.New("enrollmenttarget: existing pending request differs from confirmed setup material")
		}
		if err := verifyImportedPending(root, *state.PendingRequest, material); err != nil {
			return RequestResult{}, err
		}
		return RequestResult{RequestBytes: append([]byte(nil), material.RequestBytes...), RequestSHA256: digestText, Sequence: 1, RecordID: payload.Nonce}, nil
	}
	if state.ActiveRecordID != "" || state.RequestSequenceHighWater != 0 || state.StateGeneration == math.MaxUint64 {
		return RequestResult{}, errors.New("enrollmenttarget: client lifecycle is not a fresh confirmed setup target")
	}
	recordName, err := recordDirectoryName(payload.Nonce)
	if err != nil {
		return RequestResult{}, err
	}
	if err := root.MkdirExclusive(recordName, 0o700); err != nil {
		existing, openErr := root.OpenDir(recordName)
		if openErr != nil {
			return RequestResult{}, err
		}
		_ = existing.Close()
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return RequestResult{}, err
	}
	defer record.Close()
	for _, file := range []struct {
		name string
		data []byte
	}{
		{requestFile, material.RequestBytes},
		{outerPrivateKeyFile, material.OuterPrivateKey},
		{innerPrivateKeyFile, material.InnerPrivateKey},
		{responseIdentityFile, []byte(material.ResponseIdentity)},
	} {
		if err := record.EnsureFile(file.name, file.data, 0o600); err != nil {
			return RequestResult{}, err
		}
	}
	if err := record.Sync(); err != nil {
		return RequestResult{}, err
	}
	next := state
	next.StateGeneration++
	next.RequestSequenceHighWater = 1
	next.PendingRequest = &localstate.PendingRequestMetadata{
		Sequence: 1, RequestSHA256: digestText, Nonce: payload.Nonce,
		CreatedUnix: payload.CreatedUnix, ExpiresUnix: payload.ExpiresUnix,
	}
	if err := commitState(root, state, next, boundary); err != nil {
		return RequestResult{}, err
	}
	return RequestResult{RequestBytes: append([]byte(nil), material.RequestBytes...), RequestSHA256: digestText, Sequence: 1, RecordID: payload.Nonce}, nil
}

func verifyImportedPending(root *securefs.Root, pending localstate.PendingRequestMetadata, material enrollment.PendingMaterial) error {
	recordName, err := recordDirectoryName(pending.Nonce)
	if err != nil {
		return err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return err
	}
	defer record.Close()
	for _, file := range []struct {
		name  string
		data  []byte
		limit int64
	}{
		{requestFile, material.RequestBytes, enrollment.MaxRequestSize},
		{outerPrivateKeyFile, material.OuterPrivateKey, maxPrivateKeySize},
		{innerPrivateKeyFile, material.InnerPrivateKey, maxPrivateKeySize},
		{responseIdentityFile, []byte(material.ResponseIdentity), maxAgeIdentity},
	} {
		value, err := record.ReadFile(file.name, file.limit)
		if err != nil || !bytes.Equal(value, file.data) {
			return errors.New("enrollmenttarget: imported pending material differs from the confirmed exact bytes")
		}
	}
	return nil
}

// InitRequest generates both endpoint keys and the response identity inside a
// new immutable record directory. state.json advances only after all files are
// durable; request bytes are returned only after that commit.
func InitRequest(options RequestOptions) (RequestResult, error) {
	now := options.Now.UTC().Truncate(time.Second)
	if now.IsZero() || options.Validity <= 0 || options.Validity > enrollment.MaxRequestValidity {
		return RequestResult{}, errors.New("enrollmenttarget: bounded request time and validity are required")
	}
	root, err := securefs.OpenRoot(options.RootPath)
	if err != nil {
		return RequestResult{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return RequestResult{}, err
	}
	defer lock.Close()
	boundary, err := acquireLifecycleBoundary(root)
	if err != nil {
		return RequestResult{}, err
	}
	defer boundary.Close()

	state, err := readState(root)
	if err != nil {
		return RequestResult{}, err
	}
	if state.PendingRequest != nil {
		return RequestResult{}, errors.New("enrollmenttarget: a pending request already exists; export or cancel it first")
	}
	if state.RequestSequenceHighWater == math.MaxUint64 || state.StateGeneration == math.MaxUint64 {
		return RequestResult{}, errors.New("enrollmenttarget: local sequence space is exhausted")
	}
	bootstrap, signer, err := readBootstrap(root, state, now)
	if err != nil {
		return RequestResult{}, err
	}
	sequence := state.RequestSequenceHighWater + 1
	effectivePolicy, err := effectiveLifecyclePolicy(root, state, bootstrap, signer)
	if err != nil {
		return RequestResult{}, err
	}
	pending, err := enrollment.NewPendingRequest(enrollment.InitOptions{
		Role: bootstrap.Role, InstallationID: bootstrap.InstallationID,
		RouteID: options.RouteID, ConnectorInstallationID: options.ConnectorInstallationID,
		Sequence: sequence, Now: now, RequestValidity: options.Validity,
		Trust: effectivePolicy.Trust, DeploymentSigner: signer, Runtime: bootstrap.Runtime,
	})
	if err != nil {
		return RequestResult{}, err
	}
	digest := sha256.Sum256(pending.RequestBytes)
	digestText := hex.EncodeToString(digest[:])
	recordID := pending.Payload.Nonce
	recordName, err := recordDirectoryName(recordID)
	if err != nil {
		return RequestResult{}, err
	}
	if err := root.MkdirExclusive(recordName, 0o700); err != nil {
		return RequestResult{}, err
	}
	recordRoot, err := root.OpenDir(recordName)
	if err != nil {
		return RequestResult{}, err
	}
	defer recordRoot.Close()
	files := []struct {
		name string
		data []byte
	}{
		{requestFile, pending.RequestBytes},
		{outerPrivateKeyFile, pending.OuterPrivateKey},
		{responseIdentityFile, []byte(pending.ResponseIdentity)},
	}
	if bootstrap.Role != enrollment.RoleRelay {
		files = append(files, struct {
			name string
			data []byte
		}{innerPrivateKeyFile, pending.InnerPrivateKey})
	}
	for _, file := range files {
		if err := recordRoot.EnsureFile(file.name, file.data, 0o600); err != nil {
			return RequestResult{}, err
		}
	}
	if err := recordRoot.Sync(); err != nil {
		return RequestResult{}, err
	}
	next := state
	next.StateGeneration++
	next.RequestSequenceHighWater = sequence
	next.PendingRequest = &localstate.PendingRequestMetadata{
		Sequence: sequence, RequestSHA256: digestText, Nonce: pending.Payload.Nonce,
		CreatedUnix: pending.Payload.CreatedUnix, ExpiresUnix: pending.Payload.ExpiresUnix,
	}
	if err := commitState(root, state, next, boundary); err != nil {
		return RequestResult{}, err
	}
	return RequestResult{
		RequestBytes: append([]byte(nil), pending.RequestBytes...), RequestSHA256: digestText,
		Sequence: sequence, RecordID: recordID,
	}, nil
}

// PendingRequest returns the exact public request currently bound by durable
// state. It works even after expiry so the operator can inspect or cancel it.
func PendingRequest(rootPath string) (RequestResult, error) {
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return RequestResult{}, err
	}
	defer root.Close()
	state, err := readState(root)
	if err != nil {
		return RequestResult{}, err
	}
	if state.PendingRequest == nil {
		return RequestResult{}, errors.New("enrollmenttarget: no pending request")
	}
	encoded, err := readPendingFile(root, *state.PendingRequest, requestFile, enrollment.MaxRequestSize)
	if err != nil {
		return RequestResult{}, err
	}
	digest := sha256.Sum256(encoded)
	digestText := hex.EncodeToString(digest[:])
	if digestText != state.PendingRequest.RequestSHA256 {
		return RequestResult{}, errors.New("enrollmenttarget: pending request bytes do not match durable state")
	}
	return RequestResult{
		RequestBytes: encoded, RequestSHA256: digestText,
		Sequence: state.PendingRequest.Sequence, RecordID: state.PendingRequest.Nonce,
	}, nil
}

// CancelPending durably consumes the request digest before clearing it. The
// immutable record directory is intentionally retained for explicit later GC;
// failure to delete storage can never resurrect an enrollment request.
func CancelPending(rootPath string) (localstate.State, error) {
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return localstate.State{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return localstate.State{}, err
	}
	defer lock.Close()
	boundary, err := acquireLifecycleBoundary(root)
	if err != nil {
		return localstate.State{}, err
	}
	defer boundary.Close()
	state, err := readState(root)
	if err != nil {
		return localstate.State{}, err
	}
	if state.PendingRequest == nil {
		return localstate.State{}, errors.New("enrollmenttarget: no pending request")
	}
	if state.StateGeneration == math.MaxUint64 {
		return localstate.State{}, errors.New("enrollmenttarget: local state generation is exhausted")
	}
	pending := *state.PendingRequest
	next := state
	next.StateGeneration++
	next.ConsumedRequestSHA256, err = insertSortedBounded(
		state.ConsumedRequestSHA256,
		state.PendingRequest.RequestSHA256,
		localstate.MaxConsumedRequestDigests,
	)
	if err != nil {
		return localstate.State{}, err
	}
	next.PendingRequest = nil
	if err := commitState(root, state, next, boundary); err != nil {
		return localstate.State{}, err
	}
	// Cleanup is deliberately after the consumption commit. A crash or failed
	// unlink can leak storage, but can never make the request usable again.
	if recordName, nameErr := recordDirectoryName(pending.Nonce); nameErr == nil {
		if record, openErr := root.OpenDir(recordName); openErr == nil {
			_ = record.UnlinkFile(responseIdentityFile)
			_ = record.UnlinkFile(outerPrivateKeyFile)
			_ = record.UnlinkFile(innerPrivateKeyFile)
			_ = record.UnlinkFile(requestFile)
			_ = record.Close()
			_ = root.RemoveDir(recordName)
		}
	}
	return next, nil
}

// ReadStatus validates and returns the complete non-secret durable snapshot.
func ReadStatus(rootPath string) (Status, error) {
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return Status{}, err
	}
	defer root.Close()
	state, digest, err := readAnchoredState(root)
	if err != nil {
		return Status{}, err
	}
	return Status{State: state, StateSHA256: digest}, nil
}

func (record bootstrapRecord) validate(now time.Time) error {
	if record.Schema != bootstrapSchema {
		return errors.New("enrollmenttarget: unsupported bootstrap schema")
	}
	if err := validateNonzeroID(record.InstallationID); err != nil {
		return fmt.Errorf("enrollmenttarget: bootstrap installation ID: %w", err)
	}
	if err := record.Runtime.Validate(record.Role); err != nil {
		return err
	}
	if err := validateAnchorRootPath(record.RollbackAnchorRoot); err != nil {
		return err
	}
	if err := record.RuntimeViews.validate(record.RollbackAnchorRoot); err != nil {
		return err
	}
	if record.BootstrapUnix <= 0 || now.UTC().Truncate(time.Second).Unix() != record.BootstrapUnix {
		return errors.New("enrollmenttarget: bootstrap ceremony time is invalid")
	}
	deploymentSigner, err := signing.ParsePublic([]byte(record.DeploymentSignerPublicPEM))
	if err != nil {
		return fmt.Errorf("enrollmenttarget: bootstrap deployment verifier: %w", err)
	}
	if err := enrollment.ValidateBootstrapAuthorities(record.Trust, deploymentSigner, now); err != nil {
		return err
	}
	_, err = localRole(record.Role)
	return err
}

func encodeBootstrap(record bootstrapRecord) ([]byte, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("enrollmenttarget: encode bootstrap: %w", err)
	}
	if len(encoded) >= maxBootstrapSize {
		return nil, errors.New("enrollmenttarget: bootstrap record exceeds size limit")
	}
	return append(encoded, '\n'), nil
}

func readBootstrap(root *securefs.Root, state localstate.State, now time.Time) (bootstrapRecord, ed25519.PublicKey, error) {
	record, err := readBootstrapRecord(root)
	if err != nil {
		return bootstrapRecord{}, nil, err
	}
	if err := record.validate(time.Unix(record.BootstrapUnix, 0).UTC()); err != nil {
		return bootstrapRecord{}, nil, err
	}
	wantRole, err := localRole(record.Role)
	if err != nil {
		return bootstrapRecord{}, nil, err
	}
	if wantRole != state.Role || record.InstallationID != state.InstallationID ||
		record.Runtime.ReleaseSequence != state.HighestReleaseSequence {
		return bootstrapRecord{}, nil, errors.New("enrollmenttarget: bootstrap does not match durable target state")
	}
	signer, err := signing.ParsePublic([]byte(record.DeploymentSignerPublicPEM))
	if err != nil {
		return bootstrapRecord{}, nil, err
	}
	return record, signer, nil
}

func readBootstrapRecord(root *securefs.Root) (bootstrapRecord, error) {
	encoded, err := root.ReadFile(bootstrapFile, maxBootstrapSize)
	if err != nil {
		return bootstrapRecord{}, err
	}
	var record bootstrapRecord
	if err := strictjson.Decode(encoded, &record); err != nil {
		return bootstrapRecord{}, fmt.Errorf("enrollmenttarget: decode bootstrap: %w", err)
	}
	if record.Schema != bootstrapSchema || record.BootstrapUnix <= 0 || validateNonzeroID(record.InstallationID) != nil || validateAnchorRootPath(record.RollbackAnchorRoot) != nil || record.RuntimeViews.validate(record.RollbackAnchorRoot) != nil {
		return bootstrapRecord{}, errors.New("enrollmenttarget: bootstrap identity or rollback anchor is invalid")
	}
	return record, nil
}

func readState(root *securefs.Root) (localstate.State, error) {
	state, _, err := readAnchoredState(root)
	return state, err
}

func commitState(root *securefs.Root, previous, next localstate.State, boundary *lifecycleBoundary) error {
	return commitAnchoredState(root, previous, next, boundary)
}

func validateAnchorRootPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return errors.New("enrollmenttarget: rollback anchor root must be an absolute canonical non-root path")
	}
	return nil
}

func readPendingFile(root *securefs.Root, pending localstate.PendingRequestMetadata, name string, limit int64) ([]byte, error) {
	recordName, err := recordDirectoryName(pending.Nonce)
	if err != nil {
		return nil, err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return nil, err
	}
	defer record.Close()
	return record.ReadFile(name, limit)
}

func recordDirectoryName(recordID string) (string, error) {
	if err := validateNonzeroID(recordID); err != nil {
		return "", fmt.Errorf("enrollmenttarget: record ID: %w", err)
	}
	return "record-" + recordID, nil
}

func validateNonzeroID(encoded string) error {
	id, err := protocol.ParseID(encoded)
	if err != nil || id == (protocol.ID{}) || id.String() != encoded {
		return errors.New("must be a nonzero canonical ID")
	}
	return nil
}

func localRole(role enrollment.Role) (localstate.Role, error) {
	switch role {
	case enrollment.RoleClient:
		return localstate.RoleClient, nil
	case enrollment.RoleConnector:
		return localstate.RoleConnector, nil
	case enrollment.RoleRelay:
		return localstate.RoleRelay, nil
	default:
		return "", errors.New("enrollmenttarget: invalid target role")
	}
}

func enrollmentRole(role localstate.Role) (enrollment.Role, error) {
	switch role {
	case localstate.RoleClient:
		return enrollment.RoleClient, nil
	case localstate.RoleConnector:
		return enrollment.RoleConnector, nil
	case localstate.RoleRelay:
		return enrollment.RoleRelay, nil
	default:
		return "", errors.New("enrollmenttarget: invalid durable role")
	}
}

func insertSortedBounded(values []string, value string, maximum int) ([]string, error) {
	result := append([]string(nil), values...)
	index := sort.SearchStrings(result, value)
	if index < len(result) && result[index] == value {
		return nil, errors.New("enrollmenttarget: durable value is already present")
	}
	if len(result) >= maximum {
		return nil, errors.New("enrollmenttarget: durable history reached its configured bound")
	}
	result = append(result, "")
	copy(result[index+1:], result[index:])
	result[index] = value
	return result, nil
}
