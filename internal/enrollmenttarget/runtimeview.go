//go:build darwin || linux

package enrollmenttarget

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/sentrybottale/owntransit/internal/activationlock"
	"github.com/sentrybottale/owntransit/internal/localstate"
	"github.com/sentrybottale/owntransit/internal/runtimebundle"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	runtimeViewSchema   = "owntransit.runtime-view.v1"
	anchorViewSchema    = "owntransit.anchor-view.v1"
	viewJournalSchema   = "owntransit.view-journal.v1"
	transitionSchema    = "owntransit.activation-transition.v1"
	runtimeViewFile     = "runtime.json"
	anchorViewFile      = "anchor.json"
	transitionFile      = "transition.json"
	transactionViewFile = "transaction-view.json"
	maxRuntimeView      = 1 << 20
	maxViewJournal      = 1 << 20
	maxTransitionMarker = 64 << 10
)

type anchoredSelection struct {
	Role            localstate.Role `json:"role"`
	InstallationID  string          `json:"installation_id"`
	StateGeneration uint64          `json:"state_generation"`
	StateSHA256     string          `json:"state_sha256"`
	RecordID        string          `json:"record_id,omitempty"`
	RecordSHA256    string          `json:"record_sha256,omitempty"`
}

type anchorView struct {
	Schema string `json:"schema"`
	anchoredSelection
}

type runtimeView struct {
	Schema string `json:"schema"`
	anchoredSelection
	Generation              string             `json:"generation"`
	ConnectorInstallationID string             `json:"connector_installation_id"`
	RouteID                 string             `json:"route_id"`
	CredentialSequence      uint64             `json:"credential_sequence"`
	OuterDNSName            string             `json:"outer_dns_name"`
	InnerDNSName            string             `json:"inner_dns_name,omitempty"`
	Files                   []recordFileDigest `json:"files"`
}

type viewJournal struct {
	Schema                  string   `json:"schema"`
	StateGeneration         uint64   `json:"state_generation"`
	StateSHA256             string   `json:"state_sha256"`
	AnchorViewSHA256        string   `json:"anchor_view_sha256"`
	RuntimeViewSHA256       string   `json:"runtime_view_sha256,omitempty"`
	Generation              string   `json:"generation,omitempty"`
	GenerationFiles         []string `json:"generation_files"`
	PreviousGeneration      string   `json:"previous_generation,omitempty"`
	PreviousGenerationFiles []string `json:"previous_generation_files"`
}

type transitionMarker struct {
	Schema            string `json:"schema"`
	StateGeneration   uint64 `json:"state_generation"`
	StateSHA256       string `json:"state_sha256"`
	AnchorViewSHA256  string `json:"anchor_view_sha256"`
	RuntimeViewSHA256 string `json:"runtime_view_sha256,omitempty"`
}

type preparedViews struct {
	anchorBytes        []byte
	runtimeBytes       []byte
	generation         string
	generationFiles    []string
	previousGeneration string
	previousFiles      []string
	stateDigest        string
	generationExposed  bool
}

// lifecycleBoundary owns the privileged side of the cross-principal
// activation gate for one complete mutating lifecycle operation. Holding it
// from before the first private write until after post-commit retirement keeps
// a runtime from admitting sessions during *any* lifecycle mutation, not only
// while the active selector is replaced.
type lifecycleBoundary struct {
	bootstrap   bootstrapRecord
	runtimeRoot *securefs.ViewWriter
	anchorRoot  *securefs.ViewWriter
	gate        *securefs.ViewLock
}

func acquireLifecycleBoundary(privateRoot *securefs.Root) (*lifecycleBoundary, error) {
	if privateRoot == nil {
		return nil, errors.New("enrollmenttarget: private lifecycle root is unavailable")
	}
	bootstrap, err := readBootstrapRecord(privateRoot)
	if err != nil {
		return nil, err
	}
	boundary := &lifecycleBoundary{bootstrap: bootstrap}
	if !bootstrap.RuntimeViews.configured() {
		return boundary, nil
	}
	runtimeRoot, err := securefs.OpenViewRoot(bootstrap.RuntimeViews.RuntimeRoot, int(bootstrap.RuntimeViews.ReaderGID))
	if err != nil {
		return nil, err
	}
	boundary.runtimeRoot = runtimeRoot
	gate, err := activationlock.AcquireExclusive(runtimeRoot)
	if err != nil {
		_ = runtimeRoot.Close()
		return nil, fmt.Errorf("enrollmenttarget: runtime remains active; stop it before lifecycle mutation: %w", err)
	}
	boundary.gate = gate
	anchorRoot, err := securefs.OpenViewRoot(bootstrap.RuntimeViews.AnchorViewRoot, int(bootstrap.RuntimeViews.ReaderGID))
	if err != nil {
		_ = gate.Close()
		_ = runtimeRoot.Close()
		return nil, err
	}
	boundary.anchorRoot = anchorRoot
	return boundary, nil
}

func (boundary *lifecycleBoundary) Close() error {
	if boundary == nil {
		return nil
	}
	var first error
	for _, close := range []func() error{
		func() error {
			if boundary.anchorRoot == nil {
				return nil
			}
			return boundary.anchorRoot.Close()
		},
		func() error {
			if boundary.gate == nil {
				return nil
			}
			return boundary.gate.Close()
		},
		func() error {
			if boundary.runtimeRoot == nil {
				return nil
			}
			return boundary.runtimeRoot.Close()
		},
	} {
		if err := close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (boundary *lifecycleBoundary) validateFor(bootstrap bootstrapRecord) error {
	if boundary == nil || !reflect.DeepEqual(boundary.bootstrap, bootstrap) {
		return errors.New("enrollmenttarget: held lifecycle boundary does not match immutable bootstrap state")
	}
	configured := bootstrap.RuntimeViews.configured()
	if !configured && (boundary.runtimeRoot != nil || boundary.anchorRoot != nil || boundary.gate != nil) {
		return errors.New("enrollmenttarget: private-only lifecycle boundary unexpectedly contains publication authority")
	}
	if configured && (boundary.runtimeRoot == nil || boundary.anchorRoot == nil || boundary.gate == nil) {
		return errors.New("enrollmenttarget: held lifecycle publication boundary is incomplete")
	}
	return nil
}

func (binding RuntimeViewBinding) configured() bool {
	return binding.RuntimeRoot != "" || binding.RuntimeConfigRoot != "" || binding.AnchorViewRoot != "" || binding.ReaderGID != 0
}

func (binding RuntimeViewBinding) validate(authorityRoot string) error {
	if !binding.configured() {
		return nil // Internal source tests retain the private-only pre-package path.
	}
	if binding.RuntimeRoot == "" || binding.RuntimeConfigRoot == "" || binding.AnchorViewRoot == "" || binding.ReaderGID == 0 {
		return errors.New("enrollmenttarget: runtime-view binding must be complete")
	}
	for _, path := range []string{binding.RuntimeRoot, binding.RuntimeConfigRoot, binding.AnchorViewRoot} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return errors.New("enrollmenttarget: runtime-view paths must be canonical absolute non-root paths")
		}
	}
	if binding.ReaderGID == math.MaxUint32 {
		return errors.New("enrollmenttarget: runtime reader GID is invalid")
	}
	if err := validateSeparateRoots(binding.RuntimeRoot, binding.AnchorViewRoot); err != nil {
		return errors.New("enrollmenttarget: runtime and anchor-view roots must be distinct and non-nested")
	}
	if authorityRoot != "" {
		for _, path := range []string{binding.RuntimeRoot, binding.AnchorViewRoot} {
			if path == authorityRoot || pathContains(path, authorityRoot) || pathContains(authorityRoot, path) {
				return errors.New("enrollmenttarget: public views and authoritative anchor must be distinct and non-nested")
			}
		}
	}
	return nil
}

func validateAllActivationRoots(privateRoot, authorityRoot string, binding RuntimeViewBinding) error {
	if !binding.configured() {
		return nil
	}
	if err := binding.validate(authorityRoot); err != nil {
		return err
	}
	for _, path := range []string{authorityRoot, binding.RuntimeRoot, binding.AnchorViewRoot} {
		if privateRoot == path || pathContains(privateRoot, path) || pathContains(path, privateRoot) {
			return errors.New("enrollmenttarget: private, authority, runtime and anchor-view roots must be distinct and non-nested")
		}
	}
	return nil
}

func initializeRuntimeViews(privateRoot string, bootstrap bootstrapRecord, state localstate.State, encodedState []byte) (*securefs.ViewWriter, *securefs.ViewWriter, error) {
	if !bootstrap.RuntimeViews.configured() {
		return nil, nil, nil
	}
	if err := validateAllActivationRoots(privateRoot, bootstrap.RollbackAnchorRoot, bootstrap.RuntimeViews); err != nil {
		return nil, nil, err
	}
	runtimeRoot, err := securefs.CreateViewRoot(bootstrap.RuntimeViews.RuntimeRoot, int(bootstrap.RuntimeViews.ReaderGID))
	if err != nil {
		return nil, nil, fmt.Errorf("enrollmenttarget: create runtime view: %w", err)
	}
	fail := func(value error) (*securefs.ViewWriter, *securefs.ViewWriter, error) {
		_ = runtimeRoot.Close()
		return nil, nil, value
	}
	if err := runtimeRoot.CreateExclusive(activationlock.FileName, []byte(activationlock.Contents)); err != nil {
		return fail(err)
	}
	anchorRoot, err := securefs.CreateViewRoot(bootstrap.RuntimeViews.AnchorViewRoot, int(bootstrap.RuntimeViews.ReaderGID))
	if err != nil {
		return fail(fmt.Errorf("enrollmenttarget: create anchor view: %w", err))
	}
	anchorBytes, err := encodeAnchorView(anchorViewForState(state, encodedState))
	if err != nil {
		_ = anchorRoot.Close()
		return fail(err)
	}
	if err := anchorRoot.CreateExclusive(anchorViewFile, anchorBytes); err != nil {
		_ = anchorRoot.Close()
		return fail(err)
	}
	return runtimeRoot, anchorRoot, nil
}

func prepareViewCommit(privateRoot *securefs.Root, bootstrap bootstrapRecord, next localstate.State, nextBytes []byte, boundary *lifecycleBoundary) (preparedViews, error) {
	if err := boundary.validateFor(bootstrap); err != nil {
		return preparedViews{}, err
	}
	if !bootstrap.RuntimeViews.configured() {
		return preparedViews{}, nil
	}
	runtimeRoot := boundary.runtimeRoot
	fail := func(value error) (preparedViews, error) { return preparedViews{}, value }
	// This exact state journal is private and durable before either the visible
	// fail-closed marker or authoritative anchor can advance. The activation
	// gate is already exclusive, so no compliant runtime can admit new work.
	if err := privateRoot.ReplaceFile(transactionStateFile, nextBytes, 0o600); err != nil {
		return fail(err)
	}

	anchorBytes, err := encodeAnchorView(anchorViewForState(next, nextBytes))
	if err != nil {
		return fail(err)
	}
	prepared := preparedViews{anchorBytes: anchorBytes, stateDigest: digestBytes(nextBytes)}
	if previousBytes, readErr := runtimeRoot.ReadRecoverableFile(runtimeViewFile, maxRuntimeView); readErr == nil {
		previous, decodeErr := decodeRuntimeView(previousBytes)
		if decodeErr != nil {
			return fail(decodeErr)
		}
		prepared.previousGeneration = previous.Generation
		prepared.previousFiles = digestNames(previous.Files)
	} else if !errors.Is(readErr, unix.ENOENT) {
		return fail(readErr)
	}

	if next.ActiveRecordID != "" {
		manifest, contents, err := privateRecordForState(privateRoot, next)
		if err != nil {
			return fail(err)
		}
		prepared.generation = generationName(next.StateGeneration, prepared.stateDigest)
		configDirectory := filepath.Join(bootstrap.RuntimeViews.RuntimeConfigRoot, prepared.generation)
		files, err := runtimebundle.RebaseVerifiedFiles(manifest.Role, contents, configDirectory)
		if err != nil {
			return fail(err)
		}
		viewFiles := make([]recordFileDigest, len(files))
		for index, file := range files {
			name := filepath.Base(file.Path)
			digest := sha256.Sum256(file.Contents)
			viewFiles[index] = recordFileDigest{Name: name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(file.Contents))}
			prepared.generationFiles = append(prepared.generationFiles, name)
		}
		sort.Slice(viewFiles, func(i, j int) bool { return viewFiles[i].Name < viewFiles[j].Name })
		view := runtimeView{
			Schema: runtimeViewSchema, anchoredSelection: selectionForState(next, nextBytes),
			Generation: prepared.generation, ConnectorInstallationID: manifest.ConnectorInstallationID,
			RouteID: manifest.RouteID, CredentialSequence: manifest.CredentialSequence,
			OuterDNSName: manifest.OuterDNSName, InnerDNSName: manifest.InnerDNSName, Files: viewFiles,
		}
		prepared.runtimeBytes, err = encodeRuntimeView(view)
		if err != nil {
			return fail(err)
		}

		if existing, openErr := runtimeRoot.OpenDir(prepared.generation); openErr == nil {
			prepared.generationExposed = true
			if err := verifyWriterGeneration(existing, viewFiles); err != nil {
				_ = existing.Close()
				return fail(err)
			}
			if err := existing.Close(); err != nil {
				return fail(err)
			}
		} else {
			stage, stageErr := runtimeRoot.OpenPrivateDir(prepared.generation)
			if stageErr != nil {
				stage, stageErr = runtimeRoot.MkdirPrivateExclusive(prepared.generation)
			}
			if stageErr != nil {
				return fail(stageErr)
			}
			for _, file := range files {
				if err := stage.ReplaceFile(filepath.Base(file.Path), file.Contents, 0o600); err != nil {
					_ = stage.Close()
					return fail(err)
				}
			}
			if err := stage.Sync(); err != nil {
				_ = stage.Close()
				return fail(err)
			}
			if err := stage.Close(); err != nil {
				return fail(err)
			}
		}
	}

	journal := viewJournal{
		Schema: viewJournalSchema, StateGeneration: next.StateGeneration, StateSHA256: prepared.stateDigest,
		AnchorViewSHA256: digestBytes(prepared.anchorBytes), Generation: prepared.generation,
		GenerationFiles: clonePresentStrings(prepared.generationFiles), PreviousGeneration: prepared.previousGeneration,
		PreviousGenerationFiles: clonePresentStrings(prepared.previousFiles),
	}
	if len(prepared.runtimeBytes) != 0 {
		journal.RuntimeViewSHA256 = digestBytes(prepared.runtimeBytes)
	}
	journalBytes, err := encodeViewJournal(journal)
	if err != nil {
		return fail(err)
	}
	markerBytes, err := encodeTransitionMarker(transitionMarker{
		Schema: transitionSchema, StateGeneration: next.StateGeneration, StateSHA256: prepared.stateDigest,
		AnchorViewSHA256: journal.AnchorViewSHA256, RuntimeViewSHA256: journal.RuntimeViewSHA256,
	})
	if err != nil {
		return fail(err)
	}
	if err := privateRoot.ReplaceFile(transactionViewFile, journalBytes, 0o600); err != nil {
		return fail(err)
	}
	// The visible marker is durable before any future generation is placed in
	// the group-readable tree. It remains until every view and retirement step
	// has completed, so a crash always leaves runtime startup fail closed.
	if err := runtimeRoot.ReplaceFile(transitionFile, markerBytes); err != nil {
		return fail(err)
	}
	return prepared, nil
}

func publishPreparedViews(prepared preparedViews, runtimeRoot, anchorRoot *securefs.ViewWriter) error {
	if runtimeRoot == nil && anchorRoot == nil {
		return nil
	}
	if runtimeRoot == nil || anchorRoot == nil {
		return errors.New("enrollmenttarget: runtime publication roots are incomplete")
	}
	if err := anchorRoot.ReplaceFile(anchorViewFile, prepared.anchorBytes); err != nil {
		return err
	}
	if len(prepared.runtimeBytes) != 0 {
		if !prepared.generationExposed {
			if err := runtimeRoot.ExposeDir(prepared.generation, prepared.generationFiles); err != nil {
				return err
			}
		}
	}
	if prepared.previousGeneration != "" && prepared.previousGeneration != prepared.generation {
		if err := runtimeRoot.RetireDir(prepared.previousGeneration, prepared.previousFiles); err != nil {
			return err
		}
	}
	// Select the new runtime generation only after it is complete and every
	// previous generation has been retired. With the transition marker and
	// exclusive gate still held, a crash before this replacement remains fail
	// closed and recovery can resume retirement from the old selector. Once the
	// selector changes, there is no old group-readable credential tree left for
	// recovery to forget.
	if len(prepared.runtimeBytes) != 0 {
		if err := runtimeRoot.ReplaceFile(runtimeViewFile, prepared.runtimeBytes); err != nil {
			return err
		}
	}
	if err := runtimeRoot.UnlinkFile(transitionFile); err != nil {
		return fmt.Errorf("enrollmenttarget: clear activation transition: %w", err)
	}
	return nil
}

func privateRecordForState(root *securefs.Root, state localstate.State) (recordManifest, map[string][]byte, error) {
	name, err := recordDirectoryName(state.ActiveRecordID)
	if err != nil {
		return recordManifest{}, nil, err
	}
	record, err := root.OpenDir(name)
	if err != nil {
		return recordManifest{}, nil, err
	}
	defer record.Close()
	return readAndVerifyRecord(record, state)
}

func verifyWriterGeneration(root *securefs.ViewWriter, files []recordFileDigest) error {
	if root == nil {
		return errors.New("enrollmenttarget: published generation is unavailable")
	}
	names := digestNames(files)
	if err := root.ValidateExactFiles(names); err != nil {
		return err
	}
	for _, file := range files {
		contents, err := root.ReadFile(file.Name, securefs.MaxReadBytes)
		if err != nil {
			return err
		}
		if int64(len(contents)) != file.Size || digestBytes(contents) != file.SHA256 {
			return fmt.Errorf("enrollmenttarget: published runtime file %q does not match its manifest", file.Name)
		}
	}
	return nil
}

func selectionForState(state localstate.State, encoded []byte) anchoredSelection {
	return anchoredSelection{
		Role: state.Role, InstallationID: state.InstallationID, StateGeneration: state.StateGeneration,
		StateSHA256: digestBytes(encoded), RecordID: state.ActiveRecordID, RecordSHA256: state.ActiveRecordSHA256,
	}
}

func anchorViewForState(state localstate.State, encoded []byte) anchorView {
	return anchorView{Schema: anchorViewSchema, anchoredSelection: selectionForState(state, encoded)}
}

func (selection anchoredSelection) validate() error {
	if selection.StateGeneration == 0 || validateNonzeroID(selection.InstallationID) != nil || !validDigest(selection.StateSHA256) {
		return errors.New("enrollmenttarget: anchored runtime selection is invalid")
	}
	if selection.Role != localstate.RoleClient && selection.Role != localstate.RoleConnector && selection.Role != localstate.RoleRelay {
		return errors.New("enrollmenttarget: anchored runtime role is invalid")
	}
	if (selection.RecordID == "") != (selection.RecordSHA256 == "") {
		return errors.New("enrollmenttarget: anchored runtime record binding is incomplete")
	}
	if selection.RecordID != "" && (validateNonzeroID(selection.RecordID) != nil || !validDigest(selection.RecordSHA256)) {
		return errors.New("enrollmenttarget: anchored runtime record binding is invalid")
	}
	return nil
}

func (view runtimeView) validate() error {
	if view.Schema != runtimeViewSchema || view.anchoredSelection.validate() != nil || view.RecordID == "" ||
		view.Generation != generationName(view.StateGeneration, view.StateSHA256) || view.CredentialSequence == 0 ||
		validateNonzeroID(view.ConnectorInstallationID) != nil || view.RouteID == "" || view.OuterDNSName == "" {
		return errors.New("enrollmenttarget: runtime view is invalid")
	}
	if len(view.Files) == 0 || len(view.Files) > 16 {
		return errors.New("enrollmenttarget: runtime view file set is invalid")
	}
	seen := make(map[string]struct{}, len(view.Files))
	for index, file := range view.Files {
		if file.Name == "" || filepath.Base(file.Name) != file.Name || file.Size <= 0 || file.Size > securefs.MaxReadBytes || !validDigest(file.SHA256) {
			return errors.New("enrollmenttarget: runtime view file is invalid")
		}
		if _, duplicate := seen[file.Name]; duplicate || index > 0 && view.Files[index-1].Name >= file.Name {
			return errors.New("enrollmenttarget: runtime view files are not sorted and unique")
		}
		seen[file.Name] = struct{}{}
	}
	return nil
}

func encodeRuntimeView(view runtimeView) ([]byte, error) {
	if err := view.validate(); err != nil {
		return nil, err
	}
	return encodeBoundedJSON(view, maxRuntimeView, "runtime view")
}

func decodeRuntimeView(encoded []byte) (runtimeView, error) {
	if len(encoded) == 0 || len(encoded) > maxRuntimeView {
		return runtimeView{}, errors.New("enrollmenttarget: runtime view size is invalid")
	}
	var view runtimeView
	if err := strictjson.Decode(encoded, &view); err != nil {
		return runtimeView{}, fmt.Errorf("enrollmenttarget: decode runtime view: %w", err)
	}
	if err := view.validate(); err != nil {
		return runtimeView{}, err
	}
	return view, nil
}

func encodeAnchorView(view anchorView) ([]byte, error) {
	if view.Schema != anchorViewSchema || view.anchoredSelection.validate() != nil {
		return nil, errors.New("enrollmenttarget: anchor view is invalid")
	}
	return encodeBoundedJSON(view, maxRollbackAnchor, "anchor view")
}

func decodeAnchorView(encoded []byte) (anchorView, error) {
	if len(encoded) == 0 || len(encoded) > maxRollbackAnchor {
		return anchorView{}, errors.New("enrollmenttarget: anchor view size is invalid")
	}
	var view anchorView
	if err := strictjson.Decode(encoded, &view); err != nil {
		return anchorView{}, fmt.Errorf("enrollmenttarget: decode anchor view: %w", err)
	}
	if view.Schema != anchorViewSchema || view.anchoredSelection.validate() != nil {
		return anchorView{}, errors.New("enrollmenttarget: anchor view is invalid")
	}
	return view, nil
}

func encodeViewJournal(journal viewJournal) ([]byte, error) {
	if journal.Schema != viewJournalSchema || journal.StateGeneration == 0 || !validDigest(journal.StateSHA256) ||
		!validDigest(journal.AnchorViewSHA256) || (journal.RuntimeViewSHA256 == "") != (journal.Generation == "") ||
		journal.RuntimeViewSHA256 != "" && !validDigest(journal.RuntimeViewSHA256) {
		return nil, errors.New("enrollmenttarget: view transaction journal is invalid")
	}
	return encodeBoundedJSON(journal, maxViewJournal, "view transaction journal")
}

func encodeTransitionMarker(marker transitionMarker) ([]byte, error) {
	if marker.Schema != transitionSchema || marker.StateGeneration == 0 || !validDigest(marker.StateSHA256) ||
		!validDigest(marker.AnchorViewSHA256) || marker.RuntimeViewSHA256 != "" && !validDigest(marker.RuntimeViewSHA256) {
		return nil, errors.New("enrollmenttarget: activation transition marker is invalid")
	}
	return encodeBoundedJSON(marker, maxTransitionMarker, "activation transition marker")
}

func encodeBoundedJSON(value any, maximum int, name string) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("enrollmenttarget: encode %s: %w", name, err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximum {
		return nil, fmt.Errorf("enrollmenttarget: %s exceeds its size limit", name)
	}
	return encoded, nil
}

func generationName(generation uint64, stateDigest string) string {
	prefix := "invalid"
	if len(stateDigest) >= 16 {
		prefix = stateDigest[:16]
	}
	return fmt.Sprintf("generation-%020d-%s", generation, prefix)
}

func digestNames(files []recordFileDigest) []string {
	result := make([]string, len(files))
	for index, file := range files {
		result[index] = file.Name
	}
	return result
}

func selectionsEqual(left, right anchoredSelection) bool { return left == right }

func exactViewRoots(runtimeRoot, anchorRoot string) error {
	if runtimeRoot == "" || anchorRoot == "" || !filepath.IsAbs(runtimeRoot) || !filepath.IsAbs(anchorRoot) ||
		filepath.Clean(runtimeRoot) != runtimeRoot || filepath.Clean(anchorRoot) != anchorRoot ||
		runtimeRoot == anchorRoot || pathContains(runtimeRoot, anchorRoot) || pathContains(anchorRoot, runtimeRoot) ||
		strings.ContainsRune(runtimeRoot, 0) || strings.ContainsRune(anchorRoot, 0) {
		return errors.New("enrollmenttarget: runtime and anchor-view roots must be canonical, distinct and non-nested")
	}
	return nil
}
