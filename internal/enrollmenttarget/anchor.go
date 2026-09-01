//go:build darwin || linux

package enrollmenttarget

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/sentrybottale/owntransit/internal/localstate"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	rollbackAnchorSchema = "owntransit.rollback-anchor.v1"
	rollbackAnchorFile   = "anchor.json"
	transactionStateFile = "transaction-state.json"
	maxRollbackAnchor    = 64 << 10
)

// rollbackAnchor lives in a distinct installer-owned root. It binds the exact
// state bytes, not merely counters, so restoring state.json cannot forget a
// consumed request, tombstone, verifier root, floor, or active record tuple.
type rollbackAnchor struct {
	Schema          string          `json:"schema"`
	Role            localstate.Role `json:"role"`
	InstallationID  string          `json:"installation_id"`
	StateGeneration uint64          `json:"state_generation"`
	StateSHA256     string          `json:"state_sha256"`
}

// RecoveryResult describes completion of an interrupted anchor-first local
// transaction. It contains no private material.
type RecoveryResult struct {
	Recovered       bool
	StateGeneration uint64
	StateSHA256     string
}

func createRollbackAnchor(stateRootPath, anchorRootPath string, state localstate.State) (*securefs.Root, error) {
	if err := validateSeparateRoots(stateRootPath, anchorRootPath); err != nil {
		return nil, err
	}
	encodedState, err := localstate.Encode(state)
	if err != nil {
		return nil, err
	}
	encodedAnchor, err := encodeRollbackAnchor(anchorForState(state, encodedState))
	if err != nil {
		return nil, err
	}
	root, err := securefs.CreateRoot(anchorRootPath)
	if err != nil {
		return nil, fmt.Errorf("enrollmenttarget: create rollback anchor root: %w", err)
	}
	if err := root.CreateExclusive(rollbackAnchorFile, encodedAnchor, 0o600); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func readAnchoredState(root *securefs.Root) (localstate.State, string, error) {
	encoded, err := root.ReadFile(stateFile, localstate.MaxStateSize)
	if err != nil {
		return localstate.State{}, "", err
	}
	state, err := localstate.Decode(encoded)
	if err != nil {
		return localstate.State{}, "", err
	}
	bootstrap, err := readBootstrapRecord(root)
	if err != nil {
		return localstate.State{}, "", err
	}
	anchor, err := readRollbackAnchor(bootstrap.RollbackAnchorRoot)
	if err != nil {
		return localstate.State{}, "", err
	}
	digest := digestBytes(encoded)
	if err := anchor.validateForState(state, digest); err != nil {
		return localstate.State{}, "", err
	}
	return state, digest, nil
}

func commitAnchoredState(root *securefs.Root, previous, next localstate.State, boundary *lifecycleBoundary) error {
	current, _, err := readAnchoredState(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, previous) {
		return errors.New("enrollmenttarget: durable state changed before compare-and-swap commit")
	}
	if err := localstate.ValidateTransition(previous, next); err != nil {
		return err
	}
	nextBytes, err := localstate.Encode(next)
	if err != nil {
		return err
	}
	bootstrap, err := readBootstrapRecord(root)
	if err != nil {
		return err
	}
	ownedBoundary := false
	if boundary == nil {
		boundary, err = acquireLifecycleBoundary(root)
		if err != nil {
			return err
		}
		ownedBoundary = true
	}
	if ownedBoundary {
		defer boundary.Close()
	}
	if err := boundary.validateFor(bootstrap); err != nil {
		return err
	}
	prepared, err := prepareViewCommit(root, bootstrap, next, nextBytes, boundary)
	if err != nil {
		return err
	}
	if boundary.runtimeRoot == nil {
		// Private-only source tests retain the original journal path. Packaged
		// activation writes it inside prepareViewCommit after acquiring the
		// cross-principal exclusive gate.
		if err := root.ReplaceFile(transactionStateFile, nextBytes, 0o600); err != nil {
			return err
		}
	}
	anchorRoot, err := securefs.OpenRoot(bootstrap.RollbackAnchorRoot)
	if err != nil {
		return fmt.Errorf("enrollmenttarget: open rollback anchor root: %w", err)
	}
	defer anchorRoot.Close()

	// Once the anchor advances, old state is intentionally rejected; recovery
	// can only install the exact transition journal written above.
	anchorBytes, err := encodeRollbackAnchor(anchorForState(next, nextBytes))
	if err != nil {
		return err
	}
	if err := anchorRoot.ReplaceFile(rollbackAnchorFile, anchorBytes, 0o600); err != nil {
		return err
	}
	if err := root.ReplaceFile(stateFile, nextBytes, 0o600); err != nil {
		return err
	}
	if err := publishPreparedViews(prepared, boundary.runtimeRoot, boundary.anchorRoot); err != nil {
		return fmt.Errorf("enrollmenttarget: publish read-only runtime views: %w", err)
	}
	// Cleanup is best-effort and never security-sensitive. The anchor already
	// selects the committed state exactly and the transition marker was cleared
	// only after both read-only views and retirement completed.
	_ = root.UnlinkFile(transactionStateFile)
	_ = root.UnlinkFile(transactionViewFile)
	return nil
}

// RecoverTransaction finishes an interrupted anchor-first commit and repairs
// the two read-only publication views. It cannot select an arbitrary state:
// when the authoritative anchor is ahead, the journal bytes must hash to that
// anchor and be exactly one valid transition from the current private state.
// When the anchor still selects current state, recovery aborts any pre-anchor
// attempt and republishes current state instead of completing it.
func RecoverTransaction(rootPath string) (RecoveryResult, error) {
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return RecoveryResult{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return RecoveryResult{}, err
	}
	defer lock.Close()

	currentBytes, err := root.ReadFile(stateFile, localstate.MaxStateSize)
	if err != nil {
		return RecoveryResult{}, err
	}
	current, err := localstate.Decode(currentBytes)
	if err != nil {
		return RecoveryResult{}, err
	}
	bootstrap, err := readBootstrapRecord(root)
	if err != nil {
		return RecoveryResult{}, err
	}
	boundary, err := acquireLifecycleBoundary(root)
	if err != nil {
		return RecoveryResult{}, err
	}
	defer boundary.Close()
	if err := boundary.validateFor(bootstrap); err != nil {
		return RecoveryResult{}, err
	}
	anchor, err := readRollbackAnchor(bootstrap.RollbackAnchorRoot)
	if err != nil {
		return RecoveryResult{}, err
	}
	currentDigest := digestBytes(currentBytes)
	target := current
	targetBytes := currentBytes
	targetDigest := currentDigest
	stateRecovered := false
	if anchor.validateForState(current, currentDigest) != nil {
		nextBytes, readErr := root.ReadFile(transactionStateFile, localstate.MaxStateSize)
		if readErr != nil {
			return RecoveryResult{}, errors.New("enrollmenttarget: rollback anchor is ahead but no exact recovery journal is available")
		}
		next, decodeErr := localstate.Decode(nextBytes)
		if decodeErr != nil {
			return RecoveryResult{}, fmt.Errorf("enrollmenttarget: recovery journal: %w", decodeErr)
		}
		nextDigest := digestBytes(nextBytes)
		if err := anchor.validateForState(next, nextDigest); err != nil {
			return RecoveryResult{}, errors.New("enrollmenttarget: recovery journal does not match the external rollback anchor")
		}
		if err := localstate.ValidateTransition(current, next); err != nil {
			return RecoveryResult{}, fmt.Errorf("enrollmenttarget: recovery transition: %w", err)
		}
		target = next
		targetBytes = nextBytes
		targetDigest = nextDigest
		stateRecovered = true
	}

	prepared, err := prepareViewCommit(root, bootstrap, target, targetBytes, boundary)
	if err != nil {
		return RecoveryResult{}, err
	}
	if stateRecovered {
		if err := root.ReplaceFile(stateFile, targetBytes, 0o600); err != nil {
			return RecoveryResult{}, err
		}
	}
	if err := publishPreparedViews(prepared, boundary.runtimeRoot, boundary.anchorRoot); err != nil {
		return RecoveryResult{}, fmt.Errorf("enrollmenttarget: repair read-only runtime views: %w", err)
	}
	_ = root.UnlinkFile(transactionStateFile)
	_ = root.UnlinkFile(transactionViewFile)
	return RecoveryResult{
		Recovered:       stateRecovered,
		StateGeneration: target.StateGeneration,
		StateSHA256:     targetDigest,
	}, nil
}

func readRollbackAnchor(path string) (rollbackAnchor, error) {
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return rollbackAnchor{}, fmt.Errorf("enrollmenttarget: open rollback anchor root: %w", err)
	}
	defer root.Close()
	encoded, err := root.ReadFile(rollbackAnchorFile, maxRollbackAnchor)
	if err != nil {
		return rollbackAnchor{}, err
	}
	var anchor rollbackAnchor
	if err := strictjson.Decode(encoded, &anchor); err != nil {
		return rollbackAnchor{}, fmt.Errorf("enrollmenttarget: decode rollback anchor: %w", err)
	}
	if anchor.Schema != rollbackAnchorSchema || anchor.StateGeneration == 0 || !validDigest(anchor.StateSHA256) {
		return rollbackAnchor{}, errors.New("enrollmenttarget: rollback anchor is invalid")
	}
	return anchor, nil
}

func anchorForState(state localstate.State, encoded []byte) rollbackAnchor {
	return rollbackAnchor{
		Schema: rollbackAnchorSchema, Role: state.Role, InstallationID: state.InstallationID,
		StateGeneration: state.StateGeneration, StateSHA256: digestBytes(encoded),
	}
}

func encodeRollbackAnchor(anchor rollbackAnchor) ([]byte, error) {
	if anchor.Schema != rollbackAnchorSchema || anchor.StateGeneration == 0 || !validDigest(anchor.StateSHA256) {
		return nil, errors.New("enrollmenttarget: rollback anchor is invalid")
	}
	encoded, err := json.Marshal(anchor)
	if err != nil {
		return nil, fmt.Errorf("enrollmenttarget: encode rollback anchor: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxRollbackAnchor {
		return nil, errors.New("enrollmenttarget: rollback anchor exceeds its size limit")
	}
	return encoded, nil
}

func (anchor rollbackAnchor) validateForState(state localstate.State, digest string) error {
	if anchor.Schema != rollbackAnchorSchema || anchor.Role != state.Role || anchor.InstallationID != state.InstallationID ||
		anchor.StateGeneration != state.StateGeneration || anchor.StateSHA256 != digest {
		return errors.New("enrollmenttarget: durable state does not match the external rollback anchor")
	}
	return nil
}

func validateSeparateRoots(stateRoot, anchorRoot string) error {
	if err := validateAnchorRootPath(anchorRoot); err != nil {
		return err
	}
	stateRoot = filepath.Clean(stateRoot)
	if !filepath.IsAbs(stateRoot) || stateRoot == string(filepath.Separator) || stateRoot == anchorRoot || pathContains(stateRoot, anchorRoot) || pathContains(anchorRoot, stateRoot) {
		return errors.New("enrollmenttarget: state and rollback-anchor roots must be distinct and non-nested")
	}
	return nil
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
