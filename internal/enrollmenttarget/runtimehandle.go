//go:build darwin || linux

package enrollmenttarget

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/sentrybottale/owntransit/internal/activationlock"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

// RuntimeGenerationHandle holds only group-readable publication descriptors.
// It has no path or descriptor to private lifecycle state or the authoritative
// rollback anchor. The shared activation lock remains held until Close.
type RuntimeGenerationHandle struct {
	mu          sync.Mutex
	runtimeRoot *securefs.ReadOnlyRoot
	anchorRoot  *securefs.ReadOnlyRoot
	generation  *securefs.ReadOnlyRoot
	activation  *securefs.ViewLock
	view        runtimeView
	anchor      anchorView
	viewBytes   []byte
	anchorBytes []byte
	contents    map[string][]byte
	directory   string
	closed      bool
}

// OpenRuntimeGeneration opens explicit runtime and anchor views under one
// exact non-root primary reader GID. The runtime root is locked shared before
// any selection bytes are read, so lifecycle mutation and runtime startup are
// mutually exclusive.
func OpenRuntimeGeneration(runtimeRootPath, anchorViewRootPath string, readerGID int, expected enrollment.Role) (*RuntimeGenerationHandle, error) {
	if err := exactViewRoots(runtimeRootPath, anchorViewRootPath); err != nil {
		return nil, err
	}
	runtimeRoot, err := securefs.OpenReadOnlyRoot(runtimeRootPath, readerGID)
	if err != nil {
		return nil, err
	}
	failRuntime := func(value error) (*RuntimeGenerationHandle, error) {
		_ = runtimeRoot.Close()
		return nil, value
	}
	activation, err := activationlock.AcquireShared(runtimeRoot)
	if err != nil {
		return failRuntime(err)
	}
	failLocked := func(value error) (*RuntimeGenerationHandle, error) {
		_ = activation.Close()
		return failRuntime(value)
	}
	if err := requireNoTransition(runtimeRoot); err != nil {
		return failLocked(err)
	}
	anchorRoot, err := securefs.OpenReadOnlyRoot(anchorViewRootPath, readerGID)
	if err != nil {
		return failLocked(err)
	}
	failRoots := func(value error) (*RuntimeGenerationHandle, error) {
		_ = anchorRoot.Close()
		return failLocked(value)
	}

	anchorBytes, err := anchorRoot.ReadFile(anchorViewFile, maxRollbackAnchor)
	if err != nil {
		return failRoots(err)
	}
	anchor, err := decodeAnchorView(anchorBytes)
	if err != nil {
		return failRoots(err)
	}
	viewBytes, err := runtimeRoot.ReadFile(runtimeViewFile, maxRuntimeView)
	if err != nil {
		return failRoots(err)
	}
	view, err := decodeRuntimeView(viewBytes)
	if err != nil {
		return failRoots(err)
	}
	if !selectionsEqual(view.anchoredSelection, anchor.anchoredSelection) {
		return failRoots(errors.New("enrollmenttarget: runtime and anchor views select different anchored state"))
	}
	role, err := enrollmentRole(view.Role)
	if err != nil || role != expected {
		return failRoots(errors.New("enrollmenttarget: runtime view role does not match requested runtime"))
	}
	generation, err := runtimeRoot.OpenDir(view.Generation)
	if err != nil {
		return failRoots(err)
	}
	failGeneration := func(value error) (*RuntimeGenerationHandle, error) {
		_ = generation.Close()
		return failRoots(value)
	}
	contents, err := readRuntimeGeneration(generation, view.Files)
	if err != nil {
		return failGeneration(err)
	}
	directory := filepath.Join(runtimeRootPath, view.Generation)
	handle := &RuntimeGenerationHandle{
		runtimeRoot: runtimeRoot, anchorRoot: anchorRoot, generation: generation, activation: activation,
		view: view, anchor: anchor, viewBytes: viewBytes, anchorBytes: anchorBytes,
		contents: contents, directory: directory,
	}
	if err := handle.FinalCheck(); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return handle, nil
}

func requireNoTransition(root *securefs.ReadOnlyRoot) error {
	_, err := root.ReadFile(transitionFile, maxTransitionMarker)
	if err == nil {
		return errors.New("enrollmenttarget: an incomplete lifecycle transition blocks runtime startup")
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return fmt.Errorf("enrollmenttarget: inspect activation transition: %w", err)
}

func readRuntimeGeneration(root *securefs.ReadOnlyRoot, files []recordFileDigest) (map[string][]byte, error) {
	names := digestNames(files)
	if err := root.ValidateExactFiles(names); err != nil {
		return nil, err
	}
	contents := make(map[string][]byte, len(files))
	for _, file := range files {
		value, err := root.ReadFile(file.Name, securefs.MaxReadBytes)
		if err != nil {
			return nil, err
		}
		if int64(len(value)) != file.Size || digestBytes(value) != file.SHA256 {
			return nil, fmt.Errorf("enrollmenttarget: runtime file %q does not match its active manifest", file.Name)
		}
		contents[file.Name] = value
	}
	return contents, nil
}

func (handle *RuntimeGenerationHandle) ClientConfig() (config.Client, error) {
	if handle == nil {
		return config.Client{}, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return config.Client{}, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	role, _ := enrollmentRole(handle.view.Role)
	if role != enrollment.RoleClient {
		return config.Client{}, errors.New("enrollmenttarget: runtime view is not a client")
	}
	value, err := config.ParseClient(handle.contents[runtimeConfigFile])
	if err != nil {
		return config.Client{}, err
	}
	if value.InstallationID != handle.view.InstallationID || value.ConnectorInstallationID != handle.view.ConnectorInstallationID ||
		value.RouteID != handle.view.RouteID || value.CredentialEpoch != handle.view.CredentialSequence ||
		value.OuterTLS.LocalDNSName != handle.view.OuterDNSName || value.InnerTLS.LocalDNSName != handle.view.InnerDNSName {
		return config.Client{}, errors.New("enrollmenttarget: runtime client config does not match anchored selection")
	}
	if err := validateClientRuntimePaths(value, handle.directory); err != nil {
		return config.Client{}, err
	}
	return value, nil
}

func (handle *RuntimeGenerationHandle) ConnectorConfig() (config.Connector, error) {
	if handle == nil {
		return config.Connector{}, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return config.Connector{}, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	role, _ := enrollmentRole(handle.view.Role)
	if role != enrollment.RoleConnector {
		return config.Connector{}, errors.New("enrollmenttarget: runtime view is not a connector")
	}
	value, err := config.ParseConnector(handle.contents[runtimeConfigFile])
	if err != nil {
		return config.Connector{}, err
	}
	if value.InstallationID != handle.view.InstallationID || value.RouteID != handle.view.RouteID ||
		value.SSHTarget != config.ConnectorSSHTarget || value.OuterTLS.LocalDNSName != handle.view.OuterDNSName ||
		value.InnerTLS.LocalDNSName != handle.view.InnerDNSName {
		return config.Connector{}, errors.New("enrollmenttarget: runtime connector config does not match anchored selection or build target")
	}
	if err := validateConnectorRuntimePaths(value, handle.directory); err != nil {
		return config.Connector{}, err
	}
	return value, nil
}

func (handle *RuntimeGenerationHandle) RelayConfig() (config.Relay, error) {
	if handle == nil {
		return config.Relay{}, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return config.Relay{}, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	role, _ := enrollmentRole(handle.view.Role)
	if role != enrollment.RoleRelay {
		return config.Relay{}, errors.New("enrollmenttarget: runtime view is not a relay")
	}
	value, err := config.ParseRelay(handle.contents[runtimeConfigFile])
	if err != nil {
		return config.Relay{}, err
	}
	if value.Listen != enrollment.PackagedRelayListen || len(value.Routes) != 1 || value.Routes[0].RouteID != handle.view.RouteID || value.OuterTLS.LocalDNSName != handle.view.OuterDNSName {
		return config.Relay{}, errors.New("enrollmenttarget: runtime relay config does not match anchored selection")
	}
	if err := validateRelayRuntimePaths(value, handle.directory); err != nil {
		return config.Relay{}, err
	}
	return value, nil
}

func (handle *RuntimeGenerationHandle) ReadMaterial(path string) ([]byte, error) {
	if handle == nil {
		return nil, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil, errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	if path == "" || filepath.Clean(path) != path || filepath.Dir(path) != handle.directory {
		return nil, errors.New("enrollmenttarget: runtime material path is outside the held generation")
	}
	value, ok := handle.contents[filepath.Base(path)]
	if !ok {
		return nil, errors.New("enrollmenttarget: runtime material is absent from the active manifest")
	}
	return append([]byte(nil), value...), nil
}

// FinalCheck repeats selection, anchor, exact file-set, byte and held-root
// validation while the shared activation gate remains held. Call it immediately
// before the first network operation.
func (handle *RuntimeGenerationHandle) FinalCheck() error {
	if handle == nil {
		return errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return errors.New("enrollmenttarget: runtime generation handle is closed")
	}
	if err := requireNoTransition(handle.runtimeRoot); err != nil {
		return err
	}
	viewBytes, err := handle.runtimeRoot.ReadFile(runtimeViewFile, maxRuntimeView)
	if err != nil || !bytes.Equal(viewBytes, handle.viewBytes) {
		return errors.New("enrollmenttarget: runtime selection changed after validation")
	}
	anchorBytes, err := handle.anchorRoot.ReadFile(anchorViewFile, maxRollbackAnchor)
	if err != nil || !bytes.Equal(anchorBytes, handle.anchorBytes) {
		return errors.New("enrollmenttarget: anchor view changed after validation")
	}
	contents, err := readRuntimeGeneration(handle.generation, handle.view.Files)
	if err != nil {
		return err
	}
	for name, expected := range handle.contents {
		if !bytes.Equal(contents[name], expected) {
			return fmt.Errorf("enrollmenttarget: held runtime material %q changed after validation", name)
		}
	}
	for _, root := range []*securefs.ReadOnlyRoot{handle.generation, handle.anchorRoot, handle.runtimeRoot} {
		if err := root.Recheck(); err != nil {
			return err
		}
	}
	return nil
}

func (handle *RuntimeGenerationHandle) Close() error {
	if handle == nil {
		return nil
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil
	}
	handle.closed = true
	var first error
	for _, close := range []func() error{handle.generation.Close, handle.anchorRoot.Close, handle.activation.Close, handle.runtimeRoot.Close} {
		if err := close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
