//go:build darwin || linux

package enrollmenttarget

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/localstate"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

// GenerationHandle pins both the target root and selected record directory by
// descriptor. ConfigBytes and every manifest member were read through that
// descriptor; a pathname rename or substitution cannot change the held view.
// FinalCheck must run immediately before the first network operation.
type GenerationHandle struct {
	mu        sync.Mutex
	root      *securefs.Root
	record    *securefs.Root
	state     localstate.State
	manifest  recordManifest
	contents  map[string][]byte
	directory string
	closed    bool
}

func OpenActiveGeneration(rootPath string, expected enrollment.Role) (*GenerationHandle, error) {
	resolved, err := resolveActiveRoot(rootPath)
	if err != nil {
		return nil, err
	}
	root, err := securefs.OpenRoot(resolved)
	if err != nil {
		return nil, err
	}
	state, err := readState(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	role, err := enrollmentRole(state.Role)
	if err != nil || role != expected || state.ActiveRecordID == "" {
		_ = root.Close()
		return nil, errors.New("enrollmenttarget: target has no active generation for the requested role")
	}
	recordName, err := recordDirectoryName(state.ActiveRecordID)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	manifest, contents, err := readAndVerifyRecord(record, state)
	if err != nil {
		_ = record.Close()
		_ = root.Close()
		return nil, err
	}
	return &GenerationHandle{
		root: root, record: record, state: state, manifest: manifest, contents: contents,
		directory: filepath.Join(resolved, recordName),
	}, nil
}

func (handle *GenerationHandle) ConfigBytes() ([]byte, error) {
	if handle == nil {
		return nil, errors.New("enrollmenttarget: generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil, errors.New("enrollmenttarget: generation handle is closed")
	}
	return append([]byte(nil), handle.contents[runtimeConfigFile]...), nil
}

// ReadMaterial returns one manifest-verified generation member only when path
// is the exact canonical path rendered into this held generation. It never
// opens or stats the pathname.
func (handle *GenerationHandle) ReadMaterial(path string) ([]byte, error) {
	if handle == nil {
		return nil, errors.New("enrollmenttarget: generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil, errors.New("enrollmenttarget: generation handle is closed")
	}
	if path == "" || filepath.Clean(path) != path || filepath.Dir(path) != handle.directory {
		return nil, errors.New("enrollmenttarget: runtime material path is outside the held generation")
	}
	name := filepath.Base(path)
	contents, ok := handle.contents[name]
	if !ok {
		return nil, fmt.Errorf("enrollmenttarget: runtime material %q is absent from the held manifest", name)
	}
	return append([]byte(nil), contents...), nil
}

func (handle *GenerationHandle) Directory() (string, error) {
	if handle == nil {
		return "", errors.New("enrollmenttarget: generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return "", errors.New("enrollmenttarget: generation handle is closed")
	}
	return handle.directory, nil
}

// FinalCheck rejects any selection or lifecycle generation change since the
// handle was opened, and re-verifies the held directory rather than reopening
// its pathname.
func (handle *GenerationHandle) FinalCheck() error {
	if handle == nil {
		return errors.New("enrollmenttarget: generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return errors.New("enrollmenttarget: generation handle is closed")
	}
	current, err := readState(handle.root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, handle.state) {
		return errors.New("enrollmenttarget: active lifecycle state changed after generation validation")
	}
	manifest, _, err := readVerifiedRecord(handle.record, current.ActiveRecordSHA256)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(manifest, handle.manifest) {
		return errors.New("enrollmenttarget: held generation changed after validation")
	}
	return manifest.validateStateBinding(current)
}

func (handle *GenerationHandle) Close() error {
	if handle == nil {
		return nil
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil
	}
	handle.closed = true
	recordErr := handle.record.Close()
	rootErr := handle.root.Close()
	if recordErr != nil {
		return recordErr
	}
	return rootErr
}
