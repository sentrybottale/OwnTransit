//go:build darwin || linux

package packagetxn

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// RuntimeIdentity is the authenticated identity of the currently selected
// role artifact. It is derived from the anchored package selector and exact
// installed receipt, never from an enrollment invitation or caller flag.
type RuntimeIdentity struct {
	ReleaseID       string
	ReleaseSequence uint64
	ArtifactSHA256  string
	LauncherSHA256  string
	OS              string
	Arch            string
	Role            string
}

// WithCurrentRuntimeIdentity verifies one exact current role runtime, then
// invokes operation while both the external-anchor and descriptor-bound role
// transaction locks remain held. Lock acquisition is nonblocking: a concurrent
// Apply, Rollback, Recover, or another guarded operation returns ErrLocked.
//
// The callback is intentionally the only lease surface. It receives no file
// descriptor or unlock capability and must complete its finite local operation
// before returning; callers must not retain the identity as authorization for a
// later mutation.
func (manager *Manager) WithCurrentRuntimeIdentity(operation func(RuntimeIdentity) error) error {
	if manager == nil {
		return errors.New("packagetxn: package manager is nil")
	}
	if manager.self != manager {
		return errors.New("packagetxn: copied package manager handle is invalid")
	}
	if operation == nil {
		return errors.New("packagetxn: current-runtime operation is required")
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if err := manager.requireLifecycleManager(); err != nil {
		return err
	}
	anchorRoleFD, anchorLock, err := manager.lockAnchorRole()
	if err != nil {
		return err
	}
	defer unix.Close(anchorRoleFD)
	defer anchorLock.close()

	anchor, _, anchorDigest, err := manager.readPackageAnchor(anchorRoleFD)
	if err != nil {
		return err
	}
	roleFD, err := ensurePackageDirectory(manager.rootFD, manager.role, manager)
	if err != nil {
		return err
	}
	defer unix.Close(roleFD)
	roleLock, err := acquireDescriptorLock(roleFD, lockFileName, manager.ownerUID, manager.ownerGID, manager.checkACL, manager.lockOpenHook)
	if err != nil {
		return err
	}
	defer roleLock.close()

	snapshot, err := manager.readLifecycleSnapshotLocked(roleFD)
	if err != nil {
		return err
	}
	if err := validateAnchorAgainstSnapshot(anchor, anchorDigest, snapshot.state); err != nil {
		return err
	}
	if snapshot.currentReceipt == nil || snapshot.runningReceipt == nil ||
		snapshot.state.selector.Current == "" || snapshot.state.activeReleaseID != snapshot.state.selector.Current ||
		snapshot.currentReceipt.ReleaseID != snapshot.runningReceipt.ReleaseID {
		return errors.New("packagetxn: no single authenticated current runtime is selected")
	}
	if err := manager.verifyRunningLifecycle(snapshot, decision{}); err != nil {
		return err
	}
	identity, err := runtimeIdentityFromReceipt(*snapshot.currentReceipt)
	if err != nil {
		return err
	}
	return operation(identity)
}

func runtimeIdentityFromReceipt(receipt receiptRecord) (RuntimeIdentity, error) {
	artifactName, err := artifactNameForRole(receipt.Role, receipt.OS, receipt.Arch)
	if err != nil {
		return RuntimeIdentity{}, err
	}
	artifactDigest := ""
	for _, file := range receipt.Files {
		if file.ArtifactName != artifactName {
			continue
		}
		if artifactDigest != "" && artifactDigest != file.SHA256 {
			return RuntimeIdentity{}, errors.New("packagetxn: selected role artifact copies have different digests")
		}
		artifactDigest = file.SHA256
	}
	if !validDigest(artifactDigest) {
		return RuntimeIdentity{}, fmt.Errorf("packagetxn: authenticated %s artifact is absent from the current receipt", artifactName)
	}
	launcherDigest := ""
	if receipt.Role == "client" && receipt.OS == "darwin" && receipt.Arch == "arm64" {
		for _, file := range receipt.Files {
			if file.ArtifactName != "launcher-darwin-arm64" {
				continue
			}
			if launcherDigest != "" || file.Name != "owntransit" || file.Mode != 0o2751 || file.GID == 0 {
				return RuntimeIdentity{}, errors.New("packagetxn: selected Darwin client launcher receipt is invalid or duplicated")
			}
			launcherDigest = file.SHA256
		}
		if !validDigest(launcherDigest) {
			return RuntimeIdentity{}, errors.New("packagetxn: authenticated Darwin client launcher is absent from the current receipt")
		}
	}
	return RuntimeIdentity{
		ReleaseID: receipt.ReleaseID, ReleaseSequence: receipt.Sequence,
		ArtifactSHA256: artifactDigest, LauncherSHA256: launcherDigest,
		OS: receipt.OS, Arch: receipt.Arch, Role: receipt.Role,
	}, nil
}
