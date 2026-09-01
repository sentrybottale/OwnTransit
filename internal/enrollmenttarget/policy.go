//go:build darwin || linux

package enrollmenttarget

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/localstate"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/runtimebundle"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

// PolicyResult is a non-secret receipt for an authenticated verifier-first
// generation.
type PolicyResult struct {
	RecordID          string
	PolicySequence    uint64
	TombstoneSequence uint64
	StateGeneration   uint64
}

// ApplyLifecyclePolicy authenticates a target-bound offline policy, proves an
// overlap with every currently active verifier set, renders the policy into a
// new immutable generation, then commits its digest through the external
// rollback anchor before selecting it.
func ApplyLifecyclePolicy(rootPath string, encoded []byte, now time.Time) (PolicyResult, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || len(encoded) == 0 || len(encoded) > enrollment.MaxLifecyclePolicySize {
		return PolicyResult{}, errors.New("enrollmenttarget: bounded lifecycle policy and current time are required")
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return PolicyResult{}, err
	}
	defer root.Close()
	lock, err := root.TryLock(lockFile)
	if err != nil {
		return PolicyResult{}, err
	}
	defer lock.Close()
	boundary, err := acquireLifecycleBoundary(root)
	if err != nil {
		return PolicyResult{}, err
	}
	defer boundary.Close()
	state, stateDigest, err := readAnchoredState(root)
	if err != nil {
		return PolicyResult{}, err
	}
	if state.ActiveRecordID == "" || state.StateGeneration == math.MaxUint64 || state.PolicySequence == math.MaxUint64 {
		return PolicyResult{}, errors.New("enrollmenttarget: an enrolled target with available lifecycle sequence space is required")
	}
	bootstrap, signer, err := readBootstrap(root, state, now)
	if err != nil {
		return PolicyResult{}, err
	}
	policy, err := enrollment.VerifyLifecyclePolicy(encoded, signer, now)
	if err != nil {
		return PolicyResult{}, err
	}
	role, err := enrollmentRole(state.Role)
	if err != nil {
		return PolicyResult{}, err
	}
	if policy.Role != role || policy.InstallationID != state.InstallationID || policy.Sequence != state.PolicySequence+1 ||
		policy.ExpectedStateGeneration != state.StateGeneration || policy.ExpectedStateSHA256 != stateDigest {
		return PolicyResult{}, errors.New("enrollmenttarget: lifecycle policy does not bind the exact current target state")
	}

	manifest, contents, deployment, err := activeMaterial(root, state, now)
	if err != nil {
		return PolicyResult{}, err
	}
	if err := validatePolicyTrustTransition(deployment.Trust, policy.Trust, now); err != nil {
		return PolicyResult{}, err
	}
	renderPolicy, err := validateVerifierTransition(role, manifest, contents, policy, now)
	if err != nil {
		return PolicyResult{}, err
	}
	if !containsAllText(policy.RevokedClientInstallationIDs, state.RevokedClientInstallationIDs) ||
		!containsAllText(policy.RevokedClientSPKIPins, state.CredentialTombstoneSPKIPins) {
		return PolicyResult{}, errors.New("enrollmenttarget: signed policy attempted to remove a durable credential revocation")
	}
	if err := enrollment.RejectTombstonedCredentials(deployment, policy.RevokedClientSPKIPins); err != nil {
		return PolicyResult{}, errors.New("enrollmenttarget: signed policy tombstones a credential in the generation it would activate")
	}
	revocationsChanged := !reflect.DeepEqual(policy.RevokedClientInstallationIDs, state.RevokedClientInstallationIDs) ||
		!reflect.DeepEqual(policy.RevokedClientSPKIPins, state.CredentialTombstoneSPKIPins)
	nextTombstone := state.TombstoneSequence
	if revocationsChanged {
		nextTombstone = policy.Sequence
	}
	floors, err := advanceFloors(state, policy, nextTombstone)
	if err != nil {
		return PolicyResult{}, err
	}

	policyDigest := enrollment.LifecyclePolicySHA256(encoded)
	policyName := policyFileName(policy.Sequence)
	if err := root.EnsureFile(policyName, encoded, 0o600); err != nil {
		return PolicyResult{}, err
	}
	recordID, recordDigest, err := createDerivedRecord(rootPath, root, manifest, contents, deployment, renderPolicy, policy.Sequence, nextTombstone, now)
	if err != nil {
		return PolicyResult{}, err
	}
	next := state
	next.StateGeneration++
	next.PolicySequence = policy.Sequence
	next.PolicySHA256 = policyDigest
	next.TombstoneSequence = nextTombstone
	next.RollbackFloors = floors
	next.RevokedClientInstallationIDs = clonePresentStrings(policy.RevokedClientInstallationIDs)
	next.CredentialTombstoneSPKIPins = clonePresentStrings(policy.RevokedClientSPKIPins)
	next.ActiveRecordID, next.ActiveRecordSHA256 = recordID, recordDigest
	next.ActivePolicySequence, next.ActiveTombstoneSequence = policy.Sequence, nextTombstone
	if err := commitState(root, state, next, boundary); err != nil {
		return PolicyResult{}, err
	}
	_ = bootstrap // trust remains immutable bootstrap plus the signed stored policy.
	return PolicyResult{RecordID: recordID, PolicySequence: policy.Sequence, TombstoneSequence: nextTombstone, StateGeneration: next.StateGeneration}, nil
}

func effectiveLifecyclePolicy(root *securefs.Root, state localstate.State, bootstrap bootstrapRecord, signer ed25519.PublicKey) (enrollment.LifecyclePolicy, error) {
	if state.PolicySequence == 0 {
		return enrollment.LifecyclePolicy{Trust: bootstrap.Trust}, nil
	}
	encoded, err := root.ReadFile(policyFileName(state.PolicySequence), enrollment.MaxLifecyclePolicySize)
	if err != nil {
		return enrollment.LifecyclePolicy{}, err
	}
	if enrollment.LifecyclePolicySHA256(encoded) != state.PolicySHA256 {
		return enrollment.LifecyclePolicy{}, errors.New("enrollmenttarget: active lifecycle policy does not match durable state")
	}
	policy, err := enrollment.VerifyStoredLifecyclePolicy(encoded, signer)
	if err != nil {
		return enrollment.LifecyclePolicy{}, err
	}
	role, _ := enrollmentRole(state.Role)
	if policy.Role != role || policy.InstallationID != state.InstallationID || policy.Sequence != state.PolicySequence {
		return enrollment.LifecyclePolicy{}, errors.New("enrollmenttarget: stored lifecycle policy target binding is invalid")
	}
	return policy, nil
}

func policyFileName(sequence uint64) string { return fmt.Sprintf("policy-%020d.json", sequence) }

func validatePolicyTrustTransition(current, next enrollment.Trust, now time.Time) error {
	currentPins, err := enrollment.IssuerPinsFromTrust(current, now)
	if err != nil {
		return err
	}
	nextPins, err := enrollment.IssuerPinsFromTrust(next, now)
	if err != nil {
		return err
	}
	if currentPins.RelayAdmissionCA != nextPins.RelayAdmissionCA || currentPins.InnerConnectorCA != nextPins.InnerConnectorCA {
		return errors.New("enrollmenttarget: v1 lifecycle policy may rotate only the route-scoped client capability root")
	}
	return nil
}

func validateVerifierTransition(role enrollment.Role, manifest recordManifest, contents map[string][]byte, policy enrollment.LifecyclePolicy, now time.Time) (runtimebundle.VerifierPolicy, error) {
	result := runtimebundle.VerifierPolicy{
		CapabilityClientRoots: append([]string(nil), policy.CapabilityClientRoots...),
		RelayServerSPKIPins:   append([]string(nil), policy.RelayServerSPKIPins...),
		ConnectorSPKIPins:     append([]string(nil), policy.ConnectorSPKIPins...),
		RelayClients:          clonePeers(policy.RelayClients), RelayRoutes: cloneRoutes(policy.RelayRoutes),
	}
	configBytes := contents[runtimeConfigFile]
	switch role {
	case enrollment.RoleConnector:
		result.Revocations = runtimebundle.ConnectorRevocations{
			ClientIDs: append([]string(nil), policy.RevokedClientInstallationIDs...),
			SPKIPins:  append([]string(nil), policy.RevokedClientSPKIPins...),
		}
		current, err := config.ParseConnector(configBytes)
		if err != nil {
			return runtimebundle.VerifierPolicy{}, err
		}
		if !overlappingSetTransition(current.OuterTLS.SPKIPins, policy.RelayServerSPKIPins, 4) {
			return runtimebundle.VerifierPolicy{}, errors.New("enrollmenttarget: connector relay pins lack verifier-first overlap")
		}
		currentRoots := make([]string, len(current.InnerTLS.ClientCAFiles))
		for index, path := range current.InnerTLS.ClientCAFiles {
			value, ok := contents[filepath.Base(path)]
			if !ok {
				return runtimebundle.VerifierPolicy{}, errors.New("enrollmenttarget: active connector capability root is absent from its record")
			}
			currentRoots[index] = string(value)
		}
		currentPins, err := enrollment.CapabilityRootPins(currentRoots, now)
		if err != nil {
			return runtimebundle.VerifierPolicy{}, err
		}
		nextPins, err := enrollment.CapabilityRootPins(policy.CapabilityClientRoots, now)
		if err != nil || !rootRotationTransition(currentPins, nextPins) {
			return runtimebundle.VerifierPolicy{}, errors.New("enrollmenttarget: capability-root change is not a verifier-first add/retire transition")
		}
	case enrollment.RoleClient:
		current, err := config.ParseClient(configBytes)
		if err != nil {
			return runtimebundle.VerifierPolicy{}, err
		}
		if !overlappingSetTransition(current.OuterTLS.SPKIPins, policy.RelayServerSPKIPins, 4) ||
			!overlappingSetTransition(current.InnerTLS.SPKIPins, policy.ConnectorSPKIPins, 4) {
			return runtimebundle.VerifierPolicy{}, errors.New("enrollmenttarget: client peer pins lack verifier-first overlap")
		}
	case enrollment.RoleRelay:
		current, err := config.ParseRelay(configBytes)
		if err != nil {
			return runtimebundle.VerifierPolicy{}, err
		}
		if !relayVerifierTransition(current, policy.RelayClients, policy.RelayRoutes) {
			return runtimebundle.VerifierPolicy{}, errors.New("enrollmenttarget: relay authorization change lacks exact identity and pin overlap")
		}
	default:
		return runtimebundle.VerifierPolicy{}, errors.New("enrollmenttarget: unsupported policy role")
	}
	_ = manifest
	return result, nil
}

func advanceFloors(state localstate.State, policy enrollment.LifecyclePolicy, nextTombstone uint64) (localstate.RollbackFloors, error) {
	next := state.RollbackFloors
	values := []struct {
		desired          uint64
		current, highest *uint64
	}{
		{policy.Floors.DeploymentSequence, &next.DeploymentSequence, &state.HighestDeploymentSequence},
		{policy.Floors.ReleaseSequence, &next.ReleaseSequence, &state.HighestReleaseSequence},
		{policy.Floors.CredentialSequence, &next.CredentialSequence, &state.HighestCredentialSequence},
	}
	for _, value := range values {
		if value.desired == 0 {
			continue
		}
		if value.desired < *value.current || value.desired > *value.highest {
			return localstate.RollbackFloors{}, errors.New("enrollmenttarget: signed rollback floor is outside local durable bounds")
		}
		*value.current = value.desired
	}
	if policy.Floors.PolicySequence != 0 {
		if policy.Floors.PolicySequence < next.PolicySequence || policy.Floors.PolicySequence > policy.Sequence {
			return localstate.RollbackFloors{}, errors.New("enrollmenttarget: signed policy floor is outside local durable bounds")
		}
		next.PolicySequence = policy.Floors.PolicySequence
	}
	if policy.Floors.TombstoneSequence != 0 {
		if policy.Floors.TombstoneSequence < next.TombstoneSequence || policy.Floors.TombstoneSequence > nextTombstone {
			return localstate.RollbackFloors{}, errors.New("enrollmenttarget: signed tombstone floor is outside local durable bounds")
		}
		next.TombstoneSequence = policy.Floors.TombstoneSequence
	}
	return next, nil
}

func activeMaterial(root *securefs.Root, state localstate.State, now time.Time) (recordManifest, map[string][]byte, enrollment.Deployment, error) {
	recordName, err := recordDirectoryName(state.ActiveRecordID)
	if err != nil {
		return recordManifest{}, nil, enrollment.Deployment{}, err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return recordManifest{}, nil, enrollment.Deployment{}, err
	}
	defer record.Close()
	manifest, contents, err := readAndVerifyRecord(record, state)
	if err != nil {
		return recordManifest{}, nil, enrollment.Deployment{}, err
	}
	deployment, err := enrollment.ParseBoundDeployment(contents[deploymentFile], contents[requestFile], now)
	if err != nil {
		return recordManifest{}, nil, enrollment.Deployment{}, err
	}
	return manifest, contents, deployment, nil
}

func createDerivedRecord(rootPath string, root *securefs.Root, manifest recordManifest, contents map[string][]byte, deployment enrollment.Deployment, policy runtimebundle.VerifierPolicy, policySequence, tombstoneSequence uint64, now time.Time) (string, string, error) {
	id, err := protocol.NewID()
	if err != nil {
		return "", "", err
	}
	recordID := id.String()
	recordName, _ := recordDirectoryName(recordID)
	if err := root.MkdirExclusive(recordName, 0o700); err != nil {
		return "", "", err
	}
	record, err := root.OpenDir(recordName)
	if err != nil {
		return "", "", err
	}
	defer record.Close()
	directory := filepath.Join(rootPath, recordName)
	files, err := runtimebundle.RenderWithPolicy(deployment, directory, runtimebundle.PrivateKeys{
		OuterPEM: contents[outerPrivateKeyFile], InnerPEM: contents[innerPrivateKeyFile],
	}, policy, now)
	if err != nil {
		return "", "", err
	}
	for _, file := range files {
		if filepath.Dir(file.Path) != directory {
			return "", "", errors.New("enrollmenttarget: policy renderer escaped the immutable generation")
		}
		if err := record.EnsureFile(filepath.Base(file.Path), file.Contents, file.Mode); err != nil {
			return "", "", err
		}
	}
	if err := record.EnsureFile(deploymentFile, contents[deploymentFile], 0o600); err != nil {
		return "", "", err
	}
	if err := record.EnsureFile(requestFile, contents[requestFile], 0o600); err != nil {
		return "", "", err
	}
	verified := enrollment.VerifiedApply{
		Deployment: deployment, DeploymentBytes: contents[deploymentFile],
		Request: enrollment.RequestPayload{Nonce: recordID}, RequestSHA256: manifest.RequestSHA256,
		NextDeploymentSequence: manifest.DeploymentSequence, NextCredentialEpoch: manifest.CredentialSequence,
	}
	recordBytes, recordDigest, err := buildRecordManifest(
		verified, files, contents[requestFile], manifest.AppliedResponseSHA256, policySequence, tombstoneSequence,
	)
	if err != nil {
		return "", "", err
	}
	if err := record.EnsureFile(recordFile, recordBytes, 0o600); err != nil {
		return "", "", err
	}
	if err := record.Sync(); err != nil {
		return "", "", err
	}
	return recordID, recordDigest, nil
}

func rootRotationTransition(current, next []string) bool {
	if reflect.DeepEqual(current, next) {
		return true
	}
	if len(current) == 1 && len(next) == 2 {
		return containsAllText(next, current)
	}
	if len(current) == 2 && len(next) == 1 {
		return containsAllText(current, next)
	}
	return false
}

func overlappingSetTransition(current, next []string, maximum int) bool {
	if len(current) == 0 || len(next) == 0 || len(next) > maximum {
		return false
	}
	for _, value := range current {
		if sort.SearchStrings(next, value) < len(next) && next[sort.SearchStrings(next, value)] == value {
			return true
		}
	}
	return false
}

func relayVerifierTransition(current config.Relay, clients []config.AuthorizedPeer, routes []config.RelayRoute) bool {
	if len(current.Clients) != len(clients) || len(current.Routes) != len(routes) {
		return false
	}
	for index := range clients {
		if current.Clients[index].DNSName != clients[index].DNSName || !overlappingSetTransition(current.Clients[index].SPKIPins, clients[index].SPKIPins, 4) {
			return false
		}
	}
	for index := range routes {
		if current.Routes[index].RouteID != routes[index].RouteID || current.Routes[index].DNSName != routes[index].DNSName ||
			!overlappingSetTransition(current.Routes[index].SPKIPins, routes[index].SPKIPins, 4) {
			return false
		}
	}
	return true
}

func containsAllText(haystack, needles []string) bool {
	for _, value := range needles {
		index := sort.SearchStrings(haystack, value)
		if index >= len(haystack) || haystack[index] != value {
			return false
		}
	}
	return true
}

func clonePresentStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func clonePeers(values []config.AuthorizedPeer) []config.AuthorizedPeer {
	result := make([]config.AuthorizedPeer, len(values))
	for index, value := range values {
		result[index] = config.AuthorizedPeer{DNSName: value.DNSName, SPKIPins: append([]string(nil), value.SPKIPins...)}
	}
	return result
}

func cloneRoutes(values []config.RelayRoute) []config.RelayRoute {
	result := make([]config.RelayRoute, len(values))
	for index, value := range values {
		result[index] = config.RelayRoute{RouteID: value.RouteID, DNSName: value.DNSName, SPKIPins: append([]string(nil), value.SPKIPins...)}
	}
	return result
}

func runtimePolicyFromLifecycle(policy enrollment.LifecyclePolicy) runtimebundle.VerifierPolicy {
	result := runtimebundle.VerifierPolicy{
		CapabilityClientRoots: append([]string(nil), policy.CapabilityClientRoots...),
		RelayServerSPKIPins:   append([]string(nil), policy.RelayServerSPKIPins...),
		ConnectorSPKIPins:     append([]string(nil), policy.ConnectorSPKIPins...),
		RelayClients:          clonePeers(policy.RelayClients), RelayRoutes: cloneRoutes(policy.RelayRoutes),
	}
	if policy.Role == enrollment.RoleConnector {
		result.Revocations = runtimebundle.ConnectorRevocations{
			ClientIDs: append([]string(nil), policy.RevokedClientInstallationIDs...),
			SPKIPins:  append([]string(nil), policy.RevokedClientSPKIPins...),
		}
	}
	return result
}
