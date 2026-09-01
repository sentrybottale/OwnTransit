//go:build darwin || linux

package enrollmenttarget

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/localstate"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/runtimebundle"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	recordSchema = "owntransit.runtime-record.v1"
	recordFile   = "record.json"

	outerCertificateFile  = "outer-cert.pem"
	innerCertificateFile  = "inner-cert.pem"
	relayAdmissionCAFile  = "relay-admission-ca-cert.pem"
	innerClientCAFile     = "inner-client-ca-cert.pem"
	innerClientCANextFile = "inner-client-ca-cert-next.pem"
	innerConnectorCAFile  = "inner-connector-ca-cert.pem"

	maxRecordSize = 1 << 20
)

type recordManifest struct {
	Schema                  string                    `json:"schema"`
	RecordID                string                    `json:"record_id"`
	Role                    enrollment.Role           `json:"role"`
	InstallationID          string                    `json:"installation_id"`
	ConnectorInstallationID string                    `json:"connector_installation_id"`
	RouteID                 string                    `json:"route_id"`
	RequestSHA256           string                    `json:"request_sha256"`
	AppliedResponseSHA256   string                    `json:"applied_response_sha256,omitempty"`
	DeploymentSHA256        string                    `json:"deployment_sha256"`
	DeploymentSequence      uint64                    `json:"deployment_sequence"`
	CredentialSequence      uint64                    `json:"credential_sequence"`
	PolicySequence          uint64                    `json:"policy_sequence"`
	TombstoneSequence       uint64                    `json:"tombstone_sequence"`
	Runtime                 enrollment.RuntimeBinding `json:"runtime"`
	OuterDNSName            string                    `json:"outer_dns_name"`
	InnerDNSName            string                    `json:"inner_dns_name,omitempty"`
	Files                   []recordFileDigest        `json:"files"`
}

type recordFileDigest struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func buildRecordManifest(verified enrollment.VerifiedApply, files []runtimebundle.File, requestBytes []byte, appliedResponseSHA256 string, policySequence, tombstoneSequence uint64) ([]byte, string, error) {
	contents := make(map[string][]byte, len(files)+2)
	for _, file := range files {
		name := filepathBase(file.Path)
		if name == "" {
			return nil, "", errors.New("enrollmenttarget: runtime file has an invalid basename")
		}
		if _, duplicate := contents[name]; duplicate {
			return nil, "", errors.New("enrollmenttarget: runtime renderer returned duplicate basenames")
		}
		contents[name] = file.Contents
	}
	contents[deploymentFile] = verified.DeploymentBytes
	contents[requestFile] = requestBytes
	recordFiles := make([]recordFileDigest, 0, len(contents))
	for name, value := range contents {
		digest := sha256.Sum256(value)
		recordFiles = append(recordFiles, recordFileDigest{
			Name: name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(value)),
		})
	}
	sort.Slice(recordFiles, func(i, j int) bool { return recordFiles[i].Name < recordFiles[j].Name })
	deploymentDigest := sha256.Sum256(verified.DeploymentBytes)
	manifest := recordManifest{
		Schema: recordSchema, RecordID: verified.Request.Nonce, Role: verified.Deployment.Role,
		InstallationID:          verified.Deployment.InstallationID,
		ConnectorInstallationID: verified.Deployment.ConnectorInstallationID,
		RouteID:                 verified.Deployment.RouteID, RequestSHA256: verified.RequestSHA256,
		AppliedResponseSHA256: appliedResponseSHA256,
		DeploymentSHA256:      hex.EncodeToString(deploymentDigest[:]),
		DeploymentSequence:    verified.NextDeploymentSequence,
		CredentialSequence:    verified.NextCredentialEpoch,
		PolicySequence:        policySequence, TombstoneSequence: tombstoneSequence,
		Runtime: verified.Deployment.Runtime, OuterDNSName: verified.Deployment.OuterDNSName,
		InnerDNSName: verified.Deployment.InnerDNSName, Files: recordFiles,
	}
	if err := manifest.validateShape(); err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", fmt.Errorf("enrollmenttarget: encode runtime record: %w", err)
	}
	if len(encoded) >= maxRecordSize {
		return nil, "", errors.New("enrollmenttarget: runtime record exceeds size limit")
	}
	encoded = append(encoded, '\n')
	digest := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(digest[:]), nil
}

func readAndVerifyRecord(record *securefs.Root, state localstate.State) (recordManifest, map[string][]byte, error) {
	manifest, contents, err := readVerifiedRecord(record, state.ActiveRecordSHA256)
	if err != nil {
		return recordManifest{}, nil, err
	}
	if err := manifest.validateStateBinding(state); err != nil {
		return recordManifest{}, nil, err
	}
	return manifest, contents, nil
}

func readVerifiedRecord(record *securefs.Root, expectedDigest string) (recordManifest, map[string][]byte, error) {
	encoded, err := record.ReadFile(recordFile, maxRecordSize)
	if err != nil {
		return recordManifest{}, nil, err
	}
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return recordManifest{}, nil, errors.New("enrollmenttarget: active record manifest does not match durable state")
	}
	var manifest recordManifest
	if err := strictjson.Decode(encoded, &manifest); err != nil {
		return recordManifest{}, nil, fmt.Errorf("enrollmenttarget: decode active record: %w", err)
	}
	if err := manifest.validateShape(); err != nil {
		return recordManifest{}, nil, err
	}
	contents := make(map[string][]byte, len(manifest.Files))
	for _, file := range manifest.Files {
		value, err := record.ReadFile(file.Name, securefs.MaxReadBytes)
		if err != nil {
			return recordManifest{}, nil, err
		}
		digest := sha256.Sum256(value)
		if int64(len(value)) != file.Size || hex.EncodeToString(digest[:]) != file.SHA256 {
			return recordManifest{}, nil, fmt.Errorf("enrollmenttarget: active record file %q does not match its manifest", file.Name)
		}
		contents[file.Name] = value
	}
	return manifest, contents, nil
}

func (manifest recordManifest) validateStateBinding(state localstate.State) error {
	if err := manifest.validateShape(); err != nil {
		return err
	}
	role, err := enrollmentRole(state.Role)
	if err != nil {
		return err
	}
	if manifest.Role != role || manifest.RecordID != state.ActiveRecordID ||
		manifest.InstallationID != state.InstallationID ||
		manifest.DeploymentSequence != state.ActiveDeploymentSequence ||
		manifest.CredentialSequence != state.ActiveCredentialSequence ||
		manifest.Runtime.ReleaseSequence != state.ActiveReleaseSequence ||
		manifest.PolicySequence != state.ActivePolicySequence ||
		manifest.TombstoneSequence != state.ActiveTombstoneSequence {
		return errors.New("enrollmenttarget: active record identity or sequence tuple does not match durable state")
	}
	return nil
}

func (manifest recordManifest) validateShape() error {
	if manifest.Schema != recordSchema || validateNonzeroID(manifest.RecordID) != nil ||
		validateNonzeroID(manifest.InstallationID) != nil || !validDigest(manifest.RequestSHA256) ||
		!validDigest(manifest.DeploymentSHA256) || manifest.DeploymentSequence == 0 || manifest.CredentialSequence == 0 {
		return errors.New("enrollmenttarget: runtime record identity, digests, or sequences are invalid")
	}
	if manifest.AppliedResponseSHA256 != "" && !validDigest(manifest.AppliedResponseSHA256) {
		return errors.New("enrollmenttarget: runtime record applied response digest is invalid")
	}
	connectorID, err := protocol.ParseID(manifest.ConnectorInstallationID)
	if err != nil || connectorID == (protocol.ID{}) || connectorID.String() != manifest.ConnectorInstallationID {
		return errors.New("enrollmenttarget: runtime record connector installation ID is invalid")
	}
	route, err := protocol.ParseRouteID(manifest.RouteID)
	if err != nil || route == (protocol.RouteID{}) || route.String() != manifest.RouteID {
		return errors.New("enrollmenttarget: runtime record route ID is invalid")
	}
	if err := manifest.Runtime.Validate(manifest.Role); err != nil {
		return err
	}
	expected := expectedRecordFiles(manifest.Role)
	rotation := false
	for _, file := range manifest.Files {
		if file.Name == innerClientCANextFile {
			rotation = true
		}
	}
	if rotation {
		if manifest.Role != enrollment.RoleConnector {
			return errors.New("enrollmenttarget: only a connector record may contain a second capability root")
		}
		expected[innerClientCANextFile] = struct{}{}
	}
	if len(manifest.Files) != len(expected) {
		return errors.New("enrollmenttarget: runtime record does not contain the exact role file set")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for index, file := range manifest.Files {
		if _, allowed := expected[file.Name]; !allowed || !validDigest(file.SHA256) || file.Size <= 0 || file.Size > securefs.MaxReadBytes {
			return fmt.Errorf("enrollmenttarget: runtime record file %d is invalid", index)
		}
		if _, duplicate := seen[file.Name]; duplicate || (index > 0 && manifest.Files[index-1].Name >= file.Name) {
			return errors.New("enrollmenttarget: runtime record files must be sorted and unique")
		}
		seen[file.Name] = struct{}{}
		if file.Name == requestFile && file.SHA256 != manifest.RequestSHA256 {
			return errors.New("enrollmenttarget: runtime record request digest is inconsistent")
		}
		if file.Name == deploymentFile && file.SHA256 != manifest.DeploymentSHA256 {
			return errors.New("enrollmenttarget: runtime record deployment digest is inconsistent")
		}
	}
	return nil
}

func expectedRecordFiles(role enrollment.Role) map[string]struct{} {
	result := map[string]struct{}{
		runtimeConfigFile: {}, requestFile: {}, deploymentFile: {},
		outerCertificateFile: {}, outerPrivateKeyFile: {}, relayAdmissionCAFile: {},
	}
	if role != enrollment.RoleRelay {
		result[innerCertificateFile] = struct{}{}
		result[innerPrivateKeyFile] = struct{}{}
		result[innerClientCAFile] = struct{}{}
		result[innerConnectorCAFile] = struct{}{}
	}
	return result
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

// filepathBase is deliberately tiny because renderer paths have already been
// constrained to one canonical generation directory by ApplyResponse.
func filepathBase(path string) string {
	for index := len(path) - 1; index >= 0; index-- {
		if path[index] == '/' {
			return path[index+1:]
		}
	}
	return path
}
