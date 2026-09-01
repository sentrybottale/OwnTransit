//go:build darwin || linux

package enrollmenttarget

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
)

const (
	runtimeConfigFile = "config.json"
	maxRuntimeConfig  = 1 << 20
)

// LoadClient selects one immutable configuration through the atomically
// replaced local state record. It never follows an on-disk "current" symlink.
func LoadClient(rootPath string) (config.Client, error) {
	value, _, err := loadClient(rootPath)
	return value, err
}

func loadClient(rootPath string) (config.Client, localStateView, error) {
	handle, err := OpenActiveGeneration(rootPath, enrollment.RoleClient)
	if err != nil {
		return config.Client{}, localStateView{}, err
	}
	defer handle.Close()
	value, state, err := handleClientConfig(handle)
	if err != nil {
		return config.Client{}, localStateView{}, err
	}
	if err := handle.FinalCheck(); err != nil {
		return config.Client{}, localStateView{}, err
	}
	return value, state, nil
}

// ClientConfig parses and target-binds the manifest-backed client
// configuration while retaining the generation handle for credential loads
// and the caller's final pre-network selection check.
func (handle *GenerationHandle) ClientConfig() (config.Client, error) {
	value, _, err := handleClientConfig(handle)
	return value, err
}

func handleClientConfig(handle *GenerationHandle) (config.Client, localStateView, error) {
	encoded, state, err := heldActiveConfig(handle, enrollment.RoleClient)
	if err != nil {
		return config.Client{}, localStateView{}, err
	}
	value, err := config.ParseClient(encoded)
	if err != nil {
		return config.Client{}, localStateView{}, err
	}
	if value.InstallationID != state.InstallationID || value.ConnectorInstallationID != state.ConnectorInstallationID ||
		value.RouteID != state.RouteID || value.CredentialEpoch != state.CredentialSequence ||
		value.OuterTLS.LocalDNSName != state.OuterDNSName || value.InnerTLS.LocalDNSName != state.InnerDNSName {
		return config.Client{}, localStateView{}, errors.New("enrollmenttarget: active client config does not match target installation")
	}
	if err := validateClientRuntimePaths(value, state.GenerationDirectory); err != nil {
		return config.Client{}, localStateView{}, err
	}
	return value, state, nil
}

// ClientConfigPath validates the active generation before returning the fixed
// immutable config path for the client executable.
func ClientConfigPath(rootPath string) (string, error) {
	_, state, err := loadClient(rootPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(state.GenerationDirectory, runtimeConfigFile), nil
}

// LoadConnector selects and validates the production connector generation.
func LoadConnector(rootPath string) (config.Connector, error) {
	value, _, err := loadConnector(rootPath)
	return value, err
}

func loadConnector(rootPath string) (config.Connector, localStateView, error) {
	handle, err := OpenActiveGeneration(rootPath, enrollment.RoleConnector)
	if err != nil {
		return config.Connector{}, localStateView{}, err
	}
	defer handle.Close()
	value, state, err := handleConnectorConfig(handle)
	if err != nil {
		return config.Connector{}, localStateView{}, err
	}
	if err := handle.FinalCheck(); err != nil {
		return config.Connector{}, localStateView{}, err
	}
	return value, state, nil
}

// ConnectorConfig parses and target-binds the production connector config
// without releasing its held generation.
func (handle *GenerationHandle) ConnectorConfig() (config.Connector, error) {
	value, _, err := handleConnectorConfig(handle)
	return value, err
}

func handleConnectorConfig(handle *GenerationHandle) (config.Connector, localStateView, error) {
	encoded, state, err := heldActiveConfig(handle, enrollment.RoleConnector)
	if err != nil {
		return config.Connector{}, localStateView{}, err
	}
	value, err := config.ParseConnector(encoded)
	if err != nil {
		return config.Connector{}, localStateView{}, err
	}
	if value.InstallationID != state.InstallationID || value.RouteID != state.RouteID ||
		value.SSHTarget != config.ConnectorSSHTarget || value.OuterTLS.LocalDNSName != state.OuterDNSName ||
		value.InnerTLS.LocalDNSName != state.InnerDNSName {
		return config.Connector{}, localStateView{}, errors.New("enrollmenttarget: active connector config does not match target installation or build target")
	}
	if err := validateConnectorRuntimePaths(value, state.GenerationDirectory); err != nil {
		return config.Connector{}, localStateView{}, err
	}
	return value, state, nil
}

// ConnectorConfigPath validates the active generation before returning its
// fixed immutable config path.
func ConnectorConfigPath(rootPath string) (string, error) {
	_, state, err := loadConnector(rootPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(state.GenerationDirectory, runtimeConfigFile), nil
}

// LoadRelay selects and validates the active relay generation.
func LoadRelay(rootPath string) (config.Relay, error) {
	value, _, err := loadRelay(rootPath)
	return value, err
}

func loadRelay(rootPath string) (config.Relay, localStateView, error) {
	handle, err := OpenActiveGeneration(rootPath, enrollment.RoleRelay)
	if err != nil {
		return config.Relay{}, localStateView{}, err
	}
	defer handle.Close()
	value, state, err := handleRelayConfig(handle)
	if err != nil {
		return config.Relay{}, localStateView{}, err
	}
	if err := handle.FinalCheck(); err != nil {
		return config.Relay{}, localStateView{}, err
	}
	return value, state, nil
}

// RelayConfig parses and target-binds the relay configuration while retaining
// the selected generation handle.
func (handle *GenerationHandle) RelayConfig() (config.Relay, error) {
	value, _, err := handleRelayConfig(handle)
	return value, err
}

func handleRelayConfig(handle *GenerationHandle) (config.Relay, localStateView, error) {
	encoded, state, err := heldActiveConfig(handle, enrollment.RoleRelay)
	if err != nil {
		return config.Relay{}, localStateView{}, err
	}
	value, err := config.ParseRelay(encoded)
	if err != nil {
		return config.Relay{}, localStateView{}, err
	}
	if len(value.Routes) != 1 || value.Routes[0].RouteID != state.RouteID || value.OuterTLS.LocalDNSName != state.OuterDNSName {
		return config.Relay{}, localStateView{}, errors.New("enrollmenttarget: active relay config does not match its runtime record")
	}
	if err := validateRelayRuntimePaths(value, state.GenerationDirectory); err != nil {
		return config.Relay{}, localStateView{}, err
	}
	return value, state, nil
}

// RelayConfigPath validates the active generation before returning its fixed
// immutable config path.
func RelayConfigPath(rootPath string) (string, error) {
	_, state, err := loadRelay(rootPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(state.GenerationDirectory, runtimeConfigFile), nil
}

func heldActiveConfig(handle *GenerationHandle, expected enrollment.Role) ([]byte, localStateView, error) {
	if handle == nil {
		return nil, localStateView{}, errors.New("enrollmenttarget: generation handle is closed")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil, localStateView{}, errors.New("enrollmenttarget: generation handle is closed")
	}
	role, err := enrollmentRole(handle.state.Role)
	if err != nil || role != expected || handle.manifest.Role != expected {
		return nil, localStateView{}, errors.New("enrollmenttarget: held generation role does not match requested runtime")
	}
	encoded := append([]byte(nil), handle.contents[runtimeConfigFile]...)
	if len(encoded) == 0 || len(encoded) > maxRuntimeConfig {
		return nil, localStateView{}, errors.New("enrollmenttarget: active record has no bounded runtime config")
	}
	state, manifest := handle.state, handle.manifest
	return encoded, localStateView{
		InstallationID: state.InstallationID, ActiveRecordID: state.ActiveRecordID,
		ConnectorInstallationID: manifest.ConnectorInstallationID, RouteID: manifest.RouteID,
		CredentialSequence: manifest.CredentialSequence, OuterDNSName: manifest.OuterDNSName,
		InnerDNSName: manifest.InnerDNSName, GenerationDirectory: handle.directory,
	}, nil
}

// resolveActiveRoot gives long-running runtimes the same canonical parent-path
// treatment as owntransitctl. The final state-root component is deliberately
// not resolved: securefs.OpenRoot must still reject a substituted root symlink.
func resolveActiveRoot(path string) (string, error) {
	if path == "" {
		return "", errors.New("enrollmenttarget: state root is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("enrollmenttarget: resolve state root: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) {
		return "", errors.New("enrollmenttarget: state root cannot be the filesystem root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("enrollmenttarget: resolve state-root parent: %w", err)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

// localStateView keeps runtime loaders from accidentally depending on mutable
// lifecycle counters beyond the exact active-record selection.
type localStateView struct {
	InstallationID          string
	ActiveRecordID          string
	ConnectorInstallationID string
	RouteID                 string
	CredentialSequence      uint64
	OuterDNSName            string
	InnerDNSName            string
	GenerationDirectory     string
}

func validateClientRuntimePaths(value config.Client, directory string) error {
	want := runtimePaths(directory)
	if value.CarrierCAFile != "" || value.OuterTLS.CertFile != want[outerCertificateFile] || value.OuterTLS.KeyFile != want[outerPrivateKeyFile] ||
		value.OuterTLS.CAFile != want[relayAdmissionCAFile] || value.OuterTLS.IssuerCAFile != want[relayAdmissionCAFile] ||
		value.InnerTLS.CertFile != want[innerCertificateFile] || value.InnerTLS.KeyFile != want[innerPrivateKeyFile] ||
		value.InnerTLS.CAFile != want[innerConnectorCAFile] || value.InnerTLS.IssuerCAFile != want[innerClientCAFile] {
		return errors.New("enrollmenttarget: client config contains a path outside its immutable generation")
	}
	return nil
}

func validateConnectorRuntimePaths(value config.Connector, directory string) error {
	want := runtimePaths(directory)
	wantClientCAs := []string{want[innerClientCAFile]}
	if value.InnerTLS.ClientCARotation {
		wantClientCAs = append(wantClientCAs, want[innerClientCANextFile])
	}
	if value.CarrierCAFile != "" || value.OuterTLS.CertFile != want[outerCertificateFile] || value.OuterTLS.KeyFile != want[outerPrivateKeyFile] ||
		value.OuterTLS.CAFile != want[relayAdmissionCAFile] || value.OuterTLS.IssuerCAFile != want[relayAdmissionCAFile] ||
		value.InnerTLS.CertFile != want[innerCertificateFile] || value.InnerTLS.KeyFile != want[innerPrivateKeyFile] ||
		value.InnerTLS.IssuerCAFile != want[innerConnectorCAFile] || !equalPathList(value.InnerTLS.ClientCAFiles, wantClientCAs) {
		return errors.New("enrollmenttarget: connector config contains a path outside its immutable generation")
	}
	return nil
}

func validateRelayRuntimePaths(value config.Relay, directory string) error {
	want := runtimePaths(directory)
	if value.OuterTLS.CertFile != want[outerCertificateFile] || value.OuterTLS.KeyFile != want[outerPrivateKeyFile] ||
		value.OuterTLS.ClientCAFile != want[relayAdmissionCAFile] || value.OuterTLS.IssuerCAFile != want[relayAdmissionCAFile] {
		return errors.New("enrollmenttarget: relay config contains a path outside its immutable generation")
	}
	return nil
}

func runtimePaths(directory string) map[string]string {
	result := make(map[string]string, 8)
	for _, name := range []string{
		outerCertificateFile, outerPrivateKeyFile, innerCertificateFile, innerPrivateKeyFile,
		relayAdmissionCAFile, innerClientCAFile, innerClientCANextFile, innerConnectorCAFile, runtimeConfigFile,
	} {
		result[name] = filepath.Join(directory, name)
	}
	return result
}

func equalPathList(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
