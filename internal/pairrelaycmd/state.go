//go:build darwin || linux

package pairrelaycmd

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

const (
	RelayServerName = "relay.pairrelay.v2.owntransit.invalid"
	controlName     = "control.sock"
	serviceLockFile = "service.lock"

	tokenKeyFile   = "token-hmac.key"
	relayCAFile    = "relay-ca-cert.pem"
	relayCAKeyFile = "relay-ca-key.pem"
	relayCertFile  = "relay-cert.pem"
	relayKeyFile   = "relay-key.pem"
)

var stateFiles = []string{tokenKeyFile, relayCAFile, relayCAKeyFile, relayCertFile, relayKeyFile, serviceLockFile}

type initSummary struct {
	Schema          string `json:"schema"`
	HTTPListen      string `json:"http_listen"`
	ServerName      string `json:"relay_server_name"`
	RelayServerSPKI string `json:"relay_server_spki_sha256"`
}

type stateMaterial struct {
	tokenKey []byte
	tls      pairrelay.TLSMaterial
}

// Init creates a brand-new root-owned relay state containing only the token
// HMAC key and relay TLS CA/leaf material. It creates no endpoint issuer,
// advertisement, route registration, listener, or SSH state.
func Init(statePath string, now time.Time) ([]byte, error) {
	return initState(statePath, now, false)
}

// StateInfo exposes only the local relay's public identity. The store must be
// private and owned by the current UID, including an unprivileged container UID.
func StateInfo(statePath string) ([]byte, error) {
	m, err := loadState(statePath, time.Now())
	if err != nil {
		return nil, err
	}
	defer clear(m.tokenKey)
	leaf := m.tls.Certificate.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(m.tls.Certificate.Certificate[0])
		if err != nil {
			return nil, err
		}
	}
	pin, err := identity.SPKIPin(leaf)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pairrelay.ServerInfo{ServerName: m.tls.ServerName, CAPEM: m.tls.CAPEM, LeafSPKISHA256: pin})
}

func initState(statePath string, now time.Time, requireRoot bool) ([]byte, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || (requireRoot && os.Geteuid() != 0) {
		return nil, errors.New("pairrelaycmd: root and current time are required")
	}
	ca, err := pki.NewCA("OwnTransit receiver-owned relay CA", now, 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	leaf, err := pki.IssueLeaf(ca, RelayServerName, x509.ExtKeyUsageServerAuth, now, 5*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	tokenKey := make([]byte, 32)
	if _, err := rand.Read(tokenKey); err != nil {
		return nil, err
	}
	defer clear(tokenKey)
	root, err := securefs.CreateRoot(statePath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{tokenKeyFile, tokenKey, 0o600}, {relayCAFile, ca.CertPEM, 0o644},
		{relayCAKeyFile, ca.KeyPEM, 0o600}, {relayCertFile, leaf.CertPEM, 0o644},
		{relayKeyFile, leaf.KeyPEM, 0o600}, {serviceLockFile, nil, 0o600},
	}
	for _, write := range writes {
		if err := root.CreateExclusive(write.name, write.data, write.mode); err != nil {
			return nil, err
		}
	}
	certificate, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		return nil, err
	}
	certificate.Leaf = leaf.Certificate
	pin, err := identity.SPKIPin(leaf.Certificate)
	if err != nil {
		return nil, err
	}
	probe, err := pairrelay.NewRelay(pairrelay.RelayConfig{
		TokenKey: tokenKey,
		RelayTLS: pairrelay.TLSMaterial{Certificate: certificate, CAPEM: ca.CertPEM, ServerName: RelayServerName},
		VerifyAdvertisement: func([]byte, time.Time) (pairrelay.Descriptor, error) {
			return pairrelay.Descriptor{}, errors.New("not serving")
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		return nil, fmt.Errorf("pairrelaycmd: generated state did not validate: %w", err)
	}
	_ = probe.Close()
	return encodePublic(initSummary{
		Schema: "owntransit.pairrelay.state.v1", HTTPListen: HTTPListen,
		ServerName: RelayServerName, RelayServerSPKI: pin,
	})
}

func loadState(statePath string, now time.Time) (stateMaterial, error) {
	if now.IsZero() {
		return stateMaterial{}, errors.New("pairrelaycmd: current time is required")
	}
	root, err := securefs.OpenRoot(statePath)
	if err != nil {
		return stateMaterial{}, err
	}
	defer root.Close()
	if err := validateStateInventory(statePath); err != nil {
		return stateMaterial{}, err
	}
	read := func(name string, maximum int64) ([]byte, error) { return root.ReadFile(name, maximum) }
	tokenKey, err := read(tokenKeyFile, 32)
	if err != nil || len(tokenKey) != 32 {
		return stateMaterial{}, errors.New("pairrelaycmd: token key state is invalid")
	}
	caPEM, err := read(relayCAFile, pairrelay.MaxAdmissionCABytes)
	if err != nil {
		clear(tokenKey)
		return stateMaterial{}, err
	}
	caKey, err := read(relayCAKeyFile, pairrelay.MaxAdmissionCABytes)
	if err != nil {
		clear(tokenKey)
		return stateMaterial{}, err
	}
	defer clear(caKey)
	if _, err := pki.ParseIssuer(caPEM, caKey, now); err != nil {
		clear(tokenKey)
		return stateMaterial{}, err
	}
	certPEM, err := read(relayCertFile, pairrelay.MaxAdmissionCABytes)
	if err != nil {
		clear(tokenKey)
		return stateMaterial{}, err
	}
	keyPEM, err := read(relayKeyFile, pairrelay.MaxAdmissionCABytes)
	if err != nil {
		clear(tokenKey)
		return stateMaterial{}, err
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		clear(tokenKey)
		return stateMaterial{}, err
	}
	return stateMaterial{
		tokenKey: tokenKey,
		tls:      pairrelay.TLSMaterial{Certificate: certificate, CAPEM: append([]byte(nil), caPEM...), ServerName: RelayServerName},
	}, nil
}

func validateStateInventory(statePath string) error {
	entries, err := os.ReadDir(statePath)
	if err != nil {
		return err
	}
	expected := make(map[string]struct{}, len(stateFiles))
	for _, name := range stateFiles {
		expected[name] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; ok {
			if entry.Type()&os.ModeType != 0 {
				return errors.New("pairrelaycmd: durable state contains a non-regular member")
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			mode := os.FileMode(0600)
			if entry.Name() == relayCAFile || entry.Name() == relayCertFile {
				mode = 0644
			}
			if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm() != mode {
				return errors.New("pairrelaycmd: state member ownership or permissions are invalid")
			}
			delete(expected, entry.Name())
			continue
		}
		if entry.Name() == controlName && entry.Type()&os.ModeSocket != 0 {
			continue
		}
		return errors.New("pairrelaycmd: durable state inventory is not exact")
	}
	if len(expected) != 0 {
		return errors.New("pairrelaycmd: durable state inventory is incomplete")
	}
	return nil
}

func controlPath(statePath string) (string, error) {
	if !filepath.IsAbs(statePath) || filepath.Clean(statePath) != statePath {
		return "", errors.New("pairrelaycmd: state path must be canonical and absolute")
	}
	path := filepath.Join(statePath, controlName)
	if len(path) >= 100 {
		return "", errors.New("pairrelaycmd: state path is too long for a local control socket")
	}
	return path, nil
}

func encodePublic(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
