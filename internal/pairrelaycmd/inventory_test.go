//go:build darwin || linux

package pairrelaycmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func admissionStateFixture(t *testing.T) (string, *securefs.Root, pairrelay.AdmissionRecord) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "relay")
	if _, err := Init(path, time.Now()); err != nil {
		t.Fatal(err)
	}
	root, err := securefs.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	receiver, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("public relay admission fixture"))
	now := time.Now().Unix()
	return path, root, pairrelay.AdmissionRecord{ReceiverID: receiver.String(), RouteID: route.String(),
		AdmissionRootSHA256: hex.EncodeToString(digest[:]), Status: "removed", LastIssuedUnix: now, RejectIssuedThrough: now}
}

func TestAdmissionStateRoundTripAndStrictInventory(t *testing.T) {
	path, root, record := admissionStateFixture(t)
	if err := saveAdmissions(root, []pairrelay.AdmissionRecord{record}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAdmissions(root)
	if err != nil || len(loaded) != 1 || loaded[0] != record {
		t.Fatal("durable removal changed", err)
	}
	if _, err := StateInfo(path); err != nil {
		t.Fatal("valid inventory broke identity inspection", err)
	}
	valid, _ := encodeAdmissionState([]pairrelay.AdmissionRecord{record})
	for _, invalid := range [][]byte{
		append(append([]byte(nil), valid...), '\n'),
		bytes.Replace(valid, []byte(`"status":"removed"`), []byte(`"status":"ready"`), 1),
		bytes.Replace(valid, []byte(`"records":[`), []byte(`"unknown":true,"records":[`), 1),
		[]byte(`{"schema":"owntransit.relay-admissions.v1","records":null}`),
		bytes.Repeat([]byte("x"), MaxAdmissionStateBytes+1),
	} {
		if err := os.WriteFile(filepath.Join(path, admissionStateFile), invalid, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAdmissions(root); err == nil {
			t.Fatal("malformed inventory was accepted")
		}
		if _, err := StateInfo(path); err == nil {
			t.Fatal("identity inspection ignored malformed inventory")
		}
	}
	if _, err := encodeAdmissionState([]pairrelay.AdmissionRecord{record, record}); err == nil {
		t.Fatal("duplicate admission key accepted")
	}
	if err := os.WriteFile(filepath.Join(path, admissionStateFile), valid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, admissionStateFile), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdmissions(root); err == nil {
		t.Fatal("publicly readable local policy accepted")
	}
	if err := os.Chmod(filepath.Join(path, admissionStateFile), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(path, admissionStateFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relayCertFile, filepath.Join(path, admissionStateFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdmissions(root); err == nil {
		t.Fatal("symlink inventory accepted")
	}
	if err := saveAdmissions(root, []pairrelay.AdmissionRecord{record}); err == nil {
		t.Fatal("symlink inventory overwritten")
	}
}

func TestLegacyStateWithoutInventoryPreservesRelayIdentity(t *testing.T) {
	path, root, _ := admissionStateFixture(t)
	before, err := StateInfo(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.UnlinkFile(admissionStateFile); err != nil {
		t.Fatal(err)
	}
	after, err := StateInfo(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("old state required identity replacement", err)
	}
	entries, err := loadAdmissions(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("old state fabricated admission policy")
	}
}

func TestAdmissionControlRejectsMalformedAndUnscopedRequests(t *testing.T) {
	// Unix sockaddr paths are bounded independently of the filesystem path.
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(base, "ot-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	statePath := filepath.Join(directory, "relay")
	if _, err := Init(statePath, time.Now()); err != nil {
		t.Fatal(err)
	}
	material, err := loadState(statePath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.tokenKey)
	relay, err := pairrelay.NewRelay(pairrelay.RelayConfig{TokenKey: material.tokenKey, RelayTLS: material.tls,
		VerifyAdvertisement: func([]byte, time.Time) (pairrelay.Descriptor, error) {
			return pairrelay.Descriptor{}, pairrelay.ErrUnauthorized
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	path, err := controlPath(statePath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveControl(ctx, listener, relay) }()
	defer func() { _ = listener.Close(); <-done }()
	entries, err := List(ctx, statePath)
	if err != nil || len(entries) != 0 {
		t.Fatal("empty control inventory unavailable", err)
	}
	for _, request := range []string{
		`{}`, `{"schema":"unknown"}`,
		`{"schema":"owntransit.pairrelay.control-list.v1","receiver_id":"unexpected"}`,
		`{"schema":"owntransit.pairrelay.control-list.v1","schema":"owntransit.pairrelay.control-list.v1"}`,
		`{"schema":"owntransit.pairrelay.control-list.v1","unknown":true}`,
		`{ "schema":"owntransit.pairrelay.control-list.v1"}`,
		`{"schema":"owntransit.pairrelay.control-remove.v1"}`,
		`{"schema":"owntransit.pairrelay.control-remove.v1","receiver_id":"all","route_id":"all"}`,
		string(bytes.Repeat([]byte("x"), controlRequestLimit+1)),
	} {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write([]byte(request)); err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}
		_ = connection.CloseWrite()
		response, err := io.ReadAll(connection)
		_ = connection.Close()
		if err != nil || string(response) != "ERROR\n" {
			t.Fatal("invalid local control request was not rejected", err)
		}
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := List(cancelled, statePath); err == nil {
		t.Fatal("cancelled local request succeeded")
	}
}
