//go:build darwin || linux

package pairrelaycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const admissionStateFile = "admissions.v1.json"
const MaxAdmissionStateBytes = 256 << 10

type admissionState struct {
	Schema  string                      `json:"schema"`
	Records []pairrelay.AdmissionRecord `json:"records"`
}

func encodeAdmissionState(records []pairrelay.AdmissionRecord) ([]byte, error) {
	if err := pairrelay.ValidateAdmissionRecords(records); err != nil {
		return nil, err
	}
	if records == nil {
		records = []pairrelay.AdmissionRecord{}
	}
	encoded, err := encodePublic(admissionState{"owntransit.relay-admissions.v1", records})
	if err != nil || len(encoded) > MaxAdmissionStateBytes {
		return nil, errors.New("pairrelaycmd: invalid admission inventory")
	}
	return encoded, nil
}

func loadAdmissions(root *securefs.Root) ([]pairrelay.AdmissionRecord, error) {
	encoded, err := root.ReadPrivateFile(admissionStateFile, MaxAdmissionStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state admissionState
	if err := strictjson.Decode(encoded, &state); err != nil || state.Schema != "owntransit.relay-admissions.v1" || state.Records == nil {
		return nil, errors.New("pairrelaycmd: invalid admission inventory")
	}
	canonical, err := encodeAdmissionState(state.Records)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, errors.New("pairrelaycmd: invalid admission inventory")
	}
	return state.Records, nil
}

func saveAdmissions(root *securefs.Root, records []pairrelay.AdmissionRecord) error {
	encoded, err := encodeAdmissionState(records)
	if err != nil {
		return err
	}
	return root.ReplaceFile(admissionStateFile, encoded, 0600)
}

type admissionControlRequest struct {
	Schema     string `json:"schema"`
	ReceiverID string `json:"receiver_id,omitempty"`
	RouteID    string `json:"route_id,omitempty"`
}

func handleAdmissionControl(connection *net.UnixConn, relay *pairrelay.Relay, encoded []byte) bool {
	var request admissionControlRequest
	if strictjson.Decode(encoded, &request) != nil {
		return false
	}
	if request.Schema != "owntransit.pairrelay.control-list.v1" && request.Schema != "owntransit.pairrelay.control-remove.v1" {
		return false
	}
	canonical, err := encodePublic(request)
	if err != nil || !bytes.Equal(canonical, encoded) {
		_, _ = connection.Write([]byte("ERROR\n"))
		return true
	}
	if request.Schema == "owntransit.pairrelay.control-list.v1" {
		if request.ReceiverID != "" || request.RouteID != "" {
			_, _ = connection.Write([]byte("ERROR\n"))
			return true
		}
		entries, err := relay.ListAdmissions()
		if err != nil {
			_, _ = connection.Write([]byte("ERROR\n"))
			return true
		}
		result, err := json.Marshal(entries)
		if err != nil || len(result) > MaxAdmissionStateBytes {
			_, _ = connection.Write([]byte("ERROR\n"))
			return true
		}
		_, _ = connection.Write(append(result, '\n'))
		return true
	}
	receiver, e1 := protocol.ParseID(request.ReceiverID)
	route, e2 := protocol.ParseRouteID(request.RouteID)
	if e1 != nil || e2 != nil || receiver == (protocol.ID{}) || route == (protocol.RouteID{}) || relay.RemoveAdmission(receiver, route) != nil {
		_, _ = connection.Write([]byte("ERROR\n"))
		return true
	}
	_, _ = connection.Write([]byte("OK\n"))
	return true
}

// List returns only bounded public relay-local records; observed traffic is
// not evidence that an endpoint's end-to-end authentication succeeded.
func List(ctx context.Context, statePath string) ([]pairrelay.AdmissionInfo, error) {
	encoded, err := admissionControl(ctx, statePath, admissionControlRequest{Schema: "owntransit.pairrelay.control-list.v1"})
	if err != nil {
		return nil, err
	}
	var entries []pairrelay.AdmissionInfo
	if strictjson.Decode(encoded, &entries) != nil || entries == nil || len(entries) > pairrelay.MaxAdmissionRecords {
		return nil, errors.New("pairrelaycmd: invalid inventory response")
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		receiver, e1 := protocol.ParseID(entry.ReceiverID)
		route, e2 := protocol.ParseRouteID(entry.RouteID)
		key := entry.ReceiverID + entry.RouteID
		if e1 != nil || e2 != nil || receiver == (protocol.ID{}) || route == (protocol.RouteID{}) || seen[key] ||
			(entry.Status != "approved" && entry.Status != "observed" && entry.Status != "removed") ||
			entry.ActiveCarriers < 0 || entry.ActiveCarriers > 64 || entry.PendingCarriers < 0 || entry.PendingCarriers > 64 {
			return nil, errors.New("pairrelaycmd: invalid inventory response")
		}
		seen[key] = true
	}
	canonical, err := json.Marshal(entries)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, errors.New("pairrelaycmd: invalid inventory response")
	}
	return entries, nil
}

func Remove(ctx context.Context, statePath string, receiver protocol.ID, route protocol.RouteID) error {
	if receiver == (protocol.ID{}) || route == (protocol.RouteID{}) {
		return errors.New("pairrelaycmd: exact receiver and route are required")
	}
	result, err := admissionControl(ctx, statePath, admissionControlRequest{Schema: "owntransit.pairrelay.control-remove.v1", ReceiverID: receiver.String(), RouteID: route.String()})
	if err != nil {
		return err
	}
	if string(result) != "OK" {
		return errors.New("pairrelaycmd: removal was not acknowledged")
	}
	return nil
}

func admissionControl(ctx context.Context, statePath string, request admissionControlRequest) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("pairrelaycmd: context is required")
	}
	root, err := securefs.OpenRoot(statePath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	path, err := controlPath(statePath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	uid, ok := fileOwner(info)
	if err != nil || !ok || uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return nil, errors.New("pairrelaycmd: local control socket is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, errors.New("pairrelaycmd: local control connection failed")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("pairrelaycmd: invalid local connection")
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	peer, err := unixPeerUID(connection)
	if err != nil || peer != uint32(os.Geteuid()) {
		return nil, errors.New("pairrelaycmd: invalid local control owner")
	}
	encoded, err := encodePublic(request)
	if err != nil {
		return nil, err
	}
	if _, err := connection.Write(encoded); err != nil {
		return nil, errors.New("pairrelaycmd: local control write failed")
	}
	if err := connection.CloseWrite(); err != nil {
		return nil, errors.New("pairrelaycmd: local control request failed")
	}
	response, err := io.ReadAll(io.LimitReader(connection, MaxAdmissionStateBytes+2))
	if err != nil || len(response) < 2 || len(response) > MaxAdmissionStateBytes+1 || response[len(response)-1] != '\n' || string(response) == "ERROR\n" {
		return nil, errors.New("pairrelaycmd: local admission operation failed")
	}
	return response[:len(response)-1], nil
}
