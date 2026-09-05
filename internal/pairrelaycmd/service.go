//go:build darwin || linux

package pairrelaycmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	controlRequestLimit  = 4096
	controlTimeout       = 5 * time.Second
	registrationValidity = 24 * time.Hour
)

var defaultRouteLimits = pairrelay.RouteLimits{
	PendingPairings: 2,
	PendingCarriers: 4,
	ActiveCarriers:  4,
	PairingBytes:    pairrelay.MaxPairingBytes,
	SessionLifetime: 24 * time.Hour,
}

type controlRequest struct {
	Schema     string `json:"schema"`
	ReceiverID string `json:"receiver_id"`
}

// Serve loads one exact relay identity, starts the local registration socket,
// and serves the v2 WebSocket handler only on fixed IPv4 loopback. It never
// edits a reverse proxy, firewall, website, SSH configuration, or service.
func Serve(ctx context.Context, statePath string, diagnostics io.Writer) error {
	if ctx == nil || diagnostics == nil || os.Geteuid() != 0 {
		return errors.New("pairrelaycmd: root context and diagnostics are required")
	}
	stateRoot, err := securefs.OpenRoot(statePath)
	if err != nil {
		return err
	}
	defer stateRoot.Close()
	serviceLock, err := stateRoot.TryLock(serviceLockFile)
	if err != nil {
		return errors.New("pairrelaycmd: relay service is already running or locked")
	}
	defer serviceLock.Close()
	material, err := loadState(statePath, time.Now().UTC())
	if err != nil {
		return err
	}
	defer clear(material.tokenKey)
	verification := func(encoded []byte, now time.Time) (pairrelay.Descriptor, error) {
		info, err := receiverpairing.VerifyAdvertisement(encoded, now)
		if err != nil {
			return pairrelay.Descriptor{}, err
		}
		receiverID, receiverErr := protocol.ParseID(info.ReceiverID)
		routeID, routeErr := protocol.ParseRouteID(info.RouteID)
		if receiverErr != nil || routeErr != nil {
			return pairrelay.Descriptor{}, pairrelay.ErrProtocol
		}
		return pairrelay.Descriptor{
			ReceiverID: receiverID, RouteID: routeID,
			AdmissionCAPEM: append([]byte(nil), []byte(info.Trust.OuterEndpointCAPEM)...),
		}, nil
	}
	relay, err := pairrelay.NewRelay(pairrelay.RelayConfig{
		TokenKey: material.tokenKey, RelayTLS: material.tls, VerifyAdvertisement: verification,
	})
	if err != nil {
		return err
	}
	defer relay.Close()

	socketPath, err := controlPath(statePath)
	if err != nil {
		return err
	}
	control, err := listenControl(socketPath)
	if err != nil {
		return err
	}
	defer control.Close()
	defer os.Remove(socketPath)

	httpListener, err := net.Listen("tcp4", HTTPListen)
	if err != nil {
		return fmt.Errorf("pairrelaycmd: bind fixed loopback HTTP: %w", err)
	}
	defer httpListener.Close()
	server := &http.Server{
		Handler: relay, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	httpErrors := make(chan error, 1)
	controlErrors := make(chan error, 1)
	go func() { httpErrors <- server.Serve(httpListener) }()
	go func() { controlErrors <- serveControl(ctx, control, relay) }()
	fmt.Fprintf(diagnostics, "owntransit-relay: receiver-owned relay ready on %s\n", HTTPListen)

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = control.Close()
		if err := server.Shutdown(shutdown); err != nil {
			return fmt.Errorf("pairrelaycmd: shutdown: %w", err)
		}
		return nil
	case err := <-httpErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("pairrelaycmd: HTTP service stopped: %w", err)
	case err := <-controlErrors:
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("pairrelaycmd: control service stopped: %w", err)
	}
}

func listenControl(path string) (*net.UnixListener, error) {
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || uint32(stat.Uid) != uint32(os.Geteuid()) || info.Mode().Perm() != 0o600 {
			return nil, errors.New("pairrelaycmd: unsafe existing control socket")
		}
		probe, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return nil, errors.New("pairrelaycmd: relay control service is already running")
		}
		if err := os.Remove(path); err != nil {
			return nil, errors.New("pairrelaycmd: cannot remove stale owned control socket")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func serveControl(ctx context.Context, listener *net.UnixListener, relay *pairrelay.Relay) error {
	if ctx == nil || listener == nil || relay == nil {
		return errors.New("pairrelaycmd: invalid control service")
	}
	sem := make(chan struct{}, 4)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				handleControl(connection, relay)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func handleControl(connection *net.UnixConn, relay *pairrelay.Relay) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(controlTimeout))
	uid, err := unixPeerUID(connection)
	if err != nil || uid != uint32(os.Geteuid()) {
		return
	}
	encoded, err := io.ReadAll(io.LimitReader(connection, controlRequestLimit+1))
	if err != nil || len(encoded) == 0 || len(encoded) > controlRequestLimit {
		_, _ = connection.Write([]byte("ERROR\n"))
		return
	}
	var request controlRequest
	if err := strictjson.Decode(encoded, &request); err != nil || request.Schema != "owntransit.pairrelay.control-register.v1" {
		_, _ = connection.Write([]byte("ERROR\n"))
		return
	}
	canonical, err := encodePublic(request)
	receiverID, parseErr := protocol.ParseID(request.ReceiverID)
	if err != nil || !bytes.Equal(canonical, encoded) || parseErr != nil || zeroID(receiverID) {
		_, _ = connection.Write([]byte("ERROR\n"))
		return
	}
	registration, err := relay.RegisterReceiver(receiverID, defaultRouteLimits, registrationValidity)
	if err != nil {
		_, _ = connection.Write([]byte("ERROR\n"))
		return
	}
	code, err := EncodeRegistration(registration)
	if err != nil {
		_, _ = connection.Write([]byte("ERROR\n"))
		return
	}
	_, _ = connection.Write(append([]byte(code), '\n'))
}

// Register asks the running local relay to create the initial stateless token
// for one advertised public receiver ID. It never reads the token HMAC key.
func Register(ctx context.Context, statePath string, receiverID protocol.ID) (string, error) {
	if ctx == nil || os.Geteuid() != 0 || zeroID(receiverID) {
		return "", errors.New("pairrelaycmd: root and receiver ID are required")
	}
	root, err := securefs.OpenRoot(statePath)
	if err != nil {
		return "", err
	}
	if err := root.Close(); err != nil {
		return "", err
	}
	path, err := controlPath(statePath)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	stat, statOK := fileOwner(info)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !statOK || stat != uint32(os.Geteuid()) {
		return "", errors.New("pairrelaycmd: local control socket is unavailable")
	}
	dialer := net.Dialer{Timeout: controlTimeout}
	raw, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return "", errors.New("pairrelaycmd: local control connection failed")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return "", errors.New("pairrelaycmd: local control connection is invalid")
	}
	defer connection.Close()
	request, err := encodePublic(controlRequest{Schema: "owntransit.pairrelay.control-register.v1", ReceiverID: receiverID.String()})
	if err != nil {
		return "", err
	}
	if _, err := connection.Write(request); err != nil {
		return "", errors.New("pairrelaycmd: local control write failed")
	}
	if err := connection.CloseWrite(); err != nil {
		return "", errors.New("pairrelaycmd: local control request failed")
	}
	response, err := io.ReadAll(io.LimitReader(connection, MaxRegistrationCode+2))
	if err != nil || len(response) < 2 || len(response) > MaxRegistrationCode+1 || response[len(response)-1] != '\n' {
		return "", errors.New("pairrelaycmd: local control response failed")
	}
	code := string(response[:len(response)-1])
	registration, err := DecodeRegistration(code)
	if err != nil || registration.ReceiverID != receiverID {
		return "", errors.New("pairrelaycmd: local control response is invalid")
	}
	return code, nil
}

func fileOwner(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(stat.Uid), true
}
