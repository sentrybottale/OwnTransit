//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

// ReceiverAgent is a local IPC boundary. The worker receives operational
// leaves and public trust only, never receiver signing/age/issuer private keys.
type ReceiverAgent interface {
	Snapshot() (Snapshot, error)
	Policy() (uint64, bool, error)
	PeerFloor(uint64) error
	SaveToken([]byte) error
	Exchange([]byte) ([]byte, error)
}

type rpcMessage struct {
	Operation  string `json:"operation"`
	Data       []byte `json:"data"`
	Generation uint64 `json:"generation"`
	Locked     bool   `json:"locked"`
	Failed     bool   `json:"failed"`
}

const maxRPC = 2 << 20

func bytesReader(parts ...[]byte) io.Reader {
	readers := make([]io.Reader, len(parts))
	for i, p := range parts {
		readers[i] = bytes.NewReader(p)
	}
	return io.MultiReader(readers...)
}

func readRPC(input io.Reader) (rpcMessage, error) {
	var h [4]byte
	if _, err := io.ReadFull(input, h[:]); err != nil {
		return rpcMessage{}, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > maxRPC {
		return rpcMessage{}, ErrState
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(input, b); err != nil {
		return rpcMessage{}, err
	}
	var v rpcMessage
	if strictjson.Decode(b, &v) != nil {
		return v, ErrState
	}
	return v, nil
}
func writeRPC(output io.Writer, v rpcMessage) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > maxRPC {
		return ErrState
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, err := io.Copy(output, bytesReader(h[:], b)); err != nil {
		return err
	}
	return nil
}

// ServeAgent processes requests serially; it owns no network connection. An
// unknown method, malformed message or pipe error terminates the worker.
func ServeAgent(input io.Reader, output io.Writer, backend ReceiverBackend) error {
	var err error
	backend.receiver, err = backend.openReceiver()
	if err != nil {
		return err
	}
	for {
		req, err := readRPC(input)
		if err != nil {
			return err
		}
		if req.Failed || req.Locked {
			return ErrState
		}
		result := rpcMessage{Operation: req.Operation}
		switch req.Operation {
		case "snapshot":
			if len(req.Data) != 0 || req.Generation != 0 {
				return ErrState
			}
			var s Snapshot
			s, err = backend.Snapshot()
			if err == nil {
				result.Data, err = json.Marshal(s)
			}
		case "policy":
			if len(req.Data) != 0 || req.Generation != 0 {
				return ErrState
			}
			result.Generation, result.Locked, err = backend.Policy()
		case "peer-floor":
			if len(req.Data) != 0 || req.Generation == 0 {
				return ErrState
			}
			err = backend.PeerFloor(req.Generation)
		case "token":
			if req.Generation != 0 {
				return ErrState
			}
			err = backend.SaveToken(req.Data)
		case "exchange":
			if req.Generation != 0 {
				return ErrState
			}
			result.Data, err = backend.Exchange(req.Data)
		default:
			return ErrState
		}
		if err != nil {
			result.Failed = true
			result.Data = nil
		}
		if err := writeRPC(output, result); err != nil {
			return err
		}
	}
}

type AgentClient struct {
	Input  io.Reader
	Output io.Writer
	mu     sync.Mutex
}

func (a *AgentClient) call(req rpcMessage) (rpcMessage, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := writeRPC(a.Output, req); err != nil {
		return rpcMessage{}, err
	}
	r, err := readRPC(a.Input)
	if err != nil {
		return r, err
	}
	if r.Operation != req.Operation || r.Failed {
		return rpcMessage{}, ErrState
	}
	return r, nil
}
func (a *AgentClient) Snapshot() (Snapshot, error) {
	r, err := a.call(rpcMessage{Operation: "snapshot"})
	var s Snapshot
	if err != nil {
		return s, err
	}
	if strictjson.Decode(r.Data, &s) != nil {
		return s, ErrState
	}
	return s, nil
}
func (a *AgentClient) Policy() (uint64, bool, error) {
	r, err := a.call(rpcMessage{Operation: "policy"})
	return r.Generation, r.Locked, err
}
func (a *AgentClient) PeerFloor(g uint64) error {
	_, err := a.call(rpcMessage{Operation: "peer-floor", Generation: g})
	return err
}
func (a *AgentClient) SaveToken(t []byte) error {
	_, err := a.call(rpcMessage{Operation: "token", Data: t})
	return err
}
func (a *AgentClient) Exchange(t []byte) ([]byte, error) {
	r, err := a.call(rpcMessage{Operation: "exchange", Data: t})
	return r.Data, err
}

func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ServeReceiver is executed by the unprivileged worker. Every external socket
// is outbound. Cancellation closes pending rendezvous and active SSH sessions.
func ServeReceiver(ctx context.Context, agent ReceiverAgent, dial pairrelay.DialFunc) error {
	return serveReceiver(ctx, agent, dial, ServeSession)
}

func serveReceiver(ctx context.Context, agent ReceiverAgent, dial pairrelay.DialFunc, serve func(context.Context, net.Conn, *tls.Config, Scope, leasewire.Options) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s, err := agent.Snapshot()
	if err != nil {
		return err
	}
	public, err := pairrelay.NewPublicClient(s.Meta.Origin, dial)
	if err != nil {
		return err
	}
	// Policy failure is fail closed even before TLS and while rendezvous waits.
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, locked, e := agent.Policy()
				if e != nil || locked {
					cancel()
					return
				}
			}
		}
	}()
	for len(s.Meta.Token) == 0 {
		attempt, c := context.WithTimeout(ctx, 10*time.Second)
		err = public.PublishAdvertisement(attempt, s.Meta.Advertisement)
		if err == nil {
			s.Meta.Token, err = public.FetchRegistration(attempt, s.Meta.Advertisement)
		}
		c()
		if err == nil && len(s.Meta.Token) > 0 {
			if err = agent.SaveToken(s.Meta.Token); err != nil {
				return err
			}
			break
		}
		if err := pause(ctx, time.Second); err != nil {
			return err
		}
	}
	pairReceiver, err := pairrelay.NewPairingReceiver(s.Meta.Origin, dial)
	if err != nil {
		return err
	}
	var tasks sync.WaitGroup
	defer func() { cancel(); tasks.Wait() }()
	tasks.Add(1)
	go func() {
		defer tasks.Done()
		for ctx.Err() == nil {
			current, e := agent.Snapshot()
			if e != nil {
				cancel()
				return
			}
			wait, c := context.WithTimeout(ctx, 25*time.Second)
			_ = pairReceiver.AcceptPairing(wait, current.Meta.Token, func(_ context.Context, blob []byte) ([]byte, error) { return agent.Exchange(blob) })
			c()
			if pause(ctx, 100*time.Millisecond) != nil {
				return
			}
		}
	}()
	semaphore := make(chan struct{}, 4)
	for ctx.Err() == nil {
		s, err = agent.Snapshot()
		if err != nil {
			return err
		}
		if s.Status.PairedClientID == "" {
			if err := pause(ctx, 100*time.Millisecond); err != nil {
				return err
			}
			continue
		}
		scope := Scope{s.Status.ReceiverID, s.Status.RouteID, s.Status.PairedClientID, s.Status.CredentialGeneration}
		a, e := ParseAuthorization(s.Authorization, scope)
		if e != nil {
			return e
		}
		profile, e := ReceiverTLS(a, s.Meta.Leaves, s.Trust)
		if e != nil {
			if err := pause(ctx, time.Second); err != nil {
				return err
			}
			continue
		}
		r, t, _, e := scope.ids()
		if e != nil {
			return e
		}
		outer, e := identity.ParseKeyPair(s.Meta.Leaves.Outer, s.Meta.Leaves.Keys.Outer)
		if e != nil {
			return e
		}
		ca := []byte(s.Trust.OuterEndpointCAPEM)
		ecfg := pairrelay.EndpointConfig{URL: s.Meta.Origin, Token: s.Meta.Token, Descriptor: pairrelay.Descriptor{ReceiverID: r, RouteID: t, AdmissionCAPEM: ca}, AdmissionCAPEM: ca, PeerID: r, Certificate: outer, RelayCAPEM: s.Meta.ServerInfo.CAPEM, RelayServerName: s.Meta.ServerInfo.ServerName, RelayServerSPKI: s.Trust.RelayServerSPKI, Dial: dial}
		ep, e := pairrelay.NewReceiver(ecfg)
		if e != nil {
			if err := pause(ctx, time.Second); err != nil {
				return err
			}
			continue
		}
		// Refresh relay-only token before waiting for data. No endpoint authority
		// is learned from the renewed token or relay response.
		refresh, c := context.WithTimeout(ctx, 10*time.Second)
		token, e := ep.RenewToken(refresh)
		c()
		if e == nil {
			if e = agent.SaveToken(token); e != nil {
				return e
			}
			ecfg.Token = token
			ep, e = pairrelay.NewReceiver(ecfg)
			if e != nil {
				return e
			}
		}
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		raw, e := ep.Accept(ctx)
		if e != nil {
			<-semaphore
			if err := pause(ctx, 200*time.Millisecond); err != nil {
				return err
			}
			continue
		}
		// A credential renewal may have committed while this outbound leg was
		// waiting. Authorize the matched client against the current local record.
		fresh, e := agent.Snapshot()
		if e != nil {
			raw.Close()
			<-semaphore
			return e
		}
		scope = Scope{fresh.Status.ReceiverID, fresh.Status.RouteID, fresh.Status.PairedClientID, fresh.Status.CredentialGeneration}
		a, e = ParseAuthorization(fresh.Authorization, scope)
		if e == nil {
			profile, e = ReceiverTLS(a, fresh.Meta.Leaves, fresh.Trust)
		}
		if e != nil {
			raw.Close()
			<-semaphore
			continue
		}
		tasks.Add(1)
		go func(raw net.Conn, profile *tls.Config, scope Scope) {
			defer tasks.Done()
			defer func() { <-semaphore }()
			_ = serve(ctx, raw, profile, scope, leasewire.Options{Policy: agent.Policy, OnPeerGeneration: agent.PeerFloor})
		}(raw, profile, scope)
	}
	return ctx.Err()
}
