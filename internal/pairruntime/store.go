//go:build darwin || linux

package pairruntime

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const maxStoreBytes = 6 << 20

func watchPolicy(ctx context.Context, path string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p, e := ReadPolicy(path)
				if e != nil || p.Locked {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

type Policy struct {
	Schema     string `json:"schema"`
	Generation uint64 `json:"generation"`
	Locked     bool   `json:"locked"`
	PeerFloor  uint64 `json:"peer_floor"`
}

func readRecord(root *securefs.Root, name string, value any) error {
	b, err := root.ReadFile(name, maxStoreBytes)
	if err != nil {
		return err
	}
	if strictjson.Decode(b, value) != nil {
		return ErrState
	}
	return nil
}
func writeRecord(root *securefs.Root, name string, value any, create bool) error {
	b, err := json.Marshal(value)
	if err != nil || len(b) > maxStoreBytes {
		return ErrState
	}
	if create {
		return root.CreateExclusive(name, b, 0600)
	}
	return root.ReplaceFile(name, b, 0600)
}
func initPolicy(root *securefs.Root) error {
	return writeRecord(root, "policy.json", Policy{Schema: "owntransit.paired-policy.v2", Generation: 1}, true)
}
func ReadPolicy(path string) (Policy, error) {
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return Policy{}, err
	}
	defer root.Close()
	var p Policy
	if err := readRecord(root, "policy.json", &p); err != nil {
		return p, err
	}
	if p.Schema != "owntransit.paired-policy.v2" || p.Generation == 0 {
		return Policy{}, ErrState
	}
	return p, nil
}
func updatePolicy(path string, change func(*Policy) error) error {
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock("policy.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	p, err := ReadPolicy(path)
	if err != nil {
		return err
	}
	if err := change(&p); err != nil {
		return err
	}
	return writeRecord(root, "policy.json", p, false)
}
func RecordPeerFloor(path string, generation uint64) error {
	current, err := ReadPolicy(path)
	if err != nil {
		return err
	}
	if generation < current.PeerFloor {
		return ErrState
	}
	if generation == current.PeerFloor {
		return nil
	}
	return updatePolicy(path, func(p *Policy) error {
		if generation < p.PeerFloor {
			return ErrState
		}
		p.PeerFloor = generation
		return nil
	})
}

// Admission is held from before the first policy check through worker shutdown.
// It prevents a kill acknowledgement from racing a newly admitted process.
func Admission(path string) (*securefs.Lock, error) {
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	l, err := root.TrySharedLock("active.lock")
	if err != nil {
		return nil, err
	}
	p, err := ReadPolicy(path)
	if err != nil || p.Locked {
		l.Close()
		return nil, ErrState
	}
	return l, nil
}

// SetLocked writes durable denial before waiting for active workers. A timeout
// reports failure to confirm shutdown, but deliberately leaves the lock set.
func SetLocked(ctx context.Context, path string, receiver bool, locked bool) error {
	// A security alarm is terminal for this pairing, not a maintenance pause.
	// v2 policy deliberately fails closed in older development binaries whose
	// v1 policy could clear the flag. Recovery creates fresh pairing state.
	if !locked {
		return errors.New("pairruntime: a security alarm cannot be cleared; rebuild and re-pair the tunnel")
	}
	if receiver {
		r, err := receiverpairing.Open(filepath.Join(path, "authority"))
		if err != nil {
			return err
		}
		if locked {
			if _, err := r.SetLocalLocked(true); err != nil {
				return err
			}
			status, err := r.Status()
			if err != nil {
				return err
			}
			if status.PairedClientID != "" {
				if _, err := r.RevokePeer(); err != nil {
					return err
				}
			}
		}
	}
	if err := updatePolicy(path, func(p *Policy) error {
		if p.Locked == locked {
			return nil
		}
		if p.Generation == math.MaxUint64 {
			return ErrState
		}
		p.Generation++
		p.Locked = locked
		return nil
	}); err != nil {
		return err
	}
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	for {
		lock, err := root.TryLock("active.lock")
		if err == nil {
			return lock.Close()
		}
		if !errors.Is(err, securefs.ErrLocked) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("pairruntime: locked durably; worker shutdown not confirmed before deadline")
		case <-timer.C:
		}
	}
}

type ReceiverMeta struct {
	Schema        string               `json:"schema"`
	Origin        string               `json:"origin"`
	ServerInfo    pairrelay.ServerInfo `json:"server_info"`
	Advertisement []byte               `json:"advertisement"`
	Token         []byte               `json:"token"`
	Leaves        ReceiverLeaves       `json:"leaves"`
}

func (ReceiverMeta) String() string   { return "pairruntime.ReceiverMeta[REDACTED]" }
func (ReceiverMeta) GoString() string { return "pairruntime.ReceiverMeta[REDACTED]" }

type Snapshot struct {
	Meta          ReceiverMeta                   `json:"meta"`
	Status        receiverpairing.ReceiverStatus `json:"status"`
	Trust         receiverpairing.Trust          `json:"trust"`
	Authorization []byte                         `json:"authorization"`
}

func (Snapshot) String() string   { return "pairruntime.Snapshot[REDACTED]" }
func (Snapshot) GoString() string { return "pairruntime.Snapshot[REDACTED]" }

// InitializeReceiver is a local authority operation. Public relay discovery is
// performed separately by the unprivileged network worker, before key creation.
func InitializeReceiver(path, origin string, info pairrelay.ServerInfo) (receiverpairing.Attempt, error) {
	root, err := securefs.CreateRoot(path)
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	defer root.Close()
	if err := initPolicy(root); err != nil {
		return receiverpairing.Attempt{}, err
	}
	now := time.Now()
	status, err := receiverpairing.Initialize(receiverpairing.InitializeOptions{RootPath: filepath.Join(path, "authority"), RelayOrigin: origin, RelayServerSPKI: info.LeafSPKISHA256, Now: now})
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	r, err := receiverpairing.Open(filepath.Join(path, "authority"))
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	a, err := r.LoadPrivateAuthority(now)
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	leaves, err := GenerateReceiverLeaves(status, a, now)
	if err != nil {
		return receiverpairing.Attempt{}, err
	}
	attempt, err := r.CreateAttempt(now, receiverpairing.MaxAttemptValidity)
	if err != nil {
		return attempt, err
	}
	m := ReceiverMeta{Schema: "owntransit.paired-receiver.v1", Origin: origin, ServerInfo: info, Advertisement: attempt.Advertisement, Leaves: leaves}
	if err := writeRecord(root, "receiver.json", m, true); err != nil {
		return receiverpairing.Attempt{}, err
	}
	return attempt, nil
}

// ReceiverBackend lives in the authority process and is accessed by one
// serialized bounded local RPC. It is never exported to the relay.
type ReceiverBackend struct {
	Path     string
	receiver *receiverpairing.Receiver
}

func (b ReceiverBackend) openReceiver() (*receiverpairing.Receiver, error) {
	if b.receiver != nil {
		return b.receiver, nil
	}
	return receiverpairing.Open(filepath.Join(b.Path, "authority"))
}

func (b ReceiverBackend) Snapshot() (Snapshot, error) {
	root, err := securefs.OpenRoot(b.Path)
	if err != nil {
		return Snapshot{}, err
	}
	defer root.Close()
	var s Snapshot
	if err := readRecord(root, "receiver.json", &s.Meta); err != nil {
		return s, err
	}
	if s.Meta.Schema != "owntransit.paired-receiver.v1" {
		return s, ErrState
	}
	r, err := b.openReceiver()
	if err != nil {
		return s, err
	}
	s.Status, s.Trust, s.Authorization, err = r.RuntimeSnapshot(time.Now())
	if err != nil {
		return s, err
	}
	if s.Status.LocalLocked || s.Status.PeerLocked || s.Status.PeerRevoked {
		return s, ErrState
	}
	cert, e := leaf(s.Meta.Leaves.Inner)
	if e != nil {
		return s, e
	}
	if time.Until(cert.NotAfter) < 12*time.Hour {
		a, e := r.LoadPrivateAuthority(time.Now())
		if e != nil {
			return s, e
		}
		s.Meta.Leaves, e = RefreshReceiverLeaves(s.Meta.Leaves, s.Status, a, time.Now())
		if e != nil {
			return s, e
		}
		if e := writeRecord(root, "receiver.json", s.Meta, false); e != nil {
			return s, e
		}
	}
	return s, nil
}
func (b ReceiverBackend) Policy() (uint64, bool, error) {
	p, err := ReadPolicy(b.Path)
	if err != nil {
		return 0, true, err
	}
	return p.Generation, p.Locked, nil
}
func (b ReceiverBackend) PeerFloor(g uint64) error { return RecordPeerFloor(b.Path, g) }
func (b ReceiverBackend) SaveToken(token []byte) error {
	if len(token) == 0 || len(token) > pairrelay.MaxTokenBytes {
		return ErrState
	}
	root, err := securefs.OpenRoot(b.Path)
	if err != nil {
		return err
	}
	defer root.Close()
	var m ReceiverMeta
	if err := readRecord(root, "receiver.json", &m); err != nil {
		return err
	}
	m.Token = append([]byte(nil), token...)
	return writeRecord(root, "receiver.json", m, false)
}
func (b ReceiverBackend) Exchange(encoded []byte) ([]byte, error) {
	_, locked, err := b.Policy()
	if err != nil || locked {
		return nil, ErrState
	}
	r, err := receiverpairing.Open(filepath.Join(b.Path, "authority"))
	if err != nil {
		return nil, err
	}
	s, err := b.Snapshot()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	a, err := r.LoadPrivateAuthority(now)
	if err != nil {
		return nil, err
	}
	issue := func(p receiverpairing.PeerRequest) ([]byte, error) { return IssueCredentials(p, a, s.Meta.Leaves, now) }
	result, err := r.Claim(encoded, now, issue)
	if err != nil {
		result, err = r.Renew(encoded, now, issue)
	}
	if err != nil {
		return nil, ErrState
	}
	return result.Response, nil
}
