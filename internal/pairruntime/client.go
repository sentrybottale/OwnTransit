//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func exchangeRetry(ctx context.Context, public *pairrelay.PublicClient, token, request []byte) ([]byte, error) {
	for i := 0; i < 30; i++ {
		response, err := public.ExchangePairing(ctx, token, request)
		if err == nil {
			return response, nil
		}
		if err := pause(ctx, 200*time.Millisecond); err != nil {
			return nil, err
		}
	}
	return nil, pairrelay.ErrUnavailable
}

type clientRecord struct {
	Schema         string                `json:"schema"`
	Origin         string                `json:"origin"`
	Token          []byte                `json:"token"`
	ServerInfo     pairrelay.ServerInfo  `json:"server_info"`
	Advertisement  []byte                `json:"advertisement"`
	Trust          receiverpairing.Trust `json:"trust"`
	Pending        []byte                `json:"pending"`
	PendingRenewal []byte                `json:"pending_renewal"`
	PendingKeys    LeafKeys              `json:"pending_keys"`
	Pairing        []byte                `json:"pairing"`
	Keys           LeafKeys              `json:"keys"`
	Authorization  []byte                `json:"authorization"`
}

func (clientRecord) String() string   { return "pairruntime.clientRecord[REDACTED]" }
func (clientRecord) GoString() string { return "pairruntime.clientRecord[REDACTED]" }

func readClient(root *securefs.Root) (clientRecord, error) {
	var s clientRecord
	if err := readRecord(root, "client.json", &s); err != nil {
		return s, err
	}
	if s.Schema != "owntransit.paired-client.v1" || len(s.Token) == 0 || len(s.Token) > pairrelay.MaxTokenBytes {
		return s, ErrState
	}
	return s, nil
}

// PairClient saves the exact request and locally generated private keys before
// sending anything. Retry with ResumeClient; never generate a second request.
func PairClient(ctx context.Context, path, origin string, code []byte, registration pairrelay.Registration, dial pairrelay.DialFunc) error {
	public, err := pairrelay.NewPublicClient(origin, dial)
	if err != nil {
		return err
	}
	ad, err := public.FetchAdvertisement(ctx, registration.Token)
	if err != nil {
		return err
	}
	var keys LeafKeys
	req, err := receiverpairing.CreateRequestWithPayload(receiverpairing.CreateRequestOptions{Advertisement: ad, Code: code, RelayOrigin: origin, Now: time.Now(), Validity: receiverpairing.MaxMessageValidity}, func(id receiverpairing.ClientIdentity) ([]byte, error) {
		p, k, err := NewCredentialRequest(id)
		keys = k
		return p, err
	})
	if err != nil {
		return ErrState
	}
	info, err := receiverpairing.VerifyAdvertisement(ad, time.Now())
	if err != nil {
		return err
	}
	if info.ReceiverID != registration.ReceiverID.String() || info.RouteID != registration.RouteID.String() || info.Trust.RelayServerSPKI != registration.ServerInfo.LeafSPKISHA256 {
		return ErrState
	}
	private, err := req.Material.MarshalPrivate()
	if err != nil {
		return err
	}
	s := clientRecord{Schema: "owntransit.paired-client.v1", Origin: origin, Token: registration.Token, ServerInfo: registration.ServerInfo, Advertisement: ad, Trust: info.Trust, Pending: private, PendingKeys: keys}
	root, err := securefs.CreateRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := initPolicy(root); err != nil {
		return err
	}
	if err := writeRecord(root, "client.json", s, true); err != nil {
		return err
	}
	return ResumeClient(ctx, path, dial)
}

func ResumeClient(ctx context.Context, path string, dial pairrelay.DialFunc) error {
	gate, err := Admission(path)
	if err != nil {
		return err
	}
	defer gate.Close()
	ctx, cancelPolicy := watchPolicy(ctx, path)
	defer cancelPolicy()
	root, err := securefs.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock("client-operation.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	s, err := readClient(root)
	if err != nil {
		return err
	}
	if len(s.Pending) == 0 {
		if len(s.Pairing) > 0 {
			return nil
		}
		return ErrState
	}
	material, err := receiverpairing.ParseClientMaterial(s.Pending)
	if err != nil {
		return err
	}
	public, err := pairrelay.NewPublicClient(s.Origin, dial)
	if err != nil {
		return err
	}
	response, err := exchangeRetry(ctx, public, s.Token, material.RequestBytes())
	if err != nil {
		return err
	}
	opened, err := receiverpairing.OpenResponse(s.Advertisement, response, material, s.Origin, time.Now())
	if err != nil {
		return ErrState
	}
	if err := commitClient(path, root, &s, opened); err != nil {
		return err
	}
	return nil
}

func scopeOf(p receiverpairing.Pairing) Scope {
	return Scope{p.ReceiverID(), p.RouteID(), p.ClientID(), p.CredentialGeneration()}
}

func commitClient(path string, root *securefs.Root, s *clientRecord, result receiverpairing.OpenResponseResult) error {
	p, err := ReadPolicy(path)
	if err != nil || p.Locked {
		return ErrState
	}
	a, err := ParseAuthorization(result.Authorization, scopeOf(result.Pairing))
	if err != nil {
		return err
	}
	// Verify returned client certificate against locally retained private key and
	// independently authenticated receiver roots before activation.
	if _, err := ClientTLS(a, s.PendingKeys, s.Trust); err != nil {
		return err
	}
	if _, err := identity.ParseKeyPair(a.Outer, s.PendingKeys.Outer); err != nil {
		return err
	}
	private, err := result.Pairing.MarshalPrivate()
	if err != nil {
		return err
	}
	s.Pairing, s.Keys, s.Authorization = private, s.PendingKeys, result.Authorization
	s.Pending, s.PendingRenewal, s.PendingKeys = nil, nil, LeafKeys{}
	return writeRecord(root, "client.json", s, false)
}

func renewClient(ctx context.Context, path string, root *securefs.Root, s *clientRecord, dial pairrelay.DialFunc) error {
	public, err := pairrelay.NewPublicClient(s.Origin, dial)
	if err != nil {
		return err
	}
	var material receiverpairing.RenewalMaterial
	if len(s.PendingRenewal) > 0 {
		material, err = receiverpairing.ParseRenewalMaterial(s.PendingRenewal)
		if err != nil {
			return err
		}
	} else {
		pair, err := receiverpairing.ParsePairing(s.Pairing)
		if err != nil {
			return err
		}
		req, err := receiverpairing.CreateRenewalWithPayload(pair, s.Origin, time.Now(), receiverpairing.MaxMessageValidity, func(id receiverpairing.ClientIdentity) ([]byte, error) {
			p, k, err := NewCredentialRequest(id)
			s.PendingKeys = k
			return p, err
		})
		if err != nil {
			return err
		}
		material = req.Material
		s.PendingRenewal, err = material.MarshalPrivate()
		if err != nil {
			return err
		}
		if err := writeRecord(root, "client.json", s, false); err != nil {
			return err
		}
	}
	response, err := exchangeRetry(ctx, public, s.Token, material.RequestBytes())
	if err != nil {
		return err
	}
	result, err := receiverpairing.OpenRenewalResponse(response, material, s.Origin, time.Now())
	if err != nil {
		return ErrState
	}
	return commitClient(path, root, s, result)
}

func endpointConfig(s clientRecord, a Authorization, dial pairrelay.DialFunc) (pairrelay.EndpointConfig, error) {
	r, t, c, err := a.Scope.ids()
	if err != nil {
		return pairrelay.EndpointConfig{}, err
	}
	cert, err := identity.ParseKeyPair(a.Outer, s.Keys.Outer)
	if err != nil {
		return pairrelay.EndpointConfig{}, err
	}
	ca := []byte(s.Trust.OuterEndpointCAPEM)
	return pairrelay.EndpointConfig{URL: s.Origin, Token: s.Token, Descriptor: pairrelay.Descriptor{ReceiverID: r, RouteID: t, AdmissionCAPEM: ca}, AdmissionCAPEM: ca, PeerID: c, Certificate: cert, RelayCAPEM: s.ServerInfo.CAPEM, RelayServerName: s.ServerInfo.ServerName, RelayServerSPKI: s.Trust.RelayServerSPKI, Dial: dial}, nil
}

// OpenClient performs renewal if required, then opens one fresh carrier. The
// returned connection is ready for SSH DATA; it never reconnects that stream.
func OpenClient(ctx context.Context, path string, dial pairrelay.DialFunc) (*leasewire.Conn, func(), error) {
	gate, err := Admission(path)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancelPolicy := watchPolicy(ctx, path)
	release := func() { cancelPolicy(); gate.Close() }
	openingTimer := time.AfterFunc(30*time.Second, cancelPolicy)
	defer openingTimer.Stop()
	root, err := securefs.OpenRoot(path)
	if err != nil {
		release()
		return nil, nil, err
	}
	defer root.Close()
	lock, err := root.TryLock("client-operation.lock")
	if err != nil {
		release()
		return nil, nil, err
	}
	defer lock.Close()
	s, err := readClient(root)
	if err != nil {
		release()
		return nil, nil, err
	}
	pair, err := receiverpairing.ParsePairing(s.Pairing)
	if err != nil {
		release()
		return nil, nil, err
	}
	a, err := ParseAuthorization(s.Authorization, scopeOf(pair))
	if err != nil {
		release()
		return nil, nil, err
	}
	cert, err := leaf(a.Inner)
	if err != nil {
		release()
		return nil, nil, err
	}
	// A new stream may refresh operational credentials. Existing streams retain
	// their authenticated lease and are never replayed or rebound.
	if len(s.PendingRenewal) > 0 || time.Until(cert.NotAfter) < 12*time.Hour {
		if err := renewClient(ctx, path, root, &s, dial); err != nil {
			release()
			return nil, nil, err
		}
		pair, err = receiverpairing.ParsePairing(s.Pairing)
		if err != nil {
			release()
			return nil, nil, err
		}
		a, err = ParseAuthorization(s.Authorization, scopeOf(pair))
		if err != nil {
			release()
			return nil, nil, err
		}
	}
	profile, err := ClientTLS(a, s.Keys, s.Trust)
	if err != nil {
		release()
		return nil, nil, err
	}
	ecfg, err := endpointConfig(s, a, dial)
	if err != nil {
		release()
		return nil, nil, err
	}
	endpoint, err := pairrelay.NewClient(ecfg)
	if err != nil {
		release()
		return nil, nil, err
	}
	// Relay token rotation is admission-only. Failure never authorizes weaker
	// endpoint trust; the subsequent runtime dial must still succeed normally.
	renewCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	token, renewErr := endpoint.RenewToken(renewCtx)
	cancel()
	if renewErr == nil {
		s.Token = token
		if err := writeRecord(root, "client.json", s, false); err != nil {
			release()
			return nil, nil, err
		}
		ecfg.Token = token
		endpoint, err = pairrelay.NewClient(ecfg)
		if err != nil {
			release()
			return nil, nil, err
		}
	}
	var raw net.Conn
	for attempt := 0; attempt < 30; attempt++ {
		raw, err = endpoint.Dial(ctx)
		if err == nil {
			break
		}
		if e := pause(ctx, 200*time.Millisecond); e != nil {
			err = e
			break
		}
	}
	if err != nil {
		release()
		return nil, nil, err
	}
	l, err := ClientSession(ctx, raw, profile, a.Scope, leasewire.Options{Policy: func() (uint64, bool, error) { p, e := ReadPolicy(path); return p.Generation, p.Locked, e }, OnPeerGeneration: func(g uint64) error { return RecordPeerFloor(path, g) }})
	if err != nil {
		release()
		return nil, nil, err
	}
	return l, release, nil
}

func Proxy(ctx context.Context, path string, input io.Reader, output io.Writer) error {
	l, release, err := OpenClient(ctx, path, nil)
	if err != nil {
		return err
	}
	defer release()
	err = CopyStream(l, input, output)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
