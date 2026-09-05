package pairrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"time"
)

// PublicClient performs public-advertisement and opaque pairing operations. It
// never receives endpoint issuer material or decrypts a pairing body.
type PublicClient struct {
	url  string
	dial DialFunc
}

func NewPublicClient(rawURL string, dial DialFunc) (*PublicClient, error) {
	if validateRelayURL(rawURL) != nil {
		return nil, ErrProtocol
	}
	if dial == nil {
		dial = defaultWebSocketDial
	}
	return &PublicClient{url: rawURL, dial: dial}, nil
}

// PublishAdvertisement publishes one opaque signed public advertisement
// without a token. The relay's mandatory verifier authenticates its key-bound
// receiver descriptor before bounded in-memory storage.
func (client *PublicClient) PublishAdvertisement(ctx context.Context, advertisement []byte) error {
	if len(advertisement) == 0 || len(advertisement) > MaxAdvertisementBytes {
		return ErrProtocol
	}
	connection, err := client.connect(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindPublishAdvertisement, advertisement, MaxAdvertisementBytes); err != nil {
		return ErrUnavailable
	}
	frame, err := readWireFrame(connection, 0)
	if err != nil || requireKind(frame, kindOK) != nil || len(frame.data) != 0 {
		return ErrUnavailable
	}
	return nil
}

// FetchAdvertisement returns opaque signed bytes for the exact token-bound
// receiver/route/admission root. The caller must independently verify them.
func (client *PublicClient) FetchAdvertisement(ctx context.Context, token []byte) ([]byte, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return nil, ErrProtocol
	}
	connection, err := client.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindFetchAdvertisement, token, MaxTokenBytes); err != nil {
		return nil, ErrUnavailable
	}
	frame, err := readWireFrame(connection, MaxAdvertisementBytes)
	if err != nil || requireKind(frame, kindAdvertisement) != nil || len(frame.data) == 0 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), frame.data...), nil
}

// FetchServerInfo discovers public relay CA/leaf material. It is not trusted on
// its own: callers must compare LeafSPKISHA256 with the receiver-signed
// advertisement before constructing an EndpointConfig.
func (client *PublicClient) FetchServerInfo(ctx context.Context) (ServerInfo, error) {
	connection, err := client.connect(ctx)
	if err != nil {
		return ServerInfo{}, err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindFetchServerInfo, nil, 0); err != nil {
		return ServerInfo{}, ErrUnavailable
	}
	frame, err := readWireFrame(connection, maxServerInfoBytes)
	if err != nil || requireKind(frame, kindServerInfo) != nil {
		return ServerInfo{}, ErrUnavailable
	}
	info, err := decodeServerInfo(frame.data)
	if err != nil {
		return ServerInfo{}, ErrUnavailable
	}
	return info, nil
}

// FetchRegistration lets the receiver automatically retrieve the already
// root-created token by presenting the exact signed advertisement. The
// advertisement is public, so this delivery is admission convenience rather
// than endpoint authority; its exact digest is matched to local registration.
func (client *PublicClient) FetchRegistration(ctx context.Context, advertisement []byte) ([]byte, error) {
	if len(advertisement) == 0 || len(advertisement) > MaxAdvertisementBytes {
		return nil, ErrProtocol
	}
	connection, err := client.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindFetchRegistration, advertisement, MaxAdvertisementBytes); err != nil {
		return nil, ErrUnavailable
	}
	frame, err := readWireFrame(connection, MaxTokenBytes)
	if err != nil || requireKind(frame, kindRenewedToken) != nil || len(frame.data) == 0 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), frame.data...), nil
}

// ExchangePairing sends only an end-to-end encrypted request and returns only
// the receiver's opaque response. It has no outer endpoint TLS and can never
// yield a data carrier or SSH dial.
func (client *PublicClient) ExchangePairing(ctx context.Context, token, encryptedRequest []byte) ([]byte, error) {
	payload, err := encodeTokenAndBlob(token, encryptedRequest, MaxPairingBytes)
	if err != nil {
		return nil, err
	}
	connection, err := client.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindPairClient, payload, maxWirePayload); err != nil {
		return nil, ErrUnavailable
	}
	frame, err := readWireFrame(connection, MaxPairingBytes)
	if err != nil || requireKind(frame, kindPairResponse) != nil || len(frame.data) == 0 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), frame.data...), nil
}

func (client *PublicClient) connect(ctx context.Context) (net.Conn, error) {
	if client == nil || client.dial == nil || ctx == nil {
		return nil, ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := client.dial(ctx, client.url)
	if err != nil || connection == nil {
		return nil, ErrUnavailable
	}
	return connection, nil
}

// PairingReceiver owns one outbound waiting leg and handles one opaque request.
// The handler is expected to call the receiverpairing package, which performs
// signature checking, age decryption, one-use commit, and response encryption.
type PairingReceiver struct {
	public *PublicClient
}

func NewPairingReceiver(rawURL string, dial DialFunc) (*PairingReceiver, error) {
	client, err := NewPublicClient(rawURL, dial)
	if err != nil {
		return nil, err
	}
	return &PairingReceiver{public: client}, nil
}

func (receiver *PairingReceiver) AcceptPairing(
	ctx context.Context,
	token []byte,
	handle func(context.Context, []byte) ([]byte, error),
) error {
	if receiver == nil || receiver.public == nil || len(token) == 0 || len(token) > MaxTokenBytes || handle == nil {
		return ErrProtocol
	}
	connection, err := receiver.public.connect(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := writeWireFrame(connection, kindPairReceiver, token, MaxTokenBytes); err != nil {
		return ErrUnavailable
	}
	frame, err := readWireFrame(connection, MaxPairingBytes)
	if err != nil || requireKind(frame, kindPairRequest) != nil || len(frame.data) == 0 {
		return ErrUnavailable
	}
	response, err := handle(ctx, append([]byte(nil), frame.data...))
	if err != nil || len(response) == 0 || len(response) > MaxPairingBytes {
		return ErrUnavailable
	}
	if err := writeWireFrame(connection, kindPairResponse, response, MaxPairingBytes); err != nil {
		return ErrUnavailable
	}
	return nil
}

type endpoint struct {
	config EndpointConfig
	role   Role
	dial   DialFunc
}

// Receiver opens outbound waiting legs. Accept returns only after the relay has
// matched a client; the returned stream contains opaque inner TLS bytes.
type Receiver struct{ endpoint *endpoint }

// Client opens one outbound data leg and obtains the paired opaque stream.
type Client struct{ endpoint *endpoint }

func NewReceiver(config EndpointConfig) (*Receiver, error) {
	value, err := newEndpoint(config, RoleReceiver)
	if err != nil {
		return nil, err
	}
	return &Receiver{endpoint: value}, nil
}

func NewClient(config EndpointConfig) (*Client, error) {
	value, err := newEndpoint(config, RoleClient)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: value}, nil
}

func newEndpoint(config EndpointConfig, role Role) (*endpoint, error) {
	if validateRelayURL(config.URL) != nil || len(config.Token) == 0 || len(config.Token) > MaxTokenBytes ||
		zeroID(config.Descriptor.ReceiverID) || zeroRoute(config.Descriptor.RouteID) || zeroID(config.PeerID) ||
		(role == RoleReceiver && config.PeerID != config.Descriptor.ReceiverID) ||
		!bytes.Equal(config.AdmissionCAPEM, config.Descriptor.AdmissionCAPEM) {
		return nil, ErrProtocol
	}
	now := time.Now().UTC()
	if _, _, _, err := parseAdmissionCA(config.Descriptor.AdmissionCAPEM, now); err != nil {
		return nil, ErrProtocol
	}
	if _, err := endpointTLSForDescriptor(config, config.Descriptor, role, now); err != nil {
		return nil, ErrProtocol
	}
	dial := config.Dial
	if dial == nil {
		dial = defaultWebSocketDial
	}
	config.Token = append([]byte(nil), config.Token...)
	config.AdmissionCAPEM = append([]byte(nil), config.AdmissionCAPEM...)
	config.Descriptor.AdmissionCAPEM = append([]byte(nil), config.Descriptor.AdmissionCAPEM...)
	config.RelayCAPEM = append([]byte(nil), config.RelayCAPEM...)
	config.Certificate.Certificate = cloneByteSlices(config.Certificate.Certificate)
	return &endpoint{config: config, role: role, dial: dial}, nil
}

func (receiver *Receiver) Accept(ctx context.Context) (net.Conn, error) {
	if receiver == nil || receiver.endpoint == nil {
		return nil, ErrProtocol
	}
	return receiver.endpoint.open(ctx, kindRuntime)
}

func (client *Client) Dial(ctx context.Context) (net.Conn, error) {
	if client == nil || client.endpoint == nil {
		return nil, ErrProtocol
	}
	return client.endpoint.open(ctx, kindRuntime)
}

func (receiver *Receiver) RenewToken(ctx context.Context) ([]byte, error) {
	if receiver == nil || receiver.endpoint == nil {
		return nil, ErrProtocol
	}
	connection, err := receiver.endpoint.open(ctx, kindRenewToken)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	frame, err := readWireFrame(connection, MaxTokenBytes)
	if err != nil || requireKind(frame, kindRenewedToken) != nil || len(frame.data) == 0 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), frame.data...), nil
}

func (client *Client) RenewToken(ctx context.Context) ([]byte, error) {
	if client == nil || client.endpoint == nil {
		return nil, ErrProtocol
	}
	connection, err := client.endpoint.open(ctx, kindRenewToken)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	frame, err := readWireFrame(connection, MaxTokenBytes)
	if err != nil || requireKind(frame, kindRenewedToken) != nil || len(frame.data) == 0 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), frame.data...), nil
}

func (value *endpoint) open(ctx context.Context, kind byte) (net.Conn, error) {
	if value == nil || value.dial == nil || ctx == nil || (kind != kindRuntime && kind != kindRenewToken) {
		return nil, ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := value.dial(ctx, value.config.URL)
	if err != nil || raw == nil {
		return nil, ErrUnavailable
	}
	fail := func(err error) (net.Conn, error) { _ = raw.Close(); return nil, err }
	preface, err := encodeRuntimePreface(runtimePreface{
		token: value.config.Token, admissionCA: value.config.AdmissionCAPEM,
		role: value.role, peerID: value.config.PeerID,
	})
	if err != nil || writeWireFrame(raw, kind, preface, maxWirePayload) != nil {
		return fail(ErrUnavailable)
	}
	tlsConfig, err := endpointTLSForDescriptor(value.config, value.config.Descriptor, value.role, time.Now().UTC())
	if err != nil {
		return fail(ErrProtocol)
	}
	secured := tls.Client(raw, tlsConfig)
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := secured.HandshakeContext(handshakeCtx); err != nil {
		return fail(ErrUnauthorized)
	}
	if kind == kindRenewToken {
		return secured, nil
	}
	frame, err := readWireFrame(secured, 0)
	if err != nil || requireKind(frame, kindReady) != nil || len(frame.data) != 0 {
		_ = secured.Close()
		return nil, ErrUnavailable
	}
	_ = secured.SetDeadline(time.Time{})
	return secured, nil
}
