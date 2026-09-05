// Package pairrelay implements the untrusted relay boundary for the
// receiver-owned OwnTransit protocol. It has no endpoint issuer, pairing
// secret, SSH target, persistent registry, or initial-token network API.
package pairrelay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

const (
	// Path reuses the existing reverse-proxy location. Protocol selection is by
	// the exact WebSocket subprotocol, never by a new public URL.
	Path = "/connects"
	// WebSocketSubprotocol is distinct from every frozen v1 wire value.
	WebSocketSubprotocol = "owntransit.carrier.v2"
	// OuterALPN authenticates a dynamically admitted endpoint-to-relay TLS leg.
	OuterALPN = "owntransit-relay-admission/2"
)

const (
	MaxAdvertisementBytes = 128 << 10
	MaxPairingBytes       = 1 << 20
	MaxAdmissionCABytes   = 64 << 10
	MaxTokenBytes         = 1024

	MaxTokenValidity = 30 * 24 * time.Hour
	// Recovery admission covers the receiver authority's two-year lifetime,
	// including clients returning after weeks offline. It grants no endpoint
	// authority: data needs a current token and fresh mTLS, and opaque recovery
	// still needs the retained pairing key and current endpoint authorization.
	MaxExpiredRenewalGrace = 2 * 365 * 24 * time.Hour
)

var (
	ErrProtocol      = errors.New("pairrelay: invalid or unsupported protocol input")
	ErrUnauthorized  = errors.New("pairrelay: admission denied")
	ErrUnavailable   = errors.New("pairrelay: route unavailable")
	ErrCapacity      = errors.New("pairrelay: capacity exhausted")
	ErrExpired       = errors.New("pairrelay: authorization expired")
	ErrAlreadyClosed = errors.New("pairrelay: relay is closed")
)

// Role is a relay-visible connection role. It is not carried in a route token;
// the dynamic outer TLS certificate authenticates it for each connection.
type Role uint8

const (
	RoleReceiver Role = 1
	RoleClient   Role = 2
)

// Descriptor is the only projection the relay receives from a signed public
// receiver advertisement. VerifyAdvertisement must authenticate its
// self-signature and strict fields; the private receiver code separately pins
// the exact advertisement digest. ReceiverID is a public random locator, not a
// signing-key hash. AdmissionCAPEM is public verification material, never
// issuer authority.
type Descriptor struct {
	ReceiverID     protocol.ID
	RouteID        protocol.RouteID
	AdmissionCAPEM []byte
}

// AdvertisementVerifier is implemented by the receiver-owned cryptographic
// module. pairrelay deliberately treats the signed advertisement as opaque.
type AdvertisementVerifier func(encoded []byte, now time.Time) (Descriptor, error)

// RouteLimits are authenticated inside a stateless relay token. They limit an
// honest relay only; endpoint cryptography must remain safe if the relay ignores
// them. All values must be positive and within package maxima.
type RouteLimits struct {
	PendingPairings int
	PendingCarriers int
	ActiveCarriers  int
	PairingBytes    int
	SessionLifetime time.Duration
}

// Limits are process-wide memory, connection, and timeout ceilings. A token
// can only select stricter per-route bounds.
type Limits struct {
	Connections        int
	Advertisements     int
	PendingPairings    int
	PendingCarriers    int
	ActiveCarriers     int
	PerRoutePending    int
	PerRouteActive     int
	AdvertisementBytes int
	PairingBytes       int
	AdvertisementTTL   time.Duration
	PairingTimeout     time.Duration
	HandshakeTimeout   time.Duration
	SessionLifetime    time.Duration
}

func defaultLimits() Limits {
	return Limits{
		Connections: 128, Advertisements: 256, PendingPairings: 64,
		PendingCarriers: 64, ActiveCarriers: 64, PerRoutePending: 4,
		PerRouteActive: 4, AdvertisementBytes: MaxAdvertisementBytes,
		PairingBytes: MaxPairingBytes, AdvertisementTTL: 24 * time.Hour,
		PairingTimeout: 30 * time.Second, HandshakeTimeout: 10 * time.Second,
		SessionLifetime: 24 * time.Hour,
	}
}

// TokenClaims are relay admission claims, not endpoint authorization. The same
// initial token can be delivered to both endpoints before a client exists, so
// it intentionally contains neither a role nor a client identity.
type TokenClaims struct {
	ReceiverID          protocol.ID
	RouteID             protocol.RouteID
	AdmissionRootSHA256 [sha256.Size]byte
	Limits              RouteLimits
	Generation          uint64
	IssuedUnix          int64
	ExpiresUnix         int64
}

// AuthenticatedPeer can be constructed only after dynamic outer TLS has
// authenticated the declared role and peer ID under the token-bound route CA.
// RenewToken uses it to prove that renewal preserves one existing route.
type AuthenticatedPeer struct {
	ReceiverID          protocol.ID
	RouteID             protocol.RouteID
	AdmissionRootSHA256 [sha256.Size]byte
	Role                Role
	PeerID              protocol.ID
}

// TLSMaterial is relay-owned public CA material and its server leaf. It is
// unrelated to the receiver-owned endpoint admission CA.
type TLSMaterial struct {
	Certificate tls.Certificate
	CAPEM       []byte
	ServerName  string
}

// ServerInfo is public discovery material. Its leaf pin must be checked against
// the receiver-signed advertisement before it becomes endpoint trust.
type ServerInfo struct {
	ServerName     string
	CAPEM          []byte
	LeafSPKISHA256 string
}

// Registration is returned only by the local/root registration API. The
// network handler can deliver the already-created token to the receiver but
// has no operation that creates one.
type Registration struct {
	ReceiverID protocol.ID
	RouteID    protocol.RouteID
	Token      []byte
	ServerInfo ServerInfo
}

// RelayConfig has no filesystem paths. Persistence and custody of the token
// MAC key and relay TLS identity belong to the root integration outside the
// network handler.
type RelayConfig struct {
	TokenKey            []byte
	RelayTLS            TLSMaterial
	VerifyAdvertisement AdvertisementVerifier
	Limits              Limits
	Now                 func() time.Time
}

// DialFunc supplies an already upgraded byte-stream WebSocket using the exact
// v2 subprotocol. Nil selects the production canonical-public-WSS dialer. An
// injected implementation exists for isolated tests; URL validation is still
// performed before it is called.
type DialFunc func(context.Context, string) (net.Conn, error)

// EndpointConfig contains one target-generated outer leaf and only public
// trust. Token is relay-visible admission material and must never authorize the
// inner endpoint stream.
type EndpointConfig struct {
	URL             string
	Token           []byte
	Descriptor      Descriptor
	AdmissionCAPEM  []byte
	PeerID          protocol.ID
	Certificate     tls.Certificate
	RelayCAPEM      []byte
	RelayServerName string
	RelayServerSPKI string
	Dial            DialFunc
}
