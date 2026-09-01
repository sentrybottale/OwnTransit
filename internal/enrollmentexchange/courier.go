package enrollmentexchange

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"time"

	"github.com/coder/websocket"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

const (
	courierActionTimeout      = 10 * time.Second
	courierCredentialFile     = "allocation-capability.v1"
	maxCourierCredentialBytes = 128
)

// Courier performs one bounded mailbox action per fresh WSS connection. It
// deliberately has no proxy, redirect, cookie, cleartext or reusable-client
// mode. Every DNS answer must be public and the connected peer is pinned to
// the selected answer for that action.
type Courier struct {
	lookup func(context.Context, string, string) ([]net.IP, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	public func(netip.Addr) bool
}

func NewCourier() *Courier {
	resolver := net.DefaultResolver
	dialer := &net.Dialer{Timeout: courierActionTimeout, KeepAlive: -1}
	return &Courier{lookup: resolver.LookupIP, dial: dialer.DialContext, public: isPublicCourierAddress}
}

// RegisterFromCredentialStore allocates a mailbox using a capability read
// through a no-symlink private directory descriptor. The raw capability is
// never accepted as argv-like API data and its source buffer is wiped after use.
func (courier *Courier) RegisterFromCredentialStore(ctx context.Context, encodedRegistration []byte, credentialRoot string) error {
	allocationCapability, err := loadCourierCredential(credentialRoot)
	if err != nil {
		return ErrMailboxUnavailable
	}
	defer wipe(allocationCapability)
	return courier.register(ctx, encodedRegistration, string(allocationCapability))
}

func (courier *Courier) register(ctx context.Context, encodedRegistration []byte, allocationCapability string) error {
	registration, err := ParseCourierRegistration(encodedRegistration, time.Now().UTC())
	if err != nil {
		return ErrMailboxUnavailable
	}
	_, err = courier.exchange(ctx, registration.endpoint, actionCreateMailbox, registration.mailboxID, allocationCapability, encodedRegistration)
	return err
}

// CreateCourierCredentialStore creates or resumes one private online-courier
// allocation credential and returns only its relay-side hash. Existing exact
// state is reused; ambiguous different state is never regenerated.
func CreateCourierCredentialStore(rootPath string) (string, error) {
	root, err := securefs.CreateRoot(rootPath)
	if err != nil {
		root, err = securefs.OpenRoot(rootPath)
	}
	if err != nil {
		return "", err
	}
	defer root.Close()
	lock, err := root.TryLock("credential.lock")
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if encoded, readErr := root.ReadFile(courierCredentialFile, maxCourierCredentialBytes); readErr == nil {
		return courierCredentialHash(encoded)
	}
	raw := make([]byte, mailboxCapabilitySize)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer wipe(raw)
	encoded := append([]byte(base64.RawURLEncoding.EncodeToString(raw)), '\n')
	if err := root.EnsureFile(courierCredentialFile, encoded, 0o600); err != nil {
		return "", err
	}
	return courierCredentialHash(encoded)
}

// RotateCourierCredentialStore atomically replaces only the online allocation
// credential and returns its new relay-side hash for a separately signed relay
// deployment update. It never returns the raw capability.
func RotateCourierCredentialStore(rootPath string) (string, error) {
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	lock, err := root.TryLock("credential.lock")
	if err != nil {
		return "", err
	}
	defer lock.Close()
	raw := make([]byte, mailboxCapabilitySize)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer wipe(raw)
	encoded := append([]byte(base64.RawURLEncoding.EncodeToString(raw)), '\n')
	if err := root.ReplaceFile(courierCredentialFile, encoded, 0o600); err != nil {
		return "", err
	}
	return courierCredentialHash(encoded)
}

func loadCourierCredential(rootPath string) ([]byte, error) {
	if filepath.Clean(rootPath) != rootPath || !filepath.IsAbs(rootPath) {
		return nil, ErrMailboxUnavailable
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	encoded, err := root.ReadFile(courierCredentialFile, maxCourierCredentialBytes)
	if err != nil {
		return nil, err
	}
	if _, err := courierCredentialHash(encoded); err != nil {
		return nil, err
	}
	return append([]byte(nil), encoded[:len(encoded)-1]...), nil
}

func courierCredentialHash(encoded []byte) (string, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(mailboxCapabilitySize)+1 || encoded[len(encoded)-1] != '\n' {
		return "", errors.New("enrollmentexchange: invalid courier credential")
	}
	capability := string(encoded[:len(encoded)-1])
	return AllocationCapabilitySHA256(capability)
}

func (courier *Courier) PutRequest(ctx context.Context, action TargetMailboxAction) error {
	_, err := courier.exchange(ctx, action.Endpoint, actionPutRequest, action.MailboxID, action.RequestWriteCapability, action.EncryptedRequest)
	return err
}

func (courier *Courier) ReadResponse(ctx context.Context, action TargetMailboxAction) ([]byte, error) {
	return courier.exchange(ctx, action.Endpoint, actionReadResponse, action.MailboxID, action.ResponseReadCapability, nil)
}

func (courier *Courier) ReadRequest(ctx context.Context, action OperatorMailboxAction) ([]byte, error) {
	return courier.exchange(ctx, action.Endpoint, actionReadRequest, action.MailboxID, action.RequestReadCapability, nil)
}

// ReadRegisteredRequest lets the online courier use only the dedicated signed
// registration artifact. The private operator receipt never crosses this API.
func (courier *Courier) ReadRegisteredRequest(ctx context.Context, encodedRegistration []byte) ([]byte, error) {
	registration, err := ParseCourierRegistration(encodedRegistration, time.Now().UTC())
	if err != nil {
		return nil, ErrMailboxUnavailable
	}
	return courier.exchange(ctx, registration.endpoint, actionReadRequest, registration.mailboxID, registration.requestRead, nil)
}

func (courier *Courier) PutResponse(ctx context.Context, action OperatorMailboxAction, opaqueResponse []byte) error {
	_, err := courier.exchange(ctx, action.Endpoint, actionPutResponse, action.MailboxID, action.ResponseWriteCapability, opaqueResponse)
	return err
}

func (courier *Courier) PutRegisteredResponse(ctx context.Context, encodedRegistration, opaqueResponse []byte) error {
	registration, err := ParseCourierRegistration(encodedRegistration, time.Now().UTC())
	if err != nil {
		return ErrMailboxUnavailable
	}
	_, err = courier.exchange(ctx, registration.endpoint, actionPutResponse, registration.mailboxID, registration.responseWrite, opaqueResponse)
	return err
}

func (courier *Courier) Consume(ctx context.Context, tombstone TargetMailboxTombstone) error {
	_, err := courier.exchange(ctx, tombstone.Endpoint, actionConsumeMailbox, tombstone.MailboxID, tombstone.ResponseReadCapability, nil)
	return err
}

func (courier *Courier) exchange(ctx context.Context, endpoint string, action exchangeAction, mailboxID, capability string, payload []byte) ([]byte, error) {
	if courier == nil || courier.lookup == nil || courier.dial == nil || courier.public == nil || ctx == nil {
		return nil, ErrMailboxUnavailable
	}
	parsed, err := parseCourierEndpoint(endpoint)
	if err != nil {
		return nil, ErrMailboxUnavailable
	}
	encoded, err := encodeExchangeRequest(action, mailboxID, capability, payload)
	if err != nil {
		return nil, ErrMailboxUnavailable
	}
	actionContext, cancel := context.WithTimeout(ctx, courierActionTimeout)
	defer cancel()
	client, err := courier.httpClient(actionContext, parsed)
	if err != nil {
		return nil, ErrMailboxUnavailable
	}
	connection, response, err := websocket.Dial(actionContext, endpoint, &websocket.DialOptions{
		HTTPClient:      client,
		Subprotocols:    []string{ExchangeWebSocketSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrMailboxUnavailable
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != ExchangeWebSocketSubprotocol {
		return nil, ErrMailboxUnavailable
	}
	connection.SetReadLimit(int64(exchangeResponseHeaderSize + MaxBoundResponseSize))
	if err := connection.Write(actionContext, websocket.MessageBinary, encoded); err != nil {
		return nil, ErrMailboxUnavailable
	}
	messageType, responseBytes, err := connection.Read(actionContext)
	if err != nil || messageType != websocket.MessageBinary {
		return nil, ErrMailboxUnavailable
	}
	result, err := parseExchangeResponse(responseBytes)
	if err != nil {
		return nil, ErrMailboxUnavailable
	}
	_ = connection.Close(websocket.StatusNormalClosure, "")
	return result, nil
}

func (courier *Courier) httpClient(ctx context.Context, endpoint *url.URL) (*http.Client, error) {
	addresses, err := courier.lookup(ctx, "ip", endpoint.Hostname())
	if err != nil || len(addresses) == 0 {
		return nil, ErrMailboxUnavailable
	}
	canonical := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, value := range addresses {
		address, ok := netip.AddrFromSlice(value)
		if !ok {
			return nil, ErrMailboxUnavailable
		}
		address = address.Unmap()
		if !courier.public(address) {
			return nil, ErrMailboxUnavailable
		}
		if _, duplicate := seen[address]; !duplicate {
			seen[address] = struct{}{}
			canonical = append(canonical, address)
		}
	}
	selected := canonical[0]
	expectedAddress := net.JoinHostPort(endpoint.Hostname(), "443")
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   courierActionTimeout,
		ResponseHeaderTimeout: courierActionTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: endpoint.Hostname(),
		},
	}
	transport.DialContext = func(dialContext context.Context, network, address string) (net.Conn, error) {
		if address != expectedAddress {
			return nil, ErrMailboxUnavailable
		}
		connection, err := courier.dial(dialContext, "tcp", net.JoinHostPort(selected.String(), "443"))
		if err != nil {
			return nil, ErrMailboxUnavailable
		}
		peer, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = connection.Close()
			return nil, ErrMailboxUnavailable
		}
		peerAddress, ok := netip.AddrFromSlice(peer.IP)
		if !ok || peerAddress.Unmap() != selected || !courier.public(peerAddress.Unmap()) {
			_ = connection.Close()
			return nil, ErrMailboxUnavailable
		}
		return connection, nil
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("enrollmentexchange: redirects are disabled")
		},
		Jar:     nil,
		Timeout: courierActionTimeout,
	}, nil
}

func parseCourierEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" || parsed.Host != parsed.Hostname() || parsed.Port() != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.Path == "" || parsed.Path == "/" || !validPublicExchangeHostname(parsed.Hostname()) || parsed.String() != raw {
		return nil, ErrMailboxUnavailable
	}
	return parsed, nil
}

func isPublicCourierAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range courierReservedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var courierReservedPrefixes = mustCourierPrefixes(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"100::/64", "2001:2::/48", "2001:db8::/32",
)

func mustCourierPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, len(values))
	for index, value := range values {
		result[index] = netip.MustParsePrefix(value)
	}
	return result
}
