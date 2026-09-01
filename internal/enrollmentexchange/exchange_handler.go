package enrollmentexchange

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	MaxExchangeConnections = 16
	exchangeActionTimeout  = 10 * time.Second
)

var allocationCapabilityDomain = []byte("OwnTransit enrollment mailbox allocation capability v1\x00")

// AllocationCapabilitySHA256 converts a canonical 256-bit courier admission
// capability into the only value the relay is allowed to retain. The
// capability grants mailbox allocation only; it is not enrollment authority.
func AllocationCapabilitySHA256(capability string) (string, error) {
	decoded, err := parseMailboxCapability(capability)
	if err != nil {
		return "", errors.New("enrollmentexchange: invalid allocation capability")
	}
	hash := sha256.New()
	_, _ = hash.Write(allocationCapabilityDomain)
	_, _ = hash.Write(decoded)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ExchangeHandler implements the relay's deliberately tiny, opaque mailbox
// endpoint. Every action is one bounded binary WebSocket request and one
// bounded binary response. All mailbox-level failures are indistinguishable.
type ExchangeHandler struct {
	store                 *MailboxStore
	allocationHash        [sha256.Size]byte
	slots                 chan struct{}
	now                   func() time.Time
	allowPrivateProxyPeer bool
}

func NewExchangeHandler(store *MailboxStore, allocationCapabilitySHA256 string) (*ExchangeHandler, error) {
	if store == nil || allocationCapabilitySHA256 == "" || allocationCapabilitySHA256 != strings.ToLower(allocationCapabilitySHA256) {
		return nil, errors.New("enrollmentexchange: mailbox store and allocation capability hash are required")
	}
	decoded, err := hex.DecodeString(allocationCapabilitySHA256)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("enrollmentexchange: allocation capability hash must be canonical SHA-256")
	}
	handler := &ExchangeHandler{store: store, slots: make(chan struct{}, MaxExchangeConnections), now: time.Now}
	copy(handler.allocationHash[:], decoded)
	return handler, nil
}

// NewContainerExchangeHandler admits the private bridge-gateway source address
// produced by the authenticated packaged relay's rootful Podman loopback port
// publication. The ordinary constructor remains TLS-or-loopback only. This is
// deployment admission plumbing inside the already-malicious relay host; it is
// never enrollment, issuance, human-identity, or endpoint authority.
func NewContainerExchangeHandler(store *MailboxStore, allocationCapabilitySHA256 string) (*ExchangeHandler, error) {
	handler, err := NewExchangeHandler(store, allocationCapabilitySHA256)
	if err != nil {
		return nil, err
	}
	handler.allowPrivateProxyPeer = true
	return handler, nil
}

// Serve upgrades one exact exchange request. Cleartext is accepted only from
// the loopback reverse-proxy hop; forwarded headers never affect this check.
func (handler *ExchangeHandler) Serve(root context.Context, output http.ResponseWriter, request *http.Request) {
	if handler == nil || root == nil || output == nil || request == nil || !exchangeHTTPShape(request, handler.allowPrivateProxyPeer) {
		http.NotFound(output, request)
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		http.Error(output, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	connection, err := websocket.Accept(output, request, &websocket.AcceptOptions{
		Subprotocols:    []string{ExchangeWebSocketSubprotocol},
		OriginPatterns:  nil,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != ExchangeWebSocketSubprotocol {
		return
	}
	connection.SetReadLimit(int64(MaxExchangeWireMessage))
	ctx, cancel := context.WithTimeout(root, exchangeActionTimeout)
	defer cancel()
	messageType, encoded, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary {
		handler.writeFailure(ctx, connection)
		return
	}
	requestValue, err := parseExchangeRequest(encoded)
	if err != nil {
		handler.writeFailure(ctx, connection)
		return
	}
	payload, err := handler.perform(requestValue)
	if err != nil {
		handler.writeFailure(ctx, connection)
		return
	}
	response, err := encodeExchangeResponse(payload, true)
	if err != nil || connection.Write(ctx, websocket.MessageBinary, response) != nil {
		return
	}
	_ = connection.Close(websocket.StatusNormalClosure, "")
}

func (handler *ExchangeHandler) perform(request exchangeRequest) ([]byte, error) {
	switch request.action {
	case actionCreateMailbox:
		actual, err := AllocationCapabilitySHA256(request.capability)
		if err != nil {
			return nil, ErrMailboxUnavailable
		}
		decoded, _ := hex.DecodeString(actual)
		if subtle.ConstantTimeCompare(decoded, handler.allocationHash[:]) != 1 {
			return nil, ErrMailboxUnavailable
		}
		registration, err := ParseCourierRegistration(request.payload, handler.now().UTC())
		if err != nil || registration.mailboxID != request.mailboxID {
			return nil, ErrMailboxUnavailable
		}
		return nil, handler.store.Create(
			registration.mailboxID,
			registration.requestWrite,
			registration.requestRead,
			registration.responseWrite,
			registration.responseRead,
			registration.expires,
		)
	case actionPutRequest:
		return nil, handler.store.PutRequest(request.mailboxID, request.capability, request.payload)
	case actionReadRequest:
		return handler.store.ReadRequest(request.mailboxID, request.capability)
	case actionPutResponse:
		return nil, handler.store.PutResponse(request.mailboxID, request.capability, request.payload)
	case actionReadResponse:
		return handler.store.ReadResponse(request.mailboxID, request.capability)
	case actionConsumeMailbox:
		return nil, handler.store.Consume(request.mailboxID, request.capability)
	default:
		return nil, ErrMailboxUnavailable
	}
}

func (handler *ExchangeHandler) writeFailure(ctx context.Context, connection *websocket.Conn) {
	encoded, _ := encodeExchangeResponse(nil, false)
	_ = connection.Write(ctx, websocket.MessageBinary, encoded)
}

func exchangeHTTPShape(request *http.Request, allowPrivateProxyPeer bool) bool {
	if request.Method != http.MethodGet || request.ProtoMajor != 1 || !request.ProtoAtLeast(1, 1) || request.Host == "" ||
		request.URL == nil || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" ||
		headerPresentFold(request.Header, "Origin") || headerPresentFold(request.Header, "Sec-WebSocket-Extensions") ||
		!hasExactExchangeSubprotocol(request.Header) {
		return false
	}
	if request.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	return address.IsLoopback() || allowPrivateProxyPeer && address.IsPrivate()
}

func hasExactExchangeSubprotocol(header http.Header) bool {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, "Sec-WebSocket-Protocol") {
			values = append(values, entries...)
		}
	}
	return len(values) == 1 && values[0] == ExchangeWebSocketSubprotocol
}

func headerPresentFold(header http.Header, expected string) bool {
	for key := range header {
		if strings.EqualFold(key, expected) {
			return true
		}
	}
	return false
}
