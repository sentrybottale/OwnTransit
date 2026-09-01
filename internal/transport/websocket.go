// Package transport provides the byte-stream carriers used by OwnTransit.
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sentrybottale/owntransit/internal/wireprofile"

	"github.com/coder/websocket"
)

const (
	// WebSocketSubprotocol is the only WebSocket subprotocol accepted by the
	// carrier. It separates OwnTransit traffic from unrelated WebSocket users.
	WebSocketSubprotocol = wireprofile.LegacyV1WebSocketSubprotocol

	// DefaultWebSocketMessageBytes bounds one WebSocket binary message. Larger
	// byte-stream writes are split into multiple messages.
	DefaultWebSocketMessageBytes int64 = 64 << 10

	// MaxWebSocketMessageBytes is the largest limit callers may configure.
	// OwnTransit transports TLS records, so larger messages are unnecessary.
	MaxWebSocketMessageBytes int64 = 1 << 20

	// DefaultWebSocketHandshakeTimeout bounds the client's HTTP upgrade.
	DefaultWebSocketHandshakeTimeout = 10 * time.Second

	// MaxWebSocketHandshakeTimeout prevents accidentally unbounded handshakes.
	MaxWebSocketHandshakeTimeout = time.Minute
)

var (
	// ErrNilContext means a caller supplied a nil lifetime context.
	ErrNilContext = errors.New("owntransit transport: nil context")
	// ErrInvalidMessageLimit means the configured message limit was negative or
	// exceeded MaxWebSocketMessageBytes.
	ErrInvalidMessageLimit = errors.New("owntransit transport: invalid WebSocket message limit")
	// ErrInvalidHandshakeTimeout means the client timeout was negative or
	// exceeded MaxWebSocketHandshakeTimeout.
	ErrInvalidHandshakeTimeout = errors.New("owntransit transport: invalid WebSocket handshake timeout")
	// ErrWSSRequired means the client URL was not an absolute wss:// URL, or the
	// server request did not arrive over TLS.
	ErrWSSRequired = errors.New("owntransit transport: WSS is required")
	// ErrOriginNotAllowed means a browser-style Origin header was present.
	ErrOriginNotAllowed = errors.New("owntransit transport: Origin header is not allowed")
	// ErrInvalidSubprotocol means the peer did not offer or select exactly the
	// OwnTransit carrier subprotocol.
	ErrInvalidSubprotocol = errors.New("owntransit transport: invalid WebSocket subprotocol")
	// ErrExtensionsNotAllowed means a client offered a WebSocket extension.
	ErrExtensionsNotAllowed = errors.New("owntransit transport: WebSocket extensions are not allowed")
)

// WebSocketOptions configures both ends of a WebSocket carrier.
//
// MaxMessageBytes is the maximum size of one received binary WebSocket
// message. Zero selects DefaultWebSocketMessageBytes. Negative values and
// values above MaxWebSocketMessageBytes are rejected; there is no unbounded
// mode.
type WebSocketOptions struct {
	MaxMessageBytes int64

	// AllowCleartext permits a ws:// client URL or a server request whose
	// immediate HTTP connection is not TLS. It is intended only for a loopback
	// reverse-proxy hop or local development where OwnTransit TLS immediately
	// wraps the returned byte stream. Proxy forwarding headers never enable it.
	AllowCleartext bool
}

// WebSocketDialOptions configures a client WebSocket carrier.
type WebSocketDialOptions struct {
	WebSocketOptions

	// HTTPClient supplies the TLS transport and optional proxy configuration.
	// DialWebSocket clones it, disables redirects, and ignores its cookie jar.
	// Nil uses a similarly restricted clone of http.DefaultClient.
	HTTPClient *http.Client

	// HandshakeTimeout bounds only the HTTP upgrade. The ctx passed to
	// DialWebSocket controls the resulting connection's complete lifetime.
	// Zero selects DefaultWebSocketHandshakeTimeout.
	HandshakeTimeout time.Duration
}

// AcceptWebSocket upgrades r and returns a binary-message net.Conn byte
// stream. The caller owns exact path routing; this function deliberately does
// not inspect or normalize r.URL.Path.
//
// Native OwnTransit peers do not send Origin. Any Origin header, any extension,
// a missing or additional subprotocol, or a non-HTTP/1.1 request is rejected
// before the upgrade. TLS is required unless AllowCleartext is explicit.
//
// ctx controls the connection lifetime and must not be r.Context: the
// websocket package documents that using the request context after hijacking
// can behave unexpectedly. The caller must also configure the enclosing
// http.Server's header and idle timeouts, which run before this function.
func AcceptWebSocket(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	opts WebSocketOptions,
) (net.Conn, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if w == nil {
		return nil, errors.New("owntransit transport: nil HTTP response writer")
	}

	limit, err := websocketMessageLimit(opts.MaxMessageBytes)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("owntransit transport: nil HTTP request")
	}
	if r.TLS == nil && !opts.AllowCleartext {
		return nil, rejectWebSocketHandshake(w, http.StatusBadRequest, ErrWSSRequired)
	}
	if r.ProtoMajor != 1 || !r.ProtoAtLeast(1, 1) {
		return nil, rejectWebSocketHandshake(
			w,
			http.StatusUpgradeRequired,
			errors.New("owntransit transport: HTTP/1.1 is required"),
		)
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		return nil, rejectWebSocketHandshake(
			w,
			http.StatusMethodNotAllowed,
			errors.New("owntransit transport: GET is required"),
		)
	}
	if r.Host == "" {
		return nil, rejectWebSocketHandshake(
			w,
			http.StatusBadRequest,
			errors.New("owntransit transport: Host is required"),
		)
	}
	if headerPresent(r.Header, "Origin") {
		return nil, rejectWebSocketHandshake(w, http.StatusForbidden, ErrOriginNotAllowed)
	}
	if headerPresent(r.Header, "Sec-WebSocket-Extensions") {
		return nil, rejectWebSocketHandshake(
			w,
			http.StatusBadRequest,
			ErrExtensionsNotAllowed,
		)
	}
	if !hasExactSubprotocol(r.Header) {
		return nil, rejectWebSocketHandshake(
			w,
			http.StatusBadRequest,
			ErrInvalidSubprotocol,
		)
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{WebSocketSubprotocol},
		InsecureSkipVerify: false,
		OriginPatterns:     nil,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("owntransit transport: accept WebSocket: %w", err)
	}
	if ws.Subprotocol() != WebSocketSubprotocol {
		ws.CloseNow()
		return nil, ErrInvalidSubprotocol
	}
	if err := ctx.Err(); err != nil {
		ws.CloseNow()
		return nil, err
	}

	return newWebSocketStream(ctx, ws, limit), nil
}

// DialWebSocket connects to an absolute wss:// URL and returns a binary-message
// net.Conn byte stream. An absolute ws:// URL requires AllowCleartext. It does
// not follow redirects, send cookies or Origin, negotiate compression, or
// accept a missing subprotocol. The URL path and query are used exactly as
// supplied by the caller.
//
// ctx controls both dialing and the complete connection lifetime. Use
// HandshakeTimeout for a shorter bound on only the HTTP upgrade.
func DialWebSocket(
	ctx context.Context,
	rawURL string,
	opts WebSocketDialOptions,
) (net.Conn, *http.Response, error) {
	if ctx == nil {
		return nil, nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	limit, err := websocketMessageLimit(opts.MaxMessageBytes)
	if err != nil {
		return nil, nil, err
	}
	timeout, err := websocketHandshakeTimeout(opts.HandshakeTimeout)
	if err != nil {
		return nil, nil, err
	}
	if err := validateWebSocketURL(rawURL, opts.AllowCleartext); err != nil {
		return nil, nil, err
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ws, resp, err := websocket.Dial(handshakeCtx, rawURL, &websocket.DialOptions{
		HTTPClient:      strictWebSocketHTTPClient(opts.HTTPClient),
		Subprotocols:    []string{WebSocketSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, resp, fmt.Errorf("owntransit transport: dial WebSocket: %w", err)
	}
	if ws.Subprotocol() != WebSocketSubprotocol {
		ws.CloseNow()
		return nil, resp, ErrInvalidSubprotocol
	}
	if err := ctx.Err(); err != nil {
		ws.CloseNow()
		return nil, resp, err
	}

	return newWebSocketStream(ctx, ws, limit), resp, nil
}

func websocketMessageLimit(value int64) (int64, error) {
	if value == 0 {
		return DefaultWebSocketMessageBytes, nil
	}
	if value < 0 || value > MaxWebSocketMessageBytes {
		return 0, ErrInvalidMessageLimit
	}
	return value, nil
}

func websocketHandshakeTimeout(value time.Duration) (time.Duration, error) {
	if value == 0 {
		return DefaultWebSocketHandshakeTimeout, nil
	}
	if value < 0 || value > MaxWebSocketHandshakeTimeout {
		return 0, ErrInvalidHandshakeTimeout
	}
	return value, nil
}

func validateWebSocketURL(rawURL string, allowCleartext bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWSSRequired, err)
	}
	secureScheme := u.Scheme == "wss"
	cleartextScheme := allowCleartext && u.Scheme == "ws"
	if (!secureScheme && !cleartextScheme) || u.Host == "" || u.Hostname() == "" ||
		u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return ErrWSSRequired
	}
	return nil
}

func strictWebSocketHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// Authentication belongs to the OwnTransit layers, not ambient browser-like
	// cookie state attached to a reusable HTTP client.
	client.Jar = nil
	return &client
}

func rejectWebSocketHandshake(w http.ResponseWriter, status int, err error) error {
	http.Error(w, http.StatusText(status), status)
	return err
}

func headerPresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func hasExactSubprotocol(header http.Header) bool {
	var values []string
	for key, headerValues := range header {
		if strings.EqualFold(key, "Sec-WebSocket-Protocol") {
			values = append(values, headerValues...)
		}
	}
	if len(values) != 1 {
		return false
	}
	tokens := strings.Split(values[0], ",")
	return len(tokens) == 1 && strings.TrimSpace(tokens[0]) == WebSocketSubprotocol
}

func newWebSocketStream(
	ctx context.Context,
	ws *websocket.Conn,
	maxMessageBytes int64,
) net.Conn {
	stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	// websocket.NetConn deliberately disables the upstream read limit. No read
	// can begin before this unexported constructor returns, so restore it here.
	ws.SetReadLimit(maxMessageBytes)
	stopContext := context.AfterFunc(ctx, func() {
		_ = ws.CloseNow()
	})
	return &webSocketStream{
		Conn:            stream,
		maxMessageBytes: int(maxMessageBytes),
		stopContext:     stopContext,
		abort:           ws.CloseNow,
	}
}

// webSocketStream splits large local writes because websocket.NetConn maps
// each net.Conn Write to one WebSocket message. The mutex preserves byte-stream
// ordering when net.Conn.Write is called concurrently.
type webSocketStream struct {
	net.Conn

	writeMu         sync.Mutex
	maxMessageBytes int
	stopContext     func() bool
	abort           func() error
	closeOnce       sync.Once
	closeErr        error
}

var _ net.Conn = (*webSocketStream)(nil)

// Abort uses an immediate-close capability when the carrier exposes one. Its
// generic net.Conn fallback is ordinary Close, so callers that require an
// abortive guarantee must preserve the transport's Abort method when wrapping.
func Abort(connection net.Conn) error {
	if connection == nil {
		return nil
	}
	if aborter, ok := connection.(interface{ Abort() error }); ok {
		return aborter.Abort()
	}
	return connection.Close()
}

// Abort implements the immediate-close capability used by Abort.
func (c *webSocketStream) Abort() error {
	c.closeOnce.Do(func() {
		c.stopContext()
		c.closeErr = c.abort()
	})
	return c.closeErr
}

func (c *webSocketStream) Close() error {
	c.closeOnce.Do(func() {
		c.stopContext()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *webSocketStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		part := p
		if len(part) > c.maxMessageBytes {
			part = part[:c.maxMessageBytes]
		}

		n, err := c.Conn.Write(part)
		if n < 0 || n > len(part) {
			return total, io.ErrShortWrite
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n != len(part) {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
