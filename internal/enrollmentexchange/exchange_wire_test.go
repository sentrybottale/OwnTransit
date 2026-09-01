package enrollmentexchange

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/sentrybottale/owntransit/internal/enrollment"
)

func TestExchangeWireCapabilitiesAreBinaryAndNeverURLMaterial(t *testing.T) {
	target, _, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeExchangeRequest(actionPutRequest, target.MailboxID, target.RequestWriteCapability, []byte("opaque"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(target.RequestWriteCapability)) || strings.Contains(target.Endpoint, target.RequestWriteCapability) {
		t.Fatal("mailbox capability appeared as textual wire or URL material")
	}
	parsed, err := parseExchangeRequest(encoded)
	if err != nil || parsed.capability != target.RequestWriteCapability || parsed.mailboxID != target.MailboxID || !bytes.Equal(parsed.payload, []byte("opaque")) {
		t.Fatalf("wire round trip = %+v, %v", parsed, err)
	}
}

func TestExchangeRequestParserBorrowsCapacityBoundedPayload(t *testing.T) {
	target, operator, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, MaxBoundResponseSize)
	payload[0], payload[len(payload)-1] = 0x5a, 0xa5
	encoded, err := encodeExchangeRequest(actionPutResponse, target.MailboxID, operator.ResponseWriteCapability, payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseExchangeRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.payload) != MaxBoundResponseSize || cap(parsed.payload) != len(parsed.payload) {
		t.Fatalf("borrowed payload len=%d cap=%d", len(parsed.payload), cap(parsed.payload))
	}
	if &parsed.payload[0] != &encoded[exchangeRequestHeaderSize] {
		t.Fatal("parser copied the attacker-controlled payload before authorization")
	}

	store := NewMailboxStore()
	hash, err := AllocationCapabilitySHA256(operator.ResponseWriteCapability)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewExchangeHandler(store, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.perform(parsed); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("absent maximum response = %v", err)
	}
	if store.storedBytes != 0 || len(store.slots) != 0 {
		t.Fatalf("rejected maximum response changed store: slots=%d bytes=%d", len(store.slots), store.storedBytes)
	}
}

func TestExchangeHandlerRegistersAndCarriesOpaqueExactIdempotentBlobs(t *testing.T) {
	now, registrationBytes, registration, allocation := exchangeRegistrationFixture(t)
	store := NewMailboxStore()
	store.now = func() time.Time { return now }
	hash, err := AllocationCapabilitySHA256(allocation)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewExchangeHandler(store, hash)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return now }
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/connects/enrollment" || request.URL.RawQuery != "" {
			http.NotFound(output, request)
			return
		}
		handler.Serve(context.Background(), output, request)
	}))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/connects/enrollment"

	create, _ := encodeExchangeRequest(actionCreateMailbox, registration.mailboxID, allocation, registrationBytes)
	if payload, err := exchangeTestRoundTrip(t, endpoint, websocket.MessageBinary, create); err != nil || len(payload) != 0 {
		t.Fatalf("create = %x, %v", payload, err)
	}
	requestBlob := []byte("opaque encrypted request")
	put, _ := encodeExchangeRequest(actionPutRequest, registration.mailboxID, registration.requestWrite, requestBlob)
	for attempt := 0; attempt < 2; attempt++ {
		if payload, err := exchangeTestRoundTrip(t, endpoint, websocket.MessageBinary, put); err != nil || len(payload) != 0 {
			t.Fatalf("put attempt %d = %x, %v", attempt, payload, err)
		}
	}
	read, _ := encodeExchangeRequest(actionReadRequest, registration.mailboxID, registration.requestRead, nil)
	if payload, err := exchangeTestRoundTrip(t, endpoint, websocket.MessageBinary, read); err != nil || !bytes.Equal(payload, requestBlob) {
		t.Fatalf("read = %q, %v", payload, err)
	}
	overwrite, _ := encodeExchangeRequest(actionPutRequest, registration.mailboxID, registration.requestWrite, []byte("different"))
	if _, err := exchangeTestRoundTrip(t, endpoint, websocket.MessageBinary, overwrite); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("overwrite = %v", err)
	}
}

func TestExchangeHandlerFailuresHaveOneShape(t *testing.T) {
	_, _, registration, allocation := exchangeRegistrationFixture(t)
	hash, _ := AllocationCapabilitySHA256(allocation)
	handler, _ := NewExchangeHandler(NewMailboxStore(), hash)
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		handler.Serve(context.Background(), output, request)
	}))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	want, _ := encodeExchangeResponse(nil, false)
	wrongCapability := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, mailboxCapabilitySize))
	absent, _ := encodeExchangeRequest(actionReadResponse, registration.mailboxID, wrongCapability, nil)
	malformed := []byte("not an exchange frame")
	for _, test := range []struct {
		name      string
		typeValue websocket.MessageType
		body      []byte
	}{
		{name: "absent-or-wrong-capability", typeValue: websocket.MessageBinary, body: absent},
		{name: "malformed", typeValue: websocket.MessageBinary, body: malformed},
		{name: "text", typeValue: websocket.MessageText, body: absent},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := exchangeTestRawRoundTrip(t, endpoint, test.typeValue, test.body)
			if !bytes.Equal(got, want) {
				t.Fatalf("failure frame = %x, want exact %x", got, want)
			}
		})
	}
}

func TestExchangeHTTPShapeRejectsBrowserAliasesAndCleartextNonLoopback(t *testing.T) {
	base := &http.Request{
		Method: http.MethodGet, ProtoMajor: 1, ProtoMinor: 1, Host: "relay.example.com",
		URL: &urlForExchangeShape, Header: http.Header{"Sec-WebSocket-Protocol": []string{ExchangeWebSocketSubprotocol}},
		RemoteAddr: "127.0.0.1:1234",
	}
	if !exchangeHTTPShape(base.Clone(context.Background()), false) {
		t.Fatal("canonical loopback reverse-proxy request rejected")
	}
	checks := []func(*http.Request){
		func(value *http.Request) { value.Header.Set("Origin", "https://attacker.example") },
		func(value *http.Request) { value.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate") },
		func(value *http.Request) { value.Header.Set("Sec-WebSocket-Protocol", "other") },
		func(value *http.Request) { value.URL.RawQuery = "x=1" },
		func(value *http.Request) { value.URL.RawPath = "/connects%2fenrollment" },
		func(value *http.Request) { value.RemoteAddr = "203.0.113.10:1234" },
	}
	for index, mutate := range checks {
		value := base.Clone(context.Background())
		value.URL = cloneURL(base.URL)
		mutate(value)
		if exchangeHTTPShape(value, false) {
			t.Fatalf("unsafe HTTP shape %d accepted", index)
		}
	}
}

func TestContainerExchangeHTTPShapeAdmitsOnlyPrivateBridgeProxyPeers(t *testing.T) {
	base := &http.Request{
		Method: http.MethodGet, ProtoMajor: 1, ProtoMinor: 1, Host: "relay.example.com",
		URL: &urlForExchangeShape, Header: http.Header{"Sec-WebSocket-Protocol": []string{ExchangeWebSocketSubprotocol}},
	}
	for _, remote := range []string{"10.88.0.1:1234", "172.17.0.1:1234", "192.168.127.254:1234", "[fd00::1]:1234", "[::ffff:10.88.0.1]:1234"} {
		request := base.Clone(context.Background())
		request.RemoteAddr = remote
		if exchangeHTTPShape(request, false) {
			t.Fatalf("ordinary exchange handler admitted private proxy %q", remote)
		}
		if !exchangeHTTPShape(request, true) {
			t.Fatalf("container exchange handler rejected private proxy %q", remote)
		}
	}
	for _, remote := range []string{
		"203.0.113.10:1234", "100.64.0.1:1234", "169.254.1.2:1234", "224.0.0.1:1234",
		"0.0.0.0:1234", "[fe80::1]:1234", "[ff02::1]:1234", "[fe80::1%eth0]:1234", "10.88.0.1", "invalid",
	} {
		request := base.Clone(context.Background())
		request.RemoteAddr = remote
		if exchangeHTTPShape(request, true) {
			t.Fatalf("container exchange handler admitted unsafe proxy %q", remote)
		}
	}

	handler, err := NewContainerExchangeHandler(NewMailboxStore(), strings.Repeat("a", 64))
	if err != nil || !handler.allowPrivateProxyPeer {
		t.Fatalf("container exchange constructor did not bind private proxy policy: handler=%v err=%v", handler, err)
	}
}

func TestExchangeHandlerConnectionCapacityIsIndependentAndBounded(t *testing.T) {
	_, _, _, allocation := exchangeRegistrationFixture(t)
	hash, _ := AllocationCapabilitySHA256(allocation)
	handler, _ := NewExchangeHandler(NewMailboxStore(), hash)
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		handler.Serve(context.Background(), output, request)
	}))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	connections := make([]*websocket.Conn, 0, MaxExchangeConnections)
	for index := 0; index < MaxExchangeConnections; index++ {
		connection, _, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{Subprotocols: []string{ExchangeWebSocketSubprotocol}})
		if err != nil {
			t.Fatalf("connection %d: %v", index, err)
		}
		connections = append(connections, connection)
	}
	defer func() {
		for _, connection := range connections {
			connection.CloseNow()
		}
	}()
	_, response, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{Subprotocols: []string{ExchangeWebSocketSubprotocol}})
	if err == nil || response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("overflow dial response=%v err=%v", response, err)
	}
}

func TestCourierRejectsAnyUnsafeDNSAnswerAndMismatchedPeer(t *testing.T) {
	endpoint, _ := parseCourierEndpoint("wss://relay.example.com/connects/enrollment")
	for _, addresses := range [][]net.IP{
		{net.ParseIP("127.0.0.1")},
		{net.ParseIP("203.0.113.34"), net.ParseIP("10.0.0.1")},
		{net.ParseIP("192.0.2.1")},
	} {
		courier := &Courier{lookup: func(context.Context, string, string) ([]net.IP, error) { return addresses, nil }, dial: (&net.Dialer{}).DialContext, public: isPublicCourierAddress}
		if _, err := courier.httpClient(context.Background(), endpoint); !errors.Is(err, ErrMailboxUnavailable) {
			t.Fatalf("unsafe answers %v accepted: %v", addresses, err)
		}
	}
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	courier := &Courier{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.34")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			return &peerConn{Conn: clientSide, remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.35"), Port: 443}}, nil
		},
		public: func(address netip.Addr) bool { return address.IsValid() },
	}
	client, err := courier.httpClient(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "relay.example.com:443"); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("mismatched connected peer = %v", err)
	}
}

func TestCourierCredentialStoreReturnsOnlyHashAndRotatesAtomically(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "courier")
	first, err := CreateCourierCredentialStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !validSHA256Hex(first) {
		t.Fatalf("credential initializer returned non-hash metadata %q", first)
	}
	retry, err := CreateCourierCredentialStore(root)
	if err != nil || retry != first {
		t.Fatalf("credential retry = %q, %v", retry, err)
	}
	capability, err := loadCourierCredential(root)
	if err != nil {
		t.Fatal(err)
	}
	computed, err := AllocationCapabilitySHA256(string(capability))
	wipe(capability)
	if err != nil || computed != first {
		t.Fatal("stored credential does not match returned relay hash")
	}
	rotated, err := RotateCourierCredentialStore(root)
	if err != nil || !validSHA256Hex(rotated) || rotated == first {
		t.Fatalf("rotated hash = %q, %v", rotated, err)
	}
	alias := filepath.Join(parent, "courier-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCourierCredential(alias); err == nil {
		t.Fatal("courier credential loader followed a symlinked root")
	}
}

func FuzzExchangeRequestParserNeverPanics(f *testing.F) {
	f.Add([]byte("OTEX"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = parseExchangeRequest(encoded)
	})
}

var urlForExchangeShape = mustURL("http://relay.example.com/connects/enrollment")

func mustURL(value string) url.URL {
	parsed, err := url.Parse(value)
	if err != nil {
		panic(err)
	}
	return *parsed
}

func cloneURL(value *url.URL) *url.URL {
	copy := *value
	return &copy
}

type peerConn struct {
	net.Conn
	remote net.Addr
}

func (connection *peerConn) RemoteAddr() net.Addr { return connection.remote }

func exchangeRegistrationFixture(t *testing.T) (time.Time, []byte, CourierRegistration, string) {
	t.Helper()
	base, signer, now := invitationFixture(t)
	issued, err := IssueInvitation(InvitationOptions{
		Role: enrollment.RoleClient, RouteID: base.RouteID, ConnectorInstallationID: base.ConnectorInstallationID,
		Runtime: base.Runtime, Trust: base.Trust, ExchangeEndpoint: base.Exchange.Endpoint, Validity: time.Hour,
		IntendedRecipient: "Example recipient", IdentityContactReference: "EXAMPLE-123",
	}, signer.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := ParseCourierRegistration(issued.CourierRegistration, now)
	if err != nil {
		t.Fatal(err)
	}
	allocationTarget, _, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	return now, issued.CourierRegistration, registration, allocationTarget.RequestWriteCapability
}

func exchangeTestRoundTrip(t *testing.T, endpoint string, messageType websocket.MessageType, encoded []byte) ([]byte, error) {
	t.Helper()
	response := exchangeTestRawRoundTrip(t, endpoint, messageType, encoded)
	return parseExchangeResponse(response)
}

func exchangeTestRawRoundTrip(t *testing.T, endpoint string, messageType websocket.MessageType, encoded []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{Subprotocols: []string{ExchangeWebSocketSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := connection.Write(ctx, messageType, encoded); err != nil {
		t.Fatal(err)
	}
	responseType, response, err := connection.Read(ctx)
	if err != nil || responseType != websocket.MessageBinary {
		t.Fatalf("response type=%v err=%v", responseType, err)
	}
	return response
}
