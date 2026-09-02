package enrollmentexchange

import (
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

const (
	ExchangeWebSocketSubprotocol      = "owntransit-enrollment-exchange/1"
	exchangeWireVersion          byte = 1
	exchangeRequestHeaderSize         = 4 + 1 + 1 + 2 + 4 + protocol.IDSize + mailboxCapabilitySize
	exchangeResponseHeaderSize        = 4 + 1 + 1 + 2 + 4
	MaxExchangeWireMessage            = exchangeRequestHeaderSize + MaxBoundResponseSize
)

var exchangeWireMagic = [4]byte{'O', 'T', 'E', 'X'}

type exchangeAction byte

const (
	actionCreateMailbox  exchangeAction = 1
	actionPutRequest     exchangeAction = 2
	actionReadRequest    exchangeAction = 3
	actionPutResponse    exchangeAction = 4
	actionReadResponse   exchangeAction = 5
	actionConsumeMailbox exchangeAction = 6
)

type exchangeRequest struct {
	action     exchangeAction
	mailboxID  string
	capability string
	payload    []byte
}

func encodeExchangeRequest(action exchangeAction, mailboxID, capability string, payload []byte) ([]byte, error) {
	id, err := protocol.ParseID(mailboxID)
	if err != nil || id == (protocol.ID{}) {
		return nil, ErrMailboxUnavailable
	}
	decodedCapability, err := parseMailboxCapability(capability)
	if err != nil {
		return nil, ErrMailboxUnavailable
	}
	if !validExchangePayload(action, payload) {
		return nil, ErrMailboxUnavailable
	}
	encoded := make([]byte, exchangeRequestHeaderSize+len(payload))
	copy(encoded[:4], exchangeWireMagic[:])
	encoded[4], encoded[5] = exchangeWireVersion, byte(action)
	binary.BigEndian.PutUint32(encoded[8:12], uint32(len(payload)))
	copy(encoded[12:12+protocol.IDSize], id[:])
	copy(encoded[12+protocol.IDSize:exchangeRequestHeaderSize], decodedCapability)
	copy(encoded[exchangeRequestHeaderSize:], payload)
	return encoded, nil
}

func parseExchangeRequest(encoded []byte) (exchangeRequest, error) {
	if len(encoded) < exchangeRequestHeaderSize || len(encoded) > MaxExchangeWireMessage ||
		string(encoded[:4]) != string(exchangeWireMagic[:]) || encoded[4] != exchangeWireVersion ||
		encoded[6] != 0 || encoded[7] != 0 {
		return exchangeRequest{}, ErrMailboxUnavailable
	}
	action := exchangeAction(encoded[5])
	payloadSize := int(binary.BigEndian.Uint32(encoded[8:12]))
	if payloadSize != len(encoded)-exchangeRequestHeaderSize {
		return exchangeRequest{}, ErrMailboxUnavailable
	}
	var id protocol.ID
	copy(id[:], encoded[12:12+protocol.IDSize])
	if id == (protocol.ID{}) {
		return exchangeRequest{}, ErrMailboxUnavailable
	}
	capability := base64.RawURLEncoding.EncodeToString(encoded[12+protocol.IDSize : exchangeRequestHeaderSize])
	// The payload deliberately borrows the complete message buffer and is valid
	// only for synchronous dispatch. Clamp its capacity so a caller cannot append
	// into header-adjacent storage. MailboxStore.put authenticates the action
	// capability before making the sole durable copy.
	payload := encoded[exchangeRequestHeaderSize:len(encoded):len(encoded)]
	if !validExchangePayload(action, payload) {
		return exchangeRequest{}, ErrMailboxUnavailable
	}
	return exchangeRequest{action: action, mailboxID: id.String(), capability: capability, payload: payload}, nil
}

func validExchangePayload(action exchangeAction, payload []byte) bool {
	switch action {
	case actionCreateMailbox:
		return len(payload) > 0 && len(payload) <= MaxCourierRegistrationSize
	case actionPutRequest:
		return len(payload) > 0 && len(payload) <= MaxEncryptedRequestSize
	case actionReadRequest, actionReadResponse, actionConsumeMailbox:
		return len(payload) == 0
	case actionPutResponse:
		return len(payload) > 0 && len(payload) <= MaxBoundResponseSize
	default:
		return false
	}
}

func encodeExchangeResponse(payload []byte, success bool) ([]byte, error) {
	if len(payload) > MaxBoundResponseSize || !success && len(payload) != 0 {
		return nil, errors.New("enrollmentexchange: invalid exchange response")
	}
	encoded := make([]byte, exchangeResponseHeaderSize+len(payload))
	copy(encoded[:4], exchangeWireMagic[:])
	encoded[4] = exchangeWireVersion
	if !success {
		encoded[5] = 1
	}
	binary.BigEndian.PutUint32(encoded[8:12], uint32(len(payload)))
	copy(encoded[exchangeResponseHeaderSize:], payload)
	return encoded, nil
}

func parseExchangeResponse(encoded []byte) ([]byte, error) {
	if len(encoded) < exchangeResponseHeaderSize || len(encoded) > exchangeResponseHeaderSize+MaxBoundResponseSize ||
		string(encoded[:4]) != string(exchangeWireMagic[:]) || encoded[4] != exchangeWireVersion || encoded[6] != 0 || encoded[7] != 0 ||
		int(binary.BigEndian.Uint32(encoded[8:12])) != len(encoded)-exchangeResponseHeaderSize {
		return nil, ErrMailboxUnavailable
	}
	if encoded[5] != 0 {
		if encoded[5] != 1 || len(encoded) != exchangeResponseHeaderSize {
			return nil, ErrMailboxUnavailable
		}
		return nil, ErrMailboxUnavailable
	}
	return append([]byte(nil), encoded[exchangeResponseHeaderSize:]...), nil
}
