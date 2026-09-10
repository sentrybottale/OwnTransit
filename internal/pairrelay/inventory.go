package pairrelay

import (
	"encoding/hex"
	"net"
	"sort"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/transport"
)

const MaxAdmissionRecords = 256

// AdmissionRecord contains public relay policy only. A removal is an honest
// relay admission decision, never an endpoint security alarm. Cutoffs are never
// discarded, including after an explicit local reapproval.
type AdmissionRecord struct {
	ReceiverID          string `json:"receiver_id"`
	RouteID             string `json:"route_id"`
	AdmissionRootSHA256 string `json:"admission_root_sha256"`
	Status              string `json:"status"`
	LastIssuedUnix      int64  `json:"last_issued_unix"`
	RejectIssuedThrough int64  `json:"reject_issued_through"`
}

type AdmissionInfo struct {
	ReceiverID      string `json:"receiver_id"`
	RouteID         string `json:"route_id"`
	Status          string `json:"status"`
	ActiveCarriers  int    `json:"active_carriers"`
	PendingCarriers int    `json:"pending_carriers"`
}

func admissionKey(record AdmissionRecord) (routeKey, error) {
	receiver, e1 := protocol.ParseID(record.ReceiverID)
	route, e2 := protocol.ParseRouteID(record.RouteID)
	root, e3 := hex.DecodeString(record.AdmissionRootSHA256)
	if e1 != nil || e2 != nil || e3 != nil || zeroID(receiver) || zeroRoute(route) || len(root) != 32 ||
		hex.EncodeToString(root) != record.AdmissionRootSHA256 || zeroDigest([32]byte(root)) || record.LastIssuedUnix <= 0 || record.RejectIssuedThrough < 0 {
		return routeKey{}, ErrProtocol
	}
	switch record.Status {
	case "approved", "observed":
		if record.LastIssuedUnix <= record.RejectIssuedThrough {
			return routeKey{}, ErrProtocol
		}
	case "removed":
		if record.RejectIssuedThrough < record.LastIssuedUnix {
			return routeKey{}, ErrProtocol
		}
	default:
		return routeKey{}, ErrProtocol
	}
	return routeKey{receiver, route}, nil
}

func ValidateAdmissionRecords(records []AdmissionRecord) error {
	if len(records) > MaxAdmissionRecords {
		return ErrCapacity
	}
	seen := make(map[routeKey]bool, len(records))
	for _, record := range records {
		key, err := admissionKey(record)
		if err != nil || seen[key] {
			return ErrProtocol
		}
		seen[key] = true
	}
	return nil
}

func (relay *Relay) admissionRecordsLocked() []AdmissionRecord {
	result := make([]AdmissionRecord, 0, len(relay.admissions))
	for _, record := range relay.admissions {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ReceiverID == result[j].ReceiverID {
			return result[i].RouteID < result[j].RouteID
		}
		return result[i].ReceiverID < result[j].ReceiverID
	})
	return result
}

// saveAdmissionLocked serializes disk publication with token issuance and
// admission. Failed removals remain denied in memory but are never acknowledged
// as durable. A failed approval cannot reopen admission in the running process.
func (relay *Relay) saveAdmissionLocked(key routeKey, next AdmissionRecord) error {
	previous, exists := relay.admissions[key]
	if !exists && len(relay.admissions) >= MaxAdmissionRecords {
		return ErrCapacity
	}
	if exists && previous == next && next.Status != "removed" {
		return nil
	}
	relay.admissions[key] = next
	if save := relay.config.SaveAdmissions; save != nil {
		if err := save(relay.admissionRecordsLocked()); err != nil {
			if next.Status != "removed" {
				if exists {
					relay.admissions[key] = previous
				} else {
					delete(relay.admissions, key)
				}
			}
			return ErrUnavailable
		}
	}
	return nil
}

func (relay *Relay) checkAdmissionLocked(claims TokenClaims) error {
	if relay.closed {
		return ErrAlreadyClosed
	}
	record, exists := relay.admissions[routeKey{claims.ReceiverID, claims.RouteID}]
	if exists && (record.Status == "removed" || claims.IssuedUnix <= record.RejectIssuedThrough ||
		record.AdmissionRootSHA256 != hex.EncodeToString(claims.AdmissionRootSHA256[:])) {
		return ErrUnauthorized
	}
	return nil
}

func (relay *Relay) recordClaimsLocked(claims TokenClaims, status string) error {
	if err := relay.checkAdmissionLocked(claims); err != nil {
		return err
	}
	key := routeKey{claims.ReceiverID, claims.RouteID}
	record, exists := relay.admissions[key]
	if !exists {
		record = AdmissionRecord{ReceiverID: claims.ReceiverID.String(), RouteID: claims.RouteID.String(),
			AdmissionRootSHA256: hex.EncodeToString(claims.AdmissionRootSHA256[:]), Status: status}
	}
	if status == "observed" {
		record.Status = status
	}
	record.LastIssuedUnix = max(record.LastIssuedUnix, claims.IssuedUnix)
	return relay.saveAdmissionLocked(key, record)
}

func (relay *Relay) ListAdmissions() ([]AdmissionInfo, error) {
	if relay == nil {
		return nil, ErrProtocol
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return nil, ErrAlreadyClosed
	}
	result := make([]AdmissionInfo, 0, len(relay.admissions))
	for _, record := range relay.admissionRecordsLocked() {
		key, _ := admissionKey(record)
		result = append(result, AdmissionInfo{ReceiverID: record.ReceiverID, RouteID: record.RouteID, Status: record.Status,
			ActiveCarriers: relay.activePerRoute[key], PendingCarriers: relay.runtimePerRoute[key]})
	}
	return result, nil
}

// RemoveAdmission denies the exact route and aborts only its relay connections.
// It never changes endpoint credentials, endpoint alarms, or SSH state.
func (relay *Relay) RemoveAdmission(receiver protocol.ID, route protocol.RouteID) error {
	if relay == nil || zeroID(receiver) || zeroRoute(route) {
		return ErrProtocol
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return ErrAlreadyClosed
	}
	key := routeKey{receiver, route}
	record, exists := relay.admissions[key]
	if !exists {
		return ErrUnavailable
	}
	record.Status = "removed"
	record.RejectIssuedThrough = max(record.RejectIssuedThrough, record.LastIssuedUnix, relay.now().Unix())
	err := relay.saveAdmissionLocked(key, record)
	delete(relay.registrations, key)
	// Keep the bounded signed advertisement for explicit local reapproval;
	// remove offer lookup so the removed admission is no longer advertised.
	if advertisement, ok := relay.advertisements[key]; ok {
		advertisement.hasOffer = false
		relay.advertisements[key] = advertisement
	}
	for connection := range relay.routeConnections[key] {
		_ = transport.Abort(connection)
	}
	for _, pairing := range []bool{true, false} {
		queue, counts, total := relay.runtime, relay.runtimePerRoute, &relay.runtimePending
		if pairing {
			queue, counts, total = relay.pairing, relay.pairingPerRoute, &relay.pairingPending
		}
		for _, leg := range queue[key] {
			_ = transport.Abort(leg.connection)
			select {
			case leg.done <- ErrUnauthorized:
			default:
			}
		}
		*total -= len(queue[key])
		delete(queue, key)
		delete(counts, key)
	}
	return err
}

func (relay *Relay) trackRouteConnection(claims TokenClaims, connection net.Conn) (func(), error) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if err := relay.checkAdmissionLocked(claims); err != nil {
		return nil, err
	}
	key := routeKey{claims.ReceiverID, claims.RouteID}
	if relay.routeConnections[key] == nil {
		relay.routeConnections[key] = make(map[net.Conn]struct{})
	}
	relay.routeConnections[key][connection] = struct{}{}
	return func() {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		delete(relay.routeConnections[key], connection)
		if len(relay.routeConnections[key]) == 0 {
			delete(relay.routeConnections, key)
		}
	}, nil
}
