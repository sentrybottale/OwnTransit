package relaysetup

// SetupPlan describes one local administrative operation. Its private snapshot
// is revalidated under the manager lock before any service ownership changes.
type SetupPlan struct {
	Instance, URL, Kind                      string
	Verification                             string
	Port                                     int
	LegacyUnit, LegacyContainer, LegacyState string
	evidence                                 string
}

const VerificationPublic = "public"
const VerificationLocal403 = "local-route-http-403"

// SetupResult reports the verification actually completed by this VPS.
type SetupResult struct{ Verification string }
