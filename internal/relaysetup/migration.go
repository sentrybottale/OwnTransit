package relaysetup

// SetupPlan describes one local administrative operation. Its private snapshot
// is revalidated under the manager lock before any service ownership changes.
type SetupPlan struct {
	Instance, URL, Kind                      string
	Port                                     int
	LegacyUnit, LegacyContainer, LegacyState string
	evidence                                 string
}
