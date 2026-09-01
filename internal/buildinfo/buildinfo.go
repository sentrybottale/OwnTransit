// Package buildinfo exposes immutable, offline executable provenance.
package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"

	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

const (
	// Schema identifies the stable machine-readable version output contract.
	Schema = "owntransit.build.v1"
	// Product is the public artifact family name.
	Product = "OwnTransit"
	// Protocol is the authenticated v1 inner TLS/wire profile. It is deliberately
	// not ldflag-settable because changing it is a protocol migration.
	Protocol = wireprofile.LegacyV1Protocol
)

// These values may be replaced at link time with -X. Their defaults make a
// source or development build explicit rather than pretending it is a release.
var (
	Version = "dev"
	Release = "unreleased"
	Commit  = "unknown"
	Dirty   = "unknown"
)

// Info is the stable JSON document emitted by every executable's version
// command. ConnectorTarget is present only for the connector role.
type Info struct {
	Schema          string `json:"schema"`
	Product         string `json:"product"`
	Version         string `json:"version"`
	ReleaseID       string `json:"release_id"`
	SourceCommit    string `json:"source_commit"`
	SourceDirty     string `json:"source_dirty"`
	Role            string `json:"role"`
	Protocol        string `json:"protocol"`
	GOOS            string `json:"goos"`
	GOARCH          string `json:"goarch"`
	ConnectorTarget string `json:"connector_target,omitempty"`
}

// Current returns provenance for one compiled executable role.
func Current(role, connectorTarget string) Info {
	return Info{
		Schema:          Schema,
		Product:         Product,
		Version:         Version,
		ReleaseID:       Release,
		SourceCommit:    Commit,
		SourceDirty:     Dirty,
		Role:            role,
		Protocol:        Protocol,
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		ConnectorTarget: connectorTarget,
	}
}

// Write emits exactly one JSON document followed by a newline.
func Write(output io.Writer, role, connectorTarget string) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(Current(role, connectorTarget))
}
