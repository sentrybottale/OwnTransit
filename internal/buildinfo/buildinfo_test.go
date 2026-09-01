package buildinfo

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/sentrybottale/owntransit/internal/config"
)

func TestCurrentIncludesImmutableRoleAndPlatform(t *testing.T) {
	info := Current("connector", "127.0.0.1:22")
	if info.Schema != Schema || info.Product != Product || info.Protocol != Protocol {
		t.Fatalf("unexpected immutable build identity: %+v", info)
	}
	if info.Version != Version || info.ReleaseID != Release || info.SourceCommit != Commit || info.SourceDirty != Dirty {
		t.Fatalf("unexpected release provenance: %+v", info)
	}
	if info.Role != "connector" || info.ConnectorTarget != "127.0.0.1:22" {
		t.Fatalf("unexpected role identity: %+v", info)
	}
	if info.GOOS != runtime.GOOS || info.GOARCH != runtime.GOARCH {
		t.Fatalf("unexpected platform identity: %+v", info)
	}
}

func TestProtocolMatchesAuthenticatedInnerProfile(t *testing.T) {
	if Protocol != config.InnerALPN {
		t.Fatalf("build protocol = %q, authenticated inner ALPN = %q", Protocol, config.InnerALPN)
	}
}

func TestWriteEmitsOneJSONDocument(t *testing.T) {
	var output bytes.Buffer
	if err := Write(&output, "client", ""); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var info Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	if info.Role != "client" || info.ConnectorTarget != "" {
		t.Fatalf("unexpected version output: %+v", info)
	}
	if bytes.Count(output.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("version output must contain exactly one trailing newline: %q", output.Bytes())
	}
}
