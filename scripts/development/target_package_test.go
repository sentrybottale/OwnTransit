package development

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the real shell migration normalizer without touching systemd or a
// host package. Exact confinement and fixed state selection must survive the
// service-name transition; modified templates must remain different.
func TestTargetPackageTemplateMigrationPreservesConfinement(t *testing.T) {
	source, err := os.ReadFile("install-linux.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(source)
	start := strings.Index(s, "normalize_previous_unit() {")
	end := strings.Index(s[start:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("normalizer missing")
	}
	function := s[start : start+end+3]
	start = strings.Index(s, "[Unit]\n")
	end = strings.Index(s[start:], "\nEOF\n")
	if start < 0 || end < 0 {
		t.Fatal("target unit missing")
	}
	current := strings.ReplaceAll(s[start:start+end+1], "$prefix", "/opt/owntransit/0.7.0")
	legacy := strings.NewReplacer(
		"0.7.0", "0.6.1",
		"/opt/owntransit/", "/opt/owntransit-preview/",
		"/target/owntransit-target serve", "/connector/owntransit-connector pair serve",
		"/target\n", "/connector\n",
		" Target\n", " preview receiver pairing broker\n",
	).Replace(current)
	for _, tc := range []struct {
		name, unit string
		matches    bool
	}{
		{"current", current, true},
		{"previous", legacy, true},
		{"changed-confinement", strings.Replace(legacy, "ProtectSystem=strict", "ProtectSystem=no", 1), false},
		{"changed-state", strings.ReplaceAll(legacy, "/var/lib/owntransit-pair", "/var/lib/other"), false},
		{"extra-environment", legacy + "Environment=UNMANAGED=yes\n", false},
		{"unrecognized-version", strings.ReplaceAll(legacy, "0.6.1", "0.6.9"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "unit")
			if err := os.WriteFile(path, []byte(tc.unit), 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("sh", "-c", function+"\nnormalize_previous_unit \"$1\"", "fixture", path).CombinedOutput()
			if err != nil {
				t.Fatalf("normalization: %v: %s", err, out)
			}
			if bytes.Equal(out, []byte(current)) != tc.matches {
				t.Fatalf("ownership comparison mismatch: %s", out)
			}
		})
	}
}
