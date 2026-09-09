package relaysetup

import (
	"strings"
	"testing"
)

func TestRelayInstanceSelectors(t *testing.T) {
	for _, name := range []string{"", "default", "alpha", "office-2", "a", "a-", strings.Repeat("a", 32)} {
		if err := ValidateInstanceName(name); err != nil {
			t.Fatalf("valid selector %q: %v", name, err)
		}
	}
	for _, name := range []string{"all", ".", "..", "../alpha", "/alpha", "a/b", "a\\b", "A", "a b", "a\nb", "a\x00b", "a%20b", "a@b", "-a", "2alpha", "аlpha", strings.Repeat("a", 33)} {
		if ValidateInstanceName(name) == nil {
			t.Fatalf("unsafe selector %q accepted", name)
		}
	}
}
