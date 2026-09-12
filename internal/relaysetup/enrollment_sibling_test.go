package relaysetup

import (
	"bytes"
	"strings"
	"testing"
)

func TestExactLegacyEnrollmentSiblingDoesNotBlockCarrierReuse(t *testing.T) {
	config := []byte(`server {
 listen 443 ssl;
 server_name relay.example;
 location = /connects { proxy_pass http://127.0.0.1:9087/connects; }
 location = /connects/enrollment { proxy_pass http://127.0.0.1:9087/connects/enrollment; }
}`)
	edit, err := NginxRouteForPort(config, "relay.example", 9087)
	if err != nil || !edit.Reused || !bytes.Equal(edit.Before, config) || !bytes.Equal(edit.After, config) {
		t.Fatalf("exact sibling changed or blocked an existing carrier: %v", err)
	}
	for _, location := range []string{"location /connects/enrollment", "location ^~ /connects/enrollment", "location ~ /connects/enrollment", "location = /connects"} {
		bad := strings.Replace(string(config), "location = /connects/enrollment", location, 1)
		if _, err := NginxRouteForPort([]byte(bad), "relay.example", 9087); err == nil {
			t.Fatalf("ambiguous or duplicate carrier location accepted: %s", location)
		}
	}
	badPort := strings.Replace(string(config), "9087/connects;", "9088/connects;", 1)
	if _, err := NginxRouteForPort([]byte(badPort), "relay.example", 9087); err == nil {
		t.Fatal("sibling weakened cross-instance port rejection")
	}
}
