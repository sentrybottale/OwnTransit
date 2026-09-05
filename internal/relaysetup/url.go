// Package relaysetup provides one local VPS setup workflow. The selected
// public URL identifies the website integration, never an SSH target.
package relaysetup

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
)

var ErrURL = errors.New("enter a public domain URL such as wss://relay.example/connects")

func PublicURL(input string) (string, error) {
	input = strings.TrimSpace(input)
	if len(input) == 0 || len(input) > 2048 {
		return "", ErrURL
	}
	if !strings.Contains(input, "://") {
		input = "wss://" + input
	}
	u, err := url.Parse(input)
	if err != nil || (u.Scheme != "https" && u.Scheme != "wss") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" {
		return "", ErrURL
	}
	if u.Port() != "" && u.Port() != "443" {
		return "", ErrURL
	}
	host := strings.ToLower(u.Hostname())
	if !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return "", ErrURL
	}
	u.Scheme, u.Host = "wss", host
	if u.Path == "" || u.Path == "/" {
		u.Path = pairrelay.Path
	}
	if u.Path != pairrelay.Path {
		return "", ErrURL
	}
	value := u.String()
	if _, err := pairrelay.NewPublicClient(value, nil); err != nil {
		return "", ErrURL
	}
	return value, nil
}
