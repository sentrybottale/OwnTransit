package relaysetup

import (
	"bytes"
	"regexp"
	"strings"
)

// CaddyRoute targets one named site. A handle with an exact path is sorted
// before a catch-all handle by Caddy; the remainder of the site stays intact.
func CaddyRoute(data []byte, hostname string) (RouteEdit, error) {
	tokens, err := scanConfig(data)
	if err != nil {
		return RouteEdit{}, err
	}
	var normalized []token
	for i, t := range tokens {
		if i > 0 {
			p := tokens[i-1]
			linebreak := bytes.Contains(data[p.end:t.start], []byte("\n"))
			if p.text != "{" && p.text != "}" && p.text != ";" && t.text != "{" && ((linebreak && !strings.HasSuffix(p.text, ",")) || t.text == "}") {
				normalized = append(normalized, token{";", p.end, p.end})
			}
		}
		if t.text == "{" && (len(normalized) == 0 || normalized[len(normalized)-1].text == "}") {
			normalized = append(normalized, token{"__global", t.start, t.start})
		}
		normalized = append(normalized, t)
	}
	if len(normalized) > 0 && normalized[len(normalized)-1].text != "}" {
		normalized = append(normalized, token{";", len(data), len(data)})
	}
	position := 0
	tree, err := parseBlocks(normalized, &position, 0)
	if err != nil {
		return RouteEdit{}, err
	}
	var sites []block
	for _, b := range tree.children {
		for _, w := range b.words {
			for _, name := range strings.Split(w.text, ",") {
				name = strings.TrimPrefix(name, "https://")
				name = strings.TrimSuffix(name, ":443")
				if name == hostname {
					sites = append(sites, b)
					break
				}
			}
		}
	}
	if len(sites) == 0 {
		return RouteEdit{}, ErrNoSite
	}
	if len(sites) != 1 {
		return RouteEdit{}, ErrRoute
	}
	site := sites[0]
	for _, b := range site.children {
		if len(b.words) == 2 && b.words[0].text == "handle" && b.words[1].text == "/connects" {
			for _, d := range b.directives {
				if len(d) == 2 && d[0].text == "reverse_proxy" && d[1].text == "127.0.0.1:9087" {
					return RouteEdit{data, data, true}, nil
				}
			}
			return RouteEdit{}, ErrRoute
		}
	}
	for _, d := range site.directives {
		for _, w := range d {
			if strings.Contains(w.text, "/connects") {
				return RouteEdit{}, ErrRoute
			}
		}
	}
	addition := []byte("\n  # OwnTransit: selected-site WebSocket route\n  handle /connects {\n    reverse_proxy 127.0.0.1:9087\n  }\n")
	after := append([]byte(nil), data[:site.open+1]...)
	after = append(after, addition...)
	after = append(after, data[site.open+1:]...)
	return RouteEdit{append([]byte(nil), data...), after, false}, nil
}

var virtualHostOpen = regexp.MustCompile(`(?im)^[\t ]*<VirtualHost\s+([^>]+)>`)
var virtualHostClose = regexp.MustCompile(`(?im)^[\t ]*</VirtualHost\s*>`)
var apacheNames = regexp.MustCompile(`(?im)^[\t ]*(?:ServerName|ServerAlias)[\t ]+([^\r\n#]+)`)

func ApacheRoute(data []byte, hostname string) (RouteEdit, error) {
	if len(data) == 0 || len(data) > maxConfigBytes || bytes.IndexByte(data, 0) >= 0 {
		return RouteEdit{}, ErrRoute
	}
	type site struct{ begin, end int }
	var sites []site
	for _, m := range virtualHostOpen.FindAllSubmatchIndex(data, -1) {
		ssl := false
		for _, addr := range strings.Fields(string(data[m[2]:m[3]])) {
			ssl = ssl || strings.HasSuffix(addr, ":443")
		}
		if !ssl {
			continue
		}
		closing := virtualHostClose.FindIndex(data[m[1]:])
		if closing == nil {
			return RouteEdit{}, ErrRoute
		}
		end := m[1] + closing[0]
		named := false
		for _, match := range apacheNames.FindAllSubmatch(data[m[1]:end], -1) {
			for _, name := range strings.Fields(string(match[1])) {
				name = strings.Trim(name, "\"")
				name = strings.TrimPrefix(name, "https://")
				name = strings.TrimSuffix(name, ":443")
				named = named || name == hostname
			}
		}
		if named {
			sites = append(sites, site{m[1], end})
		}
	}
	if len(sites) == 0 {
		return RouteEdit{}, ErrNoSite
	}
	if len(sites) != 1 {
		return RouteEdit{}, ErrRoute
	}
	s := sites[0]
	directive := `ProxyPassMatch "^/connects$" "ws://127.0.0.1:9087/connects"`
	for _, line := range strings.Split(string(data[s.begin:s.end]), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == directive {
			return RouteEdit{data, data, true}, nil
		}
		if strings.Contains(line, "/connects") {
			return RouteEdit{}, ErrRoute
		}
	}
	addition := []byte("\n  # OwnTransit: selected-site WebSocket route\n  " + directive + "\n")
	after := append([]byte(nil), data[:s.begin]...)
	after = append(after, addition...)
	after = append(after, data[s.begin:]...)
	return RouteEdit{append([]byte(nil), data...), after, false}, nil
}
