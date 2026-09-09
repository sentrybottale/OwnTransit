package relaysetup

import (
	"bytes"
	"regexp"
	"strings"
)

// CaddyRoute targets one named site. A handle with an exact path is sorted
// before a catch-all handle by Caddy; the remainder of the site stays intact.
func CaddyRoute(data []byte, hostname string) (RouteEdit, error) {
	return CaddyRouteForPort(data, hostname, 9087)
}

// CaddyRouteForPort refuses to replace a /connects route belonging to another
// loopback port, including when the selected hostname aliases an existing site.
func CaddyRouteForPort(data []byte, hostname string, port int) (RouteEdit, error) {
	upstream, err := routeLoopback(port)
	if err != nil {
		return RouteEdit{}, err
	}
	tokens, err := scanConfig(data)
	if err != nil {
		return RouteEdit{}, err
	}
	var normalized []token
	for i, t := range tokens {
		if i > 0 {
			p := tokens[i-1]
			linebreak := bytes.Contains(data[p.end:t.start], []byte("\n"))
			if !p.isSymbol("{") && !p.isSymbol("}") && !p.isSymbol(";") && !t.isSymbol("{") && ((linebreak && !strings.HasSuffix(p.text, ",")) || t.isSymbol("}")) {
				normalized = append(normalized, token{";", p.end, p.end, true})
			}
		}
		if t.isSymbol("{") && (len(normalized) == 0 || normalized[len(normalized)-1].isSymbol("}")) {
			normalized = append(normalized, token{"__global", t.start, t.start, false})
		}
		normalized = append(normalized, t)
	}
	if len(normalized) > 0 && !normalized[len(normalized)-1].isSymbol("}") {
		normalized = append(normalized, token{";", len(data), len(data), true})
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
	var existing *block
	for i := range site.children {
		b := &site.children[i]
		matched := false
		for _, w := range b.words {
			if strings.Contains(w.text, "/connects") {
				if len(b.words) != 2 || b.words[0].text != "handle" || b.words[1].text != "/connects" || existing != nil {
					return RouteEdit{}, ErrRoute
				}
				existing = b
				matched = true
			}
		}
		if !matched && blockMentionsPath(*b, "/connects") {
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
	if existing != nil {
		if len(existing.children) != 0 || len(existing.directives) != 1 {
			return RouteEdit{}, ErrRoute
		}
		d := existing.directives[0]
		if len(d) != 2 || d[0].text != "reverse_proxy" {
			return RouteEdit{}, ErrRoute
		}
		if d[1].text == upstream {
			return RouteEdit{data, data, true}, nil
		}
		if literalRouteLoopback(d[1].text) {
			return RouteEdit{}, ErrRoutePortConflict
		}
		return RouteEdit{}, ErrRoute
	}
	addition := []byte("\n  # OwnTransit: selected-site WebSocket route\n  handle /connects {\n    reverse_proxy " + upstream + "\n  }\n")
	after := append([]byte(nil), data[:site.open+1]...)
	after = append(after, addition...)
	after = append(after, data[site.open+1:]...)
	return RouteEdit{append([]byte(nil), data...), after, false}, nil
}

// Unknown matchers/handlers may compete with the recognized exact route.
// The parser has already bounded tree depth and token count; do not interpret
// an unrecognized nested path as evidence of a simple alternate relay port.
func blockMentionsPath(b block, path string) bool {
	for _, word := range b.words {
		if strings.Contains(word.text, path) {
			return true
		}
	}
	for _, directive := range b.directives {
		for _, word := range directive {
			if strings.Contains(word.text, path) {
				return true
			}
		}
	}
	for _, child := range b.children {
		if blockMentionsPath(child, path) {
			return true
		}
	}
	return false
}

var virtualHostOpen = regexp.MustCompile(`(?im)^[\t ]*<VirtualHost\s+([^>]+)>`)
var virtualHostClose = regexp.MustCompile(`(?im)^[\t ]*</VirtualHost\s*>`)
var apacheNames = regexp.MustCompile(`(?im)^[\t ]*(?:ServerName|ServerAlias)[\t ]+([^\r\n#]+)`)

func ApacheRoute(data []byte, hostname string) (RouteEdit, error) {
	return ApacheRouteForPort(data, hostname, 9087)
}

// ApacheRouteForPort reuses only the exact /connects directive for the selected
// loopback port. Other routing in the selected site remains a conflict.
func ApacheRouteForPort(data []byte, hostname string, port int) (RouteEdit, error) {
	upstream, err := routeLoopback(port)
	if err != nil {
		return RouteEdit{}, err
	}
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
	directive := `ProxyPassMatch "^/connects$" "ws://` + upstream + `/connects"`
	existing := ""
	depth := 0
	for _, line := range strings.Split(string(data[s.begin:s.end]), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "<") {
			if strings.HasPrefix(line, "</") {
				depth--
			} else {
				depth++
			}
			if depth < 0 || depth > 32 {
				return RouteEdit{}, ErrRoute
			}
		}
		if strings.Contains(line, "/connects") {
			const prefix = `ProxyPassMatch "^/connects$" "ws://`
			const suffix = `/connects"`
			if depth != 0 || existing != "" || !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) || !literalRouteLoopback(strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix)) {
				return RouteEdit{}, ErrRoute
			}
			existing = line
		}
	}
	if depth != 0 {
		return RouteEdit{}, ErrRoute
	}
	if existing == directive {
		return RouteEdit{data, data, true}, nil
	}
	if existing != "" {
		return RouteEdit{}, ErrRoutePortConflict
	}
	addition := []byte("\n  # OwnTransit: selected-site WebSocket route\n  " + directive + "\n")
	after := append([]byte(nil), data[:s.begin]...)
	after = append(after, addition...)
	after = append(after, data[s.begin:]...)
	return RouteEdit{append([]byte(nil), data...), after, false}, nil
}
