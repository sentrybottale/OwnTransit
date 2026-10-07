package relaysetup

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const maxConfigBytes = 8 << 20

var ErrRoute = errors.New("the selected HTTPS site cannot be identified safely in this configuration")
var ErrNoSite = errors.New("the selected HTTPS site is not defined in this file")
var ErrRoutePortConflict = fmt.Errorf("%w: the exact route belongs to another host-loopback port", ErrRoute)

type RouteEdit struct {
	Before, After []byte
	Reused        bool
	// Exists distinguishes a recognized existing route needing its private-hop
	// header added from a missing route. Reused means no bytes need changing.
	Exists bool
}

const proxyPeerHeader = "OwnTransit-Peer-IP"

const nginxPeerHeader = "proxy_set_header " + proxyPeerHeader + " $realip_remote_addr;"

// Nginx inherits proxy_set_header only when the current level has none. A
// previously simple location can therefore inherit its WebSocket headers.
// Adding its first local setter must retain the ordinary carrier header set.
const nginxCarrierHeaders = "proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n    proxy_set_header Host $host;\n    proxy_set_header Origin $http_origin;\n    proxy_set_header Cookie \"\";\n    proxy_set_header Authorization \"\";\n    proxy_set_header Sec-WebSocket-Extensions \"\";"

type token struct {
	text       string
	start, end int
	symbol     bool
}

func (t token) isSymbol(value string) bool { return t.symbol && t.text == value }

type block struct {
	words       []token
	open, close int
	children    []block
	directives  [][]token
}

func routeLoopback(port int) (string, error) {
	if port < 1024 || port > 65535 {
		return "", ErrRoute
	}
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}

// scanConfig understands quoting, escapes, comments and ${variables}; braces
// inside those values never select a different site or insertion point.
func scanConfig(data []byte) ([]token, error) {
	var out []token
	err := scanConfigTokens(data, func(t token) error {
		if len(out) >= 100000 {
			return ErrRoute
		}
		out = append(out, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// The streaming scanner retains lexical and file-size bounds without building
// an AST-sized token array for unrelated generated includes such as geo maps.
func scanConfigTokens(data []byte, emit func(token) error) error {
	if len(data) == 0 || len(data) > maxConfigBytes || bytes.IndexByte(data, 0) >= 0 {
		return ErrRoute
	}
	for i := 0; i < len(data); {
		if strings.ContainsRune(" \t\r\n", rune(data[i])) {
			i++
			continue
		}
		if data[i] == '#' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		start := i
		if strings.ContainsRune("{};", rune(data[i])) && configPlaceholderEnd(data, i) == i {
			if err := emit(token{string(data[i]), i, i + 1, true}); err != nil {
				return err
			}
			i++
			continue
		}
		var word []byte
		quote := byte(0)
		for i < len(data) {
			c := data[i]
			if c == '\\' {
				if i+1 >= len(data) {
					return ErrRoute
				}
				word = append(word, data[i+1])
				i += 2
				continue
			}
			if quote != 0 {
				if c == quote {
					quote = 0
				} else {
					word = append(word, c)
				}
				i++
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				i++
				continue
			}
			if c == '$' && i+1 < len(data) && data[i+1] == '{' {
				end := bytes.IndexByte(data[i+2:], '}')
				if end < 0 {
					return ErrRoute
				}
				end += i + 3
				word = append(word, data[i:end]...)
				i = end
				continue
			}
			// Caddy placeholders are directive arguments, not configuration
			// blocks. Keep their grammar narrow so ordinary braces still delimit
			// the selected site's tree.
			if end := configPlaceholderEnd(data, i); end != i {
				word = append(word, data[i:end]...)
				i = end
				continue
			}
			if strings.ContainsRune(" \t\r\n{};#", rune(c)) {
				break
			}
			word = append(word, c)
			i++
		}
		if quote != 0 || i == start {
			return ErrRoute
		}
		if err := emit(token{string(word), start, i, false}); err != nil {
			return err
		}
	}
	return nil
}

func configPlaceholderEnd(data []byte, start int) int {
	if data[start] != '{' {
		return start
	}
	end := start + 1
	for end < len(data) && ((data[end] >= 'a' && data[end] <= 'z') || (data[end] >= 'A' && data[end] <= 'Z') || (data[end] >= '0' && data[end] <= '9') || data[end] == '_' || data[end] == '.') {
		end++
	}
	if end > start+1 && end < len(data) && data[end] == '}' {
		return end + 1
	}
	return start
}

// Every nginx -T include is inspected. A large, valid non-server fragment is
// not a failed site: validate its streaming grammar and return ErrNoSite before
// the stricter site AST token budget. Any server-block file still gets that
// complete bounded parser, regardless of its hostname, quoting or escapes.
func nginxHasServerBlock(data []byte) (bool, error) {
	// Optional includes (for example an empty blocklist) can have zero bytes.
	// They cannot select a site; keep the shared site lexer strict.
	if len(data) == 0 {
		return false, nil
	}
	depth, words := 0, 0
	first := ""
	found := false
	err := scanConfigTokens(data, func(t token) error {
		if !t.symbol {
			if words == 0 {
				first = t.text
			}
			words++
			return nil
		}
		switch t.text {
		case "{":
			if words == 0 || depth >= 32 {
				return ErrRoute
			}
			found = found || words == 1 && first == "server"
			depth++
		case "}":
			if depth == 0 || words != 0 {
				return ErrRoute
			}
			depth--
		case ";":
			if words == 0 {
				return ErrRoute
			}
		}
		words = 0
		first = ""
		return nil
	})
	if err != nil || depth != 0 || words != 0 {
		return false, ErrRoute
	}
	return found, nil
}

func parseBlocks(tokens []token, position *int, depth int) (block, error) {
	if depth > 32 {
		return block{}, ErrRoute
	}
	root := block{open: -1, close: -1}
	var words []token
	for *position < len(tokens) {
		t := tokens[*position]
		*position++
		if !t.symbol {
			words = append(words, t)
			continue
		}
		switch t.text {
		case "{":
			if len(words) == 0 {
				return block{}, ErrRoute
			}
			child, err := parseBlocks(tokens, position, depth+1)
			if err != nil {
				return block{}, err
			}
			child.words = words
			child.open = t.start
			root.children = append(root.children, child)
			words = nil
		case "}":
			if depth == 0 || len(words) != 0 {
				return block{}, ErrRoute
			}
			root.close = t.start
			return root, nil
		case ";":
			if len(words) == 0 {
				return block{}, ErrRoute
			}
			root.directives = append(root.directives, words)
			words = nil
		default:
			words = append(words, t)
		}
	}
	if depth != 0 || len(words) != 0 {
		return block{}, ErrRoute
	}
	return root, nil
}

// NginxRoute adds only an exact /connects location to one explicitly named TLS
// server. Existing matching routing receives a verified private-hop header.
// Already hardened routing is reused byte-for-byte. Ambiguous sites,
// server-level rewrites/returns and existing conflicting routes are rejected.
func NginxRoute(data []byte, hostname string) (RouteEdit, error) {
	return NginxRouteForPort(data, hostname, 9087)
}

// NginxRouteForPort selects only a validated host-loopback port. An existing
// /connects route to any other port is a conflict, never a replacement target.
func NginxRouteForPort(data []byte, hostname string, port int) (RouteEdit, error) {
	upstream, err := routeLoopback(port)
	if err != nil {
		return RouteEdit{}, err
	}
	hasServer, err := nginxHasServerBlock(data)
	if err != nil {
		return RouteEdit{}, err
	}
	if !hasServer {
		return RouteEdit{}, ErrNoSite
	}
	tokens, err := scanConfig(data)
	if err != nil {
		return RouteEdit{}, err
	}
	position := 0
	tree, err := parseBlocks(tokens, &position, 0)
	if err != nil {
		return RouteEdit{}, err
	}
	var matches []block
	var visit func(block)
	visit = func(b block) {
		if len(b.words) == 1 && b.words[0].text == "server" {
			named, tls := false, false
			for _, d := range b.directives {
				if d[0].text == "server_name" {
					for _, v := range d[1:] {
						named = named || v.text == hostname
					}
				}
				if d[0].text == "listen" && len(d) > 1 && (d[1].text == "443" || strings.HasSuffix(d[1].text, ":443")) {
					for _, v := range d[2:] {
						tls = tls || v.text == "ssl"
					}
				}
			}
			if named && tls {
				matches = append(matches, b)
			}
		}
		for _, c := range b.children {
			visit(c)
		}
	}
	visit(tree)
	if len(matches) == 0 {
		return RouteEdit{}, ErrNoSite
	}
	if len(matches) != 1 {
		return RouteEdit{}, ErrRoute
	}
	site := matches[0]
	for _, d := range site.directives {
		if d[0].text == "return" || d[0].text == "rewrite" {
			return RouteEdit{}, fmt.Errorf("%w: server-level redirect/rewrite", ErrRoute)
		}
	}
	var existing *block
	for i := range site.children {
		b := &site.children[i]
		if len(b.words) > 0 && b.words[0].text == "location" {
			// The legacy exchange is a distinct exact URI. It cannot override
			// the exact /connects carrier, and reuse must leave it untouched.
			if len(b.words) == 3 && b.words[1].text == "=" && b.words[2].text == "/connects/enrollment" {
				continue
			}
			for _, w := range b.words[1:] {
				if strings.Contains(w.text, "/connects") {
					if len(b.words) != 3 || b.words[1].text != "=" || b.words[2].text != "/connects" {
						return RouteEdit{}, ErrRoute
					}
					if existing != nil {
						return RouteEdit{}, ErrRoute
					}
					existing = b
				}
			}
		}
	}
	if existing != nil {
		if len(existing.children) != 0 {
			return RouteEdit{}, ErrRoute
		}
		proxy := ""
		proxySet := false
		peerHeader := false
		localHeaders := false
		for _, d := range existing.directives {
			if d[0].text == "return" || d[0].text == "rewrite" || d[0].text == "include" {
				return RouteEdit{}, ErrRoute
			}
			if d[0].text == "proxy_set_header" && len(d) > 1 && strings.EqualFold(d[1].text, proxyPeerHeader) {
				if peerHeader || len(d) != 3 || d[2].text != "$realip_remote_addr" {
					return RouteEdit{}, ErrRoute
				}
				peerHeader = true
			}
			localHeaders = localHeaders || d[0].text == "proxy_set_header"
			if d[0].text == "proxy_pass" {
				if len(d) != 2 || proxySet {
					return RouteEdit{}, ErrRoute
				}
				proxy = d[1].text
				proxySet = true
			}
		}
		if proxy == "http://"+upstream+"/connects" || proxy == "http://"+upstream {
			if peerHeader {
				return RouteEdit{Before: data, After: data, Reused: true, Exists: true}, nil
			}
			addition := "\n    " + nginxPeerHeader + "\n  "
			if !localHeaders {
				addition = "\n    " + nginxCarrierHeaders + addition
			}
			after := insertConfig(data, existing.close, []byte(addition))
			return RouteEdit{Before: append([]byte(nil), data...), After: after, Exists: true}, nil
		}
		if nginxLiteralLoopbackProxy(proxy) {
			return RouteEdit{}, ErrRoutePortConflict
		}
		return RouteEdit{}, ErrRoute
	}
	addition := []byte("\n  # OwnTransit: selected-site WebSocket route\n  location = /connects {\n    proxy_pass http://" + upstream + "/connects;\n    proxy_http_version 1.1;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n    proxy_set_header Host $host;\n    proxy_set_header Origin $http_origin;\n    proxy_set_header Cookie \"\";\n    proxy_set_header Authorization \"\";\n    proxy_set_header Sec-WebSocket-Extensions \"\";\n    " + nginxPeerHeader + "\n    proxy_buffering off;\n    proxy_read_timeout 1d;\n    proxy_send_timeout 1d;\n    access_log off;\n  }\n")
	after := append([]byte(nil), data[:site.close]...)
	after = append(after, addition...)
	after = append(after, data[site.close:]...)
	return RouteEdit{Before: append([]byte(nil), data...), After: after}, nil
}

func insertConfig(data []byte, offset int, addition []byte) []byte {
	after := append([]byte(nil), data[:offset]...)
	after = append(after, addition...)
	return append(after, data[offset:]...)
}

func nginxLiteralLoopbackProxy(proxy string) bool {
	const prefix = "http://"
	if !strings.HasPrefix(proxy, prefix) {
		return false
	}
	value := strings.TrimPrefix(proxy, prefix)
	value = strings.TrimSuffix(value, "/connects")
	return literalRouteLoopback(value)
}

func literalRouteLoopback(value string) bool {
	const prefix = "127.0.0.1:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	value = strings.TrimPrefix(value, prefix)
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1024 && port <= 65535 && strconv.Itoa(port) == value
}
