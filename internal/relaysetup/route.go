package relaysetup

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

const maxConfigBytes = 8 << 20

var ErrRoute = errors.New("the selected HTTPS site cannot be identified safely in this configuration")
var ErrNoSite = errors.New("the selected HTTPS site is not defined in this file")

type RouteEdit struct {
	Before, After []byte
	Reused        bool
}
type token struct {
	text       string
	start, end int
}
type block struct {
	words       []token
	open, close int
	children    []block
	directives  [][]token
}

// scanConfig understands quoting, escapes, comments and ${variables}; braces
// inside those values never select a different site or insertion point.
func scanConfig(data []byte) ([]token, error) {
	if len(data) == 0 || len(data) > maxConfigBytes || bytes.IndexByte(data, 0) >= 0 {
		return nil, ErrRoute
	}
	var out []token
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
		if strings.ContainsRune("{};", rune(data[i])) {
			out = append(out, token{string(data[i]), i, i + 1})
			i++
			continue
		}
		var word []byte
		quote := byte(0)
		for i < len(data) {
			c := data[i]
			if c == '\\' {
				if i+1 >= len(data) {
					return nil, ErrRoute
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
					return nil, ErrRoute
				}
				end += i + 3
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
			return nil, ErrRoute
		}
		out = append(out, token{string(word), start, i})
		if len(out) > 100000 {
			return nil, ErrRoute
		}
	}
	return out, nil
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
// server. Existing matching routing is reused byte-for-byte. Ambiguous sites,
// server-level rewrites/returns and existing conflicting routes are rejected.
func NginxRoute(data []byte, hostname string) (RouteEdit, error) {
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
	for _, b := range site.children {
		if len(b.words) > 0 && b.words[0].text == "location" {
			for _, w := range b.words[1:] {
				if strings.Contains(w.text, "/connects") {
					if len(b.words) != 3 || b.words[1].text != "=" || b.words[2].text != "/connects" {
						return RouteEdit{}, ErrRoute
					}
					for _, d := range b.directives {
						if len(d) == 2 && d[0].text == "proxy_pass" && (d[1].text == "http://127.0.0.1:9087/connects" || d[1].text == "http://127.0.0.1:9087") {
							return RouteEdit{Before: data, After: data, Reused: true}, nil
						}
					}
					return RouteEdit{}, ErrRoute
				}
			}
		}
	}
	addition := []byte("\n  # OwnTransit: selected-site WebSocket route\n  location = /connects {\n    proxy_pass http://127.0.0.1:9087/connects;\n    proxy_http_version 1.1;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n    proxy_set_header Host $host;\n    proxy_set_header Origin $http_origin;\n    proxy_set_header Cookie \"\";\n    proxy_set_header Authorization \"\";\n    proxy_set_header Sec-WebSocket-Extensions \"\";\n    proxy_buffering off;\n    proxy_read_timeout 1d;\n    proxy_send_timeout 1d;\n    access_log off;\n  }\n")
	after := append([]byte(nil), data[:site.close]...)
	after = append(after, addition...)
	after = append(after, data[site.close:]...)
	return RouteEdit{Before: append([]byte(nil), data...), After: after}, nil
}
