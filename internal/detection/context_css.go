package detection

import (
	"fmt"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// A CSS TOKENIZER determining the lexical position at the end of a source prefix:
// selector, at-rule prelude, property name, value, string, url(...), or comment.
// It tracks nested blocks (conditional group rules vs declaration blocks), string
// escapes, and url( with and without quotes. Like the JS lexer it is a tokenizer,
// not a full parser.

type cssKind uint8

const (
	cssSelector cssKind = iota
	cssAtRule
	cssProperty
	cssValue
	cssString
	cssURL
	cssComment
)

type cssResult struct {
	Kind    cssKind
	Quote   byte
	URLStr  bool   // a string that is the argument of url()
	AtRule  string // at-rule name for cssAtRule
	Depth   int
	Invalid bool
}

type cssBlock uint8

const (
	blockRules cssBlock = iota // contains rules (e.g. @media { ... })
	blockDecls                 // contains declarations
)

var cssGroupAtRules = map[string]bool{
	"media": true, "supports": true, "layer": true, "container": true, "document": true,
	"scope": true, "starting-style": true,
}

func isCSSIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c >= 0x80
}

// lexCSS lexes src. inDeclList starts inside a declaration list (a style="" value).
func lexCSS(src string, inDeclList bool) cssResult {
	const (
		mPrelude = iota
		mProperty
		mValue
	)
	var (
		stack     []cssBlock
		mode      = mPrelude
		atRule    string
		paren     int
		inComment bool
		inString  bool
		quote     byte
		urlStr    bool
		inURL     bool
		urlOpen   bool // just after "url(" (before the argument begins)
		invalid   bool
		word      string // identifier being accumulated
		justWord  string // identifier that ended right before the current byte
		i, n      = 0, len(src)
	)
	if inDeclList {
		stack = []cssBlock{blockDecls}
		mode = mProperty
	}

	for i < n {
		c := src[i]
		switch {
		case inComment:
			if c == '*' && i+1 < n && src[i+1] == '/' {
				inComment = false
				i += 2
			} else {
				i++
			}
			continue
		case inString:
			switch {
			case c == '\\':
				i += 2
			case c == quote:
				inString, urlStr = false, false
				i++
			case c == '\n':
				inString, urlStr, invalid = false, false, true
				i++
			default:
				i++
			}
			continue
		case inURL:
			if c == ')' {
				inURL = false
				if paren > 0 {
					paren--
				}
			}
			i++
			continue
		}

		if urlOpen {
			switch {
			case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
				i++
				continue
			case c == '"' || c == '\'':
				inString, quote, urlStr, urlOpen = true, c, true, false
				i++
				continue
			case c == ')':
				urlOpen = false
				if paren > 0 {
					paren--
				}
				i++
				continue
			default:
				urlOpen, inURL = false, true // unquoted url token begins at this byte
				continue                     // reprocess in the inURL branch
			}
		}

		// Track the identifier that ends at this byte (for url( detection).
		if isCSSIdent(c) {
			word += string(c)
			i++
			continue
		}
		justWord, word = word, ""

		switch {
		case c == '/' && i+1 < n && src[i+1] == '*':
			inComment = true
			i += 2
		case c == '"' || c == '\'':
			inString, quote = true, c
			i++
		case c == '(':
			paren++
			if strings.EqualFold(justWord, "url") {
				urlOpen = true
			}
			i++
		case c == ')':
			if paren > 0 {
				paren--
			}
			i++
		case c == '@' && mode == mPrelude:
			j := i + 1
			for j < n && isCSSIdent(src[j]) {
				j++
			}
			atRule = strings.ToLower(src[i+1 : j])
			i = j
		case c == '{':
			kind := blockDecls
			if mode == mPrelude && atRule != "" && cssGroupAtRules[atRule] {
				kind = blockRules
			}
			stack = append(stack, kind)
			atRule, paren = "", 0
			if kind == blockDecls {
				mode = mProperty
			} else {
				mode = mPrelude
			}
			i++
		case c == '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			atRule, paren = "", 0
			if len(stack) > 0 && stack[len(stack)-1] == blockDecls {
				mode = mProperty
			} else {
				mode = mPrelude
			}
			i++
		case c == ':' && mode == mProperty:
			mode = mValue
			i++
		case c == ';' && paren == 0:
			atRule = ""
			if len(stack) > 0 && stack[len(stack)-1] == blockDecls {
				mode = mProperty
			} else {
				mode = mPrelude
			}
			i++
		default:
			i++
		}
	}

	r := cssResult{Quote: quote, Depth: len(stack), Invalid: invalid}
	switch {
	case inComment:
		r.Kind = cssComment
	case inString:
		r.Kind, r.URLStr = cssString, urlStr
	case inURL || urlOpen:
		r.Kind = cssURL
	case mode == mProperty:
		r.Kind = cssProperty
	case mode == mValue:
		r.Kind = cssValue
	case atRule != "":
		r.Kind, r.AtRule = cssAtRule, atRule
	default:
		r.Kind = cssSelector
	}
	return r
}

// cssFragment classifies the end of a CSS source prefix.
func cssFragment(src string, inDeclList bool) fragment {
	r := lexCSS(src, inDeclList)
	f := fragment{ctx: CtxCSS, conf: domain.ConfidenceHigh, signals: []string{fmt.Sprintf("css_depth:%d", r.Depth)}}
	switch r.Kind {
	case cssComment:
		f.sub, f.reason = "comment", "inside a CSS /* comment */"
	case cssString:
		if r.URLStr {
			f.sub, f.reason = "url_string", "inside a quoted url(\"...\") argument in CSS"
		} else {
			f.sub = "string"
			f.reason = "inside a quoted CSS string"
		}
	case cssURL:
		f.sub, f.reason = "url_unquoted", "inside an unquoted CSS url(...) token"
	case cssProperty:
		f.sub, f.reason = "property", "at a CSS property-name position within a declaration block"
	case cssValue:
		f.sub, f.reason = "value", "in a CSS declaration value"
	case cssAtRule:
		f.sub, f.reason = "at_rule", fmt.Sprintf("in the prelude of the CSS @%s at-rule", r.AtRule)
	default:
		f.sub, f.reason = "selector", "in a CSS selector / rule prelude"
	}
	if r.Invalid {
		f.conf = domain.ConfidenceMedium
		f.signals = append(f.signals, "css_error_recovery")
		f.reason += " (an unterminated string occurs earlier, so the lexical state is approximate)"
	}
	return f
}
