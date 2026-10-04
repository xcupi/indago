package detection

import (
	"fmt"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// A JavaScript TOKENIZER (not a parser) that determines the lexical state at the
// end of a source prefix: code, string, template literal, comment, or regex
// literal. It tracks escapes, template-literal ${...} nesting, and the
// regex-vs-division decision from the previous significant token.
//
// The one genuinely ambiguous decision — whether a '/' after ')' / '}' / '++'
// starts a regex or is division — cannot be settled without a parser. Rather
// than guess, analyzeJS lexes the prefix BOTH ways; if the two readings end in
// different states the site is reported as mixed with both alternatives.

type jsKind uint8

const (
	jsCode jsKind = iota
	jsString
	jsTemplate
	jsLineComment
	jsBlockComment
	jsRegex
)

type jsResult struct {
	Kind          jsKind
	Quote         byte // ' or " when Kind == jsString
	PendingEscape bool // the prefix ends right after an unconsumed backslash
	InRegexClass  bool
	ExprDepth     int    // number of enclosing template ${ } expressions
	Invalid       bool   // error recovery was needed (unterminated string/regex)
	Prev          string // previous significant token class at the end
}

func (r jsResult) sameState(o jsResult) bool {
	return r.Kind == o.Kind && r.Quote == o.Quote && r.PendingEscape == o.PendingEscape &&
		r.InRegexClass == o.InRegexClass && r.ExprDepth == o.ExprDepth
}

// regexAfterKeyword lists keywords after which '/' starts a regex literal.
var regexAfterKeyword = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true,
	"delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true,
	"yield": true, "await": true,
}

func isIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '$' || c >= 0x80 || c == '\\'
}

// lexJS lexes src. ambiguousAsRegex selects how a '/' in an ambiguous position
// is read.
func lexJS(src string, ambiguousAsRegex bool) jsResult {
	var (
		kind    = jsCode
		quote   byte
		prev    = "start"
		stack   []int // brace depth of each open template ${ }
		inClass bool
		invalid bool
		pending bool
		i, n    = 0, len(src)
	)
	for i < n {
		c := src[i]
		switch kind {
		case jsString:
			switch {
			case c == '\\':
				if i+1 >= n {
					pending = true
					i++
				} else if src[i+1] == '\r' && i+2 < n && src[i+2] == '\n' {
					i += 3
				} else {
					i += 2
				}
			case c == quote:
				kind, prev = jsCode, "string"
				i++
			case c == '\n' || c == '\r':
				invalid = true // an unescaped newline ends a '/" string (a syntax error)
				kind, prev = jsCode, "string"
				i++
			default:
				i++
			}

		case jsTemplate:
			switch {
			case c == '\\':
				if i+1 >= n {
					pending = true
					i++
				} else {
					i += 2
				}
			case c == '`':
				kind, prev = jsCode, "string"
				i++
			case c == '$' && i+1 < n && src[i+1] == '{':
				stack = append(stack, 0)
				kind, prev = jsCode, "operator"
				i += 2
			default:
				i++
			}

		case jsLineComment:
			if c == '\n' || c == '\r' {
				kind = jsCode
			}
			i++

		case jsBlockComment:
			if c == '*' && i+1 < n && src[i+1] == '/' {
				kind = jsCode
				i += 2
			} else {
				i++
			}

		case jsRegex:
			switch {
			case c == '\\':
				if i+1 >= n {
					pending = true
				}
				i += 2
			case c == '[':
				inClass = true
				i++
			case c == ']':
				inClass = false
				i++
			case c == '/' && !inClass:
				kind, prev = jsCode, "string" // behaves as an operand
				i++
			case c == '\n' || c == '\r':
				invalid = true
				kind, inClass = jsCode, false
				i++
			default:
				i++
			}

		default: // jsCode
			switch {
			case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
				i++
			case c == '/' && i+1 < n && src[i+1] == '/':
				kind = jsLineComment
				i += 2
			case c == '/' && i+1 < n && src[i+1] == '*':
				kind = jsBlockComment
				i += 2
			case c == '/':
				regex := false
				switch prev {
				case "start", "operator", "keyword":
					regex = true
				case "close_paren", "close_brace", "postfix":
					regex = ambiguousAsRegex
				}
				if regex {
					kind, inClass = jsRegex, false
				} else {
					prev = "operator"
				}
				i++
			case c == '\'' || c == '"':
				kind, quote = jsString, c
				i++
			case c == '`':
				kind = jsTemplate
				i++
			case c == '{':
				if len(stack) > 0 {
					stack[len(stack)-1]++
				}
				prev = "operator"
				i++
			case c == '}':
				if len(stack) > 0 {
					if stack[len(stack)-1] == 0 {
						stack = stack[:len(stack)-1]
						kind = jsTemplate // back into the template's text
						i++
						continue
					}
					stack[len(stack)-1]--
				}
				prev = "close_brace"
				i++
			case c == '(' || c == '[' || c == ',' || c == ';':
				prev = "operator"
				i++
			case c == ')':
				prev = "close_paren"
				i++
			case c == ']':
				prev = "close_bracket"
				i++
			case (c == '+' || c == '-') && i+1 < n && src[i+1] == c:
				prev = "postfix"
				i += 2
			case c >= '0' && c <= '9':
				for i < n && (isIdentByte(src[i]) || src[i] == '.') {
					i++
				}
				prev = "number"
			case isIdentByte(c):
				start := i
				for i < n && isIdentByte(src[i]) {
					i++
				}
				if regexAfterKeyword[src[start:i]] {
					prev = "keyword"
				} else {
					prev = "ident"
				}
			default: // other punctuators
				prev = "operator"
				i++
			}
		}
	}
	return jsResult{
		Kind: kind, Quote: quote, PendingEscape: pending && (kind == jsString || kind == jsTemplate || kind == jsRegex),
		InRegexClass: inClass && kind == jsRegex, ExprDepth: len(stack), Invalid: invalid, Prev: prev,
	}
}

// analyzeJS lexes src both ways for the ambiguous '/' and reports whether the two
// readings disagree about the final state.
func analyzeJS(src string) (primary, alternate jsResult, ambiguous bool) {
	primary = lexJS(src, false)
	alternate = lexJS(src, true)
	return primary, alternate, !primary.sameState(alternate)
}

// jsDescribe maps a lexer result to a context, sub-kind, and reason clause.
func jsDescribe(r jsResult) (Context, string, string) {
	switch r.Kind {
	case jsString:
		q := "double"
		if r.Quote == '\'' {
			q = "single"
		}
		return CtxJSString, q + "_quoted", fmt.Sprintf("inside a %s-quoted JavaScript string literal", q)
	case jsTemplate:
		return CtxJSString, "template_literal", "inside a JavaScript template literal (text part)"
	case jsLineComment:
		return CtxJSComment, "line", "inside a JavaScript // line comment"
	case jsBlockComment:
		return CtxJSComment, "block", "inside a JavaScript /* block comment */"
	case jsRegex:
		if r.InRegexClass {
			return CtxJSRegex, "character_class", "inside a character class of a JavaScript regular-expression literal"
		}
		return CtxJSRegex, "body", "inside a JavaScript regular-expression literal"
	default:
		if r.ExprDepth > 0 {
			return CtxJSCode, "template_expression", "in JavaScript code inside a template literal ${ } expression"
		}
		return CtxJSCode, "", "at a JavaScript code position (outside any string, comment, or regex)"
	}
}

// jsFragment classifies the end of a JS source prefix.
func jsFragment(src string) fragment {
	p, alt, amb := analyzeJS(src)
	if amb {
		c1, s1, r1 := jsDescribe(p)
		c2, s2, r2 := jsDescribe(alt)
		return fragment{
			ctx: CtxMixed, sub: "regex_or_division", conf: domain.ConfidenceLow,
			reason:  "a '/' after ')', '}' or '++'/'--' can open a regex literal or be a division operator, and without a parser the two readings place the site in different contexts",
			signals: []string{"js_slash_ambiguity"},
			alts: []ContextAlternative{
				{Context: c1, Sub: s1, Reason: "if that '/' is division: " + r1},
				{Context: c2, Sub: s2, Reason: "if that '/' starts a regex: " + r2},
			},
		}
	}
	ctx, sub, reason := jsDescribe(p)
	f := fragment{ctx: ctx, sub: sub, conf: domain.ConfidenceHigh, reason: reason, signals: []string{"js_prev:" + p.Prev}}
	if p.PendingEscape {
		f.signals = append(f.signals, "pending_escape")
		f.reason += "; the preceding backslash escapes the first reflected character"
	}
	if p.Invalid {
		f.conf = domain.ConfidenceMedium
		f.signals = append(f.signals, "js_error_recovery")
		f.reason += " (the script contains an unterminated string or regex earlier, so the lexical state is approximate)"
	}
	return f
}

// percentDecodeLoose decodes %XX sequences, leaving malformed ones intact. It is
// what a browser applies to the body of a javascript: URL before executing it.
func percentDecodeLoose(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h, ok1 := unhex(s[i+1]); ok1 {
				if l, ok2 := unhex(s[i+2]); ok2 {
					b.WriteByte(h<<4 | l)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
