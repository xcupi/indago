package browser

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode/utf8"
)

// RuntimeLocation is Chromium's script identity and UTF-16 source position,
// never a page-supplied Error.stack or sourceURL identity.
type RuntimeLocation struct {
	ScriptID     string `json:"script_id"`
	URL          string `json:"url,omitempty"`
	FrameID      string `json:"frame_id"`
	ContextID    int    `json:"context_id"`
	Line         int    `json:"line"`
	Column       int    `json:"column"`
	SourceSHA256 string `json:"source_sha256,omitempty"`
}

type RuntimeException struct {
	Location         RuntimeLocation   `json:"location"`
	Description      string            `json:"description"`
	ClassName        string            `json:"class_name"`
	SourceExcerpt    string            `json:"source_excerpt,omitempty"`
	MarkerIdentifier bool              `json:"marker_identifier"`
	NodeID           int               `json:"node_id,omitempty"`
	CreationStack    []RuntimeLocation `json:"creation_stack,omitempty"`
	Stack            []RuntimeLocation `json:"stack,omitempty"`
}

// InstrumentationReport is collected from the native CDP console event only
// when the browser's call stack points into the exact installed init script.
// Public ConsoleMessages are diagnostic and must not be upgraded to this type.
type InstrumentationReport struct {
	Text     string          `json:"text"`
	Location RuntimeLocation `json:"location"`
	Caller   RuntimeLocation `json:"caller"`
	NodeIDs  []int           `json:"node_ids,omitempty"`
}

type RuntimeObservations struct {
	Available   bool                    `json:"available"`
	Note        string                  `json:"note,omitempty"`
	MainFrameID string                  `json:"main_frame_id"`
	Exceptions  []RuntimeException      `json:"exceptions,omitempty"`
	Reports     []InstrumentationReport `json:"reports,omitempty"`
}

// EnableRuntimeProvenance observes execution without evaluating payloads or
// invoking handlers/timers. Unsupported drivers fail closed in verdict code.
func (p *Page) EnableRuntimeProvenance(marker, initScript string) error {
	return p.handle.EnableRuntimeProvenance(marker, initScript)
}

func (p *Page) RuntimeObservations() RuntimeObservations { return p.handle.RuntimeObservations() }

func sourceDigest(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }

// markerAtPosition supports canonical event/timer bodies, marker statements in
// ordinary scripts, and a marker evaluated as a `${...}` substitution expression
// in a template literal. Reject ambiguous lexical constructs rather than
// guessing: regexes, non-ASCII prefixes and property/throw expressions are not
// evidence. The position is the actual paused V8 instruction, not an Error stack.
func markerAtPosition(source, marker string, line, column int) (bool, string) {
	if marker == "" || line < 0 || column < 0 {
		return false, ""
	}
	pos, ok := v8Offset(source, line, column)
	if !ok {
		return false, ""
	}
	// V8 reports a template literal's own start (the opening backtick) when the
	// throwing substitution is its FIRST element — `` `${MARKER}` `` — and the
	// identifier itself for any later substitution. Normalize that start to the
	// identifier position; every check below then applies unchanged, so the
	// marker must still be the template's first and whole substitution.
	if strings.HasPrefix(source[pos:], "`${") {
		pos += 3
	}
	if !strings.HasPrefix(source[pos:], marker) {
		return false, ""
	}
	end := pos + len(marker)
	if end < len(source) && (isIdentifierByte(source[end]) || source[end] == '.') {
		return false, ""
	}
	lastToken, ok := lastTokenBefore(source[:pos])
	if !ok {
		return false, ""
	}
	// Only a bare expression beginning a statement/body, or the expression of a
	// `${...}` substitution (whose opener the lexer reports as "{"). No throw
	// MARKER, property read, constructor call or identifier inside a fabricated
	// message.
	if lastToken != "" && lastToken != ";" && lastToken != "{" && lastToken != "}" {
		return false, ""
	}
	suffix := strings.TrimLeft(source[end:], " 	\r\n")
	if suffix != "" && !strings.HasPrefix(suffix, ";") && !strings.HasPrefix(suffix, "}") && !strings.HasPrefix(suffix, "//") {
		return false, ""
	}
	lo, hi := pos-80, end+80
	if lo < 0 {
		lo = 0
	}
	if hi > len(source) {
		hi = len(source)
	}
	return true, source[lo:hi]
}

// lastTokenBefore lexes a script prefix up to the engine's paused position and
// returns the last syntactic token it saw. It is a deliberately conservative
// allow-list: ordinary code, quoted strings, comments, and template literals
// (whose `${...}` substitutions are ordinary code again, while their text is a
// string). A regex literal, division, non-ASCII prefix or any unterminated
// construct yields ok=false instead of a guess.
//
// Template tracking is exact, not a blanket refusal: the marker must be inside
// a substitution expression, never in template text, so an echoed marker in
// “ `... ${x} MARKER` “ can never be read as an evaluation.
func lastTokenBefore(prefix string) (string, bool) {
	const (
		modeCode     = byte(0)
		modeLine     = 'l'
		modeBlock    = 'b'
		modeTemplate = '`'
	)
	mode := modeCode
	var subs []int // brace depth of each open ${ ... } substitution
	escaped := false
	lastToken := ""
	var ident strings.Builder
	flush := func() {
		if ident.Len() > 0 {
			lastToken = ident.String()
			ident.Reset()
		}
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c >= 128 {
			return "", false
		}
		switch mode {
		case '\'', '"':
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == mode {
				mode = modeCode
				lastToken = "literal"
			}
		case modeLine:
			if c == '\n' || c == '\r' {
				mode = modeCode
			}
		case modeBlock:
			if c == '*' && i+1 < len(prefix) && prefix[i+1] == '/' {
				mode = modeCode
				i++
			}
		case modeTemplate:
			if escaped {
				escaped = false
				continue
			}
			switch c {
			case '\\':
				escaped = true
			case '`':
				mode = modeCode
				lastToken = "literal"
			case '$':
				if i+1 < len(prefix) && prefix[i+1] == '{' {
					i++
					mode = modeCode
					subs = append(subs, 0)
					lastToken = "{"
				}
			}
		default: // modeCode
			if isIdentifierByte(c) {
				ident.WriteByte(c)
				continue
			}
			flush()
			switch c {
			case ' ', '	', '\r', '\n':
				// whitespace never changes the last token
			case '\'', '"':
				mode = c
			case '`':
				mode = modeTemplate
			case '/':
				if i+1 < len(prefix) && prefix[i+1] == '/' {
					mode = modeLine
					i++
				} else if i+1 < len(prefix) && prefix[i+1] == '*' {
					mode = modeBlock
					i++
				} else {
					return "", false // regex literal or division: refused
				}
			case '{':
				if n := len(subs); n > 0 {
					subs[n-1]++
				}
				lastToken = "{"
			case '}':
				if n := len(subs); n > 0 && subs[n-1] == 0 {
					// This brace closes the substitution: template text resumes,
					// so the next evaluated position would have to open another
					// `${`.
					subs = subs[:n-1]
					mode = modeTemplate
				} else {
					if n := len(subs); n > 0 {
						subs[n-1]--
					}
					lastToken = "}"
				}
			default:
				lastToken = string(c)
			}
		}
	}
	flush()
	if mode != modeCode || escaped {
		return "", false
	}
	return lastToken, true
}

// v8Offset converts V8's (line, UTF-16 column) into a byte offset. V8 ends a
// line at \n, \r, \r\n, U+2028 and U+2029. Splitting on \n alone shifts the
// mapping for a script that contains a bare \r, which would let a hostile page
// make the engine's real throw position and our reading of the source disagree
// and so place a marker identifier after a forged throw.
func v8Offset(source string, line, column int) (int, bool) {
	cur, i := 0, 0
	for cur < line {
		if i >= len(source) {
			return 0, false
		}
		r, size := utf8.DecodeRuneInString(source[i:])
		i += size
		switch {
		case r == '\r':
			if i < len(source) && source[i] == '\n' {
				i++
			}
			cur++
		case r == '\n' || r == 0x2028 || r == 0x2029:
			cur++
		}
	}
	units := 0
	for units < column {
		if i >= len(source) {
			return 0, false
		}
		r, size := utf8.DecodeRuneInString(source[i:])
		if r == '\r' || r == '\n' || r == 0x2028 || r == 0x2029 {
			return 0, false // column runs past the end of the line
		}
		if r >= 0x10000 {
			units += 2
		} else {
			units++
		}
		i += size
	}
	if units != column {
		return 0, false // landed inside a surrogate pair
	}
	return i, true
}
func isIdentifierByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

// Playwright installs an init script wrapped in an immediately invoked arrow
// function. The wrapper is part of the source Chromium reports, so identity is
// an exact match against the wrapped form (or the bare form for drivers that do
// not wrap). Containment is deliberately not accepted: a page script could
// embed the harness text in a comment and then forge harness reports.
const (
	playwrightInitScriptPrefix = "(() => {\n      "
	playwrightInitScriptSuffix = "\n    })();"
)

func isInstalledInitScript(code, initScript string) bool {
	if initScript == "" {
		return false
	}
	return code == initScript || code == playwrightInitScriptPrefix+initScript+playwrightInitScriptSuffix
}
