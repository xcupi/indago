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

// markerAtPosition supports canonical event/timer bodies and marker statements
// in ordinary scripts. Reject ambiguous lexical constructs rather than guessing:
// templates, regexes, non-ASCII prefixes and property/throw expressions are not
// evidence. The position is the actual paused V8 instruction, not an Error stack.
func markerAtPosition(source, marker string, line, column int) (bool, string) {
	if marker == "" || line < 0 || column < 0 {
		return false, ""
	}
	pos, ok := v8Offset(source, line, column)
	if !ok || !strings.HasPrefix(source[pos:], marker) {
		return false, ""
	}
	end := pos + len(marker)
	if end < len(source) && (isIdentifierByte(source[end]) || source[end] == '.') {
		return false, ""
	}
	// A conservative lexer: only normal code, quoted strings and comments.
	state := byte(0)
	escaped := false
	lastToken := ""
	token := ""
	flush := func() {
		if token != "" {
			lastToken = token
			token = ""
		}
	}
	for i := 0; i < pos; i++ {
		c := source[i]
		if c >= 128 || c == '`' {
			return false, ""
		}
		switch state {
		case '\'', '"':
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == state {
				state = 0
				lastToken = "literal"
			}
		case 'l':
			if c == '\n' || c == '\r' {
				state = 0
			}
		case 'b':
			if c == '*' && i+1 < pos && source[i+1] == '/' {
				state = 0
				i++
			}
		default:
			if isIdentifierByte(c) {
				token += string(c)
				continue
			}
			flush()
			if c == '\'' || c == '"' {
				state = c
			} else if c == '/' {
				if i+1 < pos && source[i+1] == '/' {
					state = 'l'
					i++
				} else if i+1 < pos && source[i+1] == '*' {
					state = 'b'
					i++
				} else {
					return false, ""
				}
			} else if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
				lastToken = string(c)
			}
		}
	}
	flush()
	if state != 0 {
		return false, ""
	}
	// Only a bare expression beginning a statement/body. No throw MARKER,
	// property read, constructor call or identifier inside a fabricated message.
	if lastToken != "" && lastToken != ";" && lastToken != "{" && lastToken != "}" {
		return false, ""
	}
	suffix := strings.TrimLeft(source[end:], " \t\r\n")
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
