package detection

import (
	"bytes"
	"strings"
)

// htmlScanner is a forward-only HTML tokenizer state machine, a faithful but
// reduced implementation of the WHATWG tokenizer states that determine what a
// byte inserted at a given position would be parsed as. It is driven through the
// real response bytes with advance(); its state at offset N is "what the parser
// is doing right before it reads body[N]".
//
// It is a value type holding only indices into the body, so a copy is a cheap
// snapshot.
type htmlScanner struct {
	body []byte
	pos  int
	st   hstate

	tagStart       int // offset of the '<' that opened the current tag/comment
	nameStart      int // current tag name span
	nameEnd        int
	isEnd          bool // current tag is an end tag
	selfClosing    bool
	attrStart      int // current attribute name span
	attrEnd        int
	valueStart     int // start of the current attribute value (after the quote)
	dataStart      int // start of the current text node
	rawTag         string
	rawStart       int    // start of raw-text/RCDATA/script content
	scriptType     string // lowercased type="" of the open <script>
	pendingType    string // type="" seen on the tag being parsed
	commentStart   int    // offset right after "<!--"
	foreign        int    // nesting depth inside <svg>/<math>
	anomalies      int    // parse-error-like events seen so far
	lastValueQuote byte
}

type hstate uint8

const (
	sData hstate = iota
	sTagOpen
	sEndTagOpen
	sTagName
	sBeforeAttrName
	sAttrName
	sAfterAttrName
	sBeforeAttrValue
	sAttrValueDQ
	sAttrValueSQ
	sAttrValueUnq
	sAfterAttrValueQ
	sSelfClosing
	sMarkupDecl
	sComment
	sBogusComment
	sDoctype
	sCDATA
	sRawText
)

var stateNames = [...]string{
	"data", "tag_open", "end_tag_open", "tag_name", "before_attr_name", "attr_name",
	"after_attr_name", "before_attr_value", "attr_value_dq", "attr_value_sq",
	"attr_value_unquoted", "after_attr_value_quoted", "self_closing", "markup_decl",
	"comment", "bogus_comment", "doctype", "cdata", "raw_text",
}

func (s hstate) String() string { return stateNames[s] }

func newHTMLScanner(body []byte) htmlScanner { return htmlScanner{body: body} }

// rawTextElements are the elements whose content is not tokenized as markup.
var rawTextElements = map[string]bool{
	"script": true, "style": true, "textarea": true, "title": true,
	"xmp": true, "iframe": true, "noembed": true, "noframes": true, "noscript": true,
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func isASCIIAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// tag returns the current tag name, lowercased.
func (s *htmlScanner) tag() string {
	if s.nameEnd <= s.nameStart || s.nameEnd > len(s.body) {
		return ""
	}
	return strings.ToLower(string(s.body[s.nameStart:s.nameEnd]))
}

// attr returns the current attribute name, lowercased.
func (s *htmlScanner) attr() string {
	if s.attrEnd <= s.attrStart || s.attrEnd > len(s.body) {
		return ""
	}
	return strings.ToLower(string(s.body[s.attrStart:s.attrEnd]))
}

// advance processes bytes until the scanner is positioned at `to` (the state
// "before reading body[to]") or the body ends.
func (s *htmlScanner) advance(to int) {
	if to > len(s.body) {
		to = len(s.body)
	}
	for s.pos < to {
		s.step(to)
	}
}

func (s *htmlScanner) toData(next int) {
	s.st = sData
	s.dataStart = next
}

// step consumes one input unit. `to` bounds multi-byte lookahead jumps so a jump
// never skips over the insertion point.
func (s *htmlScanner) step(to int) {
	b := s.body
	c := b[s.pos]

	switch s.st {
	case sData:
		if c == '<' {
			s.tagStart = s.pos
			s.st = sTagOpen
		}
		s.pos++

	case sTagOpen:
		switch {
		case c == '!':
			s.st = sMarkupDecl
			s.pos++
		case c == '/':
			s.st = sEndTagOpen
			s.pos++
		case isASCIIAlpha(c):
			s.beginTagName(false)
		case c == '?':
			s.commentStart = s.pos
			s.st = sBogusComment
			s.pos++
		default: // '<' was literal text
			s.toData(s.tagStart)
			// reconsume c in the data state
		}

	case sEndTagOpen:
		switch {
		case isASCIIAlpha(c):
			s.beginTagName(true)
		case c == '>':
			s.toData(s.pos + 1)
			s.pos++
		default:
			s.commentStart = s.pos
			s.st = sBogusComment
		}

	case sTagName:
		switch {
		case isHTMLSpace(c):
			s.pendingType = ""
			s.st = sBeforeAttrName
			s.pos++
		case c == '/':
			s.st = sSelfClosing
			s.pos++
		case c == '>':
			s.emitTag()
			s.pos++
		default:
			s.nameEnd = s.pos + 1
			s.pos++
		}

	case sBeforeAttrName:
		switch {
		case isHTMLSpace(c):
			s.pos++
		case c == '/':
			s.st = sSelfClosing
			s.pos++
		case c == '>':
			s.emitTag()
			s.pos++
		default:
			if c == '=' {
				s.anomalies++
			}
			s.attrStart, s.attrEnd = s.pos, s.pos+1
			s.st = sAttrName
			s.pos++
		}

	case sAttrName:
		switch {
		case isHTMLSpace(c):
			s.st = sAfterAttrName
			s.pos++
		case c == '/':
			s.st = sSelfClosing
			s.pos++
		case c == '>':
			s.emitTag()
			s.pos++
		case c == '=':
			s.st = sBeforeAttrValue
			s.pos++
		default:
			if c == '"' || c == '\'' || c == '<' {
				s.anomalies++
			}
			s.attrEnd = s.pos + 1
			s.pos++
		}

	case sAfterAttrName:
		switch {
		case isHTMLSpace(c):
			s.pos++
		case c == '/':
			s.st = sSelfClosing
			s.pos++
		case c == '=':
			s.st = sBeforeAttrValue
			s.pos++
		case c == '>':
			s.emitTag()
			s.pos++
		default: // a new attribute begins
			s.attrStart, s.attrEnd = s.pos, s.pos+1
			s.st = sAttrName
			s.pos++
		}

	case sBeforeAttrValue:
		switch {
		case isHTMLSpace(c):
			s.pos++
		case c == '"':
			s.valueStart = s.pos + 1
			s.st = sAttrValueDQ
			s.pos++
		case c == '\'':
			s.valueStart = s.pos + 1
			s.st = sAttrValueSQ
			s.pos++
		case c == '>':
			s.anomalies++ // missing attribute value
			s.emitTag()
			s.pos++
		default:
			s.valueStart = s.pos
			s.st = sAttrValueUnq // reconsume in the unquoted state
		}

	case sAttrValueDQ:
		if c == '"' {
			s.endAttrValue(s.pos)
			s.st = sAfterAttrValueQ
		}
		s.pos++

	case sAttrValueSQ:
		if c == '\'' {
			s.endAttrValue(s.pos)
			s.st = sAfterAttrValueQ
		}
		s.pos++

	case sAttrValueUnq:
		switch {
		case isHTMLSpace(c):
			s.endAttrValue(s.pos)
			s.st = sBeforeAttrName
			s.pos++
		case c == '>':
			s.endAttrValue(s.pos)
			s.emitTag()
			s.pos++
		default:
			if c == '"' || c == '\'' || c == '<' || c == '=' || c == '`' {
				s.anomalies++
			}
			s.pos++
		}

	case sAfterAttrValueQ:
		switch {
		case isHTMLSpace(c):
			s.st = sBeforeAttrName
			s.pos++
		case c == '/':
			s.st = sSelfClosing
			s.pos++
		case c == '>':
			s.emitTag()
			s.pos++
		default:
			s.anomalies++ // missing whitespace between attributes
			s.st = sBeforeAttrName
			// reconsume
		}

	case sSelfClosing:
		if c == '>' {
			s.selfClosing = true
			s.emitTag()
			s.pos++
		} else {
			s.anomalies++
			s.st = sBeforeAttrName
			// reconsume
		}

	case sMarkupDecl:
		rest := b[s.pos:]
		switch {
		case bytes.HasPrefix(rest, []byte("--")):
			if s.pos+2 > to {
				s.pos = to // insertion point is inside "<!--": leave as markup decl
				return
			}
			s.pos += 2
			s.commentStart = s.pos
			s.st = sComment
			s.abruptCommentClose()
		case len(rest) >= 7 && strings.EqualFold(string(rest[:7]), "DOCTYPE"):
			if s.pos+7 > to {
				s.pos = to
				return
			}
			s.pos += 7
			s.st = sDoctype
		case s.foreign > 0 && bytes.HasPrefix(rest, []byte("[CDATA[")):
			if s.pos+7 > to {
				s.pos = to
				return
			}
			s.pos += 7
			s.commentStart = s.pos
			s.st = sCDATA
		default:
			s.commentStart = s.pos
			s.st = sBogusComment
		}

	case sComment:
		if c == '-' {
			rest := b[s.pos:]
			switch {
			case bytes.HasPrefix(rest, []byte("-->")) && s.pos+3 <= to:
				s.pos += 3
				s.toData(s.pos)
				return
			case bytes.HasPrefix(rest, []byte("--!>")) && s.pos+4 <= to:
				s.pos += 4
				s.toData(s.pos)
				return
			}
		}
		s.pos++

	case sBogusComment, sDoctype:
		if c == '>' {
			s.toData(s.pos + 1)
		}
		s.pos++

	case sCDATA:
		if c == ']' && bytes.HasPrefix(b[s.pos:], []byte("]]>")) && s.pos+3 <= to {
			s.pos += 3
			s.toData(s.pos)
			return
		}
		s.pos++

	case sRawText:
		if c == '<' && s.closesRawText() {
			s.tagStart = s.pos
			s.st = sEndTagOpen
			s.pos += 2 // "</"; the element name is read in the tag-name state
			if s.pos > to {
				s.pos = to
				s.st = sTagOpen // insertion between '<' and '/'
			}
			return
		}
		s.pos++
	}
}

// beginTagName starts a tag name at the current byte.
func (s *htmlScanner) beginTagName(isEnd bool) {
	s.isEnd = isEnd
	s.selfClosing = false
	s.nameStart, s.nameEnd = s.pos, s.pos+1
	s.attrStart, s.attrEnd = 0, 0
	s.pendingType = ""
	s.st = sTagName
	s.pos++
}

// abruptCommentClose handles "<!-->" and "<!--->".
func (s *htmlScanner) abruptCommentClose() {
	rest := s.body[s.pos:]
	switch {
	case bytes.HasPrefix(rest, []byte(">")):
		s.pos++
		s.toData(s.pos)
	case bytes.HasPrefix(rest, []byte("->")):
		s.pos += 2
		s.toData(s.pos)
	}
}

// closesRawText reports whether body[pos:] is the matching end tag of the open
// raw-text/RCDATA/script element.
func (s *htmlScanner) closesRawText() bool {
	n := len(s.rawTag)
	rest := s.body[s.pos:]
	if len(rest) < 2+n || rest[1] != '/' || !strings.EqualFold(string(rest[2:2+n]), s.rawTag) {
		return false
	}
	if len(rest) == 2+n {
		return true
	}
	t := rest[2+n]
	return isHTMLSpace(t) || t == '/' || t == '>'
}

// endAttrValue is called when an attribute value ends at `end`.
func (s *htmlScanner) endAttrValue(end int) {
	if s.attr() == "type" && end >= s.valueStart && end <= len(s.body) {
		s.pendingType = strings.ToLower(strings.TrimSpace(string(s.body[s.valueStart:end])))
	}
}

// emitTag finishes the current tag and selects the next content state.
func (s *htmlScanner) emitTag() {
	name := s.tag()
	next := s.pos + 1

	if s.isEnd {
		if (name == "svg" || name == "math") && s.foreign > 0 {
			s.foreign--
		}
		s.toData(next)
		return
	}

	if (name == "svg" || name == "math") && !s.selfClosing {
		s.foreign++
	}
	// Inside foreign content script/style are ordinary elements, not raw text.
	if s.foreign == 0 && rawTextElements[name] {
		s.st = sRawText
		s.rawTag = name
		s.rawStart = next
		if name == "script" {
			s.scriptType = s.pendingType
		}
		return
	}
	s.toData(next)
}
