package detection

import (
	"fmt"
	"mime"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// This file is the deterministic CONTEXT ANALYZER for Reflected XSS. Given the
// response bytes and a ReflectionReport it classifies, independently for every
// reflection site, the syntactic context the marker landed in (element text,
// attribute value, JavaScript string/code, URL, CSS, ...).
//
// Properties (all enforced by tests):
//
//   - Pure. Bytes in, classification out. No network, no browser, no payload
//     generation, no LLM, no clock, no randomness: the same input always yields
//     byte-identical output.
//   - Grounded in the actual markup. A real (simplified) HTML tokenizer state
//     machine is driven through the response bytes up to each site's exact byte
//     offset; JavaScript, CSS and URL positions are then determined by lexing the
//     relevant prefix (script body, entity-decoded attribute value). Nothing is
//     decided by substring matching on the surrounding text.
//   - Descriptive, not a verdict. It says where the marker is and how confident
//     the classification is; it never says a site is exploitable.
//
// Known approximations (reflected in confidence, never hidden): the HTML
// tokenizer implements the states relevant to context (not the full WHATWG tree
// builder), script "double-escape" state is not modelled, foreign (SVG/MathML)
// content is detected but not parsed as foreign, and the JS lexer is a
// tokenizer, not a parser.

// Context names the syntactic context of a reflection site.
type Context string

const (
	CtxHTMLText      Context = "html_text"       // element content (incl. RCDATA/RAWTEXT elements)
	CtxHTMLAttrValue Context = "html_attr_value" // inside an HTML attribute value
	CtxHTMLAttrName  Context = "html_attr_name"  // where an attribute name is parsed
	CtxHTMLTagName   Context = "html_tag_name"   // where a tag name is parsed
	CtxHTMLComment   Context = "html_comment"    // comment / bogus comment / CDATA
	CtxJSString      Context = "js_string"       // inside a JS string or template literal
	CtxJSCode        Context = "js_code"         // JS code position
	CtxJSComment     Context = "js_comment"      // inside a JS comment
	CtxJSRegex       Context = "js_regex"        // inside a JS regular-expression literal
	CtxURL           Context = "url"             // a URL-valued attribute / javascript: URL host
	CtxCSS           Context = "css"             // CSS (style element or style attribute)
	CtxUnknown       Context = "unknown"         // cannot be classified
	CtxMixed         Context = "mixed"           // ambiguous between two or more contexts
)

// ContextAlternative is another plausible reading of an ambiguous site.
type ContextAlternative struct {
	Context Context `json:"context"`
	Sub     string  `json:"sub,omitempty"`
	Reason  string  `json:"reason"`
}

// Reflection forms: how the canary came back, derived from the encoding analysis.
const (
	FormRaw         = "raw"         // reflected verbatim
	FormEncoded     = "encoded"     // consistently HTML/URL/JS-encoded
	FormTransformed = "transformed" // some characters changed/removed in different ways
	FormStripped    = "stripped"    // canary removed
	FormUnknown     = "unknown"     // canary region could not be isolated
)

// ContextAnalysis is the structured classification of ONE reflection site.
type ContextAnalysis struct {
	Context Context `json:"context"`
	// Sub refines Context (e.g. double_quoted, template_literal, url start).
	Sub string `json:"sub,omitempty"`
	// Chain lists the nested contexts outer→inner, e.g. an event-handler string is
	// [html_attr_value, js_string]. Context is the innermost (effective) one.
	Chain []Context `json:"chain,omitempty"`

	Element   string `json:"element,omitempty"`   // enclosing element, lowercased
	Attribute string `json:"attribute,omitempty"` // enclosing attribute, lowercased
	Quote     string `json:"quote,omitempty"`     // HTML attribute delimiter: double|single|unquoted

	Confidence domain.Confidence `json:"confidence"`
	// Reason is a deterministic, human-readable justification.
	Reason string `json:"reason"`
	// Signals are stable machine-readable tags behind the decision.
	Signals      []string             `json:"signals,omitempty"`
	Alternatives []ContextAlternative `json:"alternatives,omitempty"`

	// Form distinguishes raw from encoded/transformed reflection.
	Form string `json:"form"`

	// Exact offsets, relative to the mutated response body. Token starts at Offset;
	// the canary region is [TokenEnd, TailOffset); the tail sentinel starts at
	// TailOffset (0 when it was not found).
	Offset     int `json:"offset"`
	TokenEnd   int `json:"token_end"`
	TailOffset int `json:"tail_offset,omitempty"`

	// ConstructStart/Kind locate the enclosing construct (attribute value, script
	// body, tag, comment, text node) for quoting surrounding markup.
	ConstructStart int    `json:"construct_start"`
	ConstructKind  string `json:"construct_kind,omitempty"`

	// ContextAtTail is the context at the tail sentinel. Straddles is true when it
	// differs from Context: the reflected canary itself changed the parse context
	// (e.g. a raw quote closed the attribute). Descriptive only.
	ContextAtTail string `json:"context_at_tail,omitempty"`
	Straddles     bool   `json:"straddles,omitempty"`
}

// ContextOptions carries response metadata the analysis needs.
type ContextOptions struct {
	// ContentType is the response Content-Type header ("" if absent).
	ContentType string
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

// ClassifyContexts classifies every reflection site in rep against body (the
// mutated response body the sites' offsets refer to) and stores the result in
// each ReflectionLocation.Context. Sites are analyzed independently. It is a
// pure function of its inputs.
func ClassifyContexts(rep *ReflectionReport, body []byte, opts ContextOptions) {
	if rep == nil {
		return
	}
	if rep.ContentType == "" {
		rep.ContentType = opts.ContentType
	}
	c := newClassifier(body, opts)
	for i := range rep.Locations {
		loc := &rep.Locations[i]
		a := c.classifySite(rep.Probe, loc)
		loc.Context = &a
	}
}

// ClassifyAt classifies the single insertion point at byte offset in body — the
// context a value inserted there would be parsed in. It has no marker and so no
// Form or tail information.
func ClassifyAt(body []byte, offset int, opts ContextOptions) ContextAnalysis {
	c := newClassifier(body, opts)
	a := c.at(offset)
	a.Offset, a.TokenEnd = offset, offset
	a.Form = FormUnknown
	return a
}

// ---------------------------------------------------------------------------
// media type
// ---------------------------------------------------------------------------

type mediaKind int

const (
	mediaHTML       mediaKind = iota // parsed as HTML
	mediaHTMLAssume                  // no Content-Type: assume HTML (browser sniffing)
	mediaXML                         // XML-ish: approximated with the HTML tokenizer
	mediaJS                          // the whole body is JavaScript
	mediaCSS                         // the whole body is CSS
	mediaOther                       // not rendered as markup (JSON, plain text, binary, ...)
)

func mediaOf(contentType string) (mediaKind, string) {
	if strings.TrimSpace(contentType) == "" {
		return mediaHTMLAssume, ""
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	switch {
	case mt == "text/html", mt == "application/xhtml+xml":
		return mediaHTML, mt
	case mt == "image/svg+xml", mt == "text/xml", mt == "application/xml":
		return mediaXML, mt
	case mt == "text/javascript", mt == "application/javascript", mt == "application/x-javascript",
		mt == "text/ecmascript", mt == "application/ecmascript":
		return mediaJS, mt
	case mt == "text/css":
		return mediaCSS, mt
	default:
		return mediaOther, mt
	}
}

// ---------------------------------------------------------------------------
// classifier
// ---------------------------------------------------------------------------

type classifier struct {
	body  []byte
	opts  ContextOptions
	media mediaKind
	mt    string
	sc    htmlScanner // advanced monotonically across ascending sites
}

func newClassifier(body []byte, opts ContextOptions) *classifier {
	c := &classifier{body: body, opts: opts}
	c.media, c.mt = mediaOf(opts.ContentType)
	c.sc = newHTMLScanner(body)
	return c
}

func (c *classifier) classifySite(p Probe, loc *ReflectionLocation) ContextAnalysis {
	tokenLen := len(p.Token)
	var a ContextAnalysis
	switch {
	case loc.Offset < 0 || loc.Offset+tokenLen > len(c.body) || string(c.body[loc.Offset:loc.Offset+tokenLen]) != p.Token:
		a = ContextAnalysis{
			Context: CtxUnknown, Confidence: domain.ConfidenceLow,
			Reason:  "the recorded offset does not address the marker token in this body, so no context can be derived",
			Signals: []string{"offset_mismatch"},
		}
	default:
		a = c.at(loc.Offset)
		c.addTailInfo(&a, loc)
	}
	a.Offset = loc.Offset
	a.TokenEnd = loc.Offset + tokenLen
	a.TailOffset = loc.TailOffset
	a.Form = formOf(loc.Encoding)
	return a
}

// addTailInfo records the context at the tail sentinel and whether the reflected
// canary moved the parser into a different context.
func (c *classifier) addTailInfo(a *ContextAnalysis, loc *ReflectionLocation) {
	if loc.TailOffset <= loc.Offset || loc.TailOffset > len(c.body) {
		return
	}
	// A throwaway scanner continues from the token start through the canary.
	tail := c.at(loc.TailOffset)
	a.ContextAtTail = describe(tail)
	a.Straddles = describe(tail) != describe(*a)
}

func describe(a ContextAnalysis) string {
	if a.Sub == "" {
		return string(a.Context)
	}
	return string(a.Context) + ":" + a.Sub
}

func formOf(encoding string) string {
	switch encoding {
	case EncNone:
		return FormRaw
	case EncHTML, EncURL, EncJS:
		return FormEncoded
	case EncMixed:
		return FormTransformed
	case EncStripped:
		return FormStripped
	default:
		return FormUnknown
	}
}

// at classifies the insertion point at offset, dispatching on media type.
func (c *classifier) at(offset int) ContextAnalysis {
	if offset < 0 {
		offset = 0
	}
	if offset > len(c.body) {
		offset = len(c.body)
	}
	switch c.media {
	case mediaOther:
		return ContextAnalysis{
			Context: CtxUnknown, Sub: "non_html_response", Chain: []Context{CtxUnknown},
			Confidence:     domain.ConfidenceHigh,
			Reason:         fmt.Sprintf("the response Content-Type is %q, which a browser does not parse as markup, so there is no HTML/JS/CSS context to classify", c.mt),
			Signals:        []string{"content_type:" + c.mt},
			ConstructStart: 0, ConstructKind: "response_body",
		}
	case mediaJS:
		return c.wholeBody("javascript", jsFragment(string(c.body[:offset])))
	case mediaCSS:
		return c.wholeBody("css", cssFragment(string(c.body[:offset]), false))
	}

	// HTML (or XML approximated as HTML): drive the tokenizer to the offset.
	if offset < c.sc.pos {
		c.sc = newHTMLScanner(c.body) // sites are normally ascending; restart if not
	}
	c.sc.advance(offset)
	a := c.fromState(c.sc, offset)

	switch c.media {
	case mediaHTMLAssume:
		a.Confidence = capConfidence(a.Confidence, domain.ConfidenceMedium)
		a.Signals = append(a.Signals, "content_type_missing")
		a.Reason += " (no Content-Type header: assumed HTML)"
	case mediaXML:
		a.Confidence = capConfidence(a.Confidence, domain.ConfidenceMedium)
		a.Signals = append(a.Signals, "content_type:"+c.mt)
		a.Reason += fmt.Sprintf(" (%s is XML; the HTML tokenizer is only an approximation)", c.mt)
	}
	return a
}

// wholeBody classifies a response whose entire body is one language.
func (c *classifier) wholeBody(lang string, f fragment) ContextAnalysis {
	a := ContextAnalysis{ConstructStart: 0, ConstructKind: "response_body"}
	a.apply(f)
	a.Signals = append(a.Signals, "content_type:"+c.mt, "whole_body:"+lang)
	a.Reason = fmt.Sprintf("the response is %s (%s); %s", c.mt, lang, f.reason)
	return a
}

// ---------------------------------------------------------------------------
// fragments: results from the JS/CSS/URL sub-analyzers
// ---------------------------------------------------------------------------

// fragment is the result of classifying a position inside one embedded language.
type fragment struct {
	ctx     Context
	chain   []Context // nested contexts within this fragment, outer→inner (default: [ctx])
	sub     string
	conf    domain.Confidence
	reason  string
	signals []string
	alts    []ContextAlternative
}

func (a *ContextAnalysis) apply(f fragment) {
	a.Context = f.ctx
	if len(f.chain) > 0 {
		a.Chain = append(a.Chain, f.chain...)
	} else {
		a.Chain = append(a.Chain, f.ctx)
	}
	a.Sub = f.sub
	a.Confidence = f.conf
	a.Reason = f.reason
	a.Signals = append(a.Signals, f.signals...)
	a.Alternatives = append(a.Alternatives, f.alts...)
}

func rank(c domain.Confidence) int {
	switch c {
	case domain.ConfidenceHigh:
		return 3
	case domain.ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

// capConfidence lowers c to at most max.
func capConfidence(c, max domain.Confidence) domain.Confidence {
	if rank(c) > rank(max) {
		return max
	}
	return c
}
