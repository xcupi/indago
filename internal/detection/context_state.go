package detection

import (
	"fmt"
	"html"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// result builds a ContextAnalysis for a single (non-nested) context.
func result(ctx Context, sub string, conf domain.Confidence, kind string, start int, reason string, signals ...string) ContextAnalysis {
	return ContextAnalysis{
		Context: ctx, Sub: sub, Chain: []Context{ctx}, Confidence: conf,
		ConstructKind: kind, ConstructStart: start, Reason: reason, Signals: signals,
	}
}

// fromState maps the tokenizer state right before body[offset] to a context.
func (c *classifier) fromState(sn htmlScanner, offset int) ContextAnalysis {
	st := "state:" + sn.st.String()
	var a ContextAnalysis

	switch sn.st {
	case sData:
		a = result(CtxHTMLText, "element_content", domain.ConfidenceHigh, "text", sn.dataStart,
			"in element content: the tokenizer is in the data state, so inserted text is parsed as markup", st)
		if sn.foreign > 0 {
			a.Confidence = domain.ConfidenceMedium
			a.Signals = append(a.Signals, "foreign_content")
			a.Reason += "; inside <svg>/<math>, where script/style elements are parsed as ordinary elements"
			a.Alternatives = append(a.Alternatives, ContextAlternative{
				Context: CtxJSCode, Reason: "if this text is the body of an SVG <script>, it is executed as JavaScript",
			})
		}

	case sRawText:
		a = c.rawText(sn, offset)

	case sComment:
		a = result(CtxHTMLComment, "comment", domain.ConfidenceHigh, "comment", sn.tagStart,
			"inside an HTML comment; text here is not rendered or parsed until the comment closes", st)
	case sBogusComment:
		a = result(CtxHTMLComment, "bogus_comment", domain.ConfidenceMedium, "comment", sn.tagStart,
			"inside a <! or <? construct, which the HTML parser treats as a bogus comment ending at the next '>'", st)
	case sCDATA:
		a = result(CtxHTMLComment, "cdata", domain.ConfidenceMedium, "cdata", sn.tagStart,
			"inside a CDATA section of foreign (SVG/MathML) content", st)
	case sDoctype:
		a = result(CtxUnknown, "doctype", domain.ConfidenceMedium, "doctype", sn.tagStart,
			"inside a DOCTYPE declaration, which has no script or markup meaning", st)
	case sMarkupDecl:
		a = result(CtxUnknown, "markup_declaration", domain.ConfidenceLow, "markup_declaration", sn.tagStart,
			"directly after '<!', before it is known whether this is a comment, DOCTYPE, or bogus comment", st)

	case sTagOpen:
		a = result(CtxHTMLTagName, "tag_name_start", domain.ConfidenceHigh, "tag", sn.tagStart,
			"directly after '<': reflected text here becomes the start of a tag name", st)
	case sEndTagOpen:
		a = result(CtxHTMLTagName, "end_tag_name_start", domain.ConfidenceHigh, "tag", sn.tagStart,
			"directly after '</': reflected text here becomes the start of an end-tag name", st)
	case sTagName:
		sub := "tag_name"
		if sn.isEnd {
			sub = "end_tag_name"
		}
		a = result(CtxHTMLTagName, sub, domain.ConfidenceHigh, "tag", sn.tagStart,
			"inside a tag name being parsed", st)
		a.Element = sn.tag()

	case sBeforeAttrName, sAfterAttrName:
		a = result(CtxHTMLAttrName, "new_attribute", domain.ConfidenceHigh, "tag", sn.tagStart,
			fmt.Sprintf("between attributes of <%s>: reflected text here starts a new attribute name", sn.tag()), st)
		a.Element = sn.tag()
	case sAttrName:
		a = result(CtxHTMLAttrName, "within_name", domain.ConfidenceHigh, "tag", sn.tagStart,
			fmt.Sprintf("inside the attribute name %q of <%s>", sn.attr(), sn.tag()), st)
		a.Element, a.Attribute = sn.tag(), sn.attr()
	case sSelfClosing:
		a = result(CtxHTMLAttrName, "after_slash", domain.ConfidenceMedium, "tag", sn.tagStart,
			fmt.Sprintf("after a '/' inside <%s>: if the next byte is not '>', the parser treats it as the start of an attribute name", sn.tag()), st)
		a.Element = sn.tag()
	case sAfterAttrValueQ:
		a = result(CtxHTMLAttrName, "missing_whitespace", domain.ConfidenceMedium, "tag", sn.tagStart,
			fmt.Sprintf("immediately after a quoted attribute value in <%s>: browsers recover from the missing whitespace by starting a new attribute name", sn.tag()), st)
		a.Element = sn.tag()

	case sBeforeAttrValue:
		a = c.attrValue(sn, offset, "unquoted")
	case sAttrValueDQ:
		a = c.attrValue(sn, offset, "double")
	case sAttrValueSQ:
		a = c.attrValue(sn, offset, "single")
	case sAttrValueUnq:
		a = c.attrValue(sn, offset, "unquoted")

	default:
		a = result(CtxUnknown, "", domain.ConfidenceLow, "", offset, "the tokenizer is in an unmodelled state", st)
	}

	// Parse errors earlier in the document mean browser error recovery may differ
	// from the model.
	if sn.anomalies > 0 {
		a.Confidence = capConfidence(a.Confidence, domain.ConfidenceMedium)
		a.Signals = append(a.Signals, fmt.Sprintf("tokenizer_anomalies:%d", sn.anomalies))
		a.Reason += fmt.Sprintf(" (the document has %d earlier markup irregularities that browsers recover from, so the model is approximate)", sn.anomalies)
	}
	return a
}

// rawText classifies a position inside a raw-text / RCDATA / script element.
func (c *classifier) rawText(sn htmlScanner, offset int) ContextAnalysis {
	st := "state:raw_text"
	elem := "element:" + sn.rawTag
	var a ContextAnalysis

	switch sn.rawTag {
	case "script":
		if !isJavaScriptType(sn.scriptType) {
			a = result(CtxUnknown, "script_data_block", domain.ConfidenceMedium, "script_body", sn.rawStart,
				fmt.Sprintf("inside <script type=%q>, which a browser does not execute as JavaScript; its body is inert data unless page script reads it", sn.scriptType),
				st, elem, "script_type:"+sn.scriptType)
			a.Alternatives = append(a.Alternatives, ContextAlternative{
				Context: CtxJSCode, Reason: "if page script evaluates this block (for example a template engine), it becomes code",
			})
			break
		}
		f := jsFragment(string(c.body[sn.rawStart:offset]))
		a = ContextAnalysis{ConstructKind: "script_body", ConstructStart: sn.rawStart}
		a.apply(f)
		a.Signals = append(a.Signals, st, elem)
		a.Reason = "inside the body of a <script> element (raw text, no markup parsing); " + f.reason
	case "style":
		f := cssFragment(string(c.body[sn.rawStart:offset]), false)
		a = ContextAnalysis{ConstructKind: "style_body", ConstructStart: sn.rawStart}
		a.apply(f)
		a.Signals = append(a.Signals, st, elem)
		a.Reason = "inside the body of a <style> element (raw text); " + f.reason
	case "textarea", "title":
		a = result(CtxHTMLText, "rcdata", domain.ConfidenceHigh, "rcdata", sn.rawStart,
			fmt.Sprintf("inside <%s> (RCDATA): character references are decoded but tags are not parsed; only the matching end tag leaves this state", sn.rawTag), st, elem)
	case "noscript":
		a = result(CtxHTMLText, "rawtext_noscript", domain.ConfidenceMedium, "rawtext", sn.rawStart,
			"inside <noscript>, parsed as raw text when scripting is enabled", st, elem)
		a.Alternatives = append(a.Alternatives, ContextAlternative{
			Context: CtxHTMLText, Sub: "element_content",
			Reason: "with scripting disabled the content is parsed as ordinary markup",
		})
	default: // xmp, iframe, noembed, noframes
		a = result(CtxHTMLText, "rawtext", domain.ConfidenceHigh, "rawtext", sn.rawStart,
			fmt.Sprintf("inside <%s> (raw text): tags are not parsed; only the matching end tag leaves this state", sn.rawTag), st, elem)
	}
	a.Element = sn.rawTag
	return a
}

// isJavaScriptType reports whether a <script type> value is executed as JS.
func isJavaScriptType(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" || t == "module" {
		return true
	}
	if i := strings.IndexByte(t, ';'); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	return strings.Contains(t, "javascript") || strings.Contains(t, "ecmascript") || t == "text/jscript" || t == "text/livescript"
}

// attrValue classifies a position inside (or about to start) an attribute value.
func (c *classifier) attrValue(sn htmlScanner, offset int, quote string) ContextAnalysis {
	elem, attr := sn.tag(), sn.attr()
	start := sn.valueStart
	if sn.st == sBeforeAttrValue {
		start = offset // the value would begin right here
	}
	if start > offset {
		start = offset
	}
	raw := string(c.body[start:offset])

	a := ContextAnalysis{
		Element: elem, Attribute: attr, Quote: quote,
		ConstructKind: "attribute_value", ConstructStart: start,
		Chain:   []Context{CtxHTMLAttrValue},
		Signals: []string{"state:" + sn.st.String(), "element:" + elem, "attr:" + attr, "quote:" + quote},
	}
	where := fmt.Sprintf("inside the %s value of <%s %s=…>", quoteWord(quote), elem, attr)
	if sn.st == sBeforeAttrValue {
		where = fmt.Sprintf("directly after '=' of <%s %s=…>, where an unquoted value would begin", elem, attr)
	}

	switch {
	case strings.HasPrefix(attr, "on") && len(attr) > 2:
		f := jsFragment(html.UnescapeString(raw)) // the browser decodes entities, then runs the JS
		a.apply(f)
		a.Reason = where + "; this event-handler attribute holds JavaScript (after HTML entity decoding), " + f.reason
		a.Signals = append(a.Signals, "handler_attribute")

	case attr == "style":
		f := cssFragment(html.UnescapeString(raw), true)
		a.apply(f)
		a.Reason = where + "; the style attribute holds a CSS declaration list, " + f.reason

	case attr == "srcdoc":
		decoded := html.UnescapeString(raw)
		inner := newClassifier([]byte(decoded), ContextOptions{ContentType: "text/html"})
		ia := inner.at(len(decoded))
		a.Chain = append(a.Chain, ia.Chain...)
		a.Context, a.Sub = ia.Context, ia.Sub
		a.Confidence = capConfidence(ia.Confidence, domain.ConfidenceMedium)
		a.Alternatives = append(a.Alternatives, ia.Alternatives...)
		a.Signals = append(a.Signals, "nested_html")
		a.Reason = where + "; srcdoc holds an HTML document (after entity decoding), whose position is: " + ia.Reason

	case isURLAttribute(attr):
		f := urlFragment(elem, attr, html.UnescapeString(raw))
		a.apply(f)
		a.Reason = where + "; this attribute is a URL, " + f.reason

	default:
		a.Context = CtxHTMLAttrValue
		a.Sub = quote + "_quoted"
		if quote == "unquoted" {
			a.Sub = "unquoted"
		}
		a.Confidence = domain.ConfidenceHigh
		a.Reason = where + "; this attribute has no script, style, or URL semantics"
	}

	if quote == "unquoted" && sn.st == sAttrValueUnq {
		// Unquoted values end at whitespace or '>', so a space or '>' in reflected
		// text leaves the value; recorded for the later phases.
		a.Signals = append(a.Signals, "unquoted_value_ends_at_whitespace")
	}
	return a
}

func quoteWord(q string) string {
	switch q {
	case "double":
		return "double-quoted"
	case "single":
		return "single-quoted"
	default:
		return "unquoted"
	}
}
