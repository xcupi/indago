package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
)

// This file is the ACTIVATION half of browser verification: for a candidate
// whose trigger is not page load (detection.TriggerInteraction), it decides
// WHICH single, bounded activation the verifier may perform after navigation
// so the browser can dispatch the event the candidate needs — and nothing
// more.
//
// The activation is NOT execution evidence. It only makes the browser dispatch
// an event (or call a native activation API) once, after which the existing,
// unchanged marker-specific provenance observation decides the verdict. A page
// that merely reflects the marker and has no handler therefore stays Rejected
// after activation: nothing observes the marker as code, so nothing confirms.
//
// Boundaries preserved here:
//   - No payload generation or reshaping: the candidate's Value is sent
//     byte-for-byte by the caller; this file only reads it to recognise which
//     activation shape the candidate expects.
//   - One attempt per candidate. No retry loop, no polling, no repeated
//     dispatch, no simulated typing/hover/scroll/keys.
//   - Load-trigger candidates (and candidates with no declared trigger, the
//     pre-existing default) are never activated: their behaviour is exactly
//     what it was before this file existed.
//   - Anything this verifier cannot honestly activate is SKIPPED with a
//     recorded reason, never silently treated as tested.

// ActivationClass is the family of activation a candidate needs.
type ActivationClass string

const (
	// ActivationNone: no activation; the candidate is observed during the
	// page's own load (TriggerLoad, or an empty legacy Trigger).
	ActivationNone ActivationClass = "none"
	// ActivationFocus: focus the injected element (native focus, or one
	// synthetic FocusEvent when the element is not natively focusable).
	ActivationFocus ActivationClass = "focus"
	// ActivationResize: dispatch one resize Event on window.
	ActivationResize ActivationClass = "resize"
	// ActivationClick: call click() once on the injected element.
	ActivationClick ActivationClass = "click"
	// ActivationAnimation: call beginElement() once on the SMIL animation.
	ActivationAnimation ActivationClass = "animation"
	// ActivationUnsupported: the candidate needs an interaction this verifier
	// deliberately does not perform.
	ActivationUnsupported ActivationClass = "unsupported"
)

// Activation statuses, recorded in Activation.Status.
const (
	// ActivationStatusDispatched: exactly one activation was performed.
	ActivationStatusDispatched = "dispatched"
	// ActivationStatusFailed: the activation was attempted and raised/returned
	// an error (missing element, missing API, driver error). Never confirms.
	ActivationStatusFailed = "failed"
	// ActivationStatusSkipped: the class is not activatable by this verifier.
	// Nothing was dispatched. Never confirms.
	ActivationStatusSkipped = "skipped_unsupported"
)

// Activation is the persisted record of ONE activation attempt (or of why none
// was made). It is evidence about observation methodology, never about
// execution: only Report.Signal / the verdict prove execution.
type Activation struct {
	Class  ActivationClass `json:"class"`
	Status string          `json:"status"`
	// Method is the exact activation API used, e.g. "element.focus()". Empty
	// when nothing was dispatched.
	Method string `json:"method,omitempty"`
	// Element is the tag name of the element the activation was aimed at
	// ("window" for the resize dispatch).
	Element string `json:"element,omitempty"`
	// Reason states why this method was chosen (or why the class is not
	// activatable), in operator-readable terms.
	Reason string `json:"reason,omitempty"`
	// Error is the activation error text. Never empty when Status is failed.
	Error string `json:"error,omitempty"`
	// Attempts is the number of activation attempts made: exactly 0 or 1. A
	// failed attempt still counts as 1 — it was made, and it is reported.
	Attempts int `json:"attempts"`
	// SettleMS is the bounded post-activation observation window in
	// milliseconds. Zero when nothing was dispatched.
	SettleMS int `json:"settle_ms,omitempty"`
}

// ClassifyActivation reports which activation (if any) a candidate needs, plus
// the operator-readable reason. It is pure and deterministic.
func ClassifyActivation(c detection.Candidate) (ActivationClass, string) {
	switch c.Trigger {
	case detection.TriggerInteraction:
		return classifyInteractionValue(c.Value)
	case detection.TriggerNone:
		return ActivationUnsupported, "markup probe: not activatable by this verifier (the candidate carries no executable reference)"
	case detection.TriggerLoad, "":
		// "" is the pre-existing default for a candidate that never declared a
		// trigger: observed on load, never activated. This keeps every such
		// candidate's behaviour byte-identical to before activation existed.
		return ActivationNone, "load-trigger candidate: observed during the page's own load, exactly as before (no activation)"
	default:
		return ActivationUnsupported, fmt.Sprintf("unknown trigger class %q: not activatable by this verifier", c.Trigger)
	}
}

// eventAttrRE finds an event-handler attribute in a candidate value, so an
// unsupported interaction can be named in the recorded reason.
var eventAttrRE = regexp.MustCompile(`(?i)\bon([a-z]+)\s*=`)

// classifyInteractionValue recognises the activation shape a TriggerInteraction
// candidate's value expects. Recognition is by ATTRIBUTE NAME / SCHEME only —
// it never rewrites or re-chooses the value.
func classifyInteractionValue(v string) (ActivationClass, string) {
	lower := strings.ToLower(v)
	switch {
	case strings.Contains(lower, "onfocus") || strings.Contains(lower, "autofocus"):
		return ActivationFocus, "focus-class: the candidate installs an autofocus/onfocus handler, so the injected element is focused once"
	case strings.Contains(lower, "onbegin"):
		return ActivationAnimation, "animation-class: the candidate installs a SMIL onbegin handler, so the marker-carrying animation is started once with beginElement()"
	case containsJavascriptScheme(lower):
		return ActivationClick, "click-class: the candidate installs a javascript: URL, so its element is clicked once"
	case strings.Contains(lower, "onclick") || strings.Contains(lower, "accesskey"):
		return ActivationClick, "click-class: the candidate installs a click handler, so its element is clicked once"
	case strings.Contains(lower, "onresize"):
		return ActivationResize, "resize-class: the candidate installs a resize handler (body onresize is a window-reflecting handler), so one resize Event is dispatched on window"
	}
	if m := eventAttrRE.FindStringSubmatch(v); m != nil {
		event := strings.ToLower(m[1])
		return ActivationUnsupported, fmt.Sprintf("interaction-class on%s: not activatable by this verifier (it activates only focus, resize, click and SMIL begin, and never simulates %s)", event, event)
	}
	return ActivationUnsupported, "the candidate declares an interaction trigger but its value contains no recognisable event handler or activation shape: not activatable by this verifier"
}

// containsJavascriptScheme reports whether v contains a javascript: scheme
// after removing the ASCII tab/newline/CR characters a browser's URL parser
// strips before parsing it — so the evasion variants ("java\tscript:",
// "JaVaScRiPt:") are recognised as the same click-class shape.
func containsJavascriptScheme(v string) bool {
	clean := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(v)
	return strings.Contains(clean, "javascript:")
}

// activationOutcome is the value the page-side script returns.
type activationOutcome struct {
	Status  string `json:"status"`
	Method  string `json:"method"`
	Element string `json:"element"`
	Detail  string `json:"detail"`
	Error   string `json:"error"`
}

// decodeActivation converts the driver's decoded Evaluate result into an
// activationOutcome. A malformed result is an error, never silently "failed".
func decodeActivation(v any) (activationOutcome, error) {
	var out activationOutcome
	raw, err := json.Marshal(v)
	if err != nil {
		return out, fmt.Errorf("marshal activation result: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode activation result: %w", err)
	}
	return out, nil
}

// activationScript builds the single page-side script that performs one
// activation. It returns a self-invoking function expression: the page's own
// APIs do the work (focus/click/dispatchEvent/beginElement), so the event is
// delivered by the browser's normal dispatch path.
//
// The script never retries: it performs at most one activation and returns a
// status describing what happened, including any error.
func activationScript(marker string, class ActivationClass) (string, error) {
	mb, err := json.Marshal(marker)
	if err != nil {
		return "", fmt.Errorf("marshal marker: %w", err)
	}
	cb, err := json.Marshal(string(class))
	if err != nil {
		return "", fmt.Errorf("marshal class: %w", err)
	}
	const body = `
  const marker = %s;
  const cls = %s;
  const out = {status: "failed", method: "", element: "", detail: "", error: ""};
  // Locating the target is isolated in its own function, with its own
  // try/catch. Its frame is gone before the activation below runs, and that is
  // deliberate: a try/catch still on the JS stack when the handler throws makes
  // V8 treat the exception as CAUGHT, which suppresses the uncaught-exception
  // pause the execution-provenance observer depends on. The dispatch itself is
  // therefore NEVER wrapped in try/catch — if it throws, the driver reports the
  // error and verification records the activation as failed.
  const target = (() => {
    try {
      const all = Array.prototype.slice.call(document.querySelectorAll("*"));
      const carries = (el) => {
        try { return (el.outerHTML || "").indexOf(marker) !== -1; } catch (e) { return false; }
      };
      const withMarker = all.filter(carries);
      const smallest = withMarker.length
        ? withMarker.reduce((a, b) => (a.outerHTML.length <= b.outerHTML.length ? a : b))
        : null;
      const attr = (el, name) => { try { return el.getAttribute(name); } catch (e) { return null; } };
      const has = (el, name) => { try { return el.hasAttribute(name); } catch (e) { return false; } };
      if (cls === "resize") { return {kind: "resize"}; }
      if (cls === "focus") {
        const el = withMarker.find((e) => has(e, "onfocus") || has(e, "autofocus")) || smallest;
        return el ? {kind: "focus", el: el} : {error: "no element carrying the marker was found"};
      }
      if (cls === "click") {
        const el = withMarker.find((e) => {
          const raw = attr(e, "href") || attr(e, "action") || attr(e, "formaction") || attr(e, "src") || "";
          return /^\s*javascript:/i.test(raw.replace(/[\t\n\r]/g, ""));
        }) || withMarker.find((e) => has(e, "onclick") || has(e, "accesskey")) || smallest;
        return el ? {kind: "click", el: el} : {error: "no element carrying the marker was found"};
      }
      if (cls === "animation") {
        const smil = Array.prototype.slice
          .call(document.querySelectorAll("animate, animateTransform, animateMotion, set"))
          .filter(carries);
        const el = smil.find((e) => typeof e.beginElement === "function") || null;
        return el ? {kind: "animation", el: el} : {error: "no SMIL animation element carrying the marker was found"};
      }
      return {error: "unsupported activation class: " + cls};
    } catch (e) {
      return {error: (e && e.name ? e.name + ": " : "") + (e && e.message ? e.message : String(e))};
    }
  })();
  if (target.error) { out.error = target.error; return out; }

  if (target.kind === "resize") {
    window.dispatchEvent(new Event("resize"));
    out.status = "dispatched";
    out.method = "window.dispatchEvent(new Event('resize'))";
    out.element = "window";
    out.detail = "a real viewport resize would fire window's own resize event too, but it re-lays out the page and can trigger unrelated resize work; dispatching the event on window reaches the same window-level handler path (a body onresize attribute is a window-reflecting handler) with no layout side effects";
    return out;
  }

  const el = target.el;
  out.element = el.tagName.toLowerCase();
  if (target.kind === "focus") {
    el.focus();
    if (document.activeElement === el) {
      out.method = "element.focus()";
      out.detail = "the element accepted focus natively, so the browser dispatched its own focus event once";
    } else {
      el.dispatchEvent(new FocusEvent("focus", {bubbles: false}));
      out.method = "element.dispatchEvent(new FocusEvent('focus'))";
      out.detail = "the element is not natively focusable, so exactly one synthetic FocusEvent was dispatched on it";
    }
  } else if (target.kind === "click") {
    el.click();
    out.method = "element.click()";
    out.detail = "the marker-carrying element was clicked exactly once through the DOM's own click() activation, which runs its click handler or javascript: URL";
  } else if (target.kind === "animation") {
    el.beginElement();
    out.method = "element.beginElement()";
    out.detail = "the marker-carrying SMIL animation was started exactly once with beginElement(), so the browser dispatches its begin event";
  } else {
    out.error = "unsupported activation class: " + cls;
    return out;
  }
  out.status = "dispatched";
  return out;
`
	return "(() => {" + fmt.Sprintf(body, string(mb), string(cb)) + "})()", nil
}

// activate performs at most ONE activation and returns its record. It never
// returns nil and never leaves an error unrecorded: a driver failure, a
// missing element, or a throwing page API all surface as Status failed with
// Error set, and the caller then simply does not confirm.
//
// The bounded settle after a dispatched activation is a fixed one-shot wait
// (DefaultActivationSettle, hard-capped at maxActivationSettle) for the
// browser's asynchronous exception report — never a poll or a retry.
func (v *BrowserVerifier) activate(ctx context.Context, page *browser.Page, marker string, class ActivationClass, reason string) *Activation {
	act := &Activation{Class: class, Reason: reason}
	if class == ActivationUnsupported {
		act.Status = ActivationStatusSkipped
		return act
	}
	script, err := activationScript(marker, class)
	if err != nil {
		act.Status = ActivationStatusFailed
		act.Error = err.Error()
		return act
	}
	act.Attempts = 1 // exactly one activation attempt, by construction
	raw, err := page.Evaluate(ctx, script)
	if err != nil {
		act.Status = ActivationStatusFailed
		act.Error = err.Error()
		return act
	}
	out, err := decodeActivation(raw)
	if err != nil {
		act.Status = ActivationStatusFailed
		act.Error = err.Error()
		return act
	}
	act.Method, act.Element = out.Method, out.Element
	if out.Detail != "" {
		act.Reason = out.Detail
	}
	switch out.Status {
	case ActivationStatusDispatched:
		act.Status = ActivationStatusDispatched
		act.SettleMS = int(v.cfg.ActivationSettle / time.Millisecond)
		sleepBounded(ctx, v.cfg.ActivationSettle)
	case ActivationStatusFailed:
		act.Status = ActivationStatusFailed
		act.Error = out.Error
		if act.Error == "" {
			act.Error = "the activation script reported failure without an error message"
		}
	default:
		act.Status = ActivationStatusFailed
		act.Error = fmt.Sprintf("unexpected activation status %q from the page script", out.Status)
	}
	return act
}

// sleepBounded waits d, or less if ctx is cancelled first. It is the only wait
// activation adds, and it is bounded by construction.
func sleepBounded(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
