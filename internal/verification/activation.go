package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
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
	// ActivationKeyboard: press the platform's access-key chord for the key the
	// candidate declares (Alt+Shift+<k> on Chromium/Linux), through the browser's
	// real keyboard input path — the activation a victim performs for an
	// accesskey, and the only one that reaches an element that never renders a
	// box (a <link> in <head>).
	ActivationKeyboard ActivationClass = "keyboard"
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
	// SettleBeforeMS is the bounded settle the keyboard class waits before it
	// presses the chord, so the page's own load-time work (handler wiring,
	// sanitizers) has finished. Zero for every other class, which are
	// dispatched immediately after the rendered DOM is read back.
	SettleBeforeMS int `json:"settle_before_ms,omitempty"`
}

// ClassifyActivation reports which activation (if any) a candidate needs, plus
// the operator-readable reason. It is pure and deterministic.
func ClassifyActivation(c detection.Candidate) (ActivationClass, string) {
	switch c.Trigger {
	case detection.TriggerJSURL:
		// The javascript: URL lives in the page's own markup and executes when
		// the element carrying it is clicked. The click class already prefers
		// exactly such an element (href starting with javascript: and carrying
		// the marker), so no handler in the value is needed.
		return ActivationClick, "the sink is a javascript: URL in the page's own markup: it executes when the element carrying it is clicked, and the browser percent-decodes the URL before evaluating it"
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

// accessKeyRE reads the KEY an accesskey declaration names, in any of the three
// attribute-value forms HTML allows (double-quoted, single-quoted, unquoted).
// It reads the value only: the candidate's bytes are never rewritten.
var accessKeyRE = regexp.MustCompile(`(?i)\baccesskey\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'` + "`" + `<>]+))`)

// DeclaredAccessKey returns the access key a candidate value declares, or ""
// when it declares none this verifier can dispatch. A multi-key declaration
// (the HTML spec allows a space-separated list) yields its first key, and only
// a single printable ASCII character is usable as one key chord.
func DeclaredAccessKey(v string) string {
	m := accessKeyRE.FindStringSubmatch(v)
	if m == nil {
		return ""
	}
	key := m[1] + m[2] + m[3]
	if i := strings.IndexAny(key, " 	\n\r"); i >= 0 {
		key = key[:i]
	}
	runes := []rune(key)
	if len(runes) != 1 || runes[0] <= 0x20 || runes[0] > 0x7e {
		return ""
	}
	return key
}

// AccessKeyChord is the keyboard shortcut a platform uses to activate an
// accesskey. Chromium uses Alt+Shift+<k> everywhere except macOS, where it is
// Control+Alt+<k>. It is exposed so the activation record can state exactly
// which chord was pressed.
func AccessKeyChord(key string) string {
	if runtime.GOOS == "darwin" {
		return "Control+Alt+" + key
	}
	return "Alt+Shift+" + key
}

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
	case strings.Contains(lower, "accesskey"):
		// A declared accesskey is activated the way a victim activates it: the
		// platform's access-key chord, pressed once through the browser's real
		// keyboard input. This takes precedence over the click class because the
		// accesskey is what the candidate itself declares as its activation, and
		// because a keyboard press reaches elements that never render a box.
		if key := DeclaredAccessKey(v); key != "" {
			return ActivationKeyboard, fmt.Sprintf("keyboard-class: the candidate declares accesskey=%q, so the platform access-key shortcut %s is pressed once through real keyboard input (the victim's activation, not element.click())", key, AccessKeyChord(key))
		}
		return ActivationUnsupported, "the candidate declares an accesskey but its value carries no single printable ASCII key: no access-key shortcut can be dispatched, so it is not activatable by this verifier"
	case containsJavascriptScheme(lower):
		return ActivationClick, "click-class: the candidate installs a javascript: URL, so its element is clicked once"
	case strings.Contains(lower, "onclick"):
		return ActivationClick, "click-class: the candidate installs a click handler, so its element is clicked once"
	case strings.Contains(lower, "onresize"):
		return ActivationResize, "resize-class: the candidate installs a resize handler (body onresize is a window-reflecting handler), so one resize Event is dispatched on window"
	}
	if m := eventAttrRE.FindStringSubmatch(v); m != nil {
		event := strings.ToLower(m[1])
		return ActivationUnsupported, fmt.Sprintf("interaction-class on%s: not activatable by this verifier (it activates only focus, resize, click, keyboard accesskeys and SMIL begin, and never simulates %s)", event, event)
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
// The keyboard class is the one exception: its page-side half only LOCATES the
// element that declares the access key (a read-only lookup) and returns
// "keyboard_ready"; the caller then presses the chord through the browser's
// real keyboard input, because an access-key shortcut is a browser-level action
// that page script cannot perform.
//
// The script never retries: it performs at most one activation and returns a
// status describing what happened, including any error.
func activationScript(marker string, class ActivationClass, key string) (string, error) {
	mb, err := json.Marshal(marker)
	if err != nil {
		return "", fmt.Errorf("marshal marker: %w", err)
	}
	cb, err := json.Marshal(string(class))
	if err != nil {
		return "", fmt.Errorf("marshal class: %w", err)
	}
	kb, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("marshal access key: %w", err)
	}
	const body = `
  const marker = %s;
  const cls = %s;
  const key = %s;
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
        }) || withMarker.find((e) => has(e, "onclick")) || smallest;
        return el ? {kind: "click", el: el} : {error: "no element carrying the marker was found"};
      }
      if (cls === "keyboard") {
        // Read-only lookup: the element must carry the marker AND declare the
        // exact access key the candidate names (case-insensitively, which is
        // how the browser matches access keys). Nothing is pressed here.
        const want = String(key).toLowerCase();
        const el = withMarker.find((e) => {
          const k = attr(e, "accesskey");
          return k !== null && String(k).toLowerCase() === want;
        });
        return el ? {kind: "keyboard", el: el} : {error: "no element carrying the marker declares accesskey=" + JSON.stringify(key)};
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

  if (target.kind === "keyboard") {
    // The page's half of this activation is the lookup only: an access-key
    // shortcut is a browser-level action, so the caller presses it through the
    // browser's real keyboard input and records that as the method.
    out.status = "keyboard_ready";
    out.element = target.el.tagName.toLowerCase();
    out.detail = "the element declaring the access key was located; the verifier now presses the platform access-key shortcut once through the browser's real keyboard input";
    return out;
  }

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
    // A click on an SVG element has to go through the anchor that owns the
    // link: SVG elements (animate, text, …) do not implement HTMLElement's
    // click(), so calling it there throws "el.click is not a function" and the
    // activation never happens. Measured on lab 11: the marker-carrying
    // element the resolver picks is the <animate> inside <a>.
    let clickable = el;
    if (typeof clickable.click !== "function") {
      const anchor = el.closest ? el.closest("a") : null;
      if (anchor) clickable = anchor;
    }
    if (typeof clickable.click === "function") {
      clickable.click();
      out.method = "element.click()";
      out.detail = "the marker-carrying element was clicked exactly once through the DOM's own click() activation, which runs its click handler or javascript: URL";
    } else {
      clickable.dispatchEvent(new MouseEvent("click", {bubbles: true, cancelable: true, view: window}));
      out.method = "element.dispatchEvent(new MouseEvent('click'))";
      out.detail = "the element does not implement click() (SVG), so exactly one bubbling MouseEvent('click') was dispatched on the link that owns it, which runs the anchor's activation behaviour";
    }
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
	return "(() => {" + fmt.Sprintf(body, string(mb), string(cb), string(kb)) + "})()", nil
}

// activationStatusKeyboardReady is the page script's report that the element
// declaring the access key was found; the chord press itself happens in the
// driver, after the page-side lookup returned.
const activationStatusKeyboardReady = "keyboard_ready"

// activate performs at most ONE activation and returns its record. It never
// returns nil and never leaves an error unrecorded: a driver failure, a
// missing element, or a throwing page API all surface as Status failed with
// Error set, and the caller then simply does not confirm.
//
// The bounded settle after a dispatched activation is a fixed one-shot wait
// (DefaultActivationSettle, hard-capped at maxActivationSettle) for the
// browser's asynchronous exception report — never a poll or a retry.
func (v *BrowserVerifier) activate(ctx context.Context, page *browser.Page, marker, value string, class ActivationClass, reason string) *Activation {
	act := &Activation{Class: class, Reason: reason}
	if class == ActivationUnsupported {
		act.Status = ActivationStatusSkipped
		return act
	}
	key := ""
	if class == ActivationKeyboard {
		key = DeclaredAccessKey(value)
		if key == "" {
			act.Status = ActivationStatusFailed
			act.Error = "the candidate declares an accesskey but its value carries no single printable ASCII key, so no access-key shortcut could be pressed"
			return act
		}
	}
	script, err := activationScript(marker, class, key)
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
	status := out.Status
	if status == activationStatusKeyboardReady {
		// A keyboard activation is the one a victim performs later, not during
		// load, so the chord is pressed after a bounded settle: the page's own
		// load handlers and any sanitizer have finished by then. The wait is the
		// same fixed one-shot window used after the press — never a poll.
		sleepBounded(ctx, v.cfg.ActivationSettle)
		act.SettleBeforeMS = int(v.cfg.ActivationSettle / time.Millisecond)
		// The access-key shortcut is the ONE press this activation performs. It
		// goes through the browser's real keyboard input path; if the driver
		// cannot dispatch it the attempt is recorded as failed, never as sent.
		chord := AccessKeyChord(key)
		if err := page.PressKeyChord(ctx, chord); err != nil {
			act.Status = ActivationStatusFailed
			act.Error = fmt.Sprintf("press access-key shortcut %s: %v", chord, err)
			return act
		}
		act.Method = fmt.Sprintf("keyboard.press('%s')", chord)
		status = ActivationStatusDispatched
	}
	switch status {
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
