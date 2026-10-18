package verification

import "strings"

// This file is the deterministic, pure core of browser verification: given the
// raw observations a page load produced, does the browser report the candidate
// marker as an unresolved JavaScript identifier? It makes no network/browser
// calls itself and performs no payload generation — it only matches strings the
// caller already collected, and accepts only the marker-specific ReferenceError
// signature rather than arbitrary messages that happen to contain the marker.
//
// Why this is a sound, deterministic signal (not a timing heuristic): every
// built-in candidate (internal/detection/candidate.go) is, at the position it
// targets, nothing more than the bare marker token used as a JavaScript
// expression (e.g. an event-handler attribute whose entire body is the token, or
// a string breakout followed by the token as its own statement). A bare,
// undeclared identifier referenced as code does nothing except cause the
// JavaScript engine to throw "ReferenceError: <token> is not defined" the
// moment it is evaluated. So "was <token> evaluated as code" and "did the
// browser report an exception naming <token>" are the same question — this
// never depends on the marker producing any actual effect (no alert/cookie/
// network call is ever part of a candidate), and it fires synchronously as part
// of the browser's own page-load event, not an arbitrary wait.

// Signal identifies which observation channel produced a match, for evidence.
type Signal string

const (
	SignalNone         Signal = "none"          // no channel reported the marker as an unresolved identifier
	SignalPageError    Signal = "page_error"    // an uncaught ReferenceError named the marker as undefined
	SignalConsoleError Signal = "console_error" // a runtime-shaped console error named the marker as undefined
)

// matchExecutionSignal scans pageErrors then consoleErrors (in that priority:
// an uncaught exception is the more direct signal) for the exact
// marker-specific ReferenceError signature. Generic application messages,
// including console.error output that merely contains the marker, are not
// execution evidence. It returns the first match's channel and text, or
// (SignalNone, "", false).
func matchExecutionSignal(token string, pageErrors, consoleErrors []string) (Signal, string, bool) {
	if token == "" {
		return SignalNone, "", false
	}
	if text, ok := firstMarkerReferenceError(token, pageErrors, true); ok {
		return SignalPageError, text, true
	}
	if text, ok := firstMarkerReferenceError(token, consoleErrors, false); ok {
		return SignalConsoleError, text, true
	}
	return SignalNone, "", false
}

// firstMarkerReferenceError returns the first message that starts with the
// browser's bare-unresolved-identifier signature for token. Playwright's
// page-error channel omits the JavaScript error name and reports the observed
// Chromium form as "playwright: TOKEN is not defined"; that fallback is only
// accepted on pageErrors, never on console.error messages. Browser runtimes may
// append stack frames, so only newline-separated stack text is permitted after
// the exact signature; arbitrary suffix text is not.
func firstMarkerReferenceError(token string, messages []string, allowPlaywrightPrefix bool) (string, bool) {
	for _, message := range messages {
		if isMarkerReferenceError(token, message, allowPlaywrightPrefix) {
			return message, true
		}
	}
	return "", false
}

func isMarkerReferenceError(token, message string, allowPlaywrightPrefix bool) bool {
	message = strings.TrimSpace(message)
	prefixes := []string{"ReferenceError: ", "Uncaught ReferenceError: "}
	if allowPlaywrightPrefix {
		prefixes = append(prefixes, "playwright: ")
	}
	for _, prefix := range prefixes {
		signature := prefix + token + " is not defined"
		if message == signature || strings.HasPrefix(message, signature+"\n") {
			return true
		}
	}
	return false
}

// MatchExecutionSignal is matchExecutionSignal's exported form, reused by
// other engines that need the SAME deterministic bare-marker-as-code
// verification mechanism Reflected XSS already uses (see this file's doc
// comment for why it is a sound, non-heuristic signal) — e.g. DOM XSS
// payload verification (internal/scan/domxss.go), which replays the
// identical bare-marker trick (an <img onerror=MARKER> assigned to an
// HTML-injection sink) and must be confirmed by the SAME
// "Uncaught ReferenceError: MARKER is not defined" signal, never a
// separately-invented one.
func MatchExecutionSignal(token string, pageErrors, consoleErrors []string) (Signal, string, bool) {
	return matchExecutionSignal(token, pageErrors, consoleErrors)
}

// domExcerpt returns a bounded window of html around the first occurrence of
// token, for a readable, auditable evidence snippet. "" when token is absent.
func domExcerpt(html, token string, window int) string {
	i := strings.Index(html, token)
	if i < 0 {
		return ""
	}
	start, end := i-window, i+len(token)+window
	if start < 0 {
		start = 0
	}
	if end > len(html) {
		end = len(html)
	}
	return html[start:end]
}
