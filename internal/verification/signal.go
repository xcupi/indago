package verification

import "strings"

// This file is the deterministic, pure core of browser verification: given the
// raw observations a page load produced, does the EXACT marker token appear
// where the browser's own JavaScript engine reports an uncaught exception or a
// console error? It makes no network/browser calls itself and performs no
// payload generation — it only matches strings the caller already collected.
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
	SignalNone         Signal = "none"          // no channel named the marker token
	SignalPageError    Signal = "page_error"    // an uncaught exception named it
	SignalConsoleError Signal = "console_error" // a console.error message named it
)

// matchExecutionSignal scans pageErrors then consoleErrors (in that priority:
// an uncaught exception is the more direct signal) for the exact marker token.
// It returns the first match's channel and text, or (SignalNone, "", false).
func matchExecutionSignal(token string, pageErrors, consoleErrors []string) (Signal, string, bool) {
	if token == "" {
		return SignalNone, "", false
	}
	if text, ok := firstContaining(token, pageErrors); ok {
		return SignalPageError, text, true
	}
	if text, ok := firstContaining(token, consoleErrors); ok {
		return SignalConsoleError, text, true
	}
	return SignalNone, "", false
}

func firstContaining(token string, messages []string) (string, bool) {
	for _, m := range messages {
		if strings.Contains(m, token) {
			return m, true
		}
	}
	return "", false
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
