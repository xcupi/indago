package verification

import "strings"

// This file explains ONE reproducible way a Rejected verdict happens even
// though the activation is correct: the page's own Content-Security-Policy
// refuses to compile an inline event handler.
//
// Measured (see HANDOFF.md and docs/browser-verification.md, "Measured: the
// box-less <link>"): on a page served with `script-src 'self'`, Chromium still
// parses the injected `onclick` attribute and still dispatches the access-key
// click, but it never compiles the handler — the element keeps the attribute
// while `element.onclick === null` — and it reports
// "Executing inline event handler violates the following Content Security
// Policy directive ... The action has been blocked." on the console. The
// verdict is correctly Rejected (a victim's browser would not run it either);
// this helper only makes the verifier SAY why, so a Rejected result is not
// mistaken for a broken activation.

// cspInlineHandlerSignature is Chromium's own wording for a blocked inline
// EVENT HANDLER (an attribute handler, not a <script> block, which Chromium
// reports as "inline script"). Matching the handler-specific form keeps an
// unrelated blocked <script> from being blamed for this verdict.
const cspInlineHandlerSignature = "Executing inline event handler violates the following Content Security Policy directive"

// cspInlineHandlerBlocked reports whether the browser's collected log records
// the page's CSP blocking an inline event handler, and returns that log line.
func cspInlineHandlerBlocked(log []string) (string, bool) {
	for _, line := range log {
		if strings.Contains(line, cspInlineHandlerSignature) && strings.Contains(line, "blocked") {
			return firstLine(strings.TrimSpace(line)), true
		}
	}
	return "", false
}
