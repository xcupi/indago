package scan

// Unit tests for the two DOM-XSS coverage-gap fixes that do not need a real
// browser: the "no DOM here" content-type gate and the postMessage sender's
// attach/not-applicable contract. The executing behaviour (a real
// attribute-breakout confirmation, a real body-less document) is covered by
// domxss_coverage_gaps_integration_test.go under the browser_integration tag.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDOMXSSContentTypeAllowsDOM(t *testing.T) {
	for _, tc := range []struct {
		contentType string
		want        bool
	}{
		{"", true}, // unknown/absent: keep probing, never assume "no DOM"
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{" TEXT/HTML ; charset=UTF-8", true},
		{"application/xhtml+xml", true},
		{"image/jpeg", false},
		{"image/png", false},
		{"application/json", false},
		{"application/xml", false},
		{"text/xml", false},
		{"text/plain", false},
		{"application/pdf", false},
		{"application/octet-stream", false},
	} {
		if got := domXSSContentTypeAllowsDOM(tc.contentType); got != tc.want {
			t.Fatalf("domXSSContentTypeAllowsDOM(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}

func TestPostMessageScriptAttachesToAnyRealRootAndReportsNoRoot(t *testing.T) {
	script := postMessageScript("PAYLOAD")
	// Attach to body or documentElement, in that order: a frameset document has
	// no body but does have a root.
	if !strings.Contains(script, "document.body || document.documentElement") {
		t.Fatalf("sender must fall back to documentElement: %s", script)
	}
	if !strings.Contains(script, "root.appendChild(sender)") {
		t.Fatalf("sender must attach to the resolved root: %s", script)
	}
	if strings.Contains(script, "document.body.appendChild") {
		t.Fatal("a body-less document must not be dereferenced unconditionally")
	}
	// Every outcome resolves through the single settle gate, which also does
	// the cleanup. Exactly one resolve call exists, so no path can bypass it.
	if got := strings.Count(script, "resolve("); got != 1 || !strings.Contains(script, "resolve(outcome)") {
		t.Fatalf("every outcome must settle through one cleanup gate, got %d resolve calls: %s", got, script)
	}
	// No attachable root is a distinct, explicit answer — not an exception.
	if !strings.Contains(script, "settle("+goQuoteJS(domXSSPostMessageNoRoot)+")") {
		t.Fatalf("no-root must settle the not-applicable sentinel: %s", script)
	}
	if !strings.Contains(script, goQuoteJS(domXSSPostMessageSent)) || !strings.Contains(script, goQuoteJS(domXSSPostMessageIndeterminate)) {
		t.Fatalf("a delivered message must resolve the sent status and an unknown delivery its own status: %s", script)
	}
	// The attachment failure path must stay uncaught so a genuine evaluate
	// error still surfaces instead of being reported as not-applicable.
	if strings.Contains(script, "catch") || strings.Contains(script, "reject(") {
		t.Fatalf("a genuine attachment failure must still reject the evaluate: %s", script)
	}
	// The opaque-origin sender contract is unchanged by this fix.
	if !strings.Contains(script, "'sandbox', 'allow-scripts'") || strings.Contains(script, "allow-same-origin") {
		t.Fatalf("opaque-origin sender contract changed: %s", script)
	}
}

// TestPostMessageScriptAlwaysSettles is the regression guard for the probe that
// could hang a browser worker for a whole job deadline: the promise must have a
// hard fallback bound (independent of the worker's job timeout), a load-failure
// handler, a distinct indeterminate outcome, and cleanup of the sender frame.
func TestPostMessageScriptAlwaysSettles(t *testing.T) {
	script := postMessageScript("PAYLOAD")
	for _, want := range []struct{ name, needle string }{
		{"hard fallback timer", fmt.Sprintf("const FALLBACK_MS = %d;", domXSSPostMessageFallback.Milliseconds())},
		{"frame load-failure handler", "sender.onerror"},
		{"frame-load evidence flag", "frameLoaded"},
		{"distinct indeterminate outcome", goQuoteJS(domXSSPostMessageIndeterminate)},
		{"sender cleanup", "removeChild(sender)"},
		{"handler cleanup", "sender.onload = null;"},
	} {
		if !strings.Contains(script, want.needle) {
			t.Fatalf("postMessage probe missing %s (%q): %s", want.name, want.needle, script)
		}
	}
	// The bound must be a small, probe-local constant: a job-scale timeout here
	// would reintroduce the defect (one wedged probe per deadline).
	if domXSSPostMessageFallback <= 0 || domXSSPostMessageFallback > 10*time.Second {
		t.Fatalf("fallback bound must be a few seconds, got %s", domXSSPostMessageFallback)
	}
	// The fallback resolves "sent" only when the frame actually loaded.
	if !strings.Contains(script, "settle(frameLoaded ? "+goQuoteJS(domXSSPostMessageSent)+" : "+goQuoteJS(domXSSPostMessageIndeterminate)+")") {
		t.Fatalf("fallback must distinguish a loaded frame from an unobservable one: %s", script)
	}
}

func TestDOMXSSPostMessageIndeterminateIsNotADelivery(t *testing.T) {
	// The indeterminate outcome must be a distinct sentinel: aliasing
	// "not applicable" would hide a policy-only failure, and aliasing a
	// cancellation/timeout would let retry logic treat it as transient.
	for _, other := range []error{errDOMXSSSourceNotApplicable, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(errDOMXSSPostMessageIndeterminate, other) {
			t.Fatalf("indeterminate must not alias %v", other)
		}
	}
	if !strings.Contains(errDOMXSSPostMessageIndeterminate.Error(), "unknown") {
		t.Fatalf("indeterminate must say the delivery is unknown, got %q", errDOMXSSPostMessageIndeterminate)
	}
	if !errors.Is(fmt.Errorf("verification navigation: %w", errDOMXSSPostMessageIndeterminate), errDOMXSSPostMessageIndeterminate) {
		t.Fatal("a wrapped indeterminate must still match, or the caller would record a negative")
	}
	if domXSSPostMessageIndeterminate == domXSSPostMessageSent || domXSSPostMessageIndeterminate == domXSSPostMessageNoRoot {
		t.Fatal("the indeterminate status must be distinct from sent/no-root")
	}
}

func TestDOMXSSSourceNotApplicableIsItsOwnOutcome(t *testing.T) {
	if errDOMXSSSourceNotApplicable == nil {
		t.Fatal("missing not-applicable sentinel")
	}
	if errDOMXSSSourceNotApplicable.Error() == "" {
		t.Fatal("not-applicable sentinel needs an explanatory message")
	}
	// A cancellation/timeout must never be mistaken for "not applicable": the
	// two outcomes have opposite meanings for coverage.
	for _, other := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(errDOMXSSSourceNotApplicable, other) {
			t.Fatalf("not-applicable must not alias %v", other)
		}
	}
	if !errors.Is(fmt.Errorf("verification navigation: %w", errDOMXSSSourceNotApplicable), errDOMXSSSourceNotApplicable) {
		t.Fatal("a wrapped not-applicable must still match, or the caller would treat it as a retryable failure")
	}
}
