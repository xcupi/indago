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
	// No attachable root is a distinct, explicit answer — not an exception.
	if !strings.Contains(script, "resolve("+goQuoteJS(domXSSPostMessageNoRoot)+")") {
		t.Fatalf("no-root must resolve the not-applicable sentinel: %s", script)
	}
	if !strings.Contains(script, "resolve("+goQuoteJS(domXSSPostMessageSent)+")") {
		t.Fatalf("a delivered message must resolve the sent status: %s", script)
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
