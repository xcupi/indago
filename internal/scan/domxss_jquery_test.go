package scan

// Pure coverage for the jQuery sink plumbing: site attribution when jQuery's
// own parse reports innerHTML inside the factory call, the per-sink activation
// map, the activation scripts' inputs, and distinct finding identity. Executing
// behaviour lives in domxss_jquery_integration_test.go (real Chromium).

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func TestDOMXSSPrimarySinkPrefersJQuerySelectorOverItsInnerHTMLParse(t *testing.T) {
	cases := []struct {
		name      string
		reachable []detection.DOMXSSSink
		want      detection.DOMXSSSink
	}{
		{"jQuery parse reports inner parse first", []detection.DOMXSSSink{detection.DOMSinkInnerHTML, detection.DOMSinkJQuerySelector}, detection.DOMSinkJQuerySelector},
		{"factory reported first", []detection.DOMXSSSink{detection.DOMSinkJQuerySelector, detection.DOMSinkInnerHTML}, detection.DOMSinkJQuerySelector},
		{"unrelated earlier sink keeps its order", []detection.DOMXSSSink{detection.DOMSinkOuterHTML, detection.DOMSinkJQueryAttr}, detection.DOMSinkOuterHTML},
		{"jQuery attr alone", []detection.DOMXSSSink{detection.DOMSinkJQueryAttr}, detection.DOMSinkJQueryAttr},
		{"no sink", nil, ""},
	}
	for _, tc := range cases {
		if got := domXSSPrimarySink(tc.reachable); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDOMXSSActivationForSink(t *testing.T) {
	cases := []struct {
		sink          detection.DOMXSSSink
		hashActivated bool
		want          domXSSActivation
	}{
		{detection.DOMSinkJQueryAttr, false, domXSSActivateHrefClick},
		{detection.DOMSinkJQueryAttr, true, domXSSActivateHrefClick},
		{detection.DOMSinkJQuerySelector, true, domXSSActivateHashChange},
		{detection.DOMSinkJQuerySelector, false, domXSSActivateNone},
		{detection.DOMSinkInnerHTML, true, domXSSActivateNone},
		{detection.DOMSinkSetTimeout, false, domXSSActivateNone},
	}
	for _, tc := range cases {
		if got := domXSSActivationForSink(tc.sink, tc.hashActivated); got != tc.want {
			t.Fatalf("%s (hashActivated=%v): got %v, want %v", tc.sink, tc.hashActivated, got, tc.want)
		}
	}
	// Labels are what evidence logs and notes carry; keep them stable.
	if domXSSActivateHrefClick.label() != "href_click" || domXSSActivateHashChange.label() != "hash_change" || domXSSActivateNone.label() != "none" {
		t.Fatal("activation labels changed; evidence-log checks depend on them")
	}
}

func TestDOMXSSActivationScriptsCarryOnlyTheCandidateValue(t *testing.T) {
	const marker = "ACTIVATIONSCRIPTMARKER"
	hash := domXSSHashChangeActivationScript("javascript:" + marker)
	if !strings.Contains(hash, `"javascript:`+marker+`"`) || !strings.Contains(hash, "location.hash") {
		t.Fatalf("hash-change activation must assign exactly the candidate value: %s", hash)
	}
	click := domXSSHrefClickScript(marker)
	if !strings.Contains(click, `"`+marker+`"`) || !strings.Contains(click, "click()") || !strings.Contains(click, "data-indago-xss-target") {
		t.Fatalf("href activation must click the harness-tagged element: %s", click)
	}
	if strings.Contains(click, "javascript:") {
		t.Fatalf("href activation must never navigate to a javascript: URL itself: %s", click)
	}
}

func TestDOMXSSJQuerySinksHaveDistinctFindingIdentityAndTitle(t *testing.T) {
	const endpoint = domain.ID("endpoint-1")
	attr := domXSSFindingDedupKey(endpoint, detection.DOMSourceQuery, detection.DOMSinkJQueryAttr, "returnUrl")
	sel := domXSSFindingDedupKey(endpoint, detection.DOMSourceHash, detection.DOMSinkJQuerySelector, "")
	inner := domXSSFindingDedupKey(endpoint, detection.DOMSourceQuery, detection.DOMSinkInnerHTML, "returnUrl")
	if attr == sel || attr == inner || sel == inner {
		t.Fatalf("jQuery sinks must not share identity with each other or innerHTML: %q %q %q", attr, sel, inner)
	}
	ep := &domain.Endpoint{ID: endpoint, URL: "http://example.test/app", Method: domain.MethodGET}
	if title := domXSSFindingTitle(ep, detection.DOMSourceQuery, detection.DOMSinkJQueryAttr, "returnUrl"); !strings.Contains(title, "jQuery.attr") {
		t.Fatalf("attribute finding title must name the sink: %q", title)
	}
	if title := domXSSFindingTitle(ep, detection.DOMSourceHash, detection.DOMSinkJQuerySelector, ""); !strings.Contains(title, "jQuery.selector") {
		t.Fatalf("selector finding title must name the sink: %q", title)
	}
}
