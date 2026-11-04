package scan

// Pure coverage for the angular_expression sink's decision layer:
//   - the harness report parsers (text result and CSP violation) accept only
//     engine-attributed, well-formed reports;
//   - the verdict rule maps compiled / csp_blocked / inert text / unobserved to
//     four DISTINCT outcomes, and CSP is never Rejected or Confirmed;
//   - a passive angular text observation never displaces a sink the page's own
//     code actively reached.
// The real-browser behaviour lives in domxss_angular_integration_test.go.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func angularReport(text string) browser.ConsoleMessage {
	return browser.ConsoleMessage{Type: "log", Text: text}
}

func TestDOMXSSAngularTextResultParsing(t *testing.T) {
	const marker = "ANGULARPARSE42"
	hit := domXSSConsolePrefix + `{"sink":"angular_expression","value":"` + marker + `","text":true,"count":1}`
	if !hasDOMXSSAngularTextResult([]browser.ConsoleMessage{angularReport(hit)}, marker) {
		t.Fatal("a text report naming the marker must count as a compiled result")
	}
	// A hooked-sink report is not a text observation, even if it names the sink.
	notText := domXSSConsolePrefix + `{"sink":"angular_expression","value":"` + marker + `"}`
	if hasDOMXSSAngularTextResult([]browser.ConsoleMessage{angularReport(notText)}, marker) {
		t.Fatal("a report without the text flag must not confirm")
	}
	// A report for another marker is unrelated.
	other := domXSSConsolePrefix + `{"sink":"angular_expression","value":"OTHER42","text":true,"count":1}`
	if hasDOMXSSAngularTextResult([]browser.ConsoleMessage{angularReport(other)}, marker) {
		t.Fatal("a report for another marker must not confirm")
	}
	if hasDOMXSSAngularTextResult([]browser.ConsoleMessage{angularReport("plain page text")}, marker) {
		t.Fatal("page-authored text outside the harness prefix must not confirm")
	}
	if hasDOMXSSAngularTextResult(nil, marker) || hasDOMXSSAngularTextResult([]browser.ConsoleMessage{angularReport(hit)}, "") {
		t.Fatal("empty input must not confirm")
	}
	// The same report must also make the sink reachable in phase one.
	reachable := parseDOMXSSReachability([]browser.ConsoleMessage{angularReport(hit)}, marker)
	if len(reachable) != 1 || reachable[0] != detection.DOMSinkAngularExpression {
		t.Fatalf("text report must be reachable as angular_expression, got %v", reachable)
	}
}

func TestDOMXSSAngularBindingResultParsing(t *testing.T) {
	const marker = "ANGULARBIND42"
	text := domXSSConsolePrefix + `{"sink":"angular_expression","value":"` + marker + `","text":true,"count":1}`
	if compiled, viaBinding := domXSSAngularResult([]browser.ConsoleMessage{angularReport(text)}, marker); !compiled || viaBinding {
		t.Fatalf("a rendered-text report must be compiled and not binding-read, got %v/%v", compiled, viaBinding)
	}
	binding := domXSSConsolePrefix + `{"sink":"angular_expression","value":"` + marker + `","text":true,"binding":true,"count":1}`
	if compiled, viaBinding := domXSSAngularResult([]browser.ConsoleMessage{angularReport(binding)}, marker); !compiled || !viaBinding {
		t.Fatalf("a binding report must be compiled and binding-read, got %v/%v", compiled, viaBinding)
	}
	other := domXSSConsolePrefix + `{"sink":"angular_expression","value":"OTHER42","text":true,"binding":true,"count":1}`
	if compiled, _ := domXSSAngularResult([]browser.ConsoleMessage{angularReport(other)}, marker); compiled {
		t.Fatal("a binding report for another marker must not confirm")
	}
	if compiled, _ := domXSSAngularResult([]browser.ConsoleMessage{angularReport(binding)}, ""); compiled {
		t.Fatal("an empty marker must not confirm")
	}
}

// TestDOMXSSAngularInertText covers the without-strings lab shape: the page
// passes the value through an HTML encoder, so the rendered DOM holds
// '{{&apos;MARK…}}' instead of our exact bytes. The source must still count as
// inert once the serialization is decoded, and a page whose source was
// replaced by the evaluated result must not.
func TestDOMXSSAngularInertText(t *testing.T) {
	const marker = "ANGULARINERT42"
	cand := "{{'" + marker[:len(marker)/2] + "' + '" + marker[len(marker)/2:] + "' + ($id ? '' : '')}}"
	encoded := strings.ReplaceAll(cand, "'", "&apos;")
	cases := []struct {
		name string
		html string
		want bool
	}{
		{"literal echo", `<h1>0 search results for ` + cand + `</h1>`, true},
		{"html-encoded echo", `<h1>0 search results for ` + encoded + `</h1>`, true},
		{"serializer re-escaped", `<h1>0 search results for ` + strings.ReplaceAll(encoded, "&", "&amp;") + `</h1>`, true},
		{"compiled away", `<h1>0 search results for ` + marker + `</h1>`, false},
		{"not delivered", `<h1>0 search results for nothing</h1>`, false},
		{"empty candidate", `<h1>x</h1>`, false},
	}
	for _, tc := range cases {
		got := domXSSAngularInertText(tc.html, cand)
		if tc.name == "empty candidate" {
			got = domXSSAngularInertText(tc.html, "")
		}
		if got != tc.want {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.want, got)
		}
	}
}

func TestDOMXSSAngularCSPParsing(t *testing.T) {
	eval := domXSSConsoleCSPPrefix + `{"directive":"script-src","blocked":"eval","disposition":"enforce"}`
	inline := domXSSConsoleCSPPrefix + `{"directive":"script-src-elem","blocked":"inline","disposition":"enforce"}`
	reportOnly := domXSSConsoleCSPPrefix + `{"directive":"script-src","blocked":"eval","disposition":"report"}`
	msgs := []browser.ConsoleMessage{
		angularReport(eval), angularReport(eval), // duplicated by the two listeners
		angularReport(inline), angularReport(reportOnly),
		angularReport("not a report"),
	}
	got := parseDOMXSSCSPViolations(msgs)
	if len(got) != 3 {
		t.Fatalf("want the three distinct violations, got %+v", got)
	}
	blocked, v := domXSSEvalBlockedByCSP(got)
	if !blocked || v.Directive != "script-src" || v.Blocked != "eval" {
		t.Fatalf("an enforced script-src eval refusal must be the CSP outcome, got %v %+v", blocked, v)
	}
	if blocked, _ := domXSSEvalBlockedByCSP([]domXSSCSPViolation{{Directive: "script-src-elem", Blocked: "inline", Disposition: "enforce"}}); blocked {
		t.Fatal("an inline-script block does not explain a missing interpolation result")
	}
	if blocked, _ := domXSSEvalBlockedByCSP([]domXSSCSPViolation{{Directive: "script-src", Blocked: "eval", Disposition: "report"}}); blocked {
		t.Fatal("a report-only policy must not produce the csp_blocked outcome")
	}
}

func TestDecideDOMXSSAngularOutcomesAreDistinct(t *testing.T) {
	confirmed, confidence, note := decideDOMXSSAngular(true, false, true, true, domXSSCSPViolation{Directive: "script-src", Blocked: "eval"})
	if confirmed != domain.VerdictConfirmed || confidence != domain.ConfidenceHigh {
		t.Fatalf("a compiled interpolation is Confirmed, got %s/%s", confirmed, confidence)
	}
	if !strings.Contains(note, "outcome="+domXSSAngularOutcomeCompiled) {
		t.Fatalf("compiled outcome token missing: %q", note)
	}

	// The same result read from Angular's compiled binding is equally
	// Confirmed, and the note must say how it was read.
	bound, boundConfidence, boundNote := decideDOMXSSAngular(true, true, false, false, domXSSCSPViolation{})
	if bound != domain.VerdictConfirmed || boundConfidence != domain.ConfidenceHigh {
		t.Fatalf("a binding-read interpolation result is Confirmed, got %s/%s", bound, boundConfidence)
	}
	if !strings.Contains(boundNote, "compiled interpolation binding") {
		t.Fatalf("binding-read confirmation must name the reading: %q", boundNote)
	}

	cspVerdict, cspConfidence, cspNote := decideDOMXSSAngular(false, false, true, true, domXSSCSPViolation{Directive: "script-src", Blocked: "eval"})
	if cspVerdict == domain.VerdictRejected || cspVerdict == domain.VerdictConfirmed {
		t.Fatalf("CSP-blocked execution must be neither Rejected nor Confirmed, got %s", cspVerdict)
	}
	if cspVerdict != domain.VerdictInconclusive || cspConfidence != domain.ConfidenceLow {
		t.Fatalf("CSP-blocked execution must be a low-confidence Inconclusive, got %s/%s", cspVerdict, cspConfidence)
	}
	if !strings.Contains(cspNote, "outcome="+domXSSAngularOutcomeCSPBlocked) || !strings.Contains(cspNote, "script-src") || !strings.Contains(cspNote, "eval") {
		t.Fatalf("CSP outcome must be explicitly recorded, got %q", cspNote)
	}

	rejected, rejectedConfidence, rejectedNote := decideDOMXSSAngular(false, false, true, false, domXSSCSPViolation{})
	if rejected != domain.VerdictRejected || rejectedConfidence != domain.ConfidenceHigh {
		t.Fatalf("inert echoed text is Rejected, got %s/%s", rejected, rejectedConfidence)
	}
	if !strings.Contains(rejectedNote, "outcome="+domXSSAngularOutcomeInertText) {
		t.Fatalf("inert outcome token missing: %q", rejectedNote)
	}

	unknown, unknownConfidence, unknownNote := decideDOMXSSAngular(false, false, false, false, domXSSCSPViolation{})
	if unknown != domain.VerdictInconclusive || unknownConfidence != domain.ConfidenceLow {
		t.Fatalf("an unobservable candidate is Inconclusive, got %s/%s", unknown, unknownConfidence)
	}
	if !strings.Contains(unknownNote, "outcome="+domXSSAngularOutcomeUnobserved) {
		t.Fatalf("unobserved outcome token missing: %q", unknownNote)
	}

	// The four outcomes must be textually distinguishable, which is what makes
	// csp_blocked a distinct result on every presentation surface.
	seen := map[string]bool{}
	for _, n := range []string{note, boundNote, cspNote, rejectedNote, unknownNote} {
		if seen[n] {
			t.Fatalf("outcome notes must be distinct: %q", n)
		}
		seen[n] = true
	}
}

func TestDOMXSSPrimarySinkKeepsAngularAsFallback(t *testing.T) {
	cases := []struct {
		name string
		in   []detection.DOMXSSSink
		want detection.DOMXSSSink
	}{
		{"angular only", []detection.DOMXSSSink{detection.DOMSinkAngularExpression}, detection.DOMSinkAngularExpression},
		{"active sink first", []detection.DOMXSSSink{detection.DOMSinkInnerHTML, detection.DOMSinkAngularExpression}, detection.DOMSinkInnerHTML},
		{"active sink last", []detection.DOMXSSSink{detection.DOMSinkAngularExpression, detection.DOMSinkSetTimeout}, detection.DOMSinkSetTimeout},
		{"jquery selector still wins", []detection.DOMXSSSink{detection.DOMSinkAngularExpression, detection.DOMSinkJQuerySelector}, detection.DOMSinkJQuerySelector},
		{"no sink", nil, ""},
	}
	for _, tc := range cases {
		if got := domXSSPrimarySink(tc.in); got != tc.want {
			t.Fatalf("%s: want %q, got %q", tc.name, tc.want, got)
		}
	}
	if got := withoutDOMXSSSink([]detection.DOMXSSSink{detection.DOMSinkInnerHTML, detection.DOMSinkAngularExpression}, detection.DOMSinkAngularExpression); len(got) != 1 || got[0] != detection.DOMSinkInnerHTML {
		t.Fatalf("passive angular report must be dropped from another sink's attribution note: %v", got)
	}
}
