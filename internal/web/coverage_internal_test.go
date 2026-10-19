package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The real notes the executors write when they skip a probe (copied from
// internal/scan). A skip that falls through to "other" would be reported as a
// medium gap with no advice, so each one must map to its own reason.
func TestClassifySkipKnowsTheNotesTheExecutorsWrite(t *testing.T) {
	cases := []struct{ note, want string }{
		{"dom-xss probe skipped: no browser configured for this scan", "browser_unavailable"},
		{"candidate builtin/html_text; parameter q (query): browser verification unavailable (no browser configured for this scan)", "browser_unavailable"},
		{"reflection test skipped: POST is state-changing and AllowStateChanging is off", "state_changing_disabled"},
		{"candidate test skipped: PUT is state-changing and AllowStateChanging is off", "state_changing_disabled"},
		{"x: browser verification supports GET/HEAD, POST/form, or bounded POST/JSON document replay only in this phase", "verification_unsupported"},
		{"x: request method or body representation is not supported for browser document replay", "verification_unsupported"},
		{"query-string DOM-XSS source not tested: no discovered query parameter on this endpoint", "source_not_applicable"},
		{"localStorage source not tested: no storage key was present and no getItem key was observed", "source_not_applicable"},
		{"something nobody anticipated", "other"},
		{"", "other"},
	}
	for _, tc := range cases {
		if got := classifySkip(tc.note).Code; got != tc.want {
			t.Errorf("classifySkip(%q) = %q, want %q", tc.note, got, tc.want)
		}
	}
}

// classifySkip matches substrings of notes written elsewhere. If an executor's
// wording changes, a skip would silently degrade to "other"; this fails first.
func TestClassifySkipPatternsStillExistInTheExecutors(t *testing.T) {
	files, err := filepath.Glob("../scan/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot read internal/scan: %v", err)
	}
	var src strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	all := strings.ToLower(src.String())
	for _, pat := range []string{
		"no browser configured",
		"allowstatechanging is off",
		"browser verification supports",
		"not supported for browser document replay",
		"source not tested:",
	} {
		if !strings.Contains(all, pat) {
			t.Errorf("pattern %q is no longer written by any executor in internal/scan; update classifySkip", pat)
		}
	}
}
