package scan

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
)

func TestParseDOMOpenRedirectReports(t *testing.T) {
	msgs := []browser.ConsoleMessage{
		{Text: "unrelated log"},
		{Text: domOpenRedirectConsolePrefix + `{malformed`},
		{Text: domOpenRedirectConsolePrefix + `{"sink":"location.href","target":""}`},
		{Text: domOpenRedirectConsolePrefix + `{"sink":"location.href","target":"https://canary.invalid/indago-redirect-ind123"}`},
		{Text: domOpenRedirectConsolePrefix + `{"sink":"window.open","target":"//canary.invalid/indago-redirect-ind123"}`},
	}
	got := parseDOMOpenRedirectReports(msgs)
	if len(got) != 2 {
		t.Fatalf("got %d reports, want 2: %+v", len(got), got)
	}
	if got[0].Sink != "location.href" || !strings.Contains(got[0].Target, "canary.invalid") {
		t.Fatalf("unexpected report[0]: %+v", got[0])
	}
	if got[1].Sink != "window.open" || !strings.Contains(got[1].Target, "//canary.invalid") {
		t.Fatalf("unexpected report[1]: %+v", got[1])
	}
}

func TestDOMXSSHarnessShortCircuitsCanaryRedirects(t *testing.T) {
	script := domXSSHarnessScript("indTEST")
	for _, want := range []string{
		"isCanaryRedirect",
		"reportRedirect",
		"__INDAGO_DOM_REDIRECT__",
		"canary.invalid",
		"window.open",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("harness script missing %q", want)
		}
	}
}
