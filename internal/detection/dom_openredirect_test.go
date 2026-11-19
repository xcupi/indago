package detection

import (
	"slices"
	"testing"
)

func TestDOMOpenRedirectPayloadsAndTargetMatching(t *testing.T) {
	marker := "ind12345"
	payloads := DOMOpenRedirectPayloads(marker)
	if len(payloads) != 2 {
		t.Fatalf("payload count = %d, want 2", len(payloads))
	}
	if payloads[0] != "https://canary.invalid/indago-redirect-ind12345" {
		t.Fatalf("payload[0] = %q", payloads[0])
	}
	if payloads[1] != "//canary.invalid/indago-redirect-ind12345" {
		t.Fatalf("payload[1] = %q", payloads[1])
	}
	if got := DOMOpenRedirectPayloads("bad!marker"); got != nil {
		t.Fatalf("invalid marker produced %v, want nil", got)
	}

	base := "https://app.example/profile"
	cases := []struct {
		target string
		want   bool
	}{
		{"https://canary.invalid/indago-redirect-ind12345", true},
		{"http://canary.invalid/indago-redirect-ind12345", true},
		{"//canary.invalid/indago-redirect-ind12345", true},
		{"https://CANARY.INVALID/indago-redirect-ind12345?x=1", true},
		{"https://app.example/login?next=https://canary.invalid/indago-redirect-ind12345", false},
		{"https://canary.invalid/other", false},
		{"javascript:ind12345", false},
		{"/local/path?m=ind12345", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsDOMOpenRedirectTarget(tc.target, marker, base); got != tc.want {
			t.Errorf("IsDOMOpenRedirectTarget(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestDOMOpenRedirectStaticSites(t *testing.T) {
	html := `<!doctype html><html><body>
<a href="#" onclick="returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : '/'">Back</a>
<script>
const next = new URLSearchParams(location.search).get('next');
if (next) { location.assign(next); }
</script>
</body></html>`
	sites := DOMOpenRedirectStaticSites(html, "https://app.example/page", nil)
	if len(sites) == 0 {
		t.Fatal("expected static open-redirect sites, got none")
	}
	params := DOMOpenRedirectOnclickParams(html)
	if !slices.Contains(params, "url") {
		t.Fatalf("onclick params = %v, want url", params)
	}
	hasLoc := false
	for _, s := range sites {
		if s.Sink == string(DOMSinkLocationAssign) && s.Source == DOMSourceQuery {
			hasLoc = true
		}
	}
	if !hasLoc {
		t.Fatalf("expected DOMSinkLocationAssign from query source in %+v", sites)
	}
}
