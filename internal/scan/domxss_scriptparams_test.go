package scan

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// Golden: a page whose own scripts read no query name contributes nothing, so
// the selector plan is exactly the discovered one — same names, same order,
// same provenance — as before page-script discovery existed.
func TestMergeDOMXSSQuerySelectorsGoldenUnchanged(t *testing.T) {
	discovered := []domXSSQuerySelector{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	got := mergeDOMXSSQuerySelectors(discovered, nil)
	if len(got) != len(discovered) {
		t.Fatalf("plan = %+v, want exactly %+v", got, discovered)
	}
	for i := range discovered {
		if got[i] != discovered[i] {
			t.Fatalf("selector %d = %+v, want %+v (unchanged)", i, got[i], discovered[i])
		}
	}
}

func TestMergeDOMXSSQuerySelectorsAppendsOnlyNewNames(t *testing.T) {
	discovered := []domXSSQuerySelector{{Name: "productId"}}
	script := []detection.DOMXSSScriptParam{
		{Name: "storeId", Script: detection.DOMXSSScriptInline, Line: 12},
		{Name: "productId", Script: detection.DOMXSSScriptInline, Line: 14}, // already discovered
		{Name: "locale", Script: "https://target.example/app.js", Line: 3},
	}
	got := mergeDOMXSSQuerySelectors(discovered, script)
	want := []domXSSQuerySelector{
		{Name: "productId"},
		{Name: "storeId", Source: detection.ParameterSourcePageScript},
		{Name: "locale", Source: detection.ParameterSourcePageScript},
	}
	if len(got) != len(want) {
		t.Fatalf("plan = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("selector %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMergeDOMXSSQuerySelectorsCapsAdditions(t *testing.T) {
	var script []detection.DOMXSSScriptParam
	for i := 0; i < detection.DOMXSSScriptParamLimit+5; i++ {
		script = append(script, detection.DOMXSSScriptParam{Name: fmt.Sprintf("p%d", i), Script: detection.DOMXSSScriptInline})
	}
	got := mergeDOMXSSQuerySelectors([]domXSSQuerySelector{{Name: "known"}}, script)
	if len(got) != 1+detection.DOMXSSScriptParamLimit {
		t.Fatalf("plan has %d selectors, want 1+%d", len(got), detection.DOMXSSScriptParamLimit)
	}
	if got[0].Name != "known" || got[0].Source != "" {
		t.Fatalf("discovered selector must stay first and unmarked: %+v", got[0])
	}
	if got[len(got)-1].Name != fmt.Sprintf("p%d", detection.DOMXSSScriptParamLimit-1) {
		t.Fatalf("cap must keep the first %d additions in order: %+v", detection.DOMXSSScriptParamLimit, got)
	}
}

func TestDOMXSSSameOriginScriptURL(t *testing.T) {
	base := "https://target.example/shop/product?productId=1"
	for _, tc := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{"/app.js", "https://target.example/app.js", true},
		{"app.js", "https://target.example/shop/app.js", true},
		{"//target.example/lib.js", "https://target.example/lib.js", true},
		{"https://target.example/x.js", "https://target.example/x.js", true},
		{"https://cdn.example.net/lib.js", "", false},
		{"http://target.example/x.js", "", false}, // scheme differs => different origin
		{"https://target.example:8443/x.js", "", false},
		{"data:text/javascript,alert(1)", "", false},
		{"javascript:alert(1)", "", false},
	} {
		got, ok := domXSSSameOriginScriptURL(tc.raw, base)
		if ok != tc.ok || got != tc.want {
			t.Errorf("domXSSSameOriginScriptURL(%q) = %q,%v; want %q,%v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

// A discovery-registered script literal (the crawler's inline matcher) is
// reported with page-script provenance rather than looking form-discovered.
func TestQueryParamSelectorsMarkScriptLiteralProvenance(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/p?productId=1", domain.MethodGET)
	env.param(ep, "productId", domain.LocationQuery, "1")
	scriptParam := &domain.Parameter{
		ID: domain.NewID(), ScanID: env.scanID, EndpointID: ep.ID, Name: "default",
		Location: domain.LocationQuery, Source: domain.SourceScriptLiteral, CreatedAt: time.Now(),
	}
	if err := env.st.Parameters().Create(context.Background(), scriptParam); err != nil {
		t.Fatal(err)
	}

	ex := newDOMXSSExecutor(env.st, nil, env.ev, domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), nil)
	got, err := ex.queryParamSelectors(context.Background(), ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []domXSSQuerySelector{
		{Name: "default", Source: detection.ParameterSourcePageScript},
		{Name: "productId"},
	}
	if len(got) != len(want) {
		t.Fatalf("selectors = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("selector %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
