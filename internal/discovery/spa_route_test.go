package discovery

import (
	"reflect"
	"testing"
)

func TestExtractSPARoutesKeepsHashRoutesOnly(t *testing.T) {
	body := `<a href="#/search?q=test">search</a>
		<a href="#lesson/WebGoatIntroduction.lesson">lesson</a>
		<a href="#section">anchor</a><span style="color:#fff"></span>
		<script>const route = "#/account?tab=one";</script>
		<script type="application/json">{"link":"#lesson/HttpBasics.lesson"}</script>`
	got := extractSPARoutes(body)
	want := []string{"/search?q=test", "lesson/WebGoatIntroduction.lesson", "/account?tab=one", "lesson/HttpBasics.lesson"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extractSPARoutes = %v, want %v", got, want)
	}
}

func TestSPAHashRouteRejectsUnsafeOrPlainFragments(t *testing.T) {
	for _, ref := range []string{"", "#", "#section", "#fff", "#//host/path", "#/ok<script>"} {
		if route := spaHashRoute(ref); route != "" {
			t.Fatalf("spaHashRoute(%q) = %q, want empty", ref, route)
		}
	}
	if route := spaHashRoute("#/search?q=x"); route != "/search?q=x" {
		t.Fatalf("route = %q", route)
	}
}
