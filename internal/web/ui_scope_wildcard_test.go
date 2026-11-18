package web_test

// Real-browser test for the SPA's scope editor: the wildcard list is its own
// field, it is saved round-trip with the exact hosts intact, and the page says
// out loud that a wildcard does not cover its apex.
//
// This is the review-scope fact QA asked for at the UI level: an imported
// program's `*.example.com` asset must not look like an exact host, and an
// operator editing the form must not silently drop it (the API preserves an
// absent field, so the form has to send the list on every save).

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

func TestUIScopeEditorShowsAndSavesWildcardHosts(t *testing.T) {
	// An operator's own browser may PUT; the non-mutating context default is for
	// the scanner's own pages, so this test asks for a mutating context.
	u := newUIHarnessWithContext(t, "", web.Capabilities{}, nil, browser.ContextOptions{AllowStateChanging: true})

	ctx := context.Background()
	proj := &domain.Project{ID: domain.NewID(), Name: "wildcard project"}
	if err := u.st.Projects().Create(ctx, proj); err != nil {
		t.Fatal(err)
	}
	if err := u.st.Scopes().Create(ctx, &domain.Scope{
		ID: domain.NewID(), ProjectID: proj.ID,
		IncludeHosts:       []string{"shop.example.com"},
		SubdomainOnlyHosts: []string{"example.com"},
	}); err != nil {
		t.Fatal(err)
	}

	// The SPA is served at "/"; project detail is a hash route.
	if _, err := u.page.Navigate(u.ctx, u.url+"/#/projects/"+string(proj.ID), browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	u.waitUI("scope editor rendered", `document.body.textContent.indexOf('Wildcard hosts (subdomains only)') >= 0`)
	// The draft is filled from the API after the first render; wait for the
	// wildcard field to carry the stored value before reading or editing it.
	u.waitUI("scope values loaded", `(function(){var el=Array.from(document.querySelectorAll('textarea')).find(function(t){return t.getAttribute('placeholder')==='example.com';});return !!el && el.value==='example.com';})()`)

	// The imported wildcard host is shown in its own field, not as an exact host.
	if got := u.evalStr(`(function(){var el=Array.from(document.querySelectorAll('textarea')).find(function(t){return (t.getAttribute('placeholder')||'').indexOf('app.example.com')===0;});return el?el.value:'<missing>';})()`); got != "shop.example.com" {
		t.Fatalf("exact-host field = %q, want only shop.example.com (the wildcard must not be listed as exact)", got)
	}
	// The page states what a wildcard means: subdomains, never the apex.
	body := u.evalStr(`document.body.textContent`)
	for _, want := range []string{"subdomains only", "itself is not"} {
		if !strings.Contains(body, want) {
			t.Fatalf("scope page does not explain the wildcard: missing %q", want)
		}
	}

	// Edit the wildcard list the way an operator would, then save. The native
	// value setter is what makes React register the change on a controlled
	// textarea.
	if !u.evalBool(`(function(){
		var el = Array.from(document.querySelectorAll('textarea')).find(function(t){return t.getAttribute('placeholder') === 'example.com';});
		if (!el) return false;
		var setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
		setter.call(el, 'example.com\napi.example.com');
		el.dispatchEvent(new Event('input', { bubbles: true }));
		return true;
	})()`) {
		t.Fatal("wildcard textarea not found")
	}
	// The scheme/port statement is explicit and is never derived, so the save
	// must carry it: the exact host and the wildcard it authorizes.
	if !u.evalBool(`(function(){
		var el = Array.from(document.querySelectorAll('textarea')).find(function(t){return (t.getAttribute('placeholder')||'').indexOf('https://app.example.com')===0;});
		if (!el) return false;
		var setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
		setter.call(el, 'https://shop.example.com\nhttps://*.example.com');
		el.dispatchEvent(new Event('input', { bubbles: true }));
		return true;
	})()`) {
		t.Fatal("origins textarea not found")
	}
	// The button's textContent carries a leading space (icon + text), so match on
	// the trimmed value instead of mustClickText's exact comparison.
	if !u.evalBool(`(function(){
		var b = Array.from(document.querySelectorAll('button')).find(function(x){return x.textContent.trim() === 'Save scope';});
		if (!b) return false;
		window.__indagoClicked = b.textContent.trim();
		b.click();
		return true;
	})()`) {
		t.Fatalf("save button not found; buttons = %s", u.evalStr(`Array.from(document.querySelectorAll('button')).map(function(b){return JSON.stringify(b.textContent.trim());}).join(',')`))
	}
	u.waitUI("scope saved", `document.body.textContent.indexOf('Scope saved.') >= 0`)

	sc, err := u.st.Scopes().GetByProject(ctx, proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"shop.example.com"}; !slices.Equal(sc.IncludeHosts, want) {
		t.Fatalf("include_hosts = %v, want %v (an exact host must survive a wildcard edit)", sc.IncludeHosts, want)
	}
	if want := []string{"example.com", "api.example.com"}; !slices.Equal(sc.SubdomainOnlyHosts, want) {
		t.Fatalf("subdomain_only_hosts = %v, want %v (the form must send the list)", sc.SubdomainOnlyHosts, want)
	}
	// The saved scope behaves as displayed: subdomains in, apex out.
	if d := sc.Permits("https://app.example.com/"); !d.Allowed {
		t.Fatalf("saved scope denies a wildcard subdomain: %+v", d)
	}
	if d := sc.Permits("https://example.com/"); d.Allowed {
		t.Fatal("saved scope authorized the wildcard apex")
	}
}
