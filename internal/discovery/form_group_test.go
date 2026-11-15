package discovery_test

// Tests for form-group isolation: several <form> elements on one page posting
// to the SAME action (bWAPP's /commandi.php has three) are separate
// submissions, so their fields must never collapse into one parameter list.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

const sameActionFormsPage = `<html><body>
<form action="/commandi.php" method="POST">
  <label for="target">Enter the IP address:</label>
  <input id="target" name="target" value="">
  <button name="form" type="submit" value="submit">Lookup</button>
</form>
<form action="/commandi.php" method="POST">
  <select name="security_level"><option value="low">low</option></select>
  <button name="form_security_level" type="submit" value="submit">Set</button>
</form>
<form action="/commandi.php" method="POST">
  <select name="bug"><option value="0">0</option></select>
  <button name="form_bug" type="submit" value="submit">Hack</button>
</form>
</body></html>`

// TestExtractFormsSameActionGroups checks the group key itself: forms sharing an
// action+method but submitting different fields get different groups, an
// identical form (even with its fields in another order) gets the same group,
// and the method is part of the identity.
func TestExtractFormsSameActionGroups(t *testing.T) {
	forms := discovery.ExtractForms(sameActionFormsPage)
	if len(forms) != 3 {
		t.Fatalf("expected 3 forms, got %d", len(forms))
	}
	byField := map[string]discovery.Form{}
	for _, f := range forms {
		if f.Action != "/commandi.php" || f.Method != domain.MethodPOST {
			t.Fatalf("form = %+v, want POST /commandi.php", f)
		}
		if f.Group == "" {
			t.Fatalf("form with fields %+v has no group", f.Inputs)
		}
		byField[f.Inputs[0].Name] = f
	}
	groups := map[string]string{}
	for name, f := range byField {
		groups[name] = f.Group
	}
	if groups["target"] == groups["security_level"] || groups["target"] == groups["bug"] || groups["security_level"] == groups["bug"] {
		t.Fatalf("distinct forms share a group: %v", groups)
	}

	// Same form, fields reordered: same group, so its parameters deduplicate.
	reordered := discovery.ExtractForms(`<form action="/commandi.php" method="POST">
  <button name="form" type="submit" value="submit">Lookup</button>
  <input name="target" value="">
</form>`)
	if len(reordered) != 1 {
		t.Fatalf("expected 1 form, got %d", len(reordered))
	}
	if reordered[0].Group != groups["target"] {
		t.Fatalf("field order changed the group: %q != %q", reordered[0].Group, groups["target"])
	}

	// A different method is a different submission shape.
	asGet := discovery.ExtractForms(`<form action="/commandi.php" method="GET"><input name="target" value=""><button name="form" type="submit" value="submit"></button></form>`)
	if len(asGet) != 1 || asGet[0].Group == groups["target"] {
		t.Fatalf("GET form reused the POST group: %+v", asGet)
	}
}

// TestCrawlRegistersSameActionFormsPerGroup drives the real crawler: one page,
// three forms, one action. Every field must land on the single POST endpoint
// carrying the group of the form it came from.
func TestCrawlRegistersSameActionFormsPerGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, sameActionFormsPage)
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	cfg.MaxDepth = 0
	m, st, _ := newManagerFor(t, cfg, nil)
	id := domain.NewID()
	if _, err := m.Run(context.Background(), discovery.RunParams{
		ScanID: id, Scope: scopeFor(srv), SeedURLs: []string{srv.URL + "/"},
	}); err != nil {
		t.Fatal(err)
	}

	eps, err := st.Endpoints().ListByScan(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var post *domain.Endpoint
	for _, ep := range eps {
		if ep.Method == domain.MethodPOST {
			if post != nil {
				t.Fatalf("one action must stay ONE POST endpoint, got %s and %s", post.URL, ep.URL)
			}
			post = ep
		}
	}
	if post == nil {
		t.Fatalf("no POST endpoint registered: %+v", eps)
	}
	params, err := st.Parameters().ListByEndpoint(context.Background(), post.ID)
	if err != nil {
		t.Fatal(err)
	}
	groupOf := map[string]string{}
	for _, p := range params {
		if p.Location != domain.LocationForm {
			continue
		}
		if p.FormGroup == "" {
			t.Fatalf("form field %q registered without a form group", p.Name)
		}
		groupOf[p.Name] = p.FormGroup
	}
	for _, pair := range [][2]string{
		{"target", "form"},
		{"security_level", "form_security_level"},
		{"bug", "form_bug"},
	} {
		if groupOf[pair[0]] == "" || groupOf[pair[0]] != groupOf[pair[1]] {
			t.Fatalf("%s and %s must share a group: %v", pair[0], pair[1], groupOf)
		}
	}
	if len(groupOf) != 6 {
		t.Fatalf("expected 6 form parameters, got %d: %v", len(groupOf), groupOf)
	}
	if groupOf["target"] == groupOf["security_level"] || groupOf["target"] == groupOf["bug"] || groupOf["security_level"] == groupOf["bug"] {
		t.Fatalf("fields from different forms share a group: %v", groupOf)
	}
}

// TestCollectorFormGroupIsPartOfParameterIdentity checks the sink side: the same
// field name submitted by two forms is two parameters (each verified in its own
// form's request), while re-registering the same form's field is still a
// duplicate — including after a restart, when Hydrate rebuilds the dedup keys.
func TestCollectorFormGroupIsPartOfParameterIdentity(t *testing.T) {
	cfg := discovery.DefaultConfig()
	c, st, q, scanID := newCollector(t, cfg)
	ctx := context.Background()
	epID, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/act", Method: domain.MethodPOST, Source: domain.SourceForm,
	})
	if err != nil || epID == "" {
		t.Fatalf("add endpoint: %v (id %q)", err, epID)
	}
	add := func(name, group string) {
		t.Helper()
		if err := c.AddParameter(ctx, discovery.ParamCandidate{
			EndpointURL: "http://example.com/act", EndpointMethod: domain.MethodPOST,
			Name: name, Location: domain.LocationForm, Example: "v-" + group,
			Source: domain.SourceForm, FormGroup: group,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("token", "fg:one")
	add("submit", "fg:one")
	add("token", "fg:two")
	add("submit", "fg:two")
	add("token", "fg:one") // duplicate of the first form's field

	params, err := st.Parameters().ListByEndpoint(ctx, epID)
	if err != nil {
		t.Fatal(err)
	}
	var formParams []*domain.Parameter
	for _, p := range params {
		if p.Location == domain.LocationForm {
			formParams = append(formParams, p)
		}
	}
	if len(formParams) != 4 {
		t.Fatalf("expected 4 form parameters (2 fields x 2 form groups), got %d: %+v", len(formParams), formParams)
	}
	groups := map[string]map[string]bool{}
	for _, p := range formParams {
		if groups[p.Name] == nil {
			groups[p.Name] = map[string]bool{}
		}
		groups[p.Name][p.FormGroup] = true
	}
	for _, name := range []string{"token", "submit"} {
		if !groups[name]["fg:one"] || !groups[name]["fg:two"] || len(groups[name]) != 2 {
			t.Fatalf("%q groups = %v, want one row per form group", name, groups[name])
		}
	}

	// Restart: a hydrated collector must recognise the same fields as known,
	// or a resumed scan would re-test every form field from scratch.
	c2 := discovery.NewCollector(st, q, scanID, domain.Scope{IncludeHosts: []string{"example.com"}}, false, cfg, quiet())
	if err := c2.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := st.Parameters().ListByScan(ctx, scanID)
	addVia := func(c *discovery.Collector, name, group string) {
		t.Helper()
		if err := c.AddParameter(ctx, discovery.ParamCandidate{
			EndpointURL: "http://example.com/act", EndpointMethod: domain.MethodPOST,
			Name: name, Location: domain.LocationForm, Example: "again",
			Source: domain.SourceForm, FormGroup: group,
		}); err != nil {
			t.Fatal(err)
		}
	}
	addVia(c2, "token", "fg:one")
	addVia(c2, "token", "fg:two")
	addVia(c2, "fresh", "fg:two") // genuinely new field of a known form
	after, err := st.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("hydrated collector re-registered known form fields: before=%d after=%d", len(before), len(after))
	}
	formIDs := map[domain.ID]bool{}
	for _, p := range after {
		if p.Location == domain.LocationForm {
			formIDs[p.ID] = true
		}
	}
	ips, err := st.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	formIPs := 0
	for _, ip := range ips {
		if formIDs[ip.ParameterID] {
			formIPs++
		}
	}
	if formIPs != 5 || len(formIDs) != 5 {
		t.Fatalf("expected one injection point per form parameter (5), got %d for %d parameters", formIPs, len(formIDs))
	}
}
