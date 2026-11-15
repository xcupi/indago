package scan

// Tests for form-group isolation on the request side: a page can hold several
// <form> elements posting to the same action (bWAPP's /commandi.php has three),
// and a request aimed at one form's field must carry that form's fields only —
// never another form's, and never another form's submit button.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

// bWAPP /commandi.php on one page: three POST forms, one action, one submit
// button each.
const (
	cmdFormGroup  = "fg:target-form"
	secFormGroup  = "fg:security-form"
	bugFormGroup  = "fg:bug-form"
	sameActionURL = "http://h/commandi.php"
)

// formParams builds the parameter set discovery persists for those three forms.
func formParams(scanID domain.ID, epID domain.ID) []*domain.Parameter {
	mk := func(name, group, example string) *domain.Parameter {
		return &domain.Parameter{
			ID: domain.NewID(), ScanID: scanID, EndpointID: epID, Name: name,
			Location: domain.LocationForm, Example: example,
			Source: domain.SourceForm, FormGroup: group, CreatedAt: time.Now(),
		}
	}
	return []*domain.Parameter{
		mk("target", cmdFormGroup, "127.0.0.1"),
		mk("form", cmdFormGroup, "submit"),
		mk("security_level", secFormGroup, "low"),
		mk("form_security_level", secFormGroup, "submit"),
		mk("bug", bugFormGroup, "0"),
		mk("form_bug", bugFormGroup, "submit"),
	}
}

func paramNames(params []*domain.Parameter) []string {
	out := make([]string, 0, len(params))
	for _, p := range params {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

func TestParamsForFocusKeepsOnlyTheFocusedFormGroup(t *testing.T) {
	ep := &domain.Endpoint{ID: domain.NewID(), URL: sameActionURL, Method: domain.MethodPOST}
	params := formParams(domain.NewID(), ep.ID)
	// An endpoint-wide (group-less) parameter must survive every narrowing: it
	// belongs to the URL, not to any one form.
	params = append(params, &domain.Parameter{ID: domain.NewID(), Name: "q", Location: domain.LocationQuery, Example: "x"})

	byName := map[string]*domain.Parameter{}
	for _, p := range params {
		byName[p.Name] = p
	}

	got := paramsForFocus(params, byName["target"])
	if names := paramNames(got); strings.Join(names, ",") != "form,q,target" {
		t.Fatalf("focused on the command form: %v, want form,q,target", names)
	}

	got = paramsForFocus(params, byName["form_security_level"])
	if names := paramNames(got); strings.Join(names, ",") != "form_security_level,q,security_level" {
		t.Fatalf("focused on the security form: %v, want form_security_level,q,security_level", names)
	}

	// A group-less focus (query, JSON, header, cookie, path) is not a form
	// field, so it keeps the endpoint's whole parameter list — unchanged
	// behaviour for every scan that has no form groups at all.
	all := paramsForFocus(params, byName["q"])
	if len(all) != len(params) {
		t.Fatalf("group-less focus narrowed the list: %d of %d", len(all), len(params))
	}
	if got := paramsForFocus(params, nil); len(got) != len(params) {
		t.Fatalf("nil focus narrowed the list: %d of %d", len(got), len(params))
	}
}

// TestBuildRequestCarriesOnlyTheFocusedForm is the regression test for the
// reported bug: one POST carrying every form's submit button makes the target
// run the wrong handler.
func TestBuildRequestCarriesOnlyTheFocusedForm(t *testing.T) {
	ep := &domain.Endpoint{ID: domain.NewID(), URL: sameActionURL, Method: domain.MethodPOST}
	params := formParams(domain.NewID(), ep.ID)
	byName := map[string]*domain.Parameter{}
	for _, p := range params {
		byName[p.Name] = p
	}

	focus := byName["target"]
	req, err := buildRequest(ep, paramsForFocus(params, focus), &injection{param: focus, value: "indago-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "form=submit&target=indago-marker"; string(req.Body) != want {
		t.Fatalf("body = %q, want %q", req.Body, want)
	}

	// The same rule for each of the other two forms.
	focus = byName["form_security_level"]
	req, err = buildRequest(ep, paramsForFocus(params, focus), &injection{param: focus, value: "indago-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "form_security_level=indago-marker&security_level=low"; string(req.Body) != want {
		t.Fatalf("body = %q, want %q", req.Body, want)
	}

	// A request built from the UNSCOPED list still carries everything: that is
	// exactly the request this bug produced, kept here as the contrast case.
	req, err = buildRequest(ep, params, &injection{param: focus, value: "indago-marker"})
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{"target=", "form=", "form_bug="} {
		if !strings.Contains(string(req.Body), other) {
			t.Fatalf("contrast request should carry %q: %q", other, req.Body)
		}
	}
}

// TestResolveJobTargetScopesParametersToTheFocusedForm checks the shared
// resolution path every engine uses: the parameter list handed to an engine for
// a focused injection point is already narrowed to that parameter's form.
func TestResolveJobTargetScopesParametersToTheFocusedForm(t *testing.T) {
	env := newExecEnv(t)
	ctx := context.Background()
	ep := env.endpoint(sameActionURL, domain.MethodPOST)
	var focus *domain.Parameter
	for _, p := range formParams(env.scanID, ep.ID) {
		if err := env.st.Parameters().Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		if p.Name == "target" {
			focus = p
		}
	}
	job := env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: env.injection(ep, focus).ID})

	_, params, gotFocus, err := resolveJobTarget(ctx, env.st, job)
	if err != nil {
		t.Fatal(err)
	}
	if gotFocus == nil || gotFocus.Name != "target" {
		t.Fatalf("focus = %+v, want target", gotFocus)
	}
	if names := paramNames(params); strings.Join(names, ",") != "form,target" {
		t.Fatalf("engine got parameters %v, want form,target", names)
	}

	// An endpoint-level job (no injection point) still sees the whole endpoint.
	_, params, _, err = resolveJobTarget(ctx, env.st, env.job(domain.JobTarget{EndpointID: ep.ID}))
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 6 {
		t.Fatalf("endpoint-level job got %d parameters, want all 6", len(params))
	}
}

// TestFormInjectionJobSendsOnlyItsOwnFormFields runs a real reflection job
// against a server that records what it receives: neither the baseline nor the
// mutated request may carry another form's fields.
func TestFormInjectionJobSendsOnlyItsOwnFormFields(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ctx := context.Background()
	ep := env.endpoint(srv.URL+"/commandi.php", domain.MethodPOST)
	var focus *domain.Parameter
	for _, p := range formParams(env.scanID, ep.ID) {
		if err := env.st.Parameters().Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		if p.Name == "target" {
			focus = p
		}
	}
	job := env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: env.injection(ep, focus).ID})
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{AllowStateChanging: true}).Handle(ctx, job); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("expected baseline + mutated request, got %d: %q", len(bodies), bodies)
	}
	var sawBaseline, sawMarker bool
	for _, b := range bodies {
		for _, foreign := range []string{"security_level=", "form_security_level=", "bug=", "form_bug="} {
			if strings.Contains(b, foreign) {
				t.Fatalf("request carried another form's field %q: %q", foreign, b)
			}
		}
		if !strings.Contains(b, "form=submit") {
			t.Fatalf("request lost its own submit button: %q", b)
		}
		switch {
		case b == "form=submit&target=127.0.0.1":
			sawBaseline = true
		case strings.HasPrefix(b, "form=submit&target=ind"):
			sawMarker = true
		}
	}
	if !sawBaseline || !sawMarker {
		t.Fatalf("bodies missing the focused form's baseline/mutated shape: %q", bodies)
	}
}

// TestCurrentFormValuesPrefersTheFocusedFormGroup: a rotating token is refreshed
// from the form the focused parameter belongs to, not from whichever form the
// parser saw last.
func TestCurrentFormValuesPrefersTheFocusedFormGroup(t *testing.T) {
	body := `<html><body>
<form action="/commandi.php" method="POST">
  <input type="hidden" name="token" value="token-for-target-form">
  <input name="target" value="">
  <button name="form" value="submit"></button>
</form>
<form action="/commandi.php" method="POST">
  <input type="hidden" name="token" value="token-for-security-form">
  <select name="security_level"></select>
  <button name="form_security_level" value="submit"></button>
</form>
</body></html>`

	forms := tokensByGroup(t, body)
	if v := currentFormValues(body, forms[0]); v["token"] != "token-for-target-form" {
		t.Fatalf("focused form's token = %q, want token-for-target-form (%v)", v["token"], v)
	}
	if v := currentFormValues(body, forms[1]); v["token"] != "token-for-security-form" {
		t.Fatalf("second form's token = %q, want token-for-security-form", v["token"])
	}
	// No group at all (every pre-existing scan): unchanged flattening behaviour.
	if v := currentFormValues(body, ""); v["token"] != "token-for-security-form" {
		t.Fatalf("group-less flatten = %q, want last form's token", v["token"])
	}
	// A group that is not on this page falls back instead of dropping the
	// refresh entirely; the field is identified by name either way.
	if v := currentFormValues(body, "fg:not-on-this-page"); v["token"] == "" {
		t.Fatal("unknown group lost the token refresh instead of falling back")
	}
}

// tokensByGroup returns the group keys of the page's forms, in document order,
// so the test never hard-codes how the key is derived.
func tokensByGroup(t *testing.T, body string) []string {
	t.Helper()
	var out []string
	for _, f := range discovery.ExtractForms(body) {
		out = append(out, f.Group)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 form groups, got %d", len(out))
	}
	return out
}
