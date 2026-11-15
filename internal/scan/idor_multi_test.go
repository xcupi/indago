package scan

// Two-account differential IDOR helper tests.
//
// The mandate here is the NEGATIVE controls: a resource that is public, a
// second account that is denied, a login page, a per-account document and a
// same-template/different-principal page must all stay unconfirmed, because the
// helper's only claim is "User B was served User A's object". The positive
// cases pin the two independent confirm signals (A's principal named in B's
// document; the same document served to B's session), the request bound, and
// the credential isolation between legs.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
)

// multiAccountRecord is one request as it reached the test server.
type multiAccountRecord struct {
	Method        string
	Path          string
	Cookie        string
	Authorization string
	BodyBytes     int64
}

type multiAccountRecorder struct {
	mu   sync.Mutex
	reqs []multiAccountRecord
}

func (rec *multiAccountRecorder) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.reqs = append(rec.reqs, multiAccountRecord{
			Method:        r.Method,
			Path:          r.URL.RequestURI(),
			Cookie:        r.Header.Get("Cookie"),
			Authorization: r.Header.Get("Authorization"),
			BodyBytes:     r.ContentLength,
		})
		rec.mu.Unlock()
		next(w, r)
	}
}

func (rec *multiAccountRecorder) all() []multiAccountRecord {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]multiAccountRecord(nil), rec.reqs...)
}

func (rec *multiAccountRecorder) count() int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return len(rec.reqs)
}

// multiAccountPrincipal resolves the account a request claims to be, from the
// session cookie or the bearer token — the two carriers the helper accepts.
func multiAccountPrincipal(r *http.Request) string {
	if c, err := r.Cookie("session"); err == nil && c.Value != "" {
		return c.Value
	}
	const bearer = "Bearer "
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, bearer) {
		return strings.TrimPrefix(auth, bearer)
	}
	return ""
}

// multiAccountBoilerplate is the shared body of the fixture page: identical for
// every account, so a same-template/different-principal page still scores high
// on content similarity. That is exactly the false positive the identity guard
// has to catch.
func multiAccountBoilerplate() []string {
	return []string{
		"Billing reference: INV-2026-0001",
		"Plan: Business",
		"Seats: 12",
		"Region: eu-west-1",
		"Support tier: Priority",
		"Two-factor authentication: enabled",
		"Password rotation: 90 days",
		"Notification email: enabled",
		"Notification sms: disabled",
		"API access: enabled",
		"Audit log retention: 400 days",
		"Single sign-on: not configured",
		"Data residency: europe",
		"Export format: csv",
		"Timezone: UTC",
		"Language: en-GB",
		"Currency: EUR",
		"Invoice delivery: monthly",
		"Payment method: card ending 4242",
		"Next renewal: 2026-12-01",
		"Trial: no",
		"Contract: annual",
		"Discount: none",
		"Owner: procurement",
		"Cost centre: CC-88",
		"Purchase order: required",
		"Onboarding: complete",
		"Health check: ok",
		"Status: active",
		"Last reviewed: 2026-02-01",
	}
}

// multiAccountDocument is a realistic account page: identity-labelled text plus
// the shared boilerplate above.
func multiAccountDocument(principal string) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html>\n<head><title>Account</title></head>\n<body>\n")
	b.WriteString("<h1>Account settings</h1>\n")
	fmt.Fprintf(&b, "<p>Username: %s</p>\n", principal)
	fmt.Fprintf(&b, "<p>Email: %s@example.test</p>\n", principal)
	for _, line := range multiAccountBoilerplate() {
		fmt.Fprintf(&b, "<p>%s</p>\n", line)
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// multiAccountInvoice is a plain document with NO identity fields: the only
// signal available is that the content itself is the same.
func multiAccountInvoice(reference string) string {
	return `{"invoice":"` + reference + `","amount":"42.00","currency":"EUR","issued":"2026-02-01",` +
		`"status":"paid","line_items":[{"sku":"A-1","qty":1},{"sku":"B-2","qty":3}],` +
		`"terms":"net 30","note":"thank you for your business"}`
}

func newMultiAccountTestExecutor(t *testing.T) *MultiAccountExecutor {
	t.Helper()
	eng, err := httpengine.New(httpengine.DefaultConfig())
	if err != nil {
		t.Fatalf("httpengine.New: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewMultiAccountExecutor(eng, MultiAccountConfig{RequestTimeout: 5 * time.Second}, log)
}

func multiAccountCookie(value string) MultiAccountSubject {
	return MultiAccountSubject{Label: value, Cookies: []*http.Cookie{{Name: "session", Value: value}}}
}

func runMultiAccountProbe(t *testing.T, probe MultiAccountProbe) MultiAccountResult {
	t.Helper()
	res, err := newMultiAccountTestExecutor(t).Run(context.Background(), probe)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// TestIDORMultiConfirmsCrossAccountExposure is the positive case: User A's
// cookie sees A's page, User B's bearer token is served the SAME page, and the
// unauthenticated control is refused.
func TestIDORMultiConfirmsCrossAccountExposure(t *testing.T) {
	rec := &multiAccountRecorder{}
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch multiAccountPrincipal(r) {
		case "alice":
			fmt.Fprint(w, doc)
		case "bob":
			// The vulnerability: the object is selected by the URL, not by the
			// session, so Bob is served Alice's page.
			fmt.Fprint(w, doc)
		default:
			http.Error(w, "authentication required", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  MultiAccountSubject{Label: "bob", Headers: map[string]string{"Authorization": "Bearer bob"}},
	})

	if res.Outcome != MultiAccountConfirmed {
		t.Fatalf("outcome = %q, want confirmed (reason: %s)", res.Outcome, res.Reason)
	}
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed", res.Verdict)
	}
	if res.Requests != maxMultiAccountReadsPerProbe {
		t.Fatalf("requests = %d, want %d", res.Requests, maxMultiAccountReadsPerProbe)
	}
	if got := len(res.EvidencePairs()); got != 3 {
		t.Fatalf("evidence pairs = %d, want 3 (A, B, anonymous)", got)
	}
	if !res.Signals.NamesUserA {
		t.Fatalf("the confirming signal should be A's principal named in B's document: %+v", res.Signals)
	}
	if res.Signals.PubliclyReadable {
		t.Fatalf("the anonymous control was denied, so the resource is not public: %+v", res.Signals)
	}
	for _, want := range []string{"User A's principal", "username=alice"} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("reason %q does not explain %q", res.Reason, want)
		}
	}
	for _, rec := range rec.all() {
		if rec.Method != http.MethodGet {
			t.Errorf("unexpected method %s: the differential is read-only", rec.Method)
		}
		if rec.BodyBytes != 0 {
			t.Errorf("request %s carried a %d-byte body", rec.Path, rec.BodyBytes)
		}
	}
}

// TestIDORMultiConfirmsSameDocumentWithoutIdentityFields covers the second
// confirm signal: a plain document that names nobody, served verbatim to User
// B's session while the anonymous control is refused.
func TestIDORMultiConfirmsSameDocumentWithoutIdentityFields(t *testing.T) {
	doc := multiAccountInvoice("INV-2026-0001")
	if !idor.ExtractIdentity([]byte(doc)).Empty() {
		t.Fatalf("the fixture must carry no identity fields: %v", idor.ExtractIdentity([]byte(doc)).Fields)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch multiAccountPrincipal(r) {
		case "alice", "bob":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, doc)
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/api/invoices/1",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountConfirmed {
		t.Fatalf("outcome = %q, want confirmed (reason: %s)", res.Outcome, res.Reason)
	}
	if res.Signals.NamesUserA {
		t.Fatalf("the document names nobody, so the identity signal cannot be what confirmed: %+v", res.Signals)
	}
	if res.Signals.ABContentSimilarity != 1 {
		t.Fatalf("identical documents should score 1.0, got %v", res.Signals.ABContentSimilarity)
	}
	if !strings.Contains(res.Reason, "same document") {
		t.Fatalf("reason = %q, want the content-similarity explanation", res.Reason)
	}
}

// TestIDORMultiConfirmsWithSuppliedBaseline proves the caller can hand in User
// A's already-observed response: the probe then sends only two requests (B and
// the anonymous control).
func TestIDORMultiConfirmsWithSuppliedBaseline(t *testing.T) {
	rec := &multiAccountRecorder{}
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(rec.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if multiAccountPrincipal(r) == "bob" {
			fmt.Fprint(w, doc)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method:    domain.MethodGET,
		URL:       srv.URL + "/account/settings",
		UserB:     multiAccountCookie("bob"),
		BaselineA: &MultiAccountBaseline{Status: 200, Body: []byte(doc), FinalURL: srv.URL + "/account/settings"},
	})
	if res.Outcome != MultiAccountConfirmed {
		t.Fatalf("outcome = %q, want confirmed (reason: %s)", res.Outcome, res.Reason)
	}
	if res.Requests != 2 {
		t.Fatalf("requests = %d, want 2 with a supplied baseline", res.Requests)
	}
	if res.Signals.BaselineSource != multiAccountBaselineSup {
		t.Fatalf("baseline source = %q, want %q", res.Signals.BaselineSource, multiAccountBaselineSup)
	}
	if got := rec.count(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

// TestIDORMultiRejectsWhenUserBIsDenied is the primary negative control.
func TestIDORMultiRejectsWhenUserBIsDenied(t *testing.T) {
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch multiAccountPrincipal(r) {
		case "alice":
			fmt.Fprint(w, doc)
		case "bob":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountRejected {
		t.Fatalf("outcome = %q, want rejected (reason: %s)", res.Outcome, res.Reason)
	}
	if !res.Signals.BDenied {
		t.Fatalf("signals should record the denial: %+v", res.Signals)
	}
	if !strings.Contains(res.Reason, "403") {
		t.Fatalf("reason = %q, want the status code", res.Reason)
	}
}

// TestIDORMultiRejectsLoginPageForUserB: a login page means B's session never
// reached the object, which is a denial, not an exposure.
func TestIDORMultiRejectsLoginPageForUserB(t *testing.T) {
	doc := multiAccountDocument("alice")
	login := `<!doctype html><html><body><h1>Sign in</h1><form method="post" action="/login">` +
		`<input type="text" name="username"><input type="password" name="password">` +
		`<button>Sign in</button></form></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if multiAccountPrincipal(r) == "alice" {
			fmt.Fprint(w, doc)
			return
		}
		fmt.Fprint(w, login)
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountRejected {
		t.Fatalf("outcome = %q, want rejected (reason: %s)", res.Outcome, res.Reason)
	}
	if !res.Signals.BLoginPage {
		t.Fatalf("signals should record the login page: %+v", res.Signals)
	}
}

// TestIDORMultiNeverConfirmsPublicResource: when the unauthenticated control
// also receives the document, there is no account boundary to break. The
// helper must not claim a cross-account exposure.
func TestIDORMultiNeverConfirmsPublicResource(t *testing.T) {
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, doc) // every caller, with or without a session
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountInconclusive {
		t.Fatalf("outcome = %q, want inconclusive (reason: %s)", res.Outcome, res.Reason)
	}
	if res.Verdict == domain.VerdictConfirmed {
		t.Fatal("a public resource must never be reported as a cross-account exposure")
	}
	if !res.Signals.PubliclyReadable {
		t.Fatalf("signals should record that the control also read it: %+v", res.Signals)
	}
	if !strings.Contains(res.Reason, "publicly readable") {
		t.Fatalf("reason = %q, want the public-resource explanation", res.Reason)
	}
}

// TestIDORMultiRejectsPerAccountDocument: User B is served its OWN page (the
// account boundary working). High content similarity must not confirm it,
// because the identities differ.
func TestIDORMultiRejectsPerAccountDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch multiAccountPrincipal(r) {
		case "alice":
			fmt.Fprint(w, multiAccountDocument("alice"))
		case "bob":
			fmt.Fprint(w, multiAccountDocument("bob"))
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountRejected {
		t.Fatalf("outcome = %q, want rejected (reason: %s)", res.Outcome, res.Reason)
	}
	if !res.Signals.IdentityConflict {
		t.Fatalf("signals should record the identity conflict: %+v", res.Signals)
	}
	if res.Signals.ABContentSimilarity < 0.8 {
		t.Fatalf("the same template should still score >= 0.8 (got %v) so the identity guard, not the score, is what rejected it",
			res.Signals.ABContentSimilarity)
	}
	t.Logf("similarity=%.2f namesUserA=%v identityConflict=%v", res.Signals.ABContentSimilarity, res.Signals.NamesUserA, res.Signals.IdentityConflict)
}

// TestIDORMultiRejectsSameDocumentDifferentPrincipal is the sharpest negative
// control: the bodies are essentially identical (same template), only the
// identity differs. Confirming here would be the classic false positive.
func TestIDORMultiRejectsSameDocumentDifferentPrincipal(t *testing.T) {
	a := multiAccountDocument("alice")
	b := strings.ReplaceAll(strings.ReplaceAll(a, "alice", "bob"), "alice@example.test", "bob@example.test")
	anon := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch multiAccountPrincipal(r) {
		case "alice":
			fmt.Fprint(w, a)
		case "bob":
			fmt.Fprint(w, b)
		default:
			anon++
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountRejected {
		t.Fatalf("outcome = %q, want rejected (reason: %s)", res.Outcome, res.Reason)
	}
	if res.Signals.ABContentSimilarity < 0.8 {
		t.Fatalf("similarity %v: the fixture must be above the threshold to prove the identity guard did the rejecting",
			res.Signals.ABContentSimilarity)
	}
	if res.Signals.NamesUserA {
		t.Fatalf("B's document does not name A's principal: %+v", res.Signals)
	}
	t.Logf("similarity=%.2f identityConflict=%v", res.Signals.ABContentSimilarity, res.Signals.IdentityConflict)
	if anon != 1 {
		t.Fatalf("the anonymous control should be requested exactly once, got %d", anon)
	}
}

// TestIDORMultiConfirmsWhenControlSeesOnlyAGenericPage guards the other side
// of the public-resource rule: a control that receives a DIFFERENT, generic
// public page must not mask a real cross-account exposure.
func TestIDORMultiConfirmsWhenControlSeesOnlyAGenericPage(t *testing.T) {
	doc := multiAccountDocument("alice")
	landing := "<!doctype html><html><body>" +
		"<h1>Welcome to the customer portal</h1>" +
		"<p>Sign in to manage your subscription, invoices and support tickets.</p>" +
		"<p>New here? Create an account in under a minute.</p>" +
		"<p>This marketing page is served to every visitor before authentication.</p>" +
		"</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch multiAccountPrincipal(r) {
		case "alice", "bob":
			fmt.Fprint(w, doc)
		default:
			fmt.Fprint(w, landing)
		}
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountConfirmed {
		t.Fatalf("outcome = %q, want confirmed: the control saw a different public page (reason: %s)", res.Outcome, res.Reason)
	}
	if res.Signals.PubliclyReadable {
		t.Fatalf("the control did not receive A's document: %+v", res.Signals)
	}
}

// TestIDORMultiNeverConfirmsLeakInAnonymousRedirectBody: a redirect BODY that
// carries A's document is leaked to an unauthenticated caller too, so it is not
// evidence that one account can read another's — the control must win.
func TestIDORMultiNeverConfirmsLeakInAnonymousRedirectBody(t *testing.T) {
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if multiAccountPrincipal(r) != "" {
			fmt.Fprint(w, doc)
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		fmt.Fprint(w, doc) // the leak: the object rides along in the 302 body
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountInconclusive {
		t.Fatalf("outcome = %q, want inconclusive (reason: %s)", res.Outcome, res.Reason)
	}
	if !res.Signals.PubliclyReadable {
		t.Fatalf("the anonymous redirect body carried the document, so the resource is public: %+v", res.Signals)
	}
}

// TestIDORMultiRejectsStateChangingMethod: a POST must be refused BEFORE any
// request, whatever the caller asks for.
func TestIDORMultiRejectsStateChangingMethod(t *testing.T) {
	rec := &multiAccountRecorder{}
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()

	for _, method := range []domain.HTTPMethod{domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH, domain.MethodDELETE} {
		res, err := newMultiAccountTestExecutor(t).Run(context.Background(), MultiAccountProbe{
			Method: method,
			URL:    srv.URL + "/account/settings",
			UserA:  multiAccountCookie("alice"),
			UserB:  multiAccountCookie("bob"),
		})
		if err != nil {
			t.Fatalf("%s: Run returned an error: %v", method, err)
		}
		if res.Outcome != MultiAccountSkipped {
			t.Fatalf("%s: outcome = %q, want skipped", method, res.Outcome)
		}
		if res.Requests != 0 {
			t.Fatalf("%s: %d requests were sent for a state-changing method", method, res.Requests)
		}
		if !strings.Contains(res.Reason, "state-changing") {
			t.Errorf("%s: reason = %q", method, res.Reason)
		}
	}
	if rec.count() != 0 {
		t.Fatalf("the server saw %d requests; a skipped probe must send none", rec.count())
	}
}

// TestIDORMultiRequiresSecondAccountCredential: without User B there is no
// differential, so nothing is sent.
func TestIDORMultiRequiresSecondAccountCredential(t *testing.T) {
	rec := &multiAccountRecorder{}
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  MultiAccountSubject{Label: "bob"},
	})
	if res.Outcome != MultiAccountSkipped || rec.count() != 0 {
		t.Fatalf("outcome = %q, requests = %d; want skipped with no request", res.Outcome, rec.count())
	}
	if !strings.Contains(res.Reason, "User B has no session cookie") {
		t.Fatalf("reason = %q", res.Reason)
	}
}

// TestIDORMultiRequiresBaselineOrUserACredential: with neither a baseline nor
// User A's credential, there is nothing to compare against.
func TestIDORMultiRequiresBaselineOrUserACredential(t *testing.T) {
	rec := &multiAccountRecorder{}
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountSkipped || rec.count() != 0 {
		t.Fatalf("outcome = %q, requests = %d; want skipped with no request", res.Outcome, rec.count())
	}
}

// TestIDORMultiRefusesRawCookieHeader: a Cookie supplied as a raw header would
// bypass the per-leg isolation, so it is refused before any request.
func TestIDORMultiRefusesRawCookieHeader(t *testing.T) {
	rec := &multiAccountRecorder{}
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  MultiAccountSubject{Headers: map[string]string{"Cookie": "session=bob"}},
	})
	if res.Outcome != MultiAccountSkipped || rec.count() != 0 {
		t.Fatalf("outcome = %q, requests = %d; want skipped with no request", res.Outcome, rec.count())
	}
	if !strings.Contains(res.Reason, "MultiAccountSubject.Cookies") {
		t.Fatalf("reason = %q, want it to point at the Cookies field", res.Reason)
	}
}

// TestIDORMultiIsolatesCredentialsPerLeg is the safety property that makes the
// comparison meaningful: each leg carries exactly its own credential and no
// ambient cookie state.
func TestIDORMultiIsolatesCredentialsPerLeg(t *testing.T) {
	rec := &multiAccountRecorder{}
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
		if p := multiAccountPrincipal(r); p != "" {
			fmt.Fprint(w, doc)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB: MultiAccountSubject{Label: "bob", Cookies: []*http.Cookie{{Name: "session", Value: "bob"}},
			Headers: map[string]string{"Authorization": "Bearer bob"}},
	})
	if res.Outcome != MultiAccountConfirmed {
		t.Fatalf("outcome = %q, want confirmed (reason: %s)", res.Outcome, res.Reason)
	}
	reqs := rec.all()
	if len(reqs) != 3 {
		t.Fatalf("server saw %d requests, want 3", len(reqs))
	}
	if reqs[0].Cookie != "session=alice" || reqs[0].Authorization != "" {
		t.Fatalf("leg A carried %q / %q; it must carry only A's cookie", reqs[0].Cookie, reqs[0].Authorization)
	}
	if reqs[1].Cookie != "session=bob" || reqs[1].Authorization != "Bearer bob" {
		t.Fatalf("leg B carried %q / %q; it must carry only B's credential", reqs[1].Cookie, reqs[1].Authorization)
	}
	if reqs[2].Cookie != "" || reqs[2].Authorization != "" {
		t.Fatalf("the anonymous control carried %q / %q; it must carry no credential", reqs[2].Cookie, reqs[2].Authorization)
	}
}

// TestIDORMultiNeverSendsBodyOrFollowsRedirects: one leg = one read = one
// response, and no request ever carries a body.
func TestIDORMultiNeverSendsBodyOrFollowsRedirects(t *testing.T) {
	rec := &multiAccountRecorder{}
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
		switch multiAccountPrincipal(r) {
		case "alice":
			fmt.Fprint(w, doc)
		case "bob":
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountRejected {
		t.Fatalf("outcome = %q, want rejected (reason: %s)", res.Outcome, res.Reason)
	}
	if !res.Signals.BRedirected {
		t.Fatalf("signals should record the redirect: %+v", res.Signals)
	}
	reqs := rec.all()
	if len(reqs) != 3 {
		t.Fatalf("server saw %d requests, want exactly 3 (no redirect follow, no retry)", len(reqs))
	}
	for _, r := range reqs {
		if r.Path == "/login" {
			t.Fatalf("the redirect target was requested: %+v", reqs)
		}
		if r.BodyBytes != 0 {
			t.Fatalf("%s carried a body", r.Path)
		}
	}
}

// TestIDORMultiHeadCannotConfirm: HEAD is an allowed read but carries no body,
// so the helper states the limitation instead of guessing.
func TestIDORMultiHeadCannotConfirm(t *testing.T) {
	rec := &multiAccountRecorder{}
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, doc)
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodHEAD,
		URL:    srv.URL + "/account/settings",
		UserA:  multiAccountCookie("alice"),
		UserB:  multiAccountCookie("bob"),
	})
	if res.Outcome != MultiAccountInconclusive {
		t.Fatalf("outcome = %q, want inconclusive (reason: %s)", res.Outcome, res.Reason)
	}
	if !strings.Contains(res.Reason, "HEAD") {
		t.Fatalf("reason = %q, want the HEAD limitation", res.Reason)
	}
	for _, r := range rec.all() {
		if r.Method != http.MethodHead {
			t.Fatalf("a HEAD probe sent %s", r.Method)
		}
	}
}

// TestIDORMultiTransportErrorIsInconclusive: a failed leg is an observation,
// never a panic and never a confirmation.
func TestIDORMultiTransportErrorIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // every later request is refused

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method:    domain.MethodGET,
		URL:       url + "/account/settings",
		UserB:     multiAccountCookie("bob"),
		BaselineA: &MultiAccountBaseline{Status: 200, Body: []byte(multiAccountDocument("alice"))},
	})
	if res.Outcome != MultiAccountInconclusive {
		t.Fatalf("outcome = %q, want inconclusive (reason: %s)", res.Outcome, res.Reason)
	}
	if !strings.Contains(res.Reason, "User B request failed") {
		t.Fatalf("reason = %q", res.Reason)
	}
}

// TestIDORMultiDetailOmitsCredentials: the detail blob is what a TestCase or a
// report carries, so it must hold no credential and no body content.
func TestIDORMultiDetailOmitsCredentials(t *testing.T) {
	doc := multiAccountDocument("alice")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := multiAccountPrincipal(r); p != "" {
			fmt.Fprint(w, doc)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	res := runMultiAccountProbe(t, MultiAccountProbe{
		Method: domain.MethodGET,
		URL:    srv.URL + "/account/settings",
		UserA:  MultiAccountSubject{Cookies: []*http.Cookie{{Name: "session", Value: "cookie-alice-secret"}}},
		UserB:  MultiAccountSubject{Headers: map[string]string{"Authorization": "Bearer bearer-bob-secret"}},
	})
	detail, err := res.DetailJSON()
	if err != nil {
		t.Fatalf("DetailJSON: %v", err)
	}
	for _, secret := range []string{"cookie-alice-secret", "bearer-bob-secret", "Username:", "Billing reference"} {
		if strings.Contains(string(detail), secret) {
			t.Errorf("detail leaked %q: %s", secret, detail)
		}
	}
	var decoded MultiAccountDetail
	if err := json.Unmarshal(detail, &decoded); err != nil {
		t.Fatalf("detail is not valid JSON: %v", err)
	}
	if len(decoded.Legs) != 3 {
		t.Fatalf("detail legs = %d, want 3", len(decoded.Legs))
	}
	for _, leg := range decoded.Legs {
		if leg.BodyBytes == 0 {
			t.Errorf("leg %s should record the body size", leg.Role)
		}
	}
	if decoded.Signals.AIdentity != "username=alice" {
		t.Errorf("detail should record the caller's identity, got %q", decoded.Signals.AIdentity)
	}
}

// TestIDORMultiSimilarityIsDeterministicAndSymmetric pins the content score
// itself: same input, same answer, and order does not matter.
func TestIDORMultiSimilarityIsDeterministicAndSymmetric(t *testing.T) {
	a := []byte(multiAccountDocument("alice"))
	b := []byte(multiAccountDocument("bob"))
	c := []byte(multiAccountInvoice("INV-1"))

	if score, ok := multiAccountSimilarity(a, a); !ok || score != 1 {
		t.Fatalf("identical bodies: score %v ok %v", score, ok)
	}
	ab, okAB := multiAccountSimilarity(a, b)
	ba, okBA := multiAccountSimilarity(b, a)
	if !okAB || !okBA || ab != ba {
		t.Fatalf("similarity is not symmetric: %v/%v vs %v/%v", ab, okAB, ba, okBA)
	}
	if ab < 0.8 {
		t.Fatalf("the same template should score >= 0.8, got %v", ab)
	}
	if ac, ok := multiAccountSimilarity(a, c); !ok || ac >= 0.5 {
		t.Fatalf("unrelated documents should score low, got %v (ok=%v)", ac, ok)
	}
	for i := 0; i < 10; i++ {
		if again, _ := multiAccountSimilarity(a, b); again != ab {
			t.Fatalf("iteration %d produced %v, want %v", i, again, ab)
		}
	}
	if _, ok := multiAccountSimilarity(nil, nil); ok {
		t.Fatal("two empty bodies are not comparable")
	}
	if _, ok := multiAccountSimilarity([]byte("x"), []byte("y")); ok {
		t.Fatal("two one-byte bodies are not comparable")
	}
}

// TestIDORMultiDecisionOrdering: the public-resource refusal must win over every
// confirm signal, including a document that names User A.
func TestIDORMultiDecisionOrdering(t *testing.T) {
	doc := multiAccountDocument("alice")
	dec := decideMultiAccount(multiAccountInput{
		Method:    domain.MethodGET,
		A:         multiAccountObserve(200, doc),
		B:         multiAccountObserve(200, doc),
		Anonymous: multiAccountObserve(200, doc),
		Threshold: 0.8,
	})
	if dec.Outcome != MultiAccountInconclusive {
		t.Fatalf("outcome = %q, want inconclusive: a public resource is not a cross-account exposure", dec.Outcome)
	}
	if !dec.Signals.PubliclyReadable {
		t.Fatalf("signals = %+v", dec.Signals)
	}

	// Same bodies, control denied: now it confirms.
	dec = decideMultiAccount(multiAccountInput{
		Method:    domain.MethodGET,
		A:         multiAccountObserve(200, doc),
		B:         multiAccountObserve(200, doc),
		Anonymous: multiAccountObserve(401, "unauthorized"),
		Threshold: 0.8,
	})
	if dec.Outcome != MultiAccountConfirmed {
		t.Fatalf("outcome = %q, want confirmed (reason: %s)", dec.Outcome, dec.Reason)
	}

	// An unusable baseline is never a reference.
	dec = decideMultiAccount(multiAccountInput{
		Method:    domain.MethodGET,
		A:         multiAccountObserve(500, doc),
		B:         multiAccountObserve(200, doc),
		Anonymous: multiAccountObserve(401, "unauthorized"),
		Threshold: 0.8,
	})
	if dec.Outcome != MultiAccountInconclusive {
		t.Fatalf("outcome = %q, want inconclusive for an unusable baseline", dec.Outcome)
	}

	// A denial page served with 200 for B is the boundary working.
	dec = decideMultiAccount(multiAccountInput{
		Method:    domain.MethodGET,
		A:         multiAccountObserve(200, doc),
		B:         multiAccountObserve(200, "<html><body><h1>Access denied</h1><p>You do not have permission to view this resource.</p></body></html>"),
		Anonymous: multiAccountObserve(401, "unauthorized"),
		Threshold: 0.8,
	})
	if dec.Outcome != MultiAccountRejected {
		t.Fatalf("outcome = %q, want rejected for a denial page", dec.Outcome)
	}
}

// multiAccountObserve mirrors observeMultiAccount for a synthetic response.
func multiAccountObserve(status int, body string) multiAccountObservation {
	raw := []byte(body)
	return multiAccountObservation{
		Status:   status,
		Body:     raw,
		Login:    idor.LooksLikeLoginPage(raw),
		Denial:   multiAccountLooksLikeDenial(raw),
		Identity: idor.ExtractIdentity(raw),
	}
}
