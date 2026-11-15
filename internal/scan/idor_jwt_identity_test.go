package scan

// Tests for the IDOR caller-identity baseline when it has more than one source:
// the session's own bearer-token claims (read offline) and several identity
// pages/APIs. The negative controls matter as much as the positive ones — an
// incomplete page must not stop the search, a complete one must, and a JWT is
// only used when the target itself cannot name the caller.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/idor"
)

func testJWT(claims string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
}

// identityBaselineCase returns the persisted identity-baseline TestCase.
func identityBaselineCase(t *testing.T, env *idorEnv) *domain.TestCase {
	t.Helper()
	var out []*domain.TestCase
	for _, tc := range env.cases() {
		if strings.HasPrefix(tc.Note, idorIdentityNote) {
			out = append(out, tc)
		}
	}
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 identity baseline test case, got %d", len(out))
	}
	return out[0]
}

// TestIDORIdentityFallsBackToJWTClaims: a JWT-only API (cRAPI is the real
// example) exposes the caller exclusively through token-protected endpoints, so
// every identity page 404s. The claims of the scan's OWN bearer token still name
// the caller, and that is enough to run the differential.
func TestIDORIdentityFallsBackToJWTClaims(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<h1>Not found</h1>`)
	})
	token := testJWT(`{"sub":"wiener","id":7,"email":"wiener@example.com"}`)
	eng := newScopedEngine(noFollowClient(t), openScope()).
		WithSessionAuthHeaders([]sessionAuthHeader{{Origin: srv.URL, Value: "Bearer " + token}})
	ep := env.endpoint(srv.URL+"/api/v1/orders?id=1", domain.MethodGET)

	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	ident, _ := ex.identity(context.Background(), env.scanID, ep)
	if ident == nil || ident.Identity.Empty() {
		t.Fatalf("JWT claims did not establish an identity: %+v", ident)
	}
	if ident.Source != identitySourceJWT {
		t.Fatalf("identity source = %q, want %q", ident.Source, identitySourceJWT)
	}
	if !ident.JWT {
		t.Fatal("a JWT-only baseline must record that its source was the token claims")
	}
	if got := ident.Identity.Values(idor.FieldEmail); len(got) != 1 || got[0] != "wiener@example.com" {
		t.Fatalf("email fields = %v, want wiener@example.com", got)
	}
	if got := ident.Identity.Values(idor.FieldUserID); len(got) != 1 || got[0] != "7" {
		t.Fatalf("user id fields = %v, want 7", got)
	}

	tc := identityBaselineCase(t, env)
	var d idorDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("decode identity detail: %v", err)
	}
	if d.IdentitySource != identitySourceJWT || !d.IdentityJWT {
		t.Fatalf("persisted identity source = %q jwt=%v, want %q true", d.IdentitySource, d.IdentityJWT, identitySourceJWT)
	}
	if len(d.IdentityEvidence) != 0 {
		t.Fatalf("a JWT-only baseline fetched no page, so it must carry no HTTP evidence: %v", d.IdentityEvidence)
	}
}

// TestIDORIdentityMergesPartialPageWithJWTClaims: /profile names the caller but
// omits the user id. The token claims supply it, and the merged baseline is
// complete — so the search stops there instead of falling back to the token
// alone or probing every remaining path.
func TestIDORIdentityMergesPartialPageWithJWTClaims(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/profile" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"email":"wiener@example.com"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<h1>Not found</h1>`)
	})
	token := testJWT(`{"id":7}`)
	eng := newScopedEngine(noFollowClient(t), openScope()).
		WithSessionAuthHeaders([]sessionAuthHeader{{Origin: srv.URL, Value: "Bearer " + token}})
	ep := env.endpoint(srv.URL+"/object?id=1", domain.MethodGET)

	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	ident, _ := ex.identity(context.Background(), env.scanID, ep)
	if ident == nil || ident.Identity.Empty() {
		t.Fatalf("identity was not established: %+v", ident)
	}
	if ident.Source != srv.URL+"/profile" {
		t.Fatalf("identity source = %q, want the page that named the caller", ident.Source)
	}
	if !ident.JWT {
		t.Fatal("the merged baseline must record that the token claims contributed")
	}
	if got := ident.Identity.Values(idor.FieldEmail); len(got) != 1 || got[0] != "wiener@example.com" {
		t.Fatalf("email fields = %v, want wiener@example.com", got)
	}
	if got := ident.Identity.Values(idor.FieldUserID); len(got) != 1 || got[0] != "7" {
		t.Fatalf("user id fields = %v, want the token's 7", got)
	}
	for _, req := range env.saw() {
		if req == "GET /account" {
			t.Fatal("a complete baseline must stop the identity search, but /account was still probed")
		}
	}
}

// TestIDORIdentityKeepsProbingIncompletePages: with no token at all, the first
// page yields only an email. The engine must keep probing and merge what the
// next page adds instead of returning a baseline the differential cannot use.
func TestIDORIdentityKeepsProbingIncompletePages(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/my-account":
			fmt.Fprint(w, `{"email":"wiener@example.com"}`)
		case "/profile":
			fmt.Fprint(w, `{"username":"wiener","user_id":"42"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	})
	ep := env.endpoint(srv.URL+"/object?id=1", domain.MethodGET)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	ident, _ := ex.identity(context.Background(), env.scanID, ep)
	if ident == nil || ident.Identity.Empty() {
		t.Fatalf("identity was not established: %+v", ident)
	}
	if ident.JWT {
		t.Fatal("no token was provided, so no JWT source may be recorded")
	}
	if ident.Source != srv.URL+"/my-account" {
		t.Fatalf("identity source = %q, want the first contributing page", ident.Source)
	}
	if got := ident.Identity.Values(idor.FieldEmail); len(got) != 1 || got[0] != "wiener@example.com" {
		t.Fatalf("email fields = %v", got)
	}
	if got := ident.Identity.Values(idor.FieldUsername); len(got) != 1 || got[0] != "wiener" {
		t.Fatalf("username fields = %v, want the second page's value", got)
	}
	if got := ident.Identity.Values(idor.FieldUserID); len(got) != 1 || got[0] != "42" {
		t.Fatalf("user id fields = %v, want the second page's value", got)
	}
	sawProfile := false
	for _, req := range env.saw() {
		if req == "GET /profile" {
			sawProfile = true
		}
		if req == "GET /account" {
			t.Fatal("the search must stop once the baseline is complete, but /account was probed")
		}
	}
	if !sawProfile {
		t.Fatalf("the incomplete first page must not stop the search; requests = %v", env.saw())
	}

	// Every page that contributed a field is stored as evidence: the merged
	// baseline has to be provable field by field.
	tc := identityBaselineCase(t, env)
	var d idorDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("decode identity detail: %v", err)
	}
	if len(d.IdentityEvidence) != 4 {
		t.Fatalf("identity evidence = %d blobs, want 4 (request+response for 2 pages)", len(d.IdentityEvidence))
	}
	var sawAccount, sawProfileEvidence bool
	for _, id := range d.IdentityEvidence {
		_, body := env.evidenceBlob(id)
		if strings.Contains(body, "GET /my-account") {
			sawAccount = true
		}
		if strings.Contains(body, "GET /profile") {
			sawProfileEvidence = true
		}
	}
	if !sawAccount || !sawProfileEvidence {
		t.Fatalf("both contributing pages need evidence (account=%v profile=%v)", sawAccount, sawProfileEvidence)
	}
}

// TestIDORIdentityCompleteFirstPageStopsProbing is the negative control for the
// multi-source search: a page that already carries a user id and a name must end
// the search immediately, so a large identity-path list can never turn into a
// gratuitous probe pass.
func TestIDORIdentityCompleteFirstPageStopsProbing(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/my-account" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"email":"wiener@example.com","user_id":"42"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	})
	ep := env.endpoint(srv.URL+"/object?id=1", domain.MethodGET)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	ident, _ := ex.identity(context.Background(), env.scanID, ep)
	if ident == nil || ident.Identity.Empty() {
		t.Fatalf("identity was not established: %+v", ident)
	}
	if got := env.saw(); len(got) != 1 || got[0] != "GET /my-account" {
		t.Fatalf("requests = %v, want exactly the one complete identity page", got)
	}
}
