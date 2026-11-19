package bounty

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestListProgramsFiltersAndCaches(t *testing.T) {
	var calls atomic.Int64
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		gotURL = r.URL.RawQuery
		if r.Header.Get("X-AUTH-TOKEN") != "" {
			t.Errorf("public listing must not send a token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[{"slug":"acme","title":"ACME","type":"bug-bounty","bounty":true}],"pagination":{"nb_results":1}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, func() string { return "" })
	q := Query{Search: "acme"}
	items, total, cached, err := c.ListPrograms(context.Background(), q, false)
	if err != nil || len(items) != 1 || cached || total != 1 {
		t.Fatalf("first call: items=%v cached=%v err=%v", items, cached, err)
	}
	for _, want := range []string{"filter%5Btype%5D%5B%5D=bug-bounty", "filter%5BscopeType%5D%5B%5D=web-application", "filter%5Bsearch%5D=acme"} {
		if !strings.Contains(gotURL, want) {
			t.Fatalf("query %q missing %q", gotURL, want)
		}
	}
	if _, _, cached, _ = c.ListPrograms(context.Background(), q, false); !cached {
		t.Fatal("second call should hit the cache")
	}
	if calls.Load() != 1 {
		t.Fatalf("server calls = %d, want 1", calls.Load())
	}
	if _, _, cached, _ = c.ListPrograms(context.Background(), q, true); cached {
		t.Fatal("refresh must bypass the cache")
	}
	if calls.Load() != 2 {
		t.Fatalf("server calls after refresh = %d, want 2", calls.Load())
	}
}

func TestScopesRequireToken(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", func() string { return "" })
	if _, err := c.Scopes(context.Background(), "acme"); err != ErrNoToken {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
}

func TestUnauthorizedIsRecognisable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, func() string { return "bad" })
	if _, err := c.Scopes(context.Background(), "acme"); err == nil || !strings.Contains(err.Error(), "rejected the token") {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenStoreRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(dir)
	if st.Configured() {
		t.Fatal("fresh store must be empty")
	}
	if err := st.Set("  tok-123  "); err != nil {
		t.Fatal(err)
	}
	if st.Token() != "tok-123" {
		t.Fatalf("token = %q", st.Token())
	}
	info, err := os.Stat(dir + "/yeswehack.token")
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token file mode = %o, want 600", perm)
	}
	if err := st.Clear(); err != nil {
		t.Fatal(err)
	}
	if st.Configured() {
		t.Fatal("token survived Clear")
	}
}

func TestExtractPublicScopesHandlesSeverityBlob(t *testing.T) {
	page := []byte(`<html>... "scopes":[{"scope":"https://www.jbl.com","scope_type":"web-application","scope_type_name":"Web application","asset_value":"MEDIUM","report_count":null},{"scope":"api.example.com","scope_type":"api","scope_type_name":"API","asset_value":"HIGH","report_count":null}], "x":1 ...</html>`)
	scopes, err := extractPublicScopes(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 || scopes[0].Scope != "https://www.jbl.com" || scopes[0].ScopeType != "web-application" {
		t.Fatalf("scopes = %+v", scopes)
	}
	if scopes[0].AssetValue != "MEDIUM" {
		t.Fatalf("asset_value should be preserved as-is: %+v", scopes[0])
	}
}

func TestCredentialKindAndExpiry(t *testing.T) {
	// header.payload.signature with exp=1900000000
	tok := "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5MDAwMDAwMDB9.sig"
	kind, exp := CredentialInfo(tok)
	if kind != "session" {
		t.Fatalf("kind = %q", kind)
	}
	if exp.Unix() != 1900000000 {
		t.Fatalf("exp = %v", exp)
	}
	if k := CredentialKind("pat-abc"); k != "pat" {
		t.Fatalf("pat kind = %q", k)
	}
}

func TestValidateSendsBearerForSessionToken(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		if r.URL.Path != "/programs/count" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"count":1}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, func() string { return "" })
	if err := c.Validate(context.Background(), "a.b.c"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "Bearer ") {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestDraftCreateUpdateNeverSubmits(t *testing.T) {
	var methods []string
	var paths []string
	var gotAuth string
	var gotBody DraftReport

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/programs/acme/reports" {
			t.Fatalf("submit endpoint /reports must never be called")
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":42,"title":"Reflected XSS","url":"https://yeswehack.com/programs/acme/drafts/42"}`))
			return
		}
		w.Write([]byte(`{"id":"42","title":"Reflected XSS v2","url":"https://yeswehack.com/programs/acme/drafts/42"}`))
	}))
	defer srv.Close()

	// Missing token must fail closed.
	noTok := NewClient(srv.URL, func() string { return "" })
	if _, err := noTok.CreateDraft(context.Background(), "acme", DraftReport{Title: "XSS"}); err != ErrNoToken {
		t.Fatalf("CreateDraft without token = %v, want ErrNoToken", err)
	}
	if _, err := noTok.UpdateDraft(context.Background(), "acme", "42", DraftReport{Title: "XSS"}); err != ErrNoToken {
		t.Fatalf("UpdateDraft without token = %v, want ErrNoToken", err)
	}

	c := NewClient(srv.URL, func() string { return "a.b.c" })
	created, err := c.CreateDraft(context.Background(), "acme", DraftReport{
		Title:               "Reflected XSS",
		BugType:             "Cross-Site Scripting (XSS)",
		EndPoint:            "https://app.acme.test/search",
		DescriptionMarkdown: "## Description\nTest",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.DraftID() != "42" {
		t.Fatalf("created DraftID = %q, want 42", created.DraftID())
	}
	if gotAuth != "Bearer a.b.c" {
		t.Fatalf("Authorization = %q", gotAuth)
	}

	updated, err := c.UpdateDraft(context.Background(), "acme", created.DraftID(), DraftReport{
		Title: "Reflected XSS v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.DraftID() != "42" || gotBody.Title != "Reflected XSS v2" {
		t.Fatalf("updated = %+v body = %+v", updated, gotBody)
	}

	if len(methods) != 2 || methods[0] != http.MethodPost || methods[1] != http.MethodPut {
		t.Fatalf("methods = %v, want [POST PUT]", methods)
	}
	if paths[0] != "/programs/acme/reports/draft" || paths[1] != "/programs/acme/reports/draft/42" {
		t.Fatalf("paths = %v", paths)
	}
}
