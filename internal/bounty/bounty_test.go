package bounty

import (
	"context"
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
