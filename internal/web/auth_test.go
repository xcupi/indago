package web_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

// testAPIToken is a dummy 50-character token for tests only.
const testAPIToken = "indago-test-token-9f2c7d41a8e6b305c1d9e2f7a4b8c6d0"

// newAuthServer returns a handler whose control API requires testAPIToken,
// plus the buffer its logger writes to (debug level, so every line is kept).
func newAuthServer(t *testing.T) (http.Handler, *bytes.Buffer) {
	t.Helper()
	st := memory.New()
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctrl := scan.NewController(st, queue.NewMemory(), log, "test", scan.Options{})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := web.NewServer(st, ctrl, "test", log, evStore, t.TempDir())
	if err := srv.SetAPIToken(testAPIToken); err != nil {
		t.Fatalf("SetAPIToken(valid token): %v", err)
	}
	return srv.Handler(), &logBuf
}

// do sends one request through h and returns the recorded response.
func do(h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAPITokenRequiredForAPIRoutes(t *testing.T) {
	h, _ := newAuthServer(t)
	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

	cases := []struct {
		name    string
		method  string
		target  string
		headers map[string]string
		want    int
	}{
		{"no header", "GET", "/api/projects", nil, http.StatusUnauthorized},
		{"wrong token", "GET", "/api/projects", bearer("not-the-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"), http.StatusUnauthorized},
		{"empty bearer", "GET", "/api/projects", bearer(""), http.StatusUnauthorized},
		{"correct token", "GET", "/api/projects", bearer(testAPIToken), http.StatusOK},
		{"version needs token too", "GET", "/api/version", nil, http.StatusUnauthorized},
		{"healthz open", "GET", "/healthz", nil, http.StatusOK},
		{"static UI open", "GET", "/", nil, http.StatusOK},
		{"static app.js open", "GET", "/app.js", nil, http.StatusOK},
		{"mutating without token is 401 even with CSRF header", "POST", "/api/projects",
			map[string]string{web.ClientHeader: "test"}, http.StatusUnauthorized},
	}
	for _, c := range cases {
		rec := do(h, c.method, c.target, c.headers)
		if rec.Code != c.want {
			t.Errorf("%s: %s %s = %d, want %d", c.name, c.method, c.target, rec.Code, c.want)
		}
	}

	// A correct token authorizes a mutating request too (CSRF header still required).
	rec := do(h, "POST", "/api/projects", map[string]string{
		"Authorization":  "Bearer " + testAPIToken,
		web.ClientHeader: "test",
	})
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("correct token rejected on POST: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAPITokenNotAcceptedFromQueryOrCookie(t *testing.T) {
	h, _ := newAuthServer(t)
	for name, c := range map[string]struct {
		target  string
		headers map[string]string
	}{
		"query token":        {"/api/projects?token=" + testAPIToken, nil},
		"query access_token": {"/api/projects?access_token=" + testAPIToken, nil},
		"cookie":             {"/api/projects", map[string]string{"Cookie": "indago_token=" + testAPIToken}},
		"generic cookie":     {"/api/projects", map[string]string{"Cookie": "token=" + testAPIToken}},
		"basic auth scheme":  {"/api/projects", map[string]string{"Authorization": "Basic " + testAPIToken}},
		"bare token header":  {"/api/projects", map[string]string{"Authorization": testAPIToken}},
	} {
		rec := do(h, "GET", c.target, c.headers)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401 (token must come only from the Bearer header)", name, rec.Code)
		}
	}
}

func TestAPIUnauthorizedResponseNeverEchoesToken(t *testing.T) {
	h, logs := newAuthServer(t)
	const wrong = "wrong-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, headers := range []map[string]string{
		{},
		{"Authorization": "Bearer " + wrong},
		{"Authorization": "Bearer " + testAPIToken[:20]},
	} {
		rec := do(h, "GET", "/api/projects?token="+testAPIToken, headers)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Errorf("WWW-Authenticate = %q, want %q", got, "Bearer")
		}
		if strings.Contains(rec.Body.String(), testAPIToken) || strings.Contains(rec.Body.String(), wrong) {
			t.Errorf("401 body echoes a token: %s", rec.Body.String())
		}
		for k, vs := range rec.Header() {
			for _, v := range vs {
				if strings.Contains(v, testAPIToken) || strings.Contains(v, wrong) {
					t.Errorf("response header %s echoes a token: %q", k, v)
				}
			}
		}
	}
	if strings.Contains(logs.String(), testAPIToken) {
		t.Errorf("server log contains the API token:\n%s", logs.String())
	}
}

func TestNoTokenConfiguredKeepsAPIOpen(t *testing.T) {
	h := newServer(t) // never calls SetAPIToken
	if rec := do(h, "GET", "/api/projects", nil); rec.Code != http.StatusOK {
		t.Fatalf("unconfigured server: GET /api/projects = %d, want 200 (loopback behaviour unchanged)", rec.Code)
	}
}

func TestSetAPITokenRefusesShortOrMalformedTokens(t *testing.T) {
	newSrv := func() *web.Server {
		st := memory.New()
		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		ctrl := scan.NewController(st, queue.NewMemory(), log, "test", scan.Options{})
		t.Cleanup(ctrl.Shutdown)
		return web.NewServer(st, ctrl, "test", log, nil, "")
	}
	for name, tok := range map[string]string{
		"short":        "s3cr3t-short",
		"31 chars":     strings.Repeat("a", 31),
		"with space":   strings.Repeat("a", 20) + " " + strings.Repeat("b", 20),
		"with newline": strings.Repeat("a", 40) + "\n",
	} {
		err := newSrv().SetAPIToken(tok)
		if err == nil {
			t.Errorf("%s: SetAPIToken accepted a malformed token", name)
			continue
		}
		if strings.Contains(err.Error(), tok) {
			t.Errorf("%s: error text contains the token: %v", name, err)
		}
	}
	if err := newSrv().SetAPIToken(strings.Repeat("a", 32)); err != nil {
		t.Errorf("32-character token refused: %v", err)
	}
	if err := newSrv().SetAPIToken(""); err != nil {
		t.Errorf("empty token must mean auth disabled, got error: %v", err)
	}
}
