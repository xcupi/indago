package web_test

// Coverage for the X-Indago-Token header, the second accepted way to present
// the control API token. Authorization: Bearer stays supported (and is what the
// bundled UI and the CLI send); the extra header exists for callers whose
// Authorization header is already spoken for (a reverse proxy, another SDK).

import (
	"net/http"
	"strings"
	"testing"

	"github.com/indago/indago/internal/web"
)

func TestAPITokenAcceptedFromXIndagoTokenHeader(t *testing.T) {
	h, _ := newAuthServer(t)
	const wrong = "not-the-token-111111111111111111111111111111"

	cases := []struct {
		name   string
		method string
		target string
		header string // X-Indago-Token value; empty means the header is absent
		want   int
	}{
		{"correct bare token", "GET", "/api/projects", testAPIToken, http.StatusOK},
		{"wrong token", "GET", "/api/projects", wrong, http.StatusUnauthorized},
		{"empty value", "GET", "/api/projects", "", http.StatusUnauthorized},
		{"bearer prefix is not accepted in this header", "GET", "/api/projects", "Bearer " + testAPIToken, http.StatusUnauthorized},
		{"version route", "GET", "/api/version", testAPIToken, http.StatusOK},
		{"metrics route", "GET", "/metrics", testAPIToken, http.StatusOK},
		{"metrics without token", "GET", "/metrics", "", http.StatusUnauthorized},
	}
	for _, c := range cases {
		var headers map[string]string
		if c.header != "" {
			headers = map[string]string{web.TokenHeader: c.header}
		}
		rec := do(h, c.method, c.target, headers)
		if rec.Code != c.want {
			t.Errorf("%s: %s %s = %d, want %d", c.name, c.method, c.target, rec.Code, c.want)
		}
		if c.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: WWW-Authenticate = %q, want Bearer", c.name, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

// Either accepted header authorizes a request on its own: a valid value in one
// must not be invalidated by an unrelated (or wrong) value in the other.
func TestAPITokenEitherHeaderSuffices(t *testing.T) {
	h, _ := newAuthServer(t)
	const wrong = "not-the-token-222222222222222222222222222222"

	for name, headers := range map[string]map[string]string{
		"valid X-Indago-Token, wrong Authorization": {
			web.TokenHeader: testAPIToken,
			"Authorization": "Bearer " + wrong,
		},
		"valid Authorization, wrong X-Indago-Token": {
			"Authorization": "Bearer " + testAPIToken,
			web.TokenHeader: wrong,
		},
	} {
		if rec := do(h, "GET", "/api/projects", headers); rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", name, rec.Code)
		}
	}

	// A mutating request needs the CSRF header as before; the token header only
	// authenticates, it does not replace that.
	rec := do(h, "POST", "/api/projects", map[string]string{web.TokenHeader: testAPIToken})
	if rec.Code != http.StatusForbidden {
		t.Errorf("mutating request with token but no %s: status %d, want 403", web.ClientHeader, rec.Code)
	}
	rec = do(h, "POST", "/api/projects", map[string]string{
		web.TokenHeader:  testAPIToken,
		web.ClientHeader: "test",
		"Content-Type":   "application/json",
	})
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("valid X-Indago-Token rejected on POST: %d %s", rec.Code, rec.Body.String())
	}
}

// The 401 must never echo what the caller presented, whichever header it used.
func TestXIndagoTokenRejectionNeverEchoesThePresentedToken(t *testing.T) {
	h, logs := newAuthServer(t)
	const wrong = "wrong-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	rec := do(h, "GET", "/api/projects", map[string]string{web.TokenHeader: wrong})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), wrong) || strings.Contains(rec.Body.String(), testAPIToken) {
		t.Errorf("401 body echoes a token: %s", rec.Body.String())
	}
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if strings.Contains(v, wrong) || strings.Contains(v, testAPIToken) {
				t.Errorf("response header %s echoes a token: %q", k, v)
			}
		}
	}
	if strings.Contains(logs.String(), wrong) || strings.Contains(logs.String(), testAPIToken) {
		t.Errorf("server log contains a token:\n%s", logs.String())
	}
}

// Probes and the static UI stay open no matter which token machinery is
// configured: a kubelet has no token, and the SPA must load to ask for one.
func TestProbesAndUIOpenWithTokenConfigured(t *testing.T) {
	h, _ := newAuthServer(t)
	for _, path := range []string{"/healthz", "/readyz", "/", "/app.js"} {
		rec := do(h, "GET", path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s without a token: status %d, want 200", path, rec.Code)
		}
	}
}
