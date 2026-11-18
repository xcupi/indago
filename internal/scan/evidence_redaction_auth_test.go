package scan

import (
	"net/http"
	"strings"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func TestDumpRequestRedactsAuthorization(t *testing.T) {
	req := &httpengine.CapturedRequest{
		Method: "GET",
		URL:    "https://app.example.test/api",
		Headers: http.Header{
			"Authorization":       {"Bearer real-secret-token"},
			"Proxy-Authorization": {"Basic proxy-secret"},
			"X-Test":              {"kept"},
		},
	}
	dump := string(dumpRequest(req))
	if strings.Contains(dump, "real-secret-token") || strings.Contains(dump, "proxy-secret") {
		t.Fatalf("credential leaked into evidence:\n%s", dump)
	}
	if !strings.Contains(dump, "Authorization: "+redactedCookieValue) || !strings.Contains(dump, "X-Test: kept") {
		t.Fatalf("unexpected redacted dump:\n%s", dump)
	}
	if req.Headers.Get("Authorization") != "Bearer real-secret-token" {
		t.Fatal("dumpRequest mutated the captured request")
	}
}

// A Cookie header is a credential exactly like Authorization. The evidence must
// keep the cookie NAMES (that is what makes it reproducible) and replace the
// values, without mutating the captured request.
func TestDumpRequestRedactsCookieValues(t *testing.T) {
	req := &httpengine.CapturedRequest{
		Method: "GET",
		URL:    "https://app.example.test/api",
		Headers: http.Header{
			"Cookie": {"sid=super-secret; theme=dark"},
			"X-Test": {"kept"},
		},
		Body: []byte("safe-body"),
	}
	dump := string(dumpRequest(req))
	for _, secret := range []string{"super-secret", "theme=dark"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("cookie value %q leaked into evidence:\n%s", secret, dump)
		}
	}
	wantCookie := "Cookie: sid=" + redactedCookieValue + "; theme=" + redactedCookieValue
	if !strings.Contains(dump, wantCookie) {
		t.Fatalf("cookie names/marker missing from evidence:\n%s", dump)
	}
	if !strings.Contains(dump, "X-Test: kept") || !strings.Contains(dump, "safe-body") {
		t.Fatalf("safe evidence was lost:\n%s", dump)
	}
	if req.Headers.Get("Cookie") != "sid=super-secret; theme=dark" {
		t.Fatal("dumpRequest mutated the captured request")
	}
}

// Set-Cookie carries the same secret on the response side; response evidence
// keeps the name and attributes but not the value.
func TestDumpResponseRedactsSetCookieValues(t *testing.T) {
	resp := &httpengine.Response{
		Status:     200,
		StatusText: "200 OK",
		Headers: http.Header{
			"Set-Cookie":   {"sid=super-secret; Path=/; HttpOnly", "theme=dark; Path=/"},
			"Content-Type": {"text/plain"},
		},
		Body: []byte("ok"),
	}
	dump := string(dumpResponse(resp))
	for _, secret := range []string{"super-secret", "theme=dark"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("Set-Cookie value %q leaked into evidence:\n%s", secret, dump)
		}
	}
	wantSID := "Set-Cookie: sid=" + redactedCookieValue + "; Path=/; HttpOnly"
	wantTheme := "Set-Cookie: theme=" + redactedCookieValue + "; Path=/"
	if !strings.Contains(dump, wantSID) || !strings.Contains(dump, wantTheme) {
		t.Fatalf("cookie names/attributes missing from evidence:\n%s", dump)
	}
	if !strings.Contains(dump, "Content-Type: text/plain") || !strings.Contains(dump, "ok") {
		t.Fatalf("safe evidence was lost:\n%s", dump)
	}
	if !strings.Contains(resp.Headers.Get("Set-Cookie"), "super-secret") {
		t.Fatal("dumpResponse mutated the response headers")
	}
}
