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
	if !strings.Contains(dump, "Authorization: <redacted>") || !strings.Contains(dump, "X-Test: kept") {
		t.Fatalf("unexpected redacted dump:\n%s", dump)
	}
	if req.Headers.Get("Authorization") != "Bearer real-secret-token" {
		t.Fatal("dumpRequest mutated the captured request")
	}
}
