package scan

import (
	"net/http"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func TestPreflightBlockReason(t *testing.T) {
	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
		want   bool
	}{
		{name: "normal page", status: 200, body: "<html>hello</html>"},
		{name: "rate limited", status: 429, header: http.Header{"Retry-After": {"120"}}, want: true},
		{name: "unavailable", status: 503, want: true},
		{name: "cloudflare challenge", status: 200, body: "<script>window._cf_chl_opt = {}</script><script src=\"/cdn-cgi/challenge-platform/x\"></script>", want: true},
		{name: "turnstile widget is not a WAF preflight block", status: 200, body: "<script src=\"https://challenges.cloudflare.com/turnstile\"></script>"},
		{name: "login recaptcha is not a WAF preflight block", status: 200, body: "<div class=\"g-recaptcha\"></div>"},
		{name: "plain app 403", status: 403, body: "forbidden"},
		{name: "cloudflare 403", status: 403, header: http.Header{"Cf-Ray": {"abc"}}, want: true},
		{name: "akamai 403", status: 403, header: http.Header{"X-Akamai-Request-Id": {"abc"}}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := preflightBlockReason(&httpengine.Response{Status: tc.status, Headers: tc.header, Body: []byte(tc.body)})
			if (got != "") != tc.want {
				t.Fatalf("preflightBlockReason = %q, want blocked=%v", got, tc.want)
			}
		})
	}
}
