package web_test

import (
	"net/http"
	"strings"
	"testing"
)

// scrape fetches /metrics from client IP remote, with an optional bearer.
func scrape(t *testing.T, h http.Handler, remote, bearer string) (int, string, string) {
	t.Helper()
	hdr := map[string]string{}
	if bearer != "" {
		hdr["Authorization"] = "Bearer " + bearer
	}
	rec := fromAddr(h, remote, "/metrics", hdr)
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.String()
}

func TestMetricsCountsRoutePatternsAcrossStatuses(t *testing.T) {
	s, _ := newWebServer(t)
	if err := s.SetAPIToken(testAPIToken); err != nil {
		t.Fatal(err)
	}
	mustSetRate(t, s, 0.01, 4)
	h := s.Handler()

	bearer := map[string]string{"Authorization": "Bearer " + testAPIToken}
	seq := []struct {
		hdr  map[string]string
		want int
	}{
		{bearer, http.StatusOK},
		{nil, http.StatusUnauthorized},
		{nil, http.StatusUnauthorized},
		{bearer, http.StatusOK},
		{bearer, http.StatusTooManyRequests},
	}
	for i, c := range seq {
		if rec := fromAddr(h, "192.0.2.60:1", "/api/version", c.hdr); rec.Code != c.want {
			t.Fatalf("step %d: status %d, want %d", i+1, rec.Code, c.want)
		}
	}
	// A raw ID in the path must be reported only as the route pattern.
	fromAddr(h, "192.0.2.61:1", "/api/projects/raw-id-XYZ123", bearer)

	code, _, body := scrape(t, h, "192.0.2.99:1", testAPIToken)
	if code != http.StatusOK {
		t.Fatalf("scrape status %d", code)
	}
	for _, line := range []string{
		`indago_http_requests_total{method="GET",route="GET /api/version",code="200"} 2`,
		`indago_http_requests_total{method="GET",route="GET /api/version",code="401"} 2`,
		`indago_http_requests_total{method="GET",route="GET /api/version",code="429"} 1`,
		`indago_http_requests_total{method="GET",route="GET /api/projects/{id}",code="404"} 1`,
		`indago_rate_limited_total 1`,
		`indago_auth_rejected_total 2`,
		`indago_http_request_duration_seconds_count{route="GET /api/version"} 5`,
		`indago_http_request_duration_seconds_bucket{route="GET /api/version",le="+Inf"} 5`,
	} {
		if !strings.Contains(body, line+"\n") {
			t.Errorf("metrics missing line %q", line)
		}
	}
	if strings.Contains(body, "raw-id-XYZ123") {
		t.Fatal("raw path segment leaked into a metric label")
	}
}

func TestMetricsExpositionWithoutTokenWhenUnset(t *testing.T) {
	s, _ := newWebServer(t)
	h := s.Handler()
	code, ctype, body := scrape(t, h, "192.0.2.70:1", "")
	if code != http.StatusOK {
		t.Fatalf("/metrics without token configured: status %d, want 200", code)
	}
	if !strings.HasPrefix(ctype, "text/plain") || !strings.Contains(ctype, "version=0.0.4") {
		t.Fatalf("Content-Type = %q, want text/plain; version=0.0.4", ctype)
	}
	for _, want := range []string{
		"# TYPE indago_http_requests_total counter",
		"# TYPE indago_http_request_duration_seconds histogram",
		"# TYPE indago_rate_limited_total counter",
		"# TYPE indago_auth_rejected_total counter",
		"# TYPE indago_build_info gauge",
		`indago_build_info{version="test"} 1`,
		"indago_rate_limited_total 0",
		"indago_auth_rejected_total 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q", want)
		}
	}
}

func TestMetricsRequiresBearerWhenTokenSet(t *testing.T) {
	s, _ := newWebServer(t)
	if err := s.SetAPIToken(testAPIToken); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if code, _, _ := scrape(t, h, "192.0.2.80:1", ""); code != http.StatusUnauthorized {
		t.Fatalf("/metrics without Bearer: status %d, want 401", code)
	}
	if code, _, _ := scrape(t, h, "192.0.2.81:1", "not-the-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); code != http.StatusUnauthorized {
		t.Fatalf("/metrics with wrong Bearer: status %d, want 401", code)
	}
	code, _, body := scrape(t, h, "192.0.2.82:1", testAPIToken)
	if code != http.StatusOK {
		t.Fatalf("/metrics with Bearer: status %d, want 200", code)
	}
	if strings.Contains(body, testAPIToken) {
		t.Fatal("token appeared in /metrics output")
	}
}

func TestMetricsSecretAndClientAddressFree(t *testing.T) {
	s, _ := newWebServer(t)
	if err := s.SetAPIToken(testAPIToken); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	// Generate traffic from a distinctive client address and with the token.
	fromAddr(h, "203.0.113.77:4242", "/api/version", map[string]string{"Authorization": "Bearer " + testAPIToken})
	fromAddr(h, "203.0.113.77:4242", "/api/version", nil)

	_, _, body := scrape(t, h, "198.51.100.9:1", testAPIToken)
	for _, forbidden := range []string{testAPIToken, "203.0.113.77", "198.51.100.9", "4242", "/tmp", "evidence"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("metrics output contains forbidden %q", forbidden)
		}
	}
}
