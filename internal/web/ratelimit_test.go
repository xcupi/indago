package web_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

// newWebServer builds a Server over an in-memory store and returns it with the
// buffer its debug log writes to.
func newWebServer(t *testing.T) (*web.Server, *bytes.Buffer) {
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
	return web.NewServer(st, ctrl, "test", log, evStore, t.TempDir()), &logBuf
}

// Black-box tests use a refill rate near zero (0.01/s = one token per 100 s) so a
// slow machine cannot refill a bucket mid-test and turn an expected 429 into a
// 200. Exact refill math is covered by the injected-clock tests in
// ratelimit_internal_test.go.

// fromAddr sends one GET from a given RemoteAddr (httptest's default is shared,
// so per-client tests must set it explicitly).
func fromAddr(h http.Handler, remote, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = remote
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustSetRate(t *testing.T, s *web.Server, rate float64, burst int) {
	t.Helper()
	if err := s.SetRateLimit(rate, burst); err != nil {
		t.Fatalf("SetRateLimit(%v, %d): %v", rate, burst, err)
	}
}

func TestRateLimitBurstThen429WithRetryAfter(t *testing.T) {
	s, _ := newWebServer(t)
	mustSetRate(t, s, 0.01, 4) // bucket of 4
	h := s.Handler()

	for i := 0; i < 4; i++ {
		if rec := fromAddr(h, "192.0.2.10:5000", "/api/version", nil); rec.Code != http.StatusOK {
			t.Fatalf("burst request %d: status %d, want 200", i+1, rec.Code)
		}
	}
	rec := fromAddr(h, "192.0.2.10:5000", "/api/version", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-burst request: status %d, want 429", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a whole number of seconds >= 1", ra)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "rate limit exceeded" {
		t.Fatalf("429 body = %q, want {\"error\":\"rate limit exceeded\"}", rec.Body.String())
	}
}

func TestRateLimitIsPerRemoteAddrAndIgnoresForwardedHeaders(t *testing.T) {
	s, _ := newWebServer(t)
	mustSetRate(t, s, 0.01, 2)
	h := s.Handler()

	// Exhaust one client, rotating a spoofed X-Forwarded-For every time.
	for i := 0; i < 2; i++ {
		fromAddr(h, "192.0.2.10:5000", "/api/version", map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i)})
	}
	spoofed := map[string]string{"X-Forwarded-For": "203.0.113.200", "X-Real-IP": "203.0.113.201"}
	if rec := fromAddr(h, "192.0.2.10:5000", "/api/version", spoofed); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed X-Forwarded-For/X-Real-IP escaped the bucket: status %d", rec.Code)
	}
	// A different RemoteAddr has its own full bucket.
	if rec := fromAddr(h, "192.0.2.11:5000", "/api/version", nil); rec.Code != http.StatusOK {
		t.Fatalf("independent client refused: status %d", rec.Code)
	}
	// Same host, different source port, is the same client.
	if rec := fromAddr(h, "192.0.2.10:6000", "/api/version", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same host on another port got a fresh bucket: status %d", rec.Code)
	}
}

func TestRateLimitExemptsHealthzAndStaticUI(t *testing.T) {
	s, _ := newWebServer(t)
	mustSetRate(t, s, 0.01, 1)
	h := s.Handler()
	for _, target := range []string{"/healthz", "/", "/app.js", "/index.html"} {
		for i := 0; i < 20; i++ {
			if rec := fromAddr(h, "192.0.2.20:1", target, nil); rec.Code == http.StatusTooManyRequests {
				t.Fatalf("%s request %d was rate limited", target, i+1)
			}
		}
	}
}

func TestRateLimitAppliesBeforeTokenCheck(t *testing.T) {
	s, _ := newWebServer(t)
	if err := s.SetAPIToken(testAPIToken); err != nil {
		t.Fatal(err)
	}
	mustSetRate(t, s, 0.01, 2)
	h := s.Handler()
	// Unauthenticated floods are limited too: the first two are 401s (they
	// spend tokens), then the bucket is empty and the answer is 429.
	want := []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests}
	for i, w := range want {
		if rec := fromAddr(h, "192.0.2.30:1", "/api/projects", nil); rec.Code != w {
			t.Fatalf("unauthenticated request %d: status %d, want %d", i+1, rec.Code, w)
		}
	}
}

func TestRateLimitZeroDisablesAndInvalidValuesRejected(t *testing.T) {
	s, _ := newWebServer(t)
	mustSetRate(t, s, 0, 0)
	h := s.Handler()
	for i := 0; i < 300; i++ {
		if rec := fromAddr(h, "192.0.2.40:1", "/api/version", nil); rec.Code != http.StatusOK {
			t.Fatalf("rate 0 must disable the limiter; request %d got %d", i+1, rec.Code)
		}
	}
	if err := s.SetRateLimit(-1, 10); err == nil {
		t.Error("negative rate accepted")
	}
	if err := s.SetRateLimit(5, 0); err == nil {
		t.Error("burst 0 with a positive rate accepted")
	}
}

func TestRateLimitLogsOncePerBurstAtInfo(t *testing.T) {
	s, logBuf := newWebServer(t)
	mustSetRate(t, s, 0.01, 1)
	h := s.Handler()
	fromAddr(h, "192.0.2.50:1", "/api/version", nil)
	for i := 0; i < 5; i++ {
		fromAddr(h, "192.0.2.50:1", "/api/version", nil)
	}
	if n := bytes.Count(logBuf.Bytes(), []byte("level=INFO msg=\"api request rate limited\"")); n != 1 {
		t.Fatalf("Info rate-limit logs = %d for one burst, want 1", n)
	}
	// The client IP may appear at Debug, but never at Info (retained by default).
	if bytes.Contains(infoLines(logBuf.Bytes()), []byte("192.0.2.50")) {
		t.Fatal("client IP leaked into an Info log line")
	}
}

// infoLines returns only the INFO records of a text-handler log.
func infoLines(b []byte) []byte {
	var out []byte
	for _, l := range bytes.Split(b, []byte("\n")) {
		if bytes.Contains(l, []byte("level=INFO")) {
			out = append(out, l...)
			out = append(out, '\n')
		}
	}
	return out
}
