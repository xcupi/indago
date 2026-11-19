package web_test

// Tests for the unauthenticated orchestration probes: /healthz is liveness (the
// process is up, no store dependency) and /readyz is readiness (the store
// answers a bounded ping). Both must stay reachable without the dashboard token,
// the X-Indago-Client header, or a rate-limit budget — that is what a kubelet,
// Docker HEALTHCHECK, or reverse-proxy health check can actually send.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

const probeVersion = "1.2.3-test"

func probeServer(t *testing.T, st store.Store) *web.Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, queue.NewMemory(), log, probeVersion, scan.Options{})
	t.Cleanup(ctrl.Shutdown)
	return web.NewServer(st, ctrl, probeVersion, log, nil, "")
}

func probeGet(t *testing.T, h http.Handler, path string) (*httptest.ResponseRecorder, map[string]string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: response is not JSON: %v (body %q)", path, err, rec.Body.String())
	}
	return rec, body
}

// failingPingStore is a real in-memory store whose Ping always fails, standing
// in for an unusable database without needing to corrupt one.
type failingPingStore struct{ store.Store }

func (failingPingStore) Ping(context.Context) error { return errors.New("sql: database is closed") }

// slowPingStore ignores its deadline only as far as a well-behaved store would:
// it waits for the context, which is what proves the handler imposes one.
type slowPingStore struct{ store.Store }

func (slowPingStore) Ping(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestHealthzReportsOKAndVersion(t *testing.T) {
	srv := probeServer(t, memory.New())
	rec, body := probeGet(t, srv.Handler(), "/healthz")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want JSON", ct)
	}
	if body["status"] != "ok" || body["version"] != probeVersion {
		t.Fatalf("body = %v, want status=ok version=%s", body, probeVersion)
	}
	if len(body) != 2 {
		t.Fatalf("body has extra fields: %v", body)
	}
}

// A broken store must not make liveness fail: restarting the process would not
// fix it, and the restart itself interrupts work that WAL recovery must undo.
func TestHealthzDoesNotDependOnStore(t *testing.T) {
	srv := probeServer(t, failingPingStore{Store: memory.New()})
	rec, body := probeGet(t, srv.Handler(), "/healthz")
	if rec.Code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("healthz with failing store: status %d body %v, want 200 ok", rec.Code, body)
	}
}

func TestReadyzReportsReady(t *testing.T) {
	srv := probeServer(t, memory.New())
	rec, body := probeGet(t, srv.Handler(), "/readyz")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if body["status"] != "ready" || body["db"] != "ok" {
		t.Fatalf("body = %v, want status=ready db=ok", body)
	}
}

func TestReadyzReportsStoreFailure(t *testing.T) {
	srv := probeServer(t, failingPingStore{Store: memory.New()})
	rec, body := probeGet(t, srv.Handler(), "/readyz")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body["status"] != "not_ready" || body["db"] != "error" {
		t.Fatalf("body = %v, want status=not_ready db=error", body)
	}
	// The unauthenticated probe must not leak the driver error (it can name the
	// database path or DSN).
	if strings.Contains(rec.Body.String(), "database is closed") {
		t.Fatalf("readyz leaked the store error: %s", rec.Body.String())
	}
}

// A store that never answers must be reported not-ready within the handler's
// own 2s bound, not whenever the orchestrator gives up.
func TestReadyzStoreCheckIsBounded(t *testing.T) {
	srv := probeServer(t, slowPingStore{Store: memory.New()})
	start := time.Now()
	rec, body := probeGet(t, srv.Handler(), "/readyz")
	elapsed := time.Since(start)

	if rec.Code != http.StatusServiceUnavailable || body["db"] != "error" {
		t.Fatalf("status %d body %v, want 503 not_ready", rec.Code, body)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("readyz took %v; the store check is not bounded", elapsed)
	}
}

// Probes must work with the bearer token configured and with the rate-limit
// budget exhausted, since neither a kubelet nor a proxy health check has either.
func TestProbesBypassTokenAndRateLimit(t *testing.T) {
	srv := probeServer(t, memory.New())
	if err := srv.SetAPIToken(strings.Repeat("k", web.MinAPITokenLen)); err != nil {
		t.Fatal(err)
	}
	if err := srv.SetRateLimit(1, 1); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// The token really is enforced on the control API…
	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/version without a token: status %d, want 401", rec.Code)
	}

	// …while repeated probes stay open. With a burst of 1, the second request
	// on any guarded path would already be 429.
	for i := 0; i < 5; i++ {
		for _, path := range []string{"/healthz", "/readyz"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s attempt %d without a token: status %d, want 200", path, i+1, rec.Code)
			}
		}
	}
}
