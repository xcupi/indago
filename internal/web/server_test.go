package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{})
	return web.NewServer(st, ctrl, "test", log).Handler()
}

func TestHealthAndVersion(t *testing.T) {
	h := newServer(t)

	for _, path := range []string{"/healthz", "/api/version"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
	}
}

func TestProjectCreateListGet(t *testing.T) {
	h := newServer(t)

	// Create.
	body, _ := json.Marshal(map[string]string{"name": "Acme"})
	req := httptest.NewRequest(http.MethodPost, "/api/projects", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("no id returned")
	}

	// List.
	req = httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 project, got %d", len(list))
	}

	// Get.
	req = httptest.NewRequest(http.MethodGet, "/api/projects/"+id, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status %d", rec.Code)
	}

	// Get missing -> 404.
	req = httptest.NewRequest(http.MethodGet, "/api/projects/does-not-exist", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing project, got %d", rec.Code)
	}
}

func TestCreateProjectValidation(t *testing.T) {
	h := newServer(t)
	// Missing name.
	req := httptest.NewRequest(http.MethodPost, "/api/projects", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestStaticUIServed(t *testing.T) {
	h := newServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index status %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("INDAGO")) {
		t.Fatal("index page does not contain expected content")
	}
}

func TestServeAndShutdown(t *testing.T) {
	h := newServerStruct(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.ListenAndServe(ctx, "127.0.0.1:0") }()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve/shutdown error: %v", err)
	}
}

func newServerStruct(t *testing.T) *web.Server {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{})
	return web.NewServer(st, ctrl, "test", log)
}
