package web

// Internal test for the probe exemption from the Host allow-list. That check is
// only active when the server binds a specific address, which ListenAndServe
// sets up; setting the field directly exercises the same guard path without
// binding a real socket.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/store/memory"
)

func TestProbesBypassHostAllowList(t *testing.T) {
	s := NewServer(memory.New(), nil, "v-test", nil, nil, "")
	s.allowedHosts = map[string]bool{"indago.internal": true}
	h := s.Handler()

	// A probe from a reverse proxy or kubelet arrives with the backend address
	// as Host, which is not in the allow-list. It must still be answered.
	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, "http://10.0.0.5:8750"+path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s with an unlisted Host: status %d, want 200 (body %s)", path, rec.Code, rec.Body.String())
		}
	}

	// The exemption is scoped to the probes: the control API still refuses a
	// rebinding-style Host.
	req := httptest.NewRequest(http.MethodGet, "http://evil.example/api/version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/api/version with an unlisted Host: status %d, want 403", rec.Code)
	}
}
