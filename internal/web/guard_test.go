package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Internal tests for the DNS-rebinding Host check, which depends on the bind
// address.

func TestHostsForListenAddr(t *testing.T) {
	if hostsForListenAddr("0.0.0.0:8750") != nil || hostsForListenAddr(":8750") != nil || hostsForListenAddr("[::]:8750") != nil {
		t.Fatal("wildcard binds cannot know their hostnames; expected no restriction")
	}
	h := hostsForListenAddr("127.0.0.1:8750")
	for _, want := range []string{"localhost", "127.0.0.1", "::1"} {
		if !h[want] {
			t.Errorf("loopback host %q should be allowed: %v", want, h)
		}
	}
	h = hostsForListenAddr("10.1.2.3:8750")
	if !h["10.1.2.3"] || !h["localhost"] {
		t.Fatalf("bound host and loopback should be allowed: %v", h)
	}
}

func TestGuardRejectsRebindingHost(t *testing.T) {
	s := &Server{allowedHosts: hostsForListenAddr("127.0.0.1:8750")}
	ok := s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))

	for host, want := range map[string]int{
		"127.0.0.1:8750":    204,
		"localhost:8750":    204,
		"[::1]:8750":        204,
		"evil.example:8750": 403, // attacker domain rebound to 127.0.0.1
		"evil.example":      403,
	} {
		req := httptest.NewRequest("GET", "/api/scans", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		ok.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: status %d, want %d", host, rec.Code, want)
		}
	}

	// Without a restriction (wildcard bind) any Host is accepted; the CSRF
	// guard still applies.
	open := &Server{}
	h := open.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Host = "anything.example"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("unrestricted server rejected a GET: %d", rec.Code)
	}
	post := httptest.NewRequest("POST", "/x", nil)
	post.Host = "anything.example"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	if rec.Code != 403 {
		t.Fatalf("CSRF guard must still apply on wildcard binds: %d", rec.Code)
	}
}
