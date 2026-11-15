package oast_test

// Poll API tests. The poll API is what lets the scan engines (SSRF, XXE, blind
// command injection) confirm an out-of-band hit from this Manager without
// knowing anything about it: a loopback-only, secret-path read endpoint whose
// body lists the interactions it recorded.

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/oast"
)

func pollGet(t *testing.T, target string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	return resp.StatusCode, string(body)
}

func TestOASTWiringPollURLIsLoopbackAndStable(t *testing.T) {
	mgr := newLocal(t, nil)
	first, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL: %v", err)
	}
	second, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL (again): %v", err)
	}
	if first != second {
		t.Fatalf("PollURL changed between calls: %q then %q", first, second)
	}
	u, err := url.Parse(first)
	if err != nil {
		t.Fatalf("parse poll URL: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("poll URL host %q is not host:port: %v", u.Host, err)
	}
	if host != "127.0.0.1" || port == "" {
		t.Fatalf("poll URL host = %q, want a bound loopback address", u.Host)
	}
	if !strings.HasPrefix(u.Path, "/poll/") || len(strings.TrimPrefix(u.Path, "/poll/")) < 16 {
		t.Fatalf("poll URL path = %q, want an unguessable /poll/<secret> path", u.Path)
	}
	// The callback base URL is the one a target sees; the poll API must not be
	// a path under it, or publishing the listener would publish the hit list.
	if strings.HasPrefix(first, mgr.BaseURL()) {
		t.Fatalf("poll URL %q is derived from the target-visible base URL %q", first, mgr.BaseURL())
	}
}

func TestOASTWiringPollReportsRecordedHits(t *testing.T) {
	mgr := newLocal(t, nil)
	poll, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL: %v", err)
	}
	// An empty manager still answers a well-formed body.
	status, body := pollGet(t, poll)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !strings.Contains(body, "0 interaction(s)") {
		t.Fatalf("empty poll body = %q, want it to report no interactions", body)
	}

	probeURL, token := mgr.GeneratePayloadURL("scan-1:xxe:/stock", "xxe")
	if status, _ := pollGet(t, probeURL+"/indago-xxe-123"); status != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", status)
	}
	// The engines search the body for the marker they planted; the raw path and
	// query must therefore appear verbatim.
	if status, _ := pollGet(t, probeURL+"?marker=indago-oob-9"); status != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", status)
	}

	status, body = pollGet(t, poll)
	if status != http.StatusOK {
		t.Fatalf("poll status = %d, want 200", status)
	}
	for _, want := range []string{
		"2 interaction(s), 2 correlated",
		"/indago-xxe-123",
		"marker=indago-oob-9",
		"token=" + token,
		"probe=scan-1:xxe:/stock",
		"tag=xxe",
		"source=local",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("poll body is missing %q:\n%s", want, body)
		}
	}
}

func TestOASTWiringPollHidesItself(t *testing.T) {
	mgr := newLocal(t, nil)
	poll, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL: %v", err)
	}
	u, err := url.Parse(poll)
	if err != nil {
		t.Fatalf("parse poll URL: %v", err)
	}
	secret := strings.TrimPrefix(u.Path, "/poll/")
	flipped := []byte(secret)
	if flipped[len(flipped)-1] == 'a' {
		flipped[len(flipped)-1] = 'b'
	} else {
		flipped[len(flipped)-1] = 'a'
	}
	for _, wrong := range []string{
		u.Scheme + "://" + u.Host + "/poll/" + string(flipped), // near-miss secret
		u.Scheme + "://" + u.Host + "/notpoll/" + secret,       // right secret, wrong prefix
		poll + "/extra", // trailing segment
	} {
		if status, _ := pollGet(t, wrong); status != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", wrong, status)
		}
	}
	body := strings.NewReader("")
	req, err := http.NewRequest(http.MethodPost, poll, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST poll: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST poll = %d, want 405", resp.StatusCode)
	}
	// A poll must never be recorded as an interaction: it is the scanner's own
	// read, and counting it would let the API report on itself.
	if hits := mgr.Interactions(); len(hits) != 0 {
		t.Fatalf("interactions = %+v, want none after polling", hits)
	}
}

func TestOASTWiringPollCannotForgeLines(t *testing.T) {
	mgr := newLocal(t, nil)
	poll, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL: %v", err)
	}
	// A bridge (or a target) can hand over arbitrary text; the body must stay
	// one line per interaction.
	mgr.RecordHit(oast.Hit{
		Protocol: "http", Method: "GET", Host: "oast.example", Path: "/p/x\nFAKE-LINE\n",
		Query: "a=1\r\nFAKE", RemoteAddr: "203.0.113.5:1234", Source: "bridge",
	})
	_, body := pollGet(t, poll)
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("poll body has %d lines, want a header and one record:\n%s", len(lines), body)
	}
	if strings.Contains(body, "\r") {
		t.Fatalf("poll body kept a carriage return:\n%q", body)
	}
}

func TestOASTWiringPollStopsWithManager(t *testing.T) {
	mgr := newLocal(t, nil)
	poll, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := mgr.PollURL(); err == nil {
		t.Fatal("PollURL after Close succeeded, want an error")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	if resp, err := client.Get(poll); err == nil {
		resp.Body.Close()
		t.Fatalf("GET %s after Close = %d, want a refused connection", poll, resp.StatusCode)
	}
	// The manager's own listener is gone too, and Close stays idempotent.
	if _, err := client.Get(mgr.BaseURL() + "/p/x"); err == nil {
		t.Fatal("callback listener still answering after Close")
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestOASTWiringPollSurvivesConcurrentCallbacks is the shared-manager property
// the scan layer relies on: one Manager serves every worker of every scan, so
// callbacks and polls interleave.
func TestOASTWiringPollSurvivesConcurrentCallbacks(t *testing.T) {
	mgr := newLocal(t, nil)
	poll, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL: %v", err)
	}
	const n = 16
	tokens := make([]string, 0, n)
	for i := 0; i < n; i++ {
		u, tok := mgr.GeneratePayloadURL("scan:"+string(rune('a'+i)), "xxe")
		tokens = append(tokens, tok)
		go func(target string) {
			resp, err := http.Get(target)
			if err == nil {
				resp.Body.Close()
			}
		}(u)
	}
	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		_, body = pollGet(t, poll)
		if strings.Contains(body, "16 interaction(s), 16 correlated") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, tok := range tokens {
		if !strings.Contains(body, "token="+tok) {
			t.Fatalf("poll body is missing token %q:\n%s", tok, body)
		}
	}
}
