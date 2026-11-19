package scan

// WebSocket handshake & Origin inspection tests: the pure URL classifier and
// the executor against real httptest servers (a foreign Origin rejected with
// 403 produces no finding, an accepted foreign Origin produces one with stored
// evidence, per-endpoint deduplication, non-WebSocket endpoints enqueue
// nothing, the anonymous/plaintext observations of an authenticated scan,
// throttling, state-changing skips, cookie redaction and the bounded enqueue).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func wsEngineFor(t *testing.T) httpengine.Engine {
	t.Helper()
	return scopedClient(t, openScope())
}

// wsAuthenticatedEngine returns a scope-enforcing engine carrying one session
// cookie, the way an authenticated scan's engine is built.
func wsAuthenticatedEngine(t *testing.T, host string) httpengine.Engine {
	t.Helper()
	return newScopedEngine(noFollowClient(t), openScope()).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: "super-secret-session", Domain: host, Path: "/"},
	})
}

// wsWriteSwitching answers a handshake with a valid RFC 6455 protocol switch.
func wsWriteSwitching(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Errorf("response writer is not a Hijacker")
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	defer conn.Close()
	accept := wsAcceptValue(r.Header.Get("Sec-WebSocket-Key"))
	if _, err := fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	_ = buf.Flush()
}

// runWebSocket executes one JobWebSocket for ep and returns that job's test
// case.
func runWebSocket(t *testing.T, env *scanEnv, eng httpengine.Engine, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobWebSocket,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newWebSocketExecutor(env.st, eng, env.ev, cfg, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list test cases: %v", err)
	}
	for _, tc := range cases {
		if tc.JobID == job.ID {
			return tc
		}
	}
	t.Fatalf("no test case recorded for job %s", job.ID)
	return nil
}

func wsDetailOf(t *testing.T, tc *domain.TestCase) webSocketDetail {
	t.Helper()
	var d webSocketDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

func wsFindings(t *testing.T, env *scanEnv) []*domain.Finding {
	t.Helper()
	var out []*domain.Finding
	for _, f := range scanFindings(t, env) {
		if f.VulnClass == domain.VulnWebSocket {
			out = append(out, f)
		}
	}
	return out
}

func wsFindingDetail(t *testing.T, f *domain.Finding) webSocketDetail {
	t.Helper()
	var d webSocketDetail
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatalf("unmarshal finding detail: %v (%s)", err, string(f.Detail))
	}
	return d
}

// wsEvidenceText concatenates every stored evidence blob for the test case.
func wsEvidenceText(t *testing.T, env *scanEnv, tc *domain.TestCase) []string {
	t.Helper()
	var blobs []string
	for _, id := range tc.EvidenceIDs {
		row, err := env.st.Evidence().Get(context.Background(), id)
		if err != nil {
			t.Fatalf("evidence %s: %v", id, err)
		}
		rc, err := env.ev.Open(row.BlobPath)
		if err != nil {
			t.Fatalf("open evidence %s: %v", id, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read evidence %s: %v", id, err)
		}
		blobs = append(blobs, string(b))
	}
	return blobs
}

// ---------------------------------------------------------------------------
// pure classification
// ---------------------------------------------------------------------------

func TestWebSocketPathLike(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://app.example.test/ws", true},
		{"https://app.example.test/chatbot/ws", true},
		{"https://app.example.test/ws?token=abc", true},
		{"https://app.example.test/socket.io/?EIO=4&transport=websocket", true},
		{"wss://app.example.test/live/socket", true},
		{"ws://app.example.test/anything", true},
		{"https://app.example.test/events?transport=websocket", true},
		{"https://app.example.test/sockjs/123/abc/websocket", true},
		{"https://app.example.test/graphql-ws", true},
		// Static assets, ordinary pages and API routes are not socket endpoints.
		{"https://app.example.test/socket.io/socket.io.js", false},
		{"https://app.example.test/js/ws-client.js", false},
		{"https://app.example.test/app.js", false},
		{"https://app.example.test/api/items", false},
		{"https://app.example.test/news", false},
		{"https://app.example.test/", false},
		{"mailto:security@app.example.test", false},
	}
	for _, tc := range cases {
		if got := webSocketPathLike(tc.url); got != tc.want {
			t.Errorf("webSocketPathLike(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestWebSocketProbeURLNormalisesSchemes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"ws://app.example.test/ws", "http://app.example.test/ws", true},
		{"wss://app.example.test/ws", "https://app.example.test/ws", true},
		{"https://app.example.test/ws#frag", "https://app.example.test/ws", true},
		{"ftp://app.example.test/ws", "", false},
		{"not a url", "", false},
	} {
		got, ok := webSocketProbeURL(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("webSocketProbeURL(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestWebSocketAcceptMatchesRFC6455(t *testing.T) {
	// The example key/accept pair from RFC 6455 §1.3 must be reproducible;
	// otherwise the executor's "a valid accept proves a WebSocket handshake"
	// observation would be meaningless.
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := wsAcceptValue(key); got != want {
		t.Fatalf("wsAcceptValue(%q) = %q, want %q", key, got, want)
	}
}

// ---------------------------------------------------------------------------
// executor against real servers
// ---------------------------------------------------------------------------

// A server that rejects the untrusted Origin must produce NO finding, even
// though the endpoint really is a WebSocket and answers a same-origin upgrade.
func TestWebSocketForeignOriginRejectedHasNoFindings(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get("Origin") == wsForeignOrigin {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		wsWriteSwitching(t, w, r)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodGET)
	tc := runWebSocket(t, env, wsEngineFor(t), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %q, want completed (note %q)", tc.Status, tc.Note)
	}
	if got := wsFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0 when the server rejects the foreign Origin", len(got))
	}
	d := wsDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected", d.Verdict)
	}
	if len(d.Probes) != 2 {
		t.Fatalf("probes = %d, want the two bounded handshakes", len(d.Probes))
	}
	if d.Probes[0].Status != http.StatusForbidden || d.Probes[0].Switched {
		t.Fatalf("cross-origin probe = %+v, want a 403 that did not switch protocols", d.Probes[0])
	}
	if !d.Probes[1].Switched || !d.Probes[1].AcceptValid {
		t.Fatalf("anonymous probe = %+v, want a valid 101 (the control that proves the endpoint really upgrades)", d.Probes[1])
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("target hits = %d, want exactly 2 handshakes", got)
	}
}

// A server that answers 101 for the untrusted Origin produces the cross-origin
// finding with the handshake stored as evidence.
func TestWebSocketForeignOriginAcceptedProducesFindingWithEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsWriteSwitching(t, w, r)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodGET)
	tc := runWebSocket(t, env, wsEngineFor(t), ep, ExecutorConfig{})

	findings := wsFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1 cross-origin finding", len(findings))
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed", f.Verdict)
	}
	if f.Severity != domain.SeverityMedium {
		t.Fatalf("severity = %q, want medium for an anonymous scan (no session to hijack)", f.Severity)
	}
	fd := wsFindingDetail(t, f)
	if len(fd.Signals) != 1 || fd.Signals[0].Kind != wsKindCrossOriginUpgrade {
		t.Fatalf("signals = %+v, want one %s", fd.Signals, wsKindCrossOriginUpgrade)
	}
	if fd.Signals[0].Category != wsCategoryHandshake {
		t.Fatalf("category = %q, want %q", fd.Signals[0].Category, wsCategoryHandshake)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("finding carries no evidence")
	}

	d := wsDetailOf(t, tc)
	if len(d.Probes) != 2 || d.Probes[0].Status != http.StatusSwitchingProtocols || !d.Probes[0].Switched {
		t.Fatalf("probes = %+v, want the cross-origin 101 recorded", d.Probes)
	}
	if d.Probes[0].Origin != wsForeignOrigin {
		t.Fatalf("cross-origin probe Origin = %q, want %q", d.Probes[0].Origin, wsForeignOrigin)
	}

	blobs := wsEvidenceText(t, env, tc)
	var sawStatus, sawOrigin bool
	for _, blob := range blobs {
		if strings.Contains(blob, "101 Switching Protocols") {
			sawStatus = true
		}
		if strings.Contains(blob, "Origin: "+wsForeignOrigin) {
			sawOrigin = true
		}
	}
	if !sawStatus || !sawOrigin {
		t.Fatalf("evidence does not contain the 101 and the foreign Origin (status=%v origin=%v): %q", sawStatus, sawOrigin, blobs)
	}
}

// A bare 101 — one that does not even echo the RFC 6455 accept value — is
// still a protocol switch and is still reported, at medium confidence.
func TestWebSocketBare101IsStillReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("response writer is not a Hijacker")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		if _, err := fmt.Fprint(buf, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			return
		}
		_ = buf.Flush()
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodGET)
	runWebSocket(t, env, wsEngineFor(t), ep, ExecutorConfig{})

	findings := wsFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the bare 101 to be reported", len(findings))
	}
	fd := wsFindingDetail(t, findings[0])
	if fd.Signals[0].Confidence != domain.ConfidenceMedium {
		t.Fatalf("confidence = %q, want medium when the server did not confirm the WebSocket headers", fd.Signals[0].Confidence)
	}
}

// An endpoint that is not WebSocket-shaped is skipped before any request: a
// stray job must never turn an ordinary page into an upgrade target.
func TestWebSocketNonSocketEndpointIsSkipped(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/items", domain.MethodGET)
	tc := runWebSocket(t, env, wsEngineFor(t), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "does not look like a WebSocket") {
		t.Fatalf("skip note = %q, want it to explain the socket-shape guard", tc.Note)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("target hits = %d, want 0 for a non-socket endpoint", got)
	}
}

// An endpoint that answers an ordinary page to both handshakes is a clean
// negative: completed, rejected, no finding, no signal.
func TestWebSocketNonUpgradeAnswerIsCleanNegative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not a socket</html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodGET)
	tc := runWebSocket(t, env, wsEngineFor(t), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %q, want completed", tc.Status)
	}
	d := wsDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected || len(d.Signals) != 0 {
		t.Fatalf("verdict/signals = %q/%d, want rejected/0", d.Verdict, len(d.Signals))
	}
	if got := wsFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0 for a page that never upgrades", len(got))
	}
}

// Two endpoints that collapse to the same origin+path share ONE finding; the
// second observation only bumps the occurrence count and unions evidence.
func TestWebSocketDeduplicatesPerEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsWriteSwitching(t, w, r)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	eng := wsEngineFor(t)
	first := env.endpoint(srv.URL+"/ws?token=a", domain.MethodGET)
	second := env.endpoint(srv.URL+"/ws?token=b", domain.MethodGET)

	runWebSocket(t, env, eng, first, ExecutorConfig{})
	runWebSocket(t, env, eng, second, ExecutorConfig{})

	findings := wsFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 for one origin+path", len(findings))
	}
	fd := wsFindingDetail(t, findings[0])
	if fd.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", fd.Occurrences)
	}
	if len(fd.TestCaseIDs) != 2 {
		t.Fatalf("test case ids = %v, want both contributing attempts", fd.TestCaseIDs)
	}
	if len(findings[0].EvidenceIDs) < 4 {
		t.Fatalf("evidence ids = %d, want the union of both attempts (>=4)", len(findings[0].EvidenceIDs))
	}
}

// An authenticated scan whose socket accepts an anonymous handshake reports the
// missing authentication, and — because the endpoint is plain http — the
// plaintext transport as a second, separately keyed finding.
func TestWebSocketAuthenticatedScanDetectsAnonymousPlaintextUpgrade(t *testing.T) {
	var mu sync.Mutex
	sawCookie := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawCookie[r.Header.Get("Origin")] = r.Header.Get("Cookie") != ""
		mu.Unlock()
		if r.Header.Get("Origin") == wsForeignOrigin {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		wsWriteSwitching(t, w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodGET)
	tc := runWebSocket(t, env, wsAuthenticatedEngine(t, hostOnly(host)), ep, ExecutorConfig{Authenticated: true})

	mu.Lock()
	crossCookie := sawCookie[wsForeignOrigin]
	anonCookie := sawCookie["http://"+host]
	mu.Unlock()
	if !crossCookie {
		t.Fatal("the cross-origin handshake did not carry the scan's session cookie")
	}
	if anonCookie {
		t.Fatal("the anonymous handshake carried a cookie; it must be genuinely anonymous")
	}

	findings := wsFindings(t, env)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want the missing-authentication and plaintext findings", len(findings))
	}
	kinds := map[string]domain.Severity{}
	for _, f := range findings {
		fd := wsFindingDetail(t, f)
		if len(fd.Signals) != 1 {
			t.Fatalf("finding %s has %d signals, want 1", f.ID, len(fd.Signals))
		}
		kinds[fd.Signals[0].Kind] = f.Severity
	}
	if kinds[wsKindUnauthenticatedUpgrade] != domain.SeverityHigh {
		t.Fatalf("kinds = %+v, want a high %s", kinds, wsKindUnauthenticatedUpgrade)
	}
	if kinds[wsKindPlaintextUpgrade] != domain.SeverityMedium {
		t.Fatalf("kinds = %+v, want a medium %s", kinds, wsKindPlaintextUpgrade)
	}
	if d := wsDetailOf(t, tc); !d.Plaintext || !d.AuthenticatedScan {
		t.Fatalf("detail plaintext/authenticated = %v/%v, want true/true", d.Plaintext, d.AuthenticatedScan)
	}
}

// A 429/503 answer disqualifies the endpoint: no judgement, no second probe.
func TestWebSocketThrottledEndpointIsNotJudged(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "slow down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodGET)
	tc := runWebSocket(t, env, wsEngineFor(t), ep, ExecutorConfig{})

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("target hits = %d, want 1 (the second probe must not be sent after a 503)", got)
	}
	d := wsDetailOf(t, tc)
	if !d.Throttled || d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("detail throttled/verdict = %v/%q, want true/inconclusive", d.Throttled, d.Verdict)
	}
	if got := wsFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0 for a throttled endpoint", len(got))
	}
}

// A state-changing endpoint is skipped before any request is sent.
func TestWebSocketStateChangingEndpointIsSkipped(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		wsWriteSwitching(t, w, r)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodPOST)
	tc := runWebSocket(t, env, wsEngineFor(t), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "state-changing") {
		t.Fatalf("skip note = %q, want it to explain the method guard", tc.Note)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("target hits = %d, want 0", got)
	}
}

// A job carrying only a ws:// URL (no discovered endpoint) is still actionable.
func TestWebSocketURLOnlyJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsWriteSwitching(t, w, r)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobWebSocket,
		Target: domain.JobTarget{URL: wsURL}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newWebSocketExecutor(env.st, wsEngineFor(t), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (err %v), want 1", len(cases), err)
	}
	origin, urlPath, ok := webSocketOriginPath(wsURL)
	if !ok {
		t.Fatalf("webSocketOriginPath(%q) failed", wsURL)
	}
	if d := wsDetailOf(t, cases[0]); d.Origin != origin || d.Path != urlPath {
		t.Fatalf("detail origin/path = %q/%q, want %q/%q", d.Origin, d.Path, origin, urlPath)
	}
	if got := wsFindings(t, env); len(got) != 1 {
		t.Fatalf("findings = %d, want the cross-origin finding from the ws:// URL", len(got))
	}
}

// Cookie values never reach the evidence store: the request dump redacts the
// Cookie header and the response dump redacts Set-Cookie.
func TestWebSocketEvidenceRedactsSecrets(t *testing.T) {
	const secret = "supersecret-session-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sessionid="+secret+"; Path=/; HttpOnly")
		wsWriteSwitching(t, w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/ws", domain.MethodGET)
	tc := runWebSocket(t, env, wsAuthenticatedEngine(t, hostOnly(host)), ep, ExecutorConfig{Authenticated: true})

	if len(tc.EvidenceIDs) == 0 {
		t.Fatal("no evidence was stored")
	}
	for _, blob := range wsEvidenceText(t, env, tc) {
		if strings.Contains(blob, secret) {
			t.Fatalf("evidence carries the raw credential value:\n%s", blob)
		}
	}
}

// hostOnly keeps an httptest host:port usable as a cookie Domain (which must be
// a bare host for the scoped engine's host-only semantics).
func hostOnly(hostPort string) string {
	if i := strings.LastIndexByte(hostPort, ':'); i >= 0 {
		return hostPort[:i]
	}
	return hostPort
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

func TestEnqueueWebSocketProbesDeduplicatesPerEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		skip bool
		want int
	}{
		{"enabled", false, 4},
		{"skipped", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, q := memory.New(), queue.NewMemory()
			now := time.Now()
			sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
				Config: domain.ScanConfig{SkipWebSocket: tc.skip}, CreatedAt: now, UpdatedAt: now}
			if err := st.Scans().Create(ctx, sc); err != nil {
				t.Fatal(err)
			}
			for _, raw := range []string{
				// Same origin+path, different query: ONE job.
				"https://app.example.test/ws?token=a",
				"https://app.example.test/ws?token=b",
				"https://app.example.test/socket.io/?EIO=4&transport=websocket",
				"https://app.example.test/chatbot/ws",
				// Not socket endpoints.
				"https://app.example.test/socket.io/socket.io.js",
				"https://app.example.test/api/items",
				"https://app.example.test/app.js",
				// A second origin is a separate endpoint.
				"https://other.example.test/ws",
			} {
				ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: raw,
					Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}
			ctrl := NewController(st, q, execLog(), "test", Options{})
			t.Cleanup(ctrl.Shutdown)
			ctrl.enqueueWebSocketProbes(ctx, sc.ID)

			jobs, err := q.Jobs(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != tc.want {
				t.Fatalf("jobs = %d, want %d", len(jobs), tc.want)
			}
			if tc.want == 0 {
				return
			}
			identities := map[string]bool{}
			for _, job := range jobs {
				if job.Type != domain.JobWebSocket || job.Priority != webSocketPriority {
					t.Fatalf("job = %+v, want a priority-%d websocket job", job, webSocketPriority)
				}
				if job.Target.EndpointID.Empty() {
					t.Fatalf("job %s carries no endpoint id", job.ID)
				}
				origin, urlPath, ok := webSocketOriginPath(job.Target.URL)
				if !ok {
					t.Fatalf("job URL %q has no identity", job.Target.URL)
				}
				identities[origin+urlPath] = true
			}
			if len(identities) != tc.want {
				t.Fatalf("identities = %v, want %d distinct origin+path pairs", identities, tc.want)
			}
		})
	}
}

// A crawl that found no WebSocket endpoint enqueues nothing at all.
func TestEnqueueWebSocketProbesNoEndpointsIsNoop(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	now := time.Now()
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated, CreatedAt: now, UpdatedAt: now}
	if err := st.Scans().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"https://app.example.test/",
		"https://app.example.test/api/items",
		"https://app.example.test/js/app.js",
	} {
		ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: raw,
			Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
		if err := st.Endpoints().Create(ctx, ep); err != nil {
			t.Fatal(err)
		}
	}
	ctrl := NewController(st, q, execLog(), "test", Options{})
	t.Cleanup(ctrl.Shutdown)
	ctrl.enqueueWebSocketProbes(ctx, sc.ID)

	jobs, err := q.Jobs(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("jobs = %d, want 0 for a scan with no WebSocket endpoint", len(jobs))
	}
}

// The pass is capped at maxWebSocketEndpoints jobs per scan.
func TestEnqueueWebSocketProbesIsCapped(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	now := time.Now()
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated, CreatedAt: now, UpdatedAt: now}
	if err := st.Scans().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxWebSocketEndpoints+5; i++ {
		raw := fmt.Sprintf("https://app.example.test/ws/%d", i)
		ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: raw,
			Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
		if err := st.Endpoints().Create(ctx, ep); err != nil {
			t.Fatal(err)
		}
	}
	ctrl := NewController(st, q, execLog(), "test", Options{})
	t.Cleanup(ctrl.Shutdown)
	ctrl.enqueueWebSocketProbes(ctx, sc.ID)

	jobs, err := q.Jobs(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != maxWebSocketEndpoints {
		t.Fatalf("jobs = %d, want the ceiling %d", len(jobs), maxWebSocketEndpoints)
	}
}
