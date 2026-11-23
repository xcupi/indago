package scan

// Read-only WebSocket handshake and Origin inspection.
//
// One job acts on ONE discovered endpoint that looks like a WebSocket endpoint
// (a ws:// or wss:// URL, or an HTTP URL whose path names one: /ws,
// /socket.io, /chatbot/ws, /sockjs, /signalr, …), not on every URL: the Origin
// policy of a socket endpoint is a property of that endpoint, and probing every
// page would multiply one observation into hundreds of meaningless requests.
//
// The executor sends exactly TWO HTTP Upgrade handshakes and reads only the
// response headers:
//
//  1. a cross-origin handshake carrying Origin: https://indago-ws-check.invalid
//     (an origin the target has no reason to trust). It is reported only when
//     the server answers 101 Switching Protocols — the missing Origin
//     validation that makes cross-site WebSocket hijacking possible
//     (CWE-1385 / CWE-346).
//  2. an anonymous handshake (no cookies, no Authorization header) carrying the
//     endpoint's own Origin. When the scan itself is authenticated, a 101 here
//     proves the upgrade needs no session at all; on a plaintext (http/ws)
//     endpoint it also proves the socket is served without TLS.
//
// Boundaries:
//   - Read-only: an HTTP Upgrade handshake only. NOT ONE WebSocket frame is
//     ever written, so no message, subscription or command is sent; the
//     connection is closed as soon as the response headers are read.
//   - Bounded: at most maxWebSocketEndpoints endpoints per scan and at most two
//     handshakes per endpoint.
//   - Deterministic: every signal is a pure function of the server's own HTTP
//     status and headers, so no browser and no LLM participate (AGENTS.md §2.5).
//   - Near-zero false positives, deliberately: a 101 is the only positive
//     signal. A non-upgrade answer (200, 400, 401, 403, 404, 426, 501) is
//     recorded as a negative observation, never reported. A 429/503 disqualifies
//     the endpoint for this pass entirely (backpressure is not a judgement on
//     the handshake).
//   - No secret retention: cookie values are redacted from the stored evidence
//     by the shared request/response dumpers.
//
// Findings are keyed per (origin, path, kind), so a second endpoint that
// collapses to the same URL path absorbs into the same row and only unions
// evidence.

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	wsEngine = "websocket_security"

	// wsCategoryHandshake / wsCategoryTransport separate the finding families
	// this one engine reports, so a report/UI can group them.
	wsCategoryHandshake = "handshake"
	wsCategoryTransport = "transport"

	// maxWebSocketEndpoints bounds the pass: one job per discovered
	// WebSocket-shaped endpoint (origin + path).
	maxWebSocketEndpoints = 20
	// webSocketPriority runs the handshake inspection just before the
	// method/TLS pass: it is two cheap read-only requests per endpoint.
	webSocketPriority = 34

	// wsForeignOrigin is the untrusted Origin the cross-origin handshake
	// carries. The .invalid TLD is reserved (RFC 2606), so no real site can
	// ever be named by it.
	wsForeignOrigin = "https://indago-ws-check.invalid"

	// wsProbeCrossOrigin / wsProbeAnonymous name the two handshakes.
	wsProbeCrossOrigin = "cross_origin"
	wsProbeAnonymous   = "anonymous"

	// wsAcceptGUID is the RFC 6455 handshake GUID. It is used only to build the
	// expected Sec-WebSocket-Accept value for the observation record; nothing is
	// derived from it that affects a verdict.
	wsAcceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// Signal kinds. Stable strings so a report/UI can group them.
const (
	wsKindCrossOriginUpgrade     = "cross_origin_upgrade_accepted"
	wsKindUnauthenticatedUpgrade = "unauthenticated_upgrade_accepted"
	wsKindPlaintextUpgrade       = "plaintext_upgrade_accepted"
)

// wsPathSegments are the path segments that identify a WebSocket-shaped
// endpoint. Matching is per path SEGMENT (never a substring), so
// /ws-client.js or /news does not match while /ws, /chatbot/ws, /socket.io/ and
// /ws/events do.
var wsPathSegments = map[string]bool{
	"ws": true, "wss": true, "websocket": true, "websockets": true,
	"socket": true, "sockets": true, "socket.io": true, "socketio": true,
	"sockjs": true, "signalr": true, "graphql-ws": true, "cable": true,
}

// wsStaticExtensions are file extensions a WebSocket endpoint never has. They
// are excluded so /socket.io/socket.io.js (the client library) is not probed as
// if it were the socket itself.
var wsStaticExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".css": true, ".map": true,
	".json": true, ".html": true, ".htm": true, ".txt": true, ".xml": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
}

// webSocketProbe is one handshake's outcome. It is persisted in the test-case
// and finding details, so it must stay a plain data value.
type webSocketProbe struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Origin is the Origin header the probe sent.
	Origin string `json:"origin,omitempty"`
	// Anonymous marks the probe that carried no cookies and no Authorization.
	Anonymous bool   `json:"anonymous,omitempty"`
	Status    int    `json:"status,omitempty"`
	Upgrade   string `json:"upgrade,omitempty"`
	// Accept is the Sec-WebSocket-Accept the server returned, and AcceptValid
	// says it matches the key this probe sent (RFC 6455 §4.1). A valid accept
	// proves a genuine WebSocket handshake rather than a proxy's generic 101.
	Accept      string `json:"accept,omitempty"`
	AcceptValid bool   `json:"accept_valid,omitempty"`
	// WebSocket reports whether the 101 response actually confirmed a
	// WebSocket upgrade (Upgrade: websocket or a valid Sec-WebSocket-Accept)
	// rather than switching to some other protocol.
	WebSocket bool   `json:"websocket,omitempty"`
	Switched  bool   `json:"switched,omitempty"`
	Blocked   string `json:"blocked,omitempty"`
	Note      string `json:"note,omitempty"`
}

// webSocketSignal is one observed weakness on one endpoint. Its Key identifies
// the (origin, path, kind) triple, so a second endpoint that collapses to the
// same path absorbs into the same finding instead of adding a row.
type webSocketSignal struct {
	Key         string            `json:"key"`
	Category    string            `json:"category"`
	Kind        string            `json:"kind"`
	Subject     string            `json:"subject"`
	Severity    domain.Severity   `json:"severity"`
	Confidence  domain.Confidence `json:"confidence"`
	Reason      string            `json:"reason"`
	Remediation string            `json:"remediation"`
	Observed    string            `json:"observed,omitempty"`
	Title       string            `json:"title"`
}

// webSocketDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type webSocketDetail struct {
	Engine      string            `json:"engine"`
	URL         string            `json:"url"`
	Origin      string            `json:"origin"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method"`
	HTTPStatus  int               `json:"http_status,omitempty"`
	DedupKey    string            `json:"dedup_key,omitempty"`
	Occurrences int               `json:"occurrences,omitempty"`
	Verdict     domain.Verdict    `json:"verdict"`
	Severity    domain.Severity   `json:"severity,omitempty"`
	Confidence  domain.Confidence `json:"confidence,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	// Plaintext records that the endpoint itself is served over http (a
	// plain ws:// socket), independent of whether that was reported.
	Plaintext bool `json:"plaintext,omitempty"`
	// AuthenticatedScan records whether the scan's own engine carried a
	// session, which is what makes the anonymous handshake meaningful.
	AuthenticatedScan bool              `json:"authenticated_scan,omitempty"`
	Probes            []webSocketProbe  `json:"probes,omitempty"`
	Signals           []webSocketSignal `json:"signals,omitempty"`
	Throttled         bool              `json:"throttled,omitempty"`
	Skipped           bool              `json:"skipped,omitempty"`
	SkipReason        string            `json:"skip_reason,omitempty"`
	TestCaseIDs       []domain.ID       `json:"test_case_ids,omitempty"`
	EvidenceIDs       []domain.ID       `json:"evidence_ids,omitempty"`
}

// ---------------------------------------------------------------------------
// pure analysis
// ---------------------------------------------------------------------------

// webSocketProbeURL normalises rawURL into the absolute http(s) URL this engine
// can actually request: a ws:// URL is probed as http:// and wss:// as https://,
// because the Upgrade handshake is an ordinary HTTP/1.1 exchange. ok is false
// for anything that is not an absolute HTTP/WebSocket URL.
func webSocketProbeURL(rawURL string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || u.User != nil {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	default:
		return "", false
	}
	// Drop the fragment: it is never sent in a request target.
	u.Fragment, u.RawFragment = "", ""
	return u.String(), true
}

// webSocketOriginPath returns the correlation identity of an endpoint: its
// scheme://host[:port] origin and its normalised path ("/" when empty). It
// applies the same ws→http, wss→https normalisation as webSocketProbeURL.
func webSocketOriginPath(rawURL string) (origin, urlPath string, ok bool) {
	probe, ok := webSocketProbeURL(rawURL)
	if !ok {
		return "", "", false
	}
	u, err := url.Parse(probe)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	p := strings.TrimRight(u.Path, "/")
	if p == "" {
		p = "/"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), p, true
}

// webSocketDedupKey is the finding identity: one row per origin, path and kind.
// The path is part of the identity because two different socket endpoints on
// one origin can carry different Origin policies.
func webSocketDedupKey(origin, urlPath, kind string) string {
	return wsEngine + "\x00" + strings.ToLower(origin) + "\x00" + strings.ToLower(urlPath) + "\x00" + kind
}

// webSocketTestKey identifies the endpoint-level inspection recorded in a
// TestCase.Detail (the finding-level keys are per kind above).
func webSocketTestKey(origin, urlPath string) string {
	return wsEngine + "\x00" + strings.ToLower(origin) + "\x00" + strings.ToLower(urlPath)
}

// webSocketPathLike reports whether rawURL names a WebSocket endpoint: a ws://
// or wss:// scheme, a path whose segments include a known socket endpoint name,
// or an explicit websocket transport in the query string. Static assets (the
// socket.io client library, source maps) are explicitly NOT endpoints.
func webSocketPathLike(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
		return true
	case "http", "https":
	default:
		return false
	}
	clean := strings.ToLower(strings.Trim(u.Path, "/"))
	if clean == "" {
		return false
	}
	if wsStaticExtensions[strings.ToLower(path.Ext(clean))] {
		return false
	}
	for _, seg := range strings.Split(clean, "/") {
		if wsPathSegments[seg] {
			return true
		}
	}
	// socket.io and SockJS can name the transport in the query string of a
	// path that does not itself contain a socket segment.
	q := strings.ToLower(u.RawQuery)
	return strings.Contains(q, "transport=websocket") || strings.Contains(q, "transport=ws")
}

// webSocketUpgradeHeader reports whether a response names a WebSocket upgrade
// in its Upgrade header.
func webSocketUpgradeHeader(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("Upgrade")), "websocket")
}

// wsAcceptValue computes the Sec-WebSocket-Accept value a compliant server must
// answer for the given Sec-WebSocket-Key (RFC 6455 §4.2.2).
func wsAcceptValue(key string) string {
	if key == "" {
		return ""
	}
	sum := sha1.Sum([]byte(key + wsAcceptGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// webSocketAcceptValid reports whether the response's Sec-WebSocket-Accept
// matches the key the probe sent.
func webSocketAcceptValid(reqHeaders http.Header, respHeaders http.Header) bool {
	key := strings.TrimSpace(reqHeaders.Get("Sec-WebSocket-Key"))
	if key == "" {
		return false
	}
	got := strings.TrimSpace(respHeaders.Get("Sec-WebSocket-Accept"))
	return got != "" && got == wsAcceptValue(key)
}

// webSocketSwitched reports whether the response is the protocol switch a
// WebSocket handshake asks for.
func webSocketSwitched(resp *httpengine.Response) bool {
	return resp != nil && resp.Status == http.StatusSwitchingProtocols
}

// webSocketSignals turns the handshake outcomes into signals. It is pure: no
// clock, no I/O, no network. authenticated is the scan's own session state and
// plaintext says the endpoint is served over http (a plain ws:// socket).
func webSocketSignals(origin, urlPath string, probes []webSocketProbe, authenticated, plaintext bool) []webSocketSignal {
	var signals []webSocketSignal
	add := func(category, kind, subject string, severity domain.Severity, confidence domain.Confidence, observed, reason, remediation, title string) {
		signals = append(signals, webSocketSignal{
			Key: webSocketDedupKey(origin, urlPath, kind), Category: category, Kind: kind, Subject: subject,
			Severity: severity, Confidence: confidence, Observed: observed,
			Reason: reason, Remediation: remediation, Title: title,
		})
	}

	switched := false
	for _, p := range probes {
		if !p.Switched || !p.AcceptValid {
			continue
		}
		switched = true
		confidence := domain.ConfidenceHigh
		switch p.Name {
		case wsProbeCrossOrigin:
			// A cross-origin 101 without a session to hijack is still a
			// missing Origin check, but the concrete CSWSH impact needs an
			// authenticated victim; it is reported at medium severity then.
			severity := domain.SeverityMedium
			if authenticated {
				severity = domain.SeverityHigh
			}
			add(wsCategoryHandshake, wsKindCrossOriginUpgrade, "Origin", severity, confidence,
				fmt.Sprintf("HTTP %d Switching Protocols for Origin: %s", p.Status, p.Origin),
				"the server completed the WebSocket handshake even though the request carried an Origin it has "+
					"no reason to trust. A browser attaches the victim's cookies to a WebSocket handshake it makes "+
					"for any page's script, so a page on an attacker-controlled origin can open an authenticated "+
					"socket to this endpoint and read or send messages as the victim — cross-site WebSocket "+
					"hijacking (CWE-1385 / CWE-346).",
				"Validate the Origin header of every Upgrade request against an explicit allow-list of the "+
					"application's own origins and answer anything else with 403 before switching protocols. Do not "+
					"rely on cookies alone to authenticate a socket: require a per-connection token that a "+
					"cross-origin page cannot obtain.",
				"WebSocket upgrade accepts an untrusted cross-origin request")
		case wsProbeAnonymous:
			if !authenticated {
				// The scan had no session of its own, so an anonymous 101 proves
				// nothing about authentication: every request this scan sends is
				// anonymous. It is recorded as a negative observation instead.
				continue
			}
			add(wsCategoryHandshake, wsKindUnauthenticatedUpgrade, "Authentication", domain.SeverityHigh, confidence,
				fmt.Sprintf("HTTP %d Switching Protocols with no cookie and no Authorization header", p.Status),
				"an unauthenticated handshake was answered with a protocol switch while this scan's own session "+
					"is authenticated. The upgrade path therefore does not require the session at all: anyone who "+
					"can reach the endpoint can open the socket without logging in, and receive or drive whatever "+
					"the socket exposes.",
				"Require the same authentication on the WebSocket upgrade that the HTTP application requires "+
					"(reject the Upgrade with 401 before switching protocols), and keep the authorization check "+
					"on every message, not just on connection establishment.",
				"WebSocket upgrade succeeds without authentication")
		}
	}
	if switched && plaintext && authenticated {
		add(wsCategoryTransport, wsKindPlaintextUpgrade, "Transport", domain.SeverityMedium, domain.ConfidenceHigh,
			"the socket endpoint is served over plain http (ws://) and answered the upgrade with HTTP 101",
			"the WebSocket endpoint is served over plain ws://. Everything exchanged on that socket crosses the "+
				"network unencrypted, and any session cookie without the Secure attribute is sent with the "+
				"handshake in the clear, where an on-path attacker can read and modify it.",
			"Serve the socket over wss:// only (TLS on the listener, redirect http:// to https://) and mark "+
				"session cookies Secure so a browser never sends them over a plaintext connection.",
			"WebSocket endpoint is reachable over plaintext")
	}
	return signals
}

// webSocketSummary is the one-line test-case/finding summary.
func webSocketSummary(signals []webSocketSignal) string {
	titles := make([]string, 0, len(signals))
	for _, s := range signals {
		titles = append(titles, s.Title)
	}
	return fmt.Sprintf("%d WebSocket handshake issue(s) on this endpoint: %s", len(signals), strings.Join(titles, "; "))
}

// webSocketTopSeverity returns the strongest severity among the signals.
func webSocketTopSeverity(signals []webSocketSignal) domain.Severity {
	best := domain.SeverityInfo
	for _, s := range signals {
		if wsSeverityRank(s.Severity) > wsSeverityRank(best) {
			best = s.Severity
		}
	}
	return best
}

// wsSeverityRank orders severities for comparison.
func wsSeverityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 4
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 1
	default:
		return 0
	}
}

// webSocketKey returns a fresh Sec-WebSocket-Key: 16 random bytes, base64. A
// random key keeps the handshake well-formed (RFC 6455 §4.1) and prevents any
// cache or proxy from treating two probes as the same exchange.
func webSocketKey() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand never fails on a supported platform; a deterministic
		// fallback keeps the probe well-formed rather than panicking a scan.
		return base64.StdEncoding.EncodeToString([]byte(markerToken("wsk")))
	}
	return base64.StdEncoding.EncodeToString(raw[:])
}

// webSocketHandshakeRequest builds one bounded Upgrade handshake. It is a GET
// with the RFC 6455 headers, always HTTP/1.1 (HTTP/2 forbids Upgrade), never
// follows a redirect (the answer at THIS URL is the observation) and carries no
// body and no frame.
func webSocketHandshakeRequest(probeURL, origin string, anonymous bool) *httpengine.Request {
	req := httpengine.NewRequest(http.MethodGet, probeURL)
	req.NoRedirects = true
	req.HTTP1Only = true
	req.NoCookies = anonymous
	req.WithHeader("Upgrade", "websocket")
	req.WithHeader("Connection", "Upgrade")
	req.WithHeader("Sec-WebSocket-Key", webSocketKey())
	req.WithHeader("Sec-WebSocket-Version", "13")
	if origin != "" {
		req.WithHeader("Origin", origin)
	}
	return req
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

type webSocketExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newWebSocketExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *webSocketExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &webSocketExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

var _ worker.Handler = (*webSocketExecutor)(nil)

// Handle implements worker.Handler: two Upgrade handshakes, then pure analysis.
func (e *webSocketExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, err := wsTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnWebSocket, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist websocket test case: %w", err)
	}

	origin, urlPath, _ := webSocketOriginPath(ep.URL)
	d := &webSocketDetail{
		Engine: wsEngine, URL: ep.URL, Origin: origin, Path: urlPath, Method: method,
		Verdict: domain.VerdictRejected,
	}
	if reason, skip := e.wsSkip(ep); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "websocket handshake check skipped: "+reason)
		return nil
	}
	d.DedupKey = webSocketTestKey(origin, urlPath)

	probeURL, ok := webSocketProbeURL(ep.URL)
	if !ok {
		d.Skipped, d.SkipReason = true, "the endpoint URL is not an absolute HTTP or WebSocket URL"
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "websocket handshake check skipped: "+d.SkipReason)
		return nil
	}
	d.Plaintext = strings.HasPrefix(strings.ToLower(probeURL), "http://")
	d.AuthenticatedScan = e.cfg.Authenticated

	// The two handshakes. The cross-origin one is the CSWSH observation; the
	// anonymous one (same-origin Origin, no cookie, no Authorization) is the
	// missing-authentication / plaintext observation. Neither ever sends a
	// frame: the connection is closed as soon as the status line is read.
	probes := []webSocketProbe{}
	throttled := false
	completed := 0
	for _, spec := range []struct {
		name      string
		origin    string
		anonymous bool
	}{
		{wsProbeCrossOrigin, wsForeignOrigin, false},
		{wsProbeAnonymous, origin, true},
	} {
		req := webSocketHandshakeRequest(probeURL, spec.origin, spec.anonymous)
		probe := webSocketProbe{Name: spec.name, URL: probeURL, Origin: spec.origin, Anonymous: spec.anonymous}
		resp, outcome, probeErr := e.wsDo(ctx, req)
		switch {
		case outcome != domain.OutcomeSuccess:
			probe.Note = "probe did not complete: " + errorText(probeErr, outcome)
		case isThrottleStatus(resp.Status):
			throttled = true
			probe.Status = resp.Status
			probe.Blocked = "throttled"
			probe.Note = fmt.Sprintf("the target answered HTTP %d, so this probe was not judged", resp.Status)
			e.persist(ctx, tc, spec.name, resp)
		default:
			completed++
			probe.Status = resp.Status
			probe.Upgrade = truncate(strings.TrimSpace(resp.Headers.Get("Upgrade")), 128)
			probe.Accept = truncate(strings.TrimSpace(resp.Headers.Get("Sec-WebSocket-Accept")), 128)
			probe.Switched = webSocketSwitched(resp)
			if probe.Switched && resp.Request != nil {
				probe.AcceptValid = webSocketAcceptValid(resp.Request.Headers, resp.Headers)
			}
			probe.WebSocket = webSocketUpgradeHeader(resp.Headers) || probe.AcceptValid
			e.persist(ctx, tc, spec.name, resp)
		}
		probes = append(probes, probe)
		if throttled {
			break
		}
	}
	d.Probes = probes
	tc.DurationMS = time.Since(started).Milliseconds()

	if throttled {
		d.Throttled = true
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the target throttled a WebSocket handshake probe, so the endpoint was not judged"
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "websocket handshake check inconclusive: "+d.Reason)
		return nil
	}

	signals := webSocketSignals(origin, urlPath, probes, e.cfg.Authenticated, d.Plaintext)
	d.Signals = signals
	note := "websocket handshake check: no origin-validation, authentication or transport issue was observed on this endpoint"
	switch {
	case len(signals) > 0:
		d.Verdict = domain.VerdictConfirmed
		d.Severity, d.Confidence = webSocketTopSeverity(signals), domain.ConfidenceHigh
		for _, s := range signals {
			if s.Confidence == domain.ConfidenceMedium && d.Confidence == domain.ConfidenceHigh {
				d.Confidence = domain.ConfidenceMedium
			}
		}
		d.Reason = webSocketSummary(signals)
		note = "websocket handshake check: " + d.Reason
		e.correlate(ctx, job, ep, tc, d)
	case completed < 2:
		// A probe that never completed is a gap, not a negative result: the
		// endpoint was not shown to be clean, so no verdict is claimed.
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one or more WebSocket handshake probes did not complete, so the endpoint was not fully judged"
		note = "websocket handshake check inconclusive: " + d.Reason
	}
	e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
	return nil
}

// wsTarget resolves the job's endpoint, tolerating an endpoint job that carries
// only a URL (nothing is persisted for such a detached endpoint).
func wsTarget(ctx context.Context, st store.Store, job *domain.TestJob) (*domain.Endpoint, error) {
	if job == nil {
		return nil, fmt.Errorf("nil job")
	}
	if !job.Target.EndpointID.Empty() {
		ep, _, _, err := resolveJobTarget(ctx, st, job)
		if err != nil {
			return nil, err
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" {
			return nil, fmt.Errorf("endpoint %q has no URL", job.Target.EndpointID)
		}
		return ep, nil
	}
	raw := strings.TrimSpace(job.Target.URL)
	if raw == "" {
		return nil, fmt.Errorf("job has neither an endpoint nor a URL")
	}
	if _, ok := webSocketProbeURL(raw); !ok {
		return nil, fmt.Errorf("job URL %q is not an absolute http(s) or ws(s) URL", raw)
	}
	return &domain.Endpoint{URL: raw, Method: domain.MethodGET, Source: domain.SourceUserProvided}, nil
}

// wsSkip applies the same read-only/write guards the other passive engines use:
// this check must never be the request that mutates a target. An Upgrade
// handshake is a GET, so a state-changing endpoint is skipped before any
// request is sent. It also refuses an endpoint that does not look like a
// WebSocket endpoint at all: the queue only ever receives socket-shaped
// endpoints (see enqueueWebSocketProbes), and a stray job must not turn an
// ordinary page into an upgrade target.
func (e *webSocketExecutor) wsSkip(ep *domain.Endpoint) (string, bool) {
	if !isSafeMethod(ep.Method) {
		return fmt.Sprintf("%s is state-changing; a WebSocket handshake check only sends GET", ep.Method), true
	}
	if !webSocketPathLike(ep.URL) {
		return "the endpoint does not look like a WebSocket endpoint (no ws/wss scheme and no socket path segment)", true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

// wsDo sends one handshake with the executor's per-request timeout.
func (e *webSocketExecutor) wsDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled, err
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err()
	case isTimeout(err):
		return nil, domain.OutcomeTimeout, err
	default:
		return nil, domain.OutcomeError, err
	}
}

// persist stores the request/response pair under a probe label. dumpRequest and
// dumpResponse redact Authorization and cookie values, so no credential reaches
// the evidence store.
func (e *webSocketExecutor) persist(ctx context.Context, tc *domain.TestCase, label string, resp *httpengine.Response) {
	if e.evidence == nil || resp == nil {
		return
	}
	var ids []domain.ID
	if resp.Request != nil {
		captured := *resp.Request
		captured.Headers = resp.Request.Headers.Clone()
		note := "test_case=" + string(tc.ID) + " websocket " + label + " request"
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(&captured), note); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("websocket: persist request evidence", "test_case", tc.ID, "probe", label, "err", err)
		}
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	note := "test_case=" + string(tc.ID) + " websocket " + label + " response"
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), note); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("websocket: persist response evidence", "test_case", tc.ID, "probe", label, "err", err)
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

// finish persists the test case.
func (e *webSocketExecutor) finish(ctx context.Context, tc *domain.TestCase, d *webSocketDetail, status domain.TestCaseStatus, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Status = status
	tc.Note = truncate(note, 1024)
	if status == domain.TestCaseSkipped {
		tc.Outcome = ""
	} else if d.Verdict == domain.VerdictInconclusive {
		tc.Outcome = domain.OutcomeError
	} else {
		tc.Outcome = domain.OutcomeSuccess
	}
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	tc.Detail, _ = json.Marshal(d)
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Warn("websocket: persist test case", "test_case", tc.ID, "err", err)
	}
}

// correlate upserts one Finding per signal. The dedup key is
// (origin, path, kind), so a second endpoint that collapses to the same path —
// or a resumed execution that re-runs the pass — absorbs into the same row and
// only unions evidence and the occurrence count.
func (e *webSocketExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *webSocketDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("websocket: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("websocket: list findings", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	// finish() runs after correlation, so the IDs this attempt earned are merged
	// in here — a finding must never be created without its evidence or without
	// a link back to the test case that proved it.
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	byKey := make(map[string]*domain.Finding, len(existing))
	for _, f := range existing {
		if f.VulnClass != domain.VulnWebSocket {
			continue
		}
		var fd webSocketDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
			continue
		}
		byKey[fd.DedupKey] = f
	}

	for _, s := range d.Signals {
		title := s.Title + ": " + originHostLabel(d.Origin) + d.Path
		findingDetail := *d
		findingDetail.DedupKey = s.Key
		findingDetail.Severity, findingDetail.Confidence = s.Severity, s.Confidence
		findingDetail.Reason = s.Reason
		findingDetail.Signals = []webSocketSignal{s}
		if findingDetail.Occurrences == 0 {
			findingDetail.Occurrences = 1
		}
		detail, _ := json.Marshal(&findingDetail)

		if f := byKey[s.Key]; f != nil {
			var fd webSocketDetail
			if err := json.Unmarshal(f.Detail, &fd); err == nil {
				if fd.Occurrences == 0 {
					fd.Occurrences = 1
				}
				fd.Occurrences++
				if wsSeverityRank(s.Severity) > wsSeverityRank(fd.Severity) {
					fd.Severity, fd.Confidence = s.Severity, s.Confidence
					f.Severity, f.Confidence = s.Severity, s.Confidence
				}
				fd.Reason, fd.Signals = s.Reason, []webSocketSignal{s}
				fd.Probes = findingDetail.Probes
				fd.TestCaseIDs = appendUniqueIDs(fd.TestCaseIDs, []domain.ID{tc.ID})
				fd.EvidenceIDs = appendUniqueIDs(fd.EvidenceIDs, tc.EvidenceIDs)
				if b, err := json.Marshal(fd); err == nil {
					f.Detail = b
				}
			}
			f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, tc.EvidenceIDs)
			f.Title, f.Summary = title, s.Reason
			f.UpdatedAt = now
			if err := e.store.Findings().Update(ctx, f); err != nil {
				e.log.Warn("websocket: update finding", "scan", job.ScanID, "err", err)
			}
			continue
		}

		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnWebSocket,
			Verdict: domain.VerdictConfirmed, Severity: s.Severity, Confidence: s.Confidence,
			Title: title, Summary: s.Reason, EndpointID: ep.ID,
			EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
			Provenance:  domain.Provenance{Engine: wsEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
			Detail:      detail, CreatedAt: now, UpdatedAt: now,
		}
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.log.Warn("websocket: create finding", "scan", job.ScanID, "err", err)
			continue
		}
		byKey[s.Key] = f
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueWebSocketProbes queues ONE JobWebSocket per unique WebSocket-shaped
// endpoint (origin + path). A crawl that sees the same socket URL with different
// query values — socket.io's EIO/transport parameters, a cache-buster, a token
// — yields ONE job, never one per URL. When nothing in the scan looks like a
// WebSocket endpoint, nothing is enqueued.
func (c *Controller) enqueueWebSocketProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipWebSocket {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	now := time.Now()
	seen := make(map[string]struct{}, len(endpoints))
	queued := 0
	for _, ep := range endpoints {
		if queued >= maxWebSocketEndpoints {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" || !isSafeMethod(ep.Method) {
			continue
		}
		// Never spend one of the bounded jobs on an endpoint the executor
		// would then skip for policy reasons.
		if sc.Config.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		if sc.Config.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
			continue
		}
		if !webSocketPathLike(ep.URL) {
			continue
		}
		identity, ok := webSocketProbeURL(ep.URL)
		if !ok {
			continue
		}
		origin, urlPath, ok := webSocketOriginPath(identity)
		if !ok {
			continue
		}
		key := origin + "\x00" + urlPath
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobWebSocket,
			State:       domain.JobQueued,
			Priority:    webSocketPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("websocket: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("websocket probes: enqueued", "scan", scanID, "jobs", queued)
	}
}
