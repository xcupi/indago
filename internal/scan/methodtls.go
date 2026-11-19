package scan

// Read-only HTTP method and TLS transport-hygiene check.
//
// One job acts on ONE origin (scheme://host[:port]), not on every URL: which
// methods an origin exposes and how it negotiates TLS are origin-level
// properties, so reporting them per endpoint would multiply one observation
// into hundreds of near-duplicate findings. The executor sends exactly three
// requests, all of them methods RFC 9110 defines as safe:
//
//  1. the scan's ordinary GET baseline (status + TLS handshake state + the one
//     response stored for the method evidence),
//  2. one OPTIONS probe, whose Allow header is the server's own statement of
//     which methods the resource supports,
//  3. one TRACE probe carrying a unique marker header, which is only reported
//     when the server echoes the request line AND the marker back — the
//     cross-site tracing primitive. A TRACE that answers 405/501 is disabled
//     and is not reported.
//
// Boundaries:
//   - Read-only: GET, OPTIONS and TRACE only. No PUT/DELETE/PATCH/POST is ever
//     sent, no body is sent, and nothing is mutated. A state-changing endpoint
//     is skipped without a request.
//   - Bounded: at most maxMethodTLSOrigins origins per scan and at most three
//     requests per origin.
//   - Cache-safe: the OPTIONS and TRACE probes carry a unique cache-buster
//     query parameter, so a shared cache can neither answer a probe from
//     another caller's entry nor store a probe response under a URL a user
//     would request.
//   - Deterministic: every signal is a pure function of the server's own
//     response bytes/headers and of the TLS state the scan's own handshake
//     produced, so no browser and no LLM participate (AGENTS.md §2.5).
//   - Near-zero false positives, deliberately:
//     * TRACE requires an exact request-line echo plus the marker header.
//     * OPTIONS write methods are only reported when the OPTIONS probe
//       succeeded (2xx), the scan is ANONYMOUS, the path is not API-shaped,
//       and the advertised set actually contains PUT/DELETE/PATCH. An
//       authenticated scan, an API origin, or an auth challenge (401/403)
//       never produces this finding: advertising writes there is normal.
//     * A self-signed certificate is RECORDED in the detail but never a
//       finding. Authorized testing routinely targets lab servers with
//       self-signed certificates; that is a trust-model choice the operator
//       already made, not a transport weakness the report should repeat.
//     * TLS protocol hygiene is observed from the handshake this toolchain can
//       actually perform: Go's client offers TLS 1.3 and 1.2 only, so a server
//       that cannot do TLS 1.2 or better refuses the handshake with a
//       protocol-version alert — that alert IS the observation, and it is
//       reported as such. A successful handshake below TLS 1.2 and a weak
//       negotiated cipher are also judged if a deployment ever makes them
//       observable (see mtTLSVersionUnsupported / mtWeakCipher).
//
// Both finding families are keyed per origin, so a second endpoint on the same
// origin absorbs into the same row and only unions evidence.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
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
	mtEngine = "method_tls_hygiene"

	// mtCategoryMethod / mtCategoryTLS separate the two finding families this
	// one engine reports, so a report/UI can group them.
	mtCategoryMethod = "method"
	mtCategoryTLS    = "tls"

	// maxMethodTLSOrigins bounds the pass: one job per origin.
	maxMethodTLSOrigins = 20
	// methodTLSPriority runs the method/TLS inspection just before the
	// security-header pass: it is three cheap safe-method requests per origin.
	methodTLSPriority = 35

	// mtTraceMarkerHeader is the client header the TRACE probe sends. Its
	// value is unique per probe, so seeing it in the response proves the
	// server echoed request HEADERS, which is the cross-site tracing risk.
	mtTraceMarkerHeader = "X-Indago-Trace"

	// mtCacheBusterParam is appended to the OPTIONS/TRACE probe URLs. Its
	// value is unique per request (see mtCacheBusted).
	mtCacheBusterParam = "indago_method_check"
)

// Signal kinds. Stable strings so a report/UI can group them.
const (
	mtKindTraceEnabled        = "trace_method_enabled"
	mtKindOptionsWriteMethods = "options_advertises_write_methods"
	mtKindLegacyTLS           = "tls_legacy_protocol"
	mtKindTLSProtocolRefused  = "tls_protocol_unsupported"
	mtKindWeakCipher          = "tls_weak_cipher"
	mtKindExpiredCertificate  = "tls_certificate_expired"
)

// mtWriteMethods are the methods an unauthenticated page should not be
// advertising. TRACE is deliberately not in this set: it has its own echo-based
// check and is never inferred from an Allow header alone.
var mtWriteMethods = []string{"PUT", "DELETE", "PATCH"}

// mtWeakCipherSuites are the negotiated cipher suites that are broken or
// cryptographically inadequate regardless of context. Names come from
// crypto/tls, so a suite this toolchain cannot even name is never guessed at.
// CBC-mode suites are deliberately NOT listed: old but not broken, and
// reporting them would drown the finding in noise.
var mtWeakCipherSuites = map[string]string{
	"TLS_RSA_WITH_RC4_128_SHA":              "RC4",
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":        "RC4",
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":      "RC4",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":         "3DES",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":   "3DES",
	"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": "3DES",
	"TLS_RSA_WITH_DES_CBC_SHA":              "single DES",
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":        "export-grade RC4",
	"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":     "export-grade DES",
	"TLS_RSA_WITH_NULL_SHA":                 "no encryption (NULL)",
	"TLS_RSA_WITH_NULL_MD5":                 "no encryption (NULL)",
	"TLS_ECDHE_RSA_WITH_NULL_SHA":           "no encryption (NULL)",
	"TLS_ECDHE_ECDSA_WITH_NULL_SHA":         "no encryption (NULL)",
}

// mtAPIPathSegments are the first path segments that mark an origin as an API
// surface, where advertising PUT/DELETE/PATCH is expected rather than notable.
var mtAPIPathSegments = map[string]bool{
	"api": true, "api2": true, "apis": true, "rest": true, "graphql": true,
	"gql": true, "rpc": true, "jsonrpc": true, "oauth": true, "oauth2": true,
	"token": true, "ws": true, "v1": true, "v2": true, "v3": true, "v4": true,
}

// methodTLSProbe is one OPTIONS/TRACE probe's outcome. It is persisted in the
// test-case and finding details, so it must stay a plain data value.
type methodTLSProbe struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Status  int      `json:"status,omitempty"`
	Allow   []string `json:"allow,omitempty"`
	Echoed  bool     `json:"echoed,omitempty"`
	Blocked string   `json:"blocked,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// methodTLSObservation is the TLS state of the origin's handshake, projected
// from httpengine.TLSState into the engine's own schema.
type methodTLSObservation struct {
	Scheme         string         `json:"scheme"`
	Version        uint16         `json:"version,omitempty"`
	VersionName    string         `json:"version_name,omitempty"`
	CipherSuite    string         `json:"cipher_suite,omitempty"`
	ALPN           string         `json:"alpn,omitempty"`
	Verified       bool           `json:"verified"`
	Certificate    *methodTLSCert `json:"certificate,omitempty"`
	ChainLength    int            `json:"chain_length,omitempty"`
	HandshakeError string         `json:"handshake_error,omitempty"`
	Unavailable    string         `json:"unavailable,omitempty"`
}

// methodTLSCert is the leaf certificate's identity and validity window. It
// never carries key material.
type methodTLSCert struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	SelfSigned bool      `json:"self_signed,omitempty"`
}

// methodTLSSignal is one observed weakness on an origin. Its Key identifies the
// (origin, kind) pair, so a second endpoint on the same origin absorbs into the
// same finding instead of adding a row.
type methodTLSSignal struct {
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

// methodTLSDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type methodTLSDetail struct {
	Engine      string                `json:"engine"`
	URL         string                `json:"url"`
	FinalURL    string                `json:"final_url,omitempty"`
	Origin      string                `json:"origin"`
	Method      string                `json:"method"`
	HTTPStatus  int                   `json:"http_status,omitempty"`
	DedupKey    string                `json:"dedup_key,omitempty"`
	Occurrences int                   `json:"occurrences,omitempty"`
	Verdict     domain.Verdict        `json:"verdict"`
	Severity    domain.Severity       `json:"severity,omitempty"`
	Confidence  domain.Confidence     `json:"confidence,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	Probes      []methodTLSProbe      `json:"probes,omitempty"`
	TLS         *methodTLSObservation `json:"tls,omitempty"`
	Signals     []methodTLSSignal     `json:"signals,omitempty"`
	Throttled   bool                  `json:"throttled,omitempty"`
	Skipped     bool                  `json:"skipped,omitempty"`
	SkipReason  string                `json:"skip_reason,omitempty"`
	TestCaseIDs []domain.ID           `json:"test_case_ids,omitempty"`
	EvidenceIDs []domain.ID           `json:"evidence_ids,omitempty"`
}

// ---------------------------------------------------------------------------
// pure analysis
// ---------------------------------------------------------------------------

// methodTLSOrigin returns the scheme://host[:port] identity of rawURL,
// lowercased, or "" when rawURL is not an absolute http(s) URL. It is the
// correlation unit for this engine, and it shares securityHeadersOrigin's
// exact normalisation so the two origin-level engines can never disagree
// about what "one origin" means.
func methodTLSOrigin(rawURL string) string {
	return securityHeadersOrigin(rawURL)
}

// methodTLSDedupKey is the finding identity: one row per origin and kind.
func methodTLSDedupKey(origin, category, kind string) string {
	return mtEngine + "\x00" + strings.ToLower(origin) + "\x00" + category + "\x00" + kind
}

// methodTLSOriginKey identifies the origin-level inspection recorded in a
// TestCase.Detail (the finding-level keys are per kind).
func methodTLSOriginKey(origin string) string {
	return mtEngine + "\x00" + strings.ToLower(origin)
}

// mtAllowMethods parses every Allow header value into an upper-cased,
// de-duplicated, sorted method set. Multiple Allow headers are legal.
func mtAllowMethods(h http.Header) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range h.Values("Allow") {
		for _, part := range strings.Split(raw, ",") {
			m := strings.ToUpper(strings.TrimSpace(part))
			if m == "" || seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// mtDangerousAllowed returns the advertised write methods that make an
// OPTIONS response worth reporting. TRACE is not included: it is decided by the
// TRACE probe's echo, never by an Allow entry alone.
func mtDangerousAllowed(allow []string) []string {
	var out []string
	for _, m := range allow {
		for _, dangerous := range mtWriteMethods {
			if m == dangerous {
				out = append(out, m)
			}
		}
	}
	return out
}

// mtAPIPath reports whether the URL's path names an API surface, where an
// OPTIONS response advertising write methods is expected.
func mtAPIPath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(strings.Trim(u.Path, "/"))
	if path == "" {
		return false
	}
	first := path
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	if mtAPIPathSegments[first] {
		return true
	}
	// A nested API surface (/backend/api/items) is just as much an API.
	for _, seg := range strings.Split(path, "/") {
		if seg == "api" || seg == "graphql" || seg == "rest" {
			return true
		}
	}
	return false
}

// mtRequestLineEcho reports whether body contains the exact request line the
// TRACE probe sent ("TRACE <target> HTTP/..."). The comparison is
// case-insensitive because some servers normalize the request line.
func mtRequestLineEcho(body []byte, target string) bool {
	if target == "" {
		return false
	}
	needle := strings.ToLower("trace " + target + " http/")
	return strings.Contains(strings.ToLower(string(body)), needle)
}

// mtTRACEEchoes decides whether a TRACE response proves cross-site tracing is
// enabled: the response must be a success, carry the unique marker header
// value back (so request HEADERS were echoed), and either echo the exact
// request line or declare itself a message/http dump. A reflection-only error
// page that happens to contain the marker is not enough.
func mtTRACEEchoes(resp *httpengine.Response, marker, target string) bool {
	if resp == nil || resp.Status < 200 || resp.Status >= 300 {
		return false
	}
	if marker == "" || !strings.Contains(string(resp.Body), marker) {
		return false
	}
	if mtRequestLineEcho(resp.Body, target) {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "message/http")
}

// mtMethodSignals turns the method probes' outcomes into signals. It is pure:
// no clock, no I/O, no network.
func mtMethodSignals(origin string, probes []methodTLSProbe, authenticated bool) []methodTLSSignal {
	var signals []methodTLSSignal
	for _, p := range probes {
		switch {
		case p.Method == http.MethodTrace && p.Echoed:
			signals = append(signals, methodTLSSignal{
				Key:      methodTLSDedupKey(origin, mtCategoryMethod, mtKindTraceEnabled),
				Category: mtCategoryMethod, Kind: mtKindTraceEnabled, Subject: "TRACE",
				Severity: domain.SeverityLow, Confidence: domain.ConfidenceHigh,
				Observed: fmt.Sprintf("HTTP %d echoed the request line and the %s header", p.Status, mtTraceMarkerHeader),
				Reason: "the server answered TRACE by echoing the request — including its headers — back to the caller. A " +
					"cross-site tracing (XST) attacker who can make a client issue TRACE can read headers that client would " +
					"normally only send to this origin, such as session cookies. Current browsers refuse TRACE from " +
					"script, so the practical exposure is to other clients, proxies and older embedded browsers.",
				Remediation: "Disable the TRACE method at the server or the reverse proxy (Apache: TraceEnable off; nginx: " +
					"reject TRACE with a 405) and allow only the methods the application actually serves.",
				Title: "TRACE method is enabled and echoes the request",
			})
		case p.Method == http.MethodOptions && p.Status >= 200 && p.Status < 300 && !authenticated && !mtAPIPath(p.URL):
			if dangerous := mtDangerousAllowed(p.Allow); len(dangerous) > 0 {
				signals = append(signals, methodTLSSignal{
					Key:      methodTLSDedupKey(origin, mtCategoryMethod, mtKindOptionsWriteMethods),
					Category: mtCategoryMethod, Kind: mtKindOptionsWriteMethods, Subject: "OPTIONS",
					Severity: domain.SeverityLow, Confidence: domain.ConfidenceMedium,
					Observed: "Allow: " + strings.Join(p.Allow, ", "),
					Reason: fmt.Sprintf("an ANONYMOUS OPTIONS request to a non-API page was answered with Allow advertising %s. "+
						"The server is telling any unauthenticated caller that the resource accepts write methods; either the "+
						"route really does without authentication, or it advertises methods it never enforces. Indago did not "+
						"send a write request — this finding is the advertisement itself.", strings.Join(dangerous, "/")),
					Remediation: "Answer OPTIONS only with the methods the route actually implements for this caller, and " +
						"require authentication before advertising or honouring PUT/DELETE/PATCH. Disable WebDAV " +
						"(Allow: PUT/DELETE/PROPFIND) on any origin that does not serve it.",
					Title: "OPTIONS advertises write methods to an unauthenticated caller",
				})
			}
		}
	}
	return signals
}

// mtTLSVersionUnsupported reports whether the handshake error is the TLS
// protocol-version alert: the server could not agree on any version this
// client offered. Go's client offers TLS 1.3 and 1.2 only, so this alert means
// the origin cannot do TLS 1.2 or better.
//
// The alert is matched by its text because crypto/tls reports it through an
// unexported type; the string is the RFC 8446 alert name rendered by
// crypto/tls and has been stable across releases.
func mtTLSVersionUnsupported(errText string) bool {
	return strings.Contains(strings.ToLower(errText), "protocol version not supported")
}

// mtWeakCipherReason returns why a negotiated cipher suite is inadequate, or ""
// when it is fine. Unknown suite names are never guessed at.
func mtWeakCipherReason(name string) string {
	if name == "" {
		return ""
	}
	if reason, ok := mtWeakCipherSuites[name]; ok {
		return reason
	}
	return ""
}

// mtTLSSignals turns the origin's TLS observation into signals. now decides
// certificate expiry, so the function stays deterministic for a fixed now. It
// is pure: no clock read, no I/O, no network.
func mtTLSSignals(origin string, obs *methodTLSObservation, now time.Time) []methodTLSSignal {
	if obs == nil || !strings.EqualFold(obs.Scheme, "https") {
		return nil
	}
	var signals []methodTLSSignal
	add := func(kind, subject string, severity domain.Severity, confidence domain.Confidence, observed, reason, remediation, title string) {
		signals = append(signals, methodTLSSignal{
			Key: methodTLSDedupKey(origin, mtCategoryTLS, kind), Category: mtCategoryTLS,
			Kind: kind, Subject: subject, Severity: severity, Confidence: confidence,
			Observed: observed, Reason: reason, Remediation: remediation, Title: title,
		})
	}

	// 1. A refused handshake: the origin cannot negotiate TLS 1.2 or later.
	if obs.HandshakeError != "" && mtTLSVersionUnsupported(obs.HandshakeError) {
		add(mtKindTLSProtocolRefused, "TLS version", domain.SeverityMedium, domain.ConfidenceHigh,
			truncate(obs.HandshakeError, 300),
			"the origin refused the TLS handshake because it could not agree on a protocol version: Indago's client "+
				"offers TLS 1.3 and 1.2 only, so this origin can do neither. Traffic protected by TLS 1.0/1.1 is open to "+
				"known protocol weaknesses and to an on-path attacker who can force a downgrade elsewhere on the path.",
			"Enable TLS 1.2 and TLS 1.3 on the listener and remove TLS 1.0/1.1 from its enabled protocols.",
			"Origin cannot negotiate TLS 1.2 or later")
	}

	// 2. A successful handshake below TLS 1.2 (only observable when a
	// deployment's transport still permits it; reported faithfully if so).
	if obs.Version != 0 && obs.Version < tls.VersionTLS12 {
		name := strings.TrimSpace(obs.VersionName)
		if name == "" {
			name = fmt.Sprintf("0x%04x", obs.Version)
		}
		add(mtKindLegacyTLS, "TLS version", domain.SeverityMedium, domain.ConfidenceHigh, name,
			fmt.Sprintf("the connection negotiated %s. TLS 1.0 and 1.1 are deprecated, have known weaknesses and "+
				"are refused by current browsers, so a client that can still reach this origin is using a channel "+
				"weaker than TLS 1.2.", name),
			"Require TLS 1.2 as the minimum protocol version and prefer TLS 1.3.",
			"Origin negotiated a deprecated TLS version")
	}

	// 3. A negotiated cipher suite that is broken or export-grade.
	if reason := mtWeakCipherReason(obs.CipherSuite); reason != "" {
		add(mtKindWeakCipher, "TLS cipher", domain.SeverityMedium, domain.ConfidenceHigh, obs.CipherSuite,
			fmt.Sprintf("the connection negotiated %s (%s), a cipher suite that does not provide adequate "+
				"confidentiality or integrity for a current transport.", obs.CipherSuite, reason),
			"Remove weak and export-grade cipher suites from the listener's configuration and allow only AEAD "+
				"suites (AES-GCM, ChaCha20-Poly1305) negotiated by TLS 1.2/1.3.",
			"Origin negotiated a weak cipher suite")
	}

	// 4. An expired leaf certificate. This is only observable when the scan's
	// own engine was configured to skip verification (the usual lab setting);
	// with verification on, an expired certificate aborts the handshake and the
	// request is recorded as inconclusive instead.
	if cert := obs.Certificate; cert != nil && !cert.NotAfter.IsZero() && cert.NotAfter.Before(now) {
		add(mtKindExpiredCertificate, "TLS certificate", domain.SeverityMedium, domain.ConfidenceHigh,
			"expired "+cert.NotAfter.UTC().Format(time.RFC3339),
			fmt.Sprintf("the certificate the origin presented expired on %s. Every browser and API client that "+
				"verifies certificates refuses this origin, and a user who clicks through the warning loses the "+
				"identity guarantee TLS exists to provide.", cert.NotAfter.UTC().Format(time.RFC3339)),
			"Renew the certificate before its NotAfter date and automate renewal so expiry cannot recur.",
			"TLS certificate has expired")
	}
	return signals
}

// mtSummary is the one-line test-case/finding summary.
func mtSummary(signals []methodTLSSignal) string {
	kinds := make([]string, 0, len(signals))
	for _, s := range signals {
		kinds = append(kinds, s.Title)
	}
	return fmt.Sprintf("%d transport-hygiene issue(s) on this origin: %s", len(signals), strings.Join(kinds, "; "))
}

// mtTopSeverity returns the strongest severity among the signals.
func mtTopSeverity(signals []methodTLSSignal) domain.Severity {
	best := domain.SeverityInfo
	for _, s := range signals {
		if mtSeverityRank(s.Severity) > mtSeverityRank(best) {
			best = s.Severity
		}
	}
	return best
}

// mtSeverityRank orders severities for comparison.
func mtSeverityRank(s domain.Severity) int {
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

// mtCacheBusted appends a unique cache-buster query parameter to rawURL,
// preserving any existing query and fragment.
func mtCacheBusted(rawURL, token string) string {
	fragment := ""
	if i := strings.IndexByte(rawURL, '#'); i >= 0 {
		rawURL, fragment = rawURL[:i], rawURL[i:]
	}
	sep := "?"
	switch {
	case strings.HasSuffix(rawURL, "?") || strings.HasSuffix(rawURL, "&"):
		sep = ""
	case strings.Contains(rawURL, "?"):
		sep = "&"
	}
	return rawURL + sep + mtCacheBusterParam + "=" + token + fragment
}

// mtRequestTarget returns the origin-form request target of an absolute URL,
// which is what a TRACE echo repeats back.
func mtRequestTarget(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.RequestURI()
}

// mtObserveTLS projects the transport's TLS capture into the engine's detail.
// A nil state on an https origin is recorded as unavailable rather than as a
// finding: it is the transport that cannot tell us, not the server that failed.
func mtObserveTLS(rawURL string, state *httpengine.TLSState) *methodTLSObservation {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil
	}
	https := strings.EqualFold(u.Scheme, "https")
	if state == nil {
		if !https {
			return nil
		}
		return &methodTLSObservation{Scheme: "https",
			Unavailable: "the transport did not expose the negotiated TLS state (randomized TLS fingerprint dialer)"}
	}
	obs := &methodTLSObservation{
		Scheme: "https", Version: state.Version, VersionName: state.VersionName,
		CipherSuite: state.CipherSuiteName, ALPN: state.ALPN, Verified: state.Verified,
		ChainLength: len(state.PeerCertificates),
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		obs.Certificate = &methodTLSCert{
			Subject: leaf.Subject, Issuer: leaf.Issuer, NotBefore: leaf.NotBefore,
			NotAfter: leaf.NotAfter, DNSNames: leaf.DNSNames, SelfSigned: leaf.SelfSigned,
		}
	}
	return obs
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

type methodTLSExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
	// now is the clock the certificate-expiry judgement uses; the constructor
	// sets it to time.Now and a test may pin it.
	now func() time.Time
}

// clock returns the engine's clock, falling back to the wall clock for a
// struct built without the constructor.
func (e *methodTLSExecutor) clock() time.Time {
	if e.now == nil {
		return time.Now()
	}
	return e.now()
}

func newMethodTLSExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *methodTLSExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &methodTLSExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu, now: time.Now}
}

var _ worker.Handler = (*methodTLSExecutor)(nil)

// Handle implements worker.Handler: one GET baseline, one OPTIONS probe, one
// TRACE probe, then pure analysis.
func (e *methodTLSExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, err := mtTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnHTTPMethods, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist method/tls test case: %w", err)
	}

	origin := methodTLSOrigin(ep.URL)
	d := &methodTLSDetail{Engine: mtEngine, URL: ep.URL, Origin: origin, Method: method, Verdict: domain.VerdictRejected}
	if reason, skip := e.mtSkip(ep); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "method and tls check skipped: "+reason)
		return nil
	}
	d.DedupKey = methodTLSOriginKey(origin)

	// 1. Baseline GET: the scan's ordinary read of the origin. It also carries
	// the TLS handshake this check inspects.
	req := httpengine.GET(ep.URL)
	baseResp, outcome, reqErr := e.mtDo(ctx, req)
	now := time.Now()
	tc.FinishedAt = &now
	if baseResp != nil {
		tc.HTTPStatus = baseResp.Status
	}
	if outcome != domain.OutcomeSuccess {
		// A refused TLS version is an observation, not a failed request: the
		// alert names exactly the transport weakness this check exists to
		// report, so it is recorded as a confirmed TLS finding instead of an
		// inconclusive baseline. Nothing else can be probed (no HTTP response
		// was ever produced).
		if obs, ok := mtRefusedTLSObservation(ep.URL, reqErr); ok {
			d.TLS = obs
			d.Signals = mtTLSSignals(origin, obs, e.clock())
			if len(d.Signals) > 0 {
				d.Verdict = domain.VerdictConfirmed
				d.Severity, d.Confidence = mtTopSeverity(d.Signals), domain.ConfidenceHigh
				d.Reason = mtSummary(d.Signals)
				e.correlate(ctx, job, ep, tc, d)
				e.finish(ctx, tc, d, domain.TestCaseCompleted, "method and tls check: "+d.Reason)
				return nil
			}
		}
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the read-only baseline request to this origin did not complete"
		tc.Note = truncate("method and tls check inconclusive: "+errorText(reqErr, outcome), 1024)
		e.finish(ctx, tc, d, domain.TestCaseFailed, tc.Note)
		return nil
	}
	tc.DurationMS = time.Since(started).Milliseconds()
	d.HTTPStatus = baseResp.Status
	d.FinalURL = baseResp.FinalURL
	d.TLS = mtObserveTLS(ep.URL, baseResp.TLS)
	e.persist(ctx, tc, "baseline", baseResp)

	if isThrottleStatus(baseResp.Status) {
		d.Throttled = true
		d.Reason = fmt.Sprintf("the target answered HTTP %d, so no method or TLS judgement was made", baseResp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "method and tls check skipped: target throttled the baseline request")
		return nil
	}

	var probes []methodTLSProbe
	// 2. OPTIONS: the server's own statement of the methods it serves.
	optionsURL := mtCacheBusted(ep.URL, markerToken("mto"))
	optionsReq := httpengine.NewRequest(http.MethodOptions, optionsURL)
	optionsReq.NoRedirects = true
	optionsResp, optionsOutcome, optionsErr := e.mtDo(ctx, optionsReq)
	switch {
	case optionsOutcome != domain.OutcomeSuccess:
		probes = append(probes, methodTLSProbe{Method: http.MethodOptions, URL: optionsURL,
			Note: "probe did not complete: " + errorText(optionsErr, optionsOutcome)})
	case isThrottleStatus(optionsResp.Status):
		d.Throttled = true
		probes = append(probes, methodTLSProbe{Method: http.MethodOptions, URL: optionsURL, Status: optionsResp.Status,
			Blocked: "throttled", Note: fmt.Sprintf("the target answered HTTP %d, so this probe was not judged", optionsResp.Status)})
		e.persist(ctx, tc, "options", optionsResp)
	default:
		probes = append(probes, methodTLSProbe{Method: http.MethodOptions, URL: optionsURL, Status: optionsResp.Status,
			Allow: mtAllowMethods(optionsResp.Headers)})
		e.persist(ctx, tc, "options", optionsResp)
	}
	if d.Throttled {
		d.Probes = probes
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the target throttled the OPTIONS probe, so no method judgement was made"
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "method and tls check inconclusive: target throttled the OPTIONS probe")
		return nil
	}

	// 3. TRACE: only reported when the server echoes the request back.
	traceURL := mtCacheBusted(ep.URL, markerToken("mtt"))
	marker := markerToken("mtm")
	traceReq := httpengine.NewRequest(http.MethodTrace, traceURL)
	traceReq.NoRedirects = true
	traceReq.WithHeader(mtTraceMarkerHeader, marker)
	traceResp, traceOutcome, traceErr := e.mtDo(ctx, traceReq)
	switch {
	case traceOutcome != domain.OutcomeSuccess:
		probes = append(probes, methodTLSProbe{Method: http.MethodTrace, URL: traceURL,
			Note: "probe did not complete: " + errorText(traceErr, traceOutcome)})
	case isThrottleStatus(traceResp.Status):
		d.Throttled = true
		probes = append(probes, methodTLSProbe{Method: http.MethodTrace, URL: traceURL, Status: traceResp.Status,
			Blocked: "throttled", Note: fmt.Sprintf("the target answered HTTP %d, so this probe was not judged", traceResp.Status)})
	default:
		probes = append(probes, methodTLSProbe{Method: http.MethodTrace, URL: traceURL, Status: traceResp.Status,
			Allow:   mtAllowMethods(traceResp.Headers),
			Echoed:  mtTRACEEchoes(traceResp, marker, mtRequestTarget(traceURL)),
			Blocked: mtTraceBlocked(traceResp.Status)})
		e.persist(ctx, tc, "trace", traceResp)
	}

	d.Probes = probes
	signals := mtMethodSignals(origin, probes, e.cfg.Authenticated)
	signals = append(signals, mtTLSSignals(origin, d.TLS, e.clock())...)
	d.Signals = signals
	tc.DurationMS = time.Since(started).Milliseconds()
	note := "method and tls check: read-only methods answered as expected and the transport negotiated acceptable TLS"
	switch {
	case len(signals) > 0:
		d.Verdict = domain.VerdictConfirmed
		d.Severity, d.Confidence = mtTopSeverity(signals), domain.ConfidenceHigh
		for _, s := range signals {
			if s.Confidence == domain.ConfidenceMedium && d.Confidence == domain.ConfidenceHigh {
				d.Confidence = domain.ConfidenceMedium
			}
		}
		d.Reason = mtSummary(signals)
		note = "method and tls check: " + d.Reason
		e.correlate(ctx, job, ep, tc, d)
	case d.Throttled:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the target throttled the TRACE probe, so the origin was not fully judged"
		note = "method and tls check inconclusive: target throttled the TRACE probe"
	}
	e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
	return nil
}

// mtTraceBlocked labels a TRACE answer that means the method is disabled.
func mtTraceBlocked(status int) string {
	switch status {
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return "disabled"
	}
	return ""
}

// mtRefusedTLSObservation recognises the TLS protocol-version alert in a
// failed https request. ok is false for any other failure: only an alert that
// names the version is evidence about the transport.
func mtRefusedTLSObservation(rawURL string, err error) (*methodTLSObservation, bool) {
	if err == nil {
		return nil, false
	}
	u, perr := url.Parse(strings.TrimSpace(rawURL))
	if perr != nil || !strings.EqualFold(u.Scheme, "https") {
		return nil, false
	}
	msg := err.Error()
	if !mtTLSVersionUnsupported(msg) {
		return nil, false
	}
	return &methodTLSObservation{Scheme: "https", HandshakeError: truncate(msg, 300)}, true
}

// mtTarget resolves the job's endpoint, tolerating an origin job that carries
// only a URL (nothing is persisted for such a detached endpoint).
func mtTarget(ctx context.Context, st store.Store, job *domain.TestJob) (*domain.Endpoint, error) {
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
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("job URL %q is not an absolute http(s) URL", raw)
	}
	return &domain.Endpoint{URL: raw, Method: domain.MethodGET, Source: domain.SourceUserProvided}, nil
}

// mtSkip applies the same read-only/write guards the other passive engines use:
// this check must never be the request that mutates a target.
func (e *methodTLSExecutor) mtSkip(ep *domain.Endpoint) (string, bool) {
	if !isSafeMethod(ep.Method) {
		return fmt.Sprintf("%s is state-changing; a method and tls check only sends GET, OPTIONS and TRACE", ep.Method), true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

// mtDo sends one request with the executor's per-request timeout.
func (e *methodTLSExecutor) mtDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
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
func (e *methodTLSExecutor) persist(ctx context.Context, tc *domain.TestCase, label string, resp *httpengine.Response) {
	if e.evidence == nil || resp == nil {
		return
	}
	var ids []domain.ID
	if resp.Request != nil {
		captured := *resp.Request
		captured.Headers = resp.Request.Headers.Clone()
		note := "test_case=" + string(tc.ID) + " method_tls " + label + " request"
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(&captured), note); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("method tls: persist request evidence", "test_case", tc.ID, "probe", label, "err", err)
		}
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	note := "test_case=" + string(tc.ID) + " method_tls " + label + " response"
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), note); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("method tls: persist response evidence", "test_case", tc.ID, "probe", label, "err", err)
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

// finish persists the test case.
func (e *methodTLSExecutor) finish(ctx context.Context, tc *domain.TestCase, d *methodTLSDetail, status domain.TestCaseStatus, note string) {
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
		e.log.Warn("method tls: persist test case", "test_case", tc.ID, "err", err)
	}
}

// correlate upserts one Finding per signal. The dedup key is (origin, kind), so
// a second endpoint on the same origin — or a resumed execution that re-runs
// the pass — absorbs into the same row and only unions evidence and the
// occurrence count.
func (e *methodTLSExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *methodTLSDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("method tls: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("method tls: list findings", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	// finish() runs after correlation, so the IDs this attempt earned are
	// merged in here — a finding must never be created without its evidence or
	// without a link back to the test case that proved it.
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	byKey := make(map[string]*domain.Finding, len(existing))
	for _, f := range existing {
		if f.VulnClass != domain.VulnHTTPMethods && f.VulnClass != domain.VulnTLSConfig {
			continue
		}
		var fd methodTLSDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
			continue
		}
		byKey[fd.DedupKey] = f
	}

	for _, s := range d.Signals {
		class := domain.VulnHTTPMethods
		if s.Category == mtCategoryTLS {
			class = domain.VulnTLSConfig
		}
		title := s.Title + ": " + originHostLabel(d.Origin)
		findingDetail := *d
		findingDetail.DedupKey = s.Key
		findingDetail.Severity, findingDetail.Confidence = s.Severity, s.Confidence
		findingDetail.Reason = s.Reason
		findingDetail.Signals = []methodTLSSignal{s}
		if findingDetail.Occurrences == 0 {
			findingDetail.Occurrences = 1
		}
		detail, _ := json.Marshal(&findingDetail)

		if f := byKey[s.Key]; f != nil {
			var fd methodTLSDetail
			if err := json.Unmarshal(f.Detail, &fd); err == nil {
				if fd.Occurrences == 0 {
					fd.Occurrences = 1
				}
				fd.Occurrences++
				if mtSeverityRank(s.Severity) > mtSeverityRank(fd.Severity) {
					fd.Severity, fd.Confidence = s.Severity, s.Confidence
					f.Severity, f.Confidence = s.Severity, s.Confidence
				}
				fd.Reason, fd.Signals = s.Reason, []methodTLSSignal{s}
				fd.Probes, fd.TLS = findingDetail.Probes, findingDetail.TLS
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
				e.log.Warn("method tls: update finding", "scan", job.ScanID, "err", err)
			}
			continue
		}

		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: class,
			Verdict: domain.VerdictConfirmed, Severity: s.Severity, Confidence: s.Confidence,
			Title: title, Summary: s.Reason, EndpointID: ep.ID,
			EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
			Provenance:  domain.Provenance{Engine: mtEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
			Detail:      detail, CreatedAt: now, UpdatedAt: now,
		}
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.log.Warn("method tls: create finding", "scan", job.ScanID, "err", err)
			continue
		}
		byKey[s.Key] = f
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueMethodTLSProbes queues ONE JobMethodTLS per unique origin. Endpoint
// URLs are collapsed to scheme://host[:port] before deduplication, so a
// 500-page crawl yields one job per site, never one per URL.
func (c *Controller) enqueueMethodTLSProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipMethodTLS {
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
		if queued >= maxMethodTLSOrigins {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" || !isSafeMethod(ep.Method) {
			continue
		}
		// Never spend the one job for an origin on an endpoint the executor
		// would then skip for policy reasons: a different endpoint on the same
		// origin carries the same method/TLS policy.
		if sc.Config.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		if sc.Config.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
			continue
		}
		origin := methodTLSOrigin(ep.URL)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobMethodTLS,
			State:       domain.JobQueued,
			Priority:    methodTLSPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("method tls: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("method/tls probes: enqueued", "scan", scanID, "jobs", queued)
	}
}
