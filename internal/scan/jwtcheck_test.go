package scan

// JWT validation & hygiene engine tests: the pure parser/analyzer (claims,
// lifetime, sensitive claim NAMES, alg=none, equivalence) and the executor
// against real httptest servers (a verifying server, a server that accepts any
// Bearer, a public endpoint, throttling, skips, per-origin dedup), plus the
// bounded enqueue.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// jwtTokenWith builds a compact JWS from a header and claim set. sig is used
// verbatim as the signature segment, so a test can make it look arbitrary.
func jwtTokenWith(t *testing.T, header, claims map[string]any, sig string) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + "." + sig
}

// cleanJWTClaims is a hygiene-clean claim set: it expires in an hour, was
// issued a minute ago, and carries no secret material.
func cleanJWTClaims(now time.Time) map[string]any {
	return map[string]any{
		"sub": "alice",
		"iss": "https://app.example.test",
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

func hs256Header() map[string]any { return map[string]any{"alg": "HS256", "typ": "JWT"} }

// jwtTestSignature is a distinctive, recognisable signature segment so the
// redaction assertions can look for it.
const jwtTestSignature = "c2lnbmF0dXJlLXNlY3JldC1ieXRlcw"

// jwtSite modes.
const (
	jwtSiteStrict   = "strict"   // verifies the exact token, 401 for anything else
	jwtSiteLax      = "lax"      // any Bearer is accepted, anonymous is 401
	jwtSitePublic   = "public"   // the same data for every caller
	jwtSiteThrottle = "throttle" // the baseline is fine, everything else is 429
)

const jwtSiteBody = `{"user":"alice","email":"alice@example.test","role":"user"}`

// newJWTSite serves /login (401 to everyone, so a baseline there fails), and
// /api/me and / (jwtSiteBody) under the requested mode.
func newJWTSite(t *testing.T, mode, validToken string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"login required"}`))
			return
		}
		auth := r.Header.Get("Authorization")
		switch mode {
		case jwtSitePublic:
			_, _ = w.Write([]byte(jwtSiteBody))
		case jwtSiteThrottle:
			if auth == "Bearer "+validToken {
				_, _ = w.Write([]byte(jwtSiteBody))
				return
			}
			w.WriteHeader(http.StatusTooManyRequests)
		case jwtSiteLax:
			if !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(jwtSiteBody))
		default: // jwtSiteStrict
			if auth != "Bearer "+validToken {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid token"}`))
				return
			}
			_, _ = w.Write([]byte(jwtSiteBody))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// jwtEngineFor returns a scope-enforcing engine carrying the scan's bearer
// credential for origin, exactly as launch() wires it.
func jwtEngineFor(t *testing.T, origin, token string) httpengine.Engine {
	t.Helper()
	return newScopedEngine(noFollowClient(t), openScope()).
		WithSessionAuthHeaders([]sessionAuthHeader{{Origin: origin, Value: "Bearer " + token}})
}

// runJWT executes one JobJWT for ep and returns that job's test case.
func runJWT(t *testing.T, env *scanEnv, eng httpengine.Engine, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobJWT,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newJWTExecutor(env.st, eng, env.ev, cfg, execLog(), nil)
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

func jwtDetailOf(t *testing.T, tc *domain.TestCase) jwtDetail {
	t.Helper()
	var d jwtDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

func jwtFindingDetail(t *testing.T, f *domain.Finding) jwtDetail {
	t.Helper()
	var d jwtDetail
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatalf("unmarshal finding detail: %v (%s)", err, string(f.Detail))
	}
	return d
}

// ---------------------------------------------------------------------------
// pure parsing / analysis
// ---------------------------------------------------------------------------

func TestParseJWTDecodesHeaderAndClaims(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)
	tok, ok := parseJWT("Bearer "+token, now)
	if !ok {
		t.Fatal("a well-formed token was not parsed")
	}
	if tok.alg != "HS256" || tok.typ != "JWT" || !tok.hasSignature {
		t.Fatalf("header = %+v, want HS256/JWT with a signature", tok)
	}
	if tok.issuer != "https://app.example.test" {
		t.Fatalf("issuer = %q", tok.issuer)
	}
	if tok.expiresAt == nil || tok.issuedAt == nil || tok.expMissing {
		t.Fatalf("timestamps not read: %+v", tok)
	}
	if tok.lifetime < 59*time.Minute || tok.lifetime > 61*time.Minute {
		t.Fatalf("lifetime = %v, want about one hour (exp-iat)", tok.lifetime)
	}
	if strings.Join(tok.claimNames, ",") != "exp,iat,iss,sub" {
		t.Fatalf("claim names = %v", tok.claimNames)
	}
	if len(tok.sensitiveKeys) != 0 {
		t.Fatalf("clean claims reported sensitive keys: %v", tok.sensitiveKeys)
	}
}

// Anything that is not a decodable compact JWS is "no JWT", never a guess.
func TestParseJWTRejectsNonJWT(t *testing.T) {
	now := time.Now()
	for _, raw := range []string{
		"",
		"opaque-api-token",
		"only.two",
		"a.b.c.d",
		"!!!." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`)) + ".sig",
		base64.RawURLEncoding.EncodeToString([]byte(`not json`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`)) + ".sig",
	} {
		if _, ok := parseJWT(raw, now); ok {
			t.Errorf("parseJWT(%q) accepted a non-JWT", raw)
		}
	}
}

func TestAnalyzeJWTTokenCleanTokenHasNoSignals(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)
	tok, ok := parseJWT(token, now)
	if !ok {
		t.Fatal("parse")
	}
	if signals := analyzeJWTToken("https://app.example.test", tok); len(signals) != 0 {
		t.Fatalf("a hygiene-clean token produced %d signal(s): %+v", len(signals), signals)
	}
}

func TestAnalyzeJWTTokenMissingExp(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), map[string]any{
		"sub": "alice", "iss": "https://app.example.test", "iat": now.Add(-time.Hour).Unix(),
	}, jwtTestSignature)
	tok, ok := parseJWT(token, now)
	if !ok {
		t.Fatal("parse")
	}
	if !tok.expMissing {
		t.Fatal("a token with no exp claim was not flagged")
	}
	signals := analyzeJWTToken("https://app.example.test", tok)
	if len(signals) != 1 || signals[0].Kind != jwtKindMissingExp {
		t.Fatalf("signals = %+v, want exactly the missing-exp signal", signals)
	}
	s := signals[0]
	if s.Severity != domain.SeverityMedium || s.Category != jwtCategoryClaims {
		t.Fatalf("signal = %+v, want the medium claims signal", s)
	}
	if s.Key == "" || s.Reason == "" || s.Remediation == "" || s.Title == "" {
		t.Fatalf("signal is not reportable: %+v", s)
	}
}

func TestAnalyzeJWTTokenExcessiveLifetime(t *testing.T) {
	now := time.Now()
	claims := map[string]any{
		"sub": "alice", "iss": "https://app.example.test",
		"iat": now.Add(-time.Hour).Unix(),
		"exp": now.Add(40 * 24 * time.Hour).Unix(), // 40 days from iat
	}
	token := jwtTokenWith(t, hs256Header(), claims, jwtTestSignature)
	tok, ok := parseJWT(token, now)
	if !ok {
		t.Fatal("parse")
	}
	signals := analyzeJWTToken("https://app.example.test", tok)
	if len(signals) != 1 || signals[0].Kind != jwtKindExcessiveLife {
		t.Fatalf("signals = %+v, want exactly the excessive-lifetime signal", signals)
	}
	if signals[0].Severity != domain.SeverityLow {
		t.Fatalf("severity = %q, want low", signals[0].Severity)
	}
	// 30 days or less is not a finding.
	claims["exp"] = now.Add(29 * 24 * time.Hour).Unix()
	token = jwtTokenWith(t, hs256Header(), claims, jwtTestSignature)
	if tok, ok = parseJWT(token, now); !ok {
		t.Fatal("parse")
	}
	if signals := analyzeJWTToken("https://app.example.test", tok); len(signals) != 0 {
		t.Fatalf("a 29-day token produced %+v", signals)
	}
}

// A sensitive claim is reported by NAME only; its value never reaches the
// analysis output.
func TestAnalyzeJWTTokenSensitiveClaimsKeepOnlyTheName(t *testing.T) {
	const secret = "s3cr3t-password-value"
	now := time.Now()
	claims := cleanJWTClaims(now)
	claims["password"] = secret
	claims["user"] = map[string]any{"api_key": "key-1234567890"}
	token := jwtTokenWith(t, hs256Header(), claims, jwtTestSignature)
	tok, ok := parseJWT(token, now)
	if !ok {
		t.Fatal("parse")
	}
	signals := analyzeJWTToken("https://app.example.test", tok)
	if len(signals) != 2 {
		t.Fatalf("signals = %+v, want one per sensitive claim path", signals)
	}
	subjects := map[string]bool{}
	for _, s := range signals {
		if s.Kind != jwtKindSensitive || s.Severity != domain.SeverityHigh {
			t.Fatalf("signal = %+v, want a high sensitive-claim signal", s)
		}
		subjects[s.Subject] = true
	}
	for _, want := range []string{"password", "user.api_key"} {
		if !subjects[want] {
			t.Fatalf("missing subject %q in %+v", want, subjects)
		}
	}
	blob, err := json.Marshal(signals)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{secret, "key-1234567890"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("the analysis output leaked a claim value: %s", blob)
		}
	}
}

func TestJWTAlgNoneIsReported(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, map[string]any{"alg": "none", "typ": "JWT"}, cleanJWTClaims(now), "")
	tok, ok := parseJWT(token, now)
	if !ok {
		t.Fatal("parse")
	}
	if tok.hasSignature {
		t.Fatal("an unsigned token reported a signature")
	}
	signals := analyzeJWTToken("https://app.example.test", tok)
	found := false
	for _, s := range signals {
		if s.Kind == jwtKindAlgNone {
			found = true
			if s.Severity != domain.SeverityHigh {
				t.Fatalf("alg=none severity = %q, want high", s.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("alg=none was not reported: %+v", signals)
	}
}

func TestJWTSensitiveClaimKeyMatching(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"password", true},
		{"user_password", true},
		{"client_secret", true},
		{"apiKey", true},
		{"access_token", true},
		{"refresh_token", true},
		{"ssn", true},
		{"cvv", true},
		{"token_type", false},
		{"pinned", false},
		{"sub", false},
		{"email", false},
	} {
		if got := jwtSensitiveClaimKey(tc.key); got != tc.want {
			t.Errorf("jwtSensitiveClaimKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestJWTResponseDataEquivalent(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", `{"a":1}`, `{"a":1}`, true},
		{"whitespace", "  {\"a\":1}\n", `{"a":1}`, true},
		{"json key order", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{"different values", `{"a":1}`, `{"a":2}`, false},
		{"text vs json", `hello`, `{"a":1}`, false},
		{"empty", ``, ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := jwtResponseDataEquivalent([]byte(tc.a), []byte(tc.b)); got != tc.want {
				t.Fatalf("equivalent(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// The control tokens never carry the original signature and keep the claims.
func TestJWTControlTokens(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)

	tampered, ok := jwtTamperedSignature(token)
	if !ok {
		t.Fatal("tampered signature not built")
	}
	_, _, sig, ok := splitJWTParts(tampered)
	if !ok || len(sig) != len(jwtTestSignature) || sig == jwtTestSignature {
		t.Fatalf("tampered signature = %q, want a same-length replacement", sig)
	}

	none, ok := jwtAlgNone(token)
	if !ok {
		t.Fatal("alg=none token not built")
	}
	h, p, s, ok := splitJWTParts(none)
	if !ok || s != "" {
		t.Fatalf("alg=none token = %q, want an empty signature", none)
	}
	headerBytes, ok := decodeJWTSegment(h)
	if !ok {
		t.Fatal("decode header")
	}
	header, ok := decodeJWTJSON(headerBytes)
	if !ok || !strings.EqualFold(strings.TrimSpace(asString(header["alg"])), "none") {
		t.Fatalf("alg=none header = %v", header)
	}
	// The payload is carried over verbatim, so the controls differ only in the
	// header/signature — exactly what the differential needs.
	if p != strings.Split(token, ".")[1] {
		t.Fatal("the alg=none control changed the claims")
	}

	// An already-unsigned token has no second control to build.
	unsigned := jwtTokenWith(t, map[string]any{"alg": "none"}, cleanJWTClaims(now), "")
	if _, ok := jwtAlgNone(unsigned); ok {
		t.Fatal("alg=none was built from an already-unsigned token")
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// ---------------------------------------------------------------------------
// executor against a real server
// ---------------------------------------------------------------------------

// (a) A properly validated token with exp: no finding at all.
func TestJWTValidatedTokenProducesNoFinding(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)
	srv := newJWTSite(t, jwtSiteStrict, token, nil)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, token), ep, ExecutorConfig{})

	d := jwtDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (%s)", d.Verdict, d.Reason)
	}
	if len(d.Signals) != 0 {
		t.Fatalf("signals = %+v, want none", d.Signals)
	}
	if d.Validation == nil || d.Validation.BaselineStatus != http.StatusOK {
		t.Fatalf("validation = %+v, want an authenticated baseline", d.Validation)
	}
	if !d.Validation.AnonymousRejected {
		t.Fatalf("anonymous control = %+v, want a rejection", d.Validation)
	}
	for _, c := range d.Validation.Controls {
		if !c.Rejected {
			t.Fatalf("control %+v was not rejected by a verifying server", c)
		}
	}
	if len(d.Validation.Controls) != 2 {
		t.Fatalf("controls = %+v, want the signature and alg=none controls", d.Validation.Controls)
	}
	if findings := scanFindings(t, env); len(findings) != 0 {
		t.Fatalf("a validating server produced findings: %+v", findings)
	}
	if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("test case = %s/%s, want completed/success", tc.Status, tc.Outcome)
	}
	// The full differential is stored as evidence: baseline + anonymous + two
	// controls, each a request/response pair.
	if len(tc.EvidenceIDs) != 8 {
		t.Fatalf("evidence = %d, want 8 (4 pairs)", len(tc.EvidenceIDs))
	}
}

// (b) A token with no exp claim is a finding even when the server is strict.
func TestJWTMissingExpProducesFinding(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), map[string]any{
		"sub": "alice", "iss": "https://app.example.test", "iat": now.Add(-time.Minute).Unix(),
	}, jwtTestSignature)
	srv := newJWTSite(t, jwtSiteStrict, token, nil)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, token), ep, ExecutorConfig{})

	findings := findingsByClass(t, env, domain.VulnJWT)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly the missing-exp finding (%+v)", len(findings), findings)
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed || f.Severity != domain.SeverityMedium {
		t.Fatalf("finding = %s/%s, want confirmed/medium", f.Verdict, f.Severity)
	}
	fd := jwtFindingDetail(t, f)
	if len(fd.Signals) != 1 || fd.Signals[0].Kind != jwtKindMissingExp {
		t.Fatalf("finding signals = %+v", fd.Signals)
	}
	if !strings.Contains(f.Title, "127.0.0.1") {
		t.Fatalf("finding title %q does not name the origin host", f.Title)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("the finding carries no evidence")
	}
	if d := jwtDetailOf(t, tc); d.Verdict != domain.VerdictConfirmed || len(d.Signals) != 1 {
		t.Fatalf("test case detail = %+v", d)
	}
}

// (c) A server that accepts a modified signature: a confirming finding whose
// evidence and detail never contain the token or its signature.
func TestJWTServerAcceptingInvalidSignatureProducesRedactedFinding(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)
	payloadSeg := strings.Split(token, ".")[1]
	srv := newJWTSite(t, jwtSiteLax, token, nil)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, token), ep, ExecutorConfig{})

	d := jwtDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (%s)", d.Verdict, d.Reason)
	}
	if d.Validation == nil || d.Validation.AnonymousRejected != true {
		t.Fatalf("validation = %+v, want the anonymous control rejected (a real auth boundary)", d.Validation)
	}
	byKind := map[string]*domain.Finding{}
	for _, f := range findingsByClass(t, env, domain.VulnJWT) {
		fd := jwtFindingDetail(t, f)
		if len(fd.Signals) != 1 {
			t.Fatalf("finding detail signals = %+v", fd.Signals)
		}
		byKind[fd.Signals[0].Kind] = f
		if f.Verdict != domain.VerdictConfirmed || f.Severity != domain.SeverityCritical {
			t.Fatalf("finding %q = %s/%s, want confirmed/critical", f.Title, f.Verdict, f.Severity)
		}
		if f.Summary == "" || len(f.EvidenceIDs) == 0 {
			t.Fatalf("finding %q is not reportable: %+v", f.Title, f)
		}
	}
	if byKind[jwtKindSigNotChecked] == nil {
		t.Fatalf("no signature-validation finding: %v", byKind)
	}
	if byKind[jwtKindUnsignedTaken] == nil {
		t.Fatalf("no alg=none finding: %v", byKind)
	}

	// The token, its signature and its payload must not survive anywhere.
	secrets := []string{token, jwtTestSignature, payloadSeg}
	blobs := [][]byte{tc.Detail, []byte(tc.Note)}
	for _, f := range scanFindings(t, env) {
		blobs = append(blobs, f.Detail, []byte(f.Title), []byte(f.Summary))
	}
	for _, id := range tc.EvidenceIDs {
		_, body := env.evidenceBlob(id)
		blobs = append(blobs, []byte(body))
	}
	for _, blob := range blobs {
		for _, secret := range secrets {
			if strings.Contains(string(blob), secret) {
				t.Fatalf("a persisted record leaked the token material %q:\n%s", secret, blob)
			}
		}
	}
	// The request evidence still proves what was sent: the Authorization header
	// is present but redacted.
	if _, body := env.evidenceBlob(tc.EvidenceIDs[0]); !strings.Contains(body, "Authorization: <redacted>") {
		t.Fatalf("the stored request does not show a redacted Authorization header:\n%s", body)
	}
}

// An endpoint the scan's own session authenticates with a COOKIE, not the
// token, must never look like a server that accepts forged tokens: the
// baseline is sent with the token only, so it fails and no differential is
// judged at all.
func TestJWTCookieAuthenticatedEndpointProducesNoValidationFinding(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)
	// This server ignores Authorization entirely: only the session cookie
	// authenticates it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if c, err := r.Cookie("sid"); err == nil && c.Value == "authed" {
			_, _ = w.Write([]byte(jwtSiteBody))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"login required"}`))
	}))
	t.Cleanup(srv.Close)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	eng := newScopedEngine(noFollowClient(t), openScope()).
		WithSessionCookies([]*http.Cookie{{Name: "sid", Value: "authed", Domain: "127.0.0.1", Path: "/"}}).
		WithSessionAuthHeaders([]sessionAuthHeader{{Origin: srv.URL, Value: "Bearer " + token}})
	tc := runJWT(t, env, eng, ep, ExecutorConfig{})

	d := jwtDetailOf(t, tc)
	if d.Validation == nil || d.Validation.BaselineStatus != http.StatusUnauthorized {
		t.Fatalf("validation = %+v, want an unauthenticated (token-only) baseline", d.Validation)
	}
	if len(d.Validation.Controls) != 0 {
		t.Fatalf("controls = %+v, want none: the baseline never proved the token works", d.Validation.Controls)
	}
	if findings := scanFindings(t, env); len(findings) != 0 {
		t.Fatalf("a cookie-authenticated endpoint produced findings: %+v", findings)
	}
}

// A public endpoint answers the same data with no credential at all, so an
// invalid token proves nothing. This is the false positive that must not be
// reported.
func TestJWTPublicEndpointProducesNoValidationFinding(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)
	srv := newJWTSite(t, jwtSitePublic, token, nil)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, token), ep, ExecutorConfig{})

	d := jwtDetailOf(t, tc)
	if d.Validation == nil || !d.Validation.AnonymousSameData {
		t.Fatalf("validation = %+v, want the public-endpoint note", d.Validation)
	}
	if len(d.Signals) != 0 {
		t.Fatalf("a public endpoint produced signals: %+v", d.Signals)
	}
	if findings := scanFindings(t, env); len(findings) != 0 {
		t.Fatalf("a public endpoint produced findings: %+v", findings)
	}
}

// (d) Two endpoints on ONE origin: the finding does not multiply, and the
// second run absorbs into the same row (occurrences/evidence union).
func TestJWTDeduplicatesAcrossEndpointsOnSameOrigin(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), map[string]any{
		"sub": "alice", "iss": "https://app.example.test", "iat": now.Add(-time.Minute).Unix(),
	}, jwtTestSignature)
	var hits atomic.Int32
	srv := newJWTSite(t, jwtSiteStrict, token, &hits)

	env := newScanEnv(t)
	eng := jwtEngineFor(t, srv.URL, token)
	// /login denies even the authenticated baseline, so the differential has to
	// fall back to another GET endpoint on the same origin.
	login := env.endpoint(srv.URL+"/login", domain.MethodGET)
	me := env.endpoint(srv.URL+"/api/me", domain.MethodGET)

	first := runJWT(t, env, eng, login, ExecutorConfig{})
	afterFirst := len(scanFindings(t, env))
	if afterFirst != 1 {
		t.Fatalf("findings = %d after the first run, want 1", afterFirst)
	}
	if d := jwtDetailOf(t, first); d.Validation == nil || d.Validation.EndpointURL != me.URL {
		t.Fatalf("validation = %+v, want the fallback endpoint %s", d.Validation, me.URL)
	}
	second := runJWT(t, env, eng, me, ExecutorConfig{})

	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d after a second endpoint on the same origin, want 1 (deduplicated)", len(findings))
	}
	f := findings[0]
	fd := jwtFindingDetail(t, f)
	if fd.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", fd.Occurrences)
	}
	if len(fd.TestCaseIDs) != 2 {
		t.Fatalf("test cases = %d, want both contributing cases", len(fd.TestCaseIDs))
	}
	wantEvidence := len(first.EvidenceIDs) + len(second.EvidenceIDs)
	if len(f.EvidenceIDs) != wantEvidence {
		t.Fatalf("finding evidence = %d, want %d (unioned)", len(f.EvidenceIDs), wantEvidence)
	}
}

// Throttling is backpressure, not a token verdict: nothing is judged from it.
func TestJWTThrottledDifferentialJudgesNothing(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), cleanJWTClaims(now), jwtTestSignature)
	srv := newJWTSite(t, jwtSiteThrottle, token, nil)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, token), ep, ExecutorConfig{})

	d := jwtDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want throttled", d)
	}
	if len(d.Signals) != 0 {
		t.Fatalf("a throttled target produced signals: %+v", d.Signals)
	}
	if findings := scanFindings(t, env); len(findings) != 0 {
		t.Fatalf("a throttled target produced findings: %+v", findings)
	}
}

// Throttling withholds only the differential: a claim-level finding is proven
// offline and is still reported, with the note saying the comparison did not
// run.
func TestJWTThrottledDifferentialKeepsClaimsFinding(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), map[string]any{
		"sub": "alice", "iss": "https://app.example.test", "iat": now.Add(-time.Minute).Unix(),
	}, jwtTestSignature)
	srv := newJWTSite(t, jwtSiteThrottle, token, nil)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, token), ep, ExecutorConfig{})

	d := jwtDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want throttled", d)
	}
	if len(d.Signals) != 1 || d.Signals[0].Kind != jwtKindMissingExp {
		t.Fatalf("signals = %+v, want exactly the missing-exp signal", d.Signals)
	}
	findings := findingsByClass(t, env, domain.VulnJWT)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the claims finding", len(findings))
	}
	if !strings.Contains(tc.Note, "throttled") {
		t.Fatalf("note = %q, want it to say the differential was withheld", tc.Note)
	}
	if !strings.Contains(tc.Note, "still inspected") {
		t.Fatalf("note = %q, want it to say the claims were still inspected", tc.Note)
	}
}

// No bearer JWT for this origin: skip, and send nothing at all.
func TestJWTNoBearerTokenSkipsWithoutRequests(t *testing.T) {
	var hits atomic.Int32
	srv := newJWTSite(t, jwtSiteStrict, "unused", &hits)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	// The engine carries a token for a DIFFERENT origin, so this origin has
	// none.
	eng := jwtEngineFor(t, "https://other.example.test", "aaaaa.bbbbb.ccccc")
	tc := runJWT(t, env, eng, ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "no bearer JWT") {
		t.Fatalf("skip note = %q, want it to explain the missing token", tc.Note)
	}
	if hits.Load() != 0 {
		t.Fatalf("target hits = %d, want 0", hits.Load())
	}
	if findings := scanFindings(t, env); len(findings) != 0 {
		t.Fatalf("a skipped check produced findings: %+v", findings)
	}
}

// A bearer credential that is not a JWT (an opaque API token) is a skip, not a
// finding and not an error.
func TestJWTNonJWTBearerSkipsWithoutRequests(t *testing.T) {
	var hits atomic.Int32
	srv := newJWTSite(t, jwtSiteStrict, "unused", &hits)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, "opaque-api-token"), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped || !strings.Contains(tc.Note, "not a JWT") {
		t.Fatalf("test case = %q / %q, want a not-a-JWT skip", tc.Status, tc.Note)
	}
	if hits.Load() != 0 {
		t.Fatalf("target hits = %d, want 0", hits.Load())
	}
}

// A state-changing endpoint is skipped without a single request.
func TestJWTSkipsStateChangingEndpoint(t *testing.T) {
	var hits atomic.Int32
	srv := newJWTSite(t, jwtSiteLax, "aaaaa.bbbbb.ccccc", &hits)

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/orders", domain.MethodPOST)
	tc := runJWT(t, env, jwtEngineFor(t, srv.URL, "aaaaa.bbbbb.ccccc"), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "state-changing") {
		t.Fatalf("skip note = %q, want it to explain the method guard", tc.Note)
	}
	if hits.Load() != 0 {
		t.Fatalf("target hits = %d, want 0", hits.Load())
	}
}

// A URL-only job (no discovered endpoint) is still actionable.
func TestJWTURLEOnlyJob(t *testing.T) {
	now := time.Now()
	token := jwtTokenWith(t, hs256Header(), map[string]any{
		"sub": "alice", "iss": "https://app.example.test", "iat": now.Add(-time.Minute).Unix(),
	}, jwtTestSignature)
	srv := newJWTSite(t, jwtSiteStrict, token, nil)

	env := newScanEnv(t)
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobJWT,
		Target: domain.JobTarget{URL: srv.URL + "/api/me"}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newJWTExecutor(env.st, jwtEngineFor(t, srv.URL, token), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (err %v), want 1", len(cases), err)
	}
	if d := jwtDetailOf(t, cases[0]); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed", d.Verdict)
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// One job per origin that carries a Bearer JWT; another origin (no token) and
// the skip switch produce nothing.
func TestEnqueueJWTProbesPerOrigin(t *testing.T) {
	for _, tc := range []struct {
		name      string
		skip      bool
		state     bool
		want      int
		wantHosts []string
	}{
		{name: "enabled", state: true, want: 1, wantHosts: []string{"app.example.test"}},
		{name: "skipped", skip: true, state: true, want: 0},
		{name: "no session", state: false, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, q := memory.New(), queue.NewMemory()
			now := time.Now()
			sessID := domain.ID("")
			if tc.state {
				statePath := writeAuthState(t, []any{map[string]any{
					"origin": "https://app.example.test",
					"localStorage": []any{
						map[string]any{"name": "access_token", "value": "aaaaa.bbbbb.ccccc"},
					},
				}})
				sess := &domain.Session{ID: domain.NewID(), ScanID: domain.NewID(),
					Mode: domain.AuthExisting, State: domain.SessionActive, StatePath: statePath,
					CreatedAt: now, UpdatedAt: now}
				if err := st.Sessions().Create(ctx, sess); err != nil {
					t.Fatal(err)
				}
				sessID = sess.ID
			}
			sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
				SessionID: sessID, Config: domain.ScanConfig{SkipJWT: tc.skip}, CreatedAt: now, UpdatedAt: now}
			if err := st.Scans().Create(ctx, sc); err != nil {
				t.Fatal(err)
			}
			for _, raw := range []string{
				"https://app.example.test/",
				"https://app.example.test/api/items?page=2",
				"https://other.example.test/",
			} {
				ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: raw,
					Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}
			ctrl := NewController(st, q, execLog(), "test", Options{})
			t.Cleanup(ctrl.Shutdown)
			ctrl.enqueueJWTProbes(ctx, sc.ID)

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
			hosts := map[string]bool{}
			for _, job := range jobs {
				if job.Type != domain.JobJWT || job.Priority != jwtPriority {
					t.Fatalf("job = %+v, want a priority-%d jwt job", job, jwtPriority)
				}
				if job.Target.EndpointID.Empty() {
					t.Fatalf("job %s carries no endpoint id", job.ID)
				}
				hosts[jwtOrigin(job.Target.URL)] = true
			}
			for _, want := range tc.wantHosts {
				if !hosts["https://"+want] {
					t.Fatalf("origins = %v, want %s", hosts, want)
				}
			}
			if len(hosts) != len(tc.wantHosts) {
				t.Fatalf("origins = %v, want only %v", hosts, tc.wantHosts)
			}
		})
	}
}
