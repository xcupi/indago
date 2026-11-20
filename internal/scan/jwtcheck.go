package scan

// Read-only JWT token validation and hygiene check.
//
// One job acts on ONE origin (scheme://host[:port]) that the scan's own session
// carries a Bearer JWT for. The job does three independent things:
//
//  1. CLAIMS/HEADER HYGIENE (offline, no request): decode the token's header and
//     payload and report what the token itself proves — no exp claim, an
//     expiry beyond 30 days, secret material placed inside the payload, or an
//     unverified "none" algorithm.
//  2. KEY-SOURCE HYGIENE (offline, no request): the same decoded header, read as
//     a key-selection surface — a kid whose shape is a filesystem path, an
//     injection fragment or a URL; a jku/x5u reference that is cleartext,
//     non-HTTP, credential-bearing, relative, or foreign to both the token's
//     issuer and this application; header-embedded key material (jwk/x5c); and a
//     header object that repeats a verification-relevant parameter (alg, kid,
//     jku, ...), which two JSON parsers can read differently. These are
//     preconditions, not demonstrations of exploitability: nothing here proves
//     the verifier resolves the value the way the shape suggests, so they are
//     reported at medium confidence and say so in the reason.
//  3. VALIDATION DIFFERENTIAL (bounded, read-only GETs): against ONE
//     authenticated GET endpoint on that origin, compare the honest baseline
//     with an anonymous control and two invalid-token controls (a modified
//     signature, and the same claims re-signed with alg=none). The server is
//     expected to answer 401/403; a 200 carrying the SAME data the
//     authenticated baseline returned is the finding.
//
// Boundaries:
//   - Read-only: GET/HEAD only, never a state-changing endpoint, never a body.
//     The differential sends a credential the server is supposed to refuse; it
//     never forges a *valid* token and never touches another principal.
//   - No request is ever aimed at a jku/x5u location, and no header-mutated
//     control is added for kid: fetching an attacker-named key URL is
//     exfiltration, and a kid-tampered token would prove no more than the
//     modified-signature control that already runs. The key-source half is
//     therefore strictly offline — the request count of this engine is
//     unchanged by it.
//   - Token-only requests: every differential request carries the token and no
//     cookies. The baseline must show the token ITSELF is a working credential,
//     and a control's 200 must be attributable to the token — never to a
//     session cookie that would authenticate the request anyway.
//   - Bounded: at most maxJWTOrigins origins per scan, one job per origin,
//     maxJWTEndpointsPerOrigin baseline attempts, and exactly one anonymous plus
//     two invalid-token controls per endpoint.
//   - Deterministic: every signal is a pure function of the token's bytes or of
//     the status/body the server itself returned. No browser, no LLM
//     (AGENTS.md §2.5).
//   - No secret retention: the token's signature, payload bytes and raw value
//     are NEVER written to the detail, the finding or the evidence. Only a
//     SHA-256 fingerprint, the algorithm/kid, timestamps, claim NAMES and
//     sensitive-claim key paths are recorded; stored request evidence has
//     Authorization (and cookie values) redacted by dumpRequest.
//   - Throttling is respected: a 429/503 anywhere in the differential stops it
//     and nothing about token validation is judged from it.
//
// Where the token comes from: the scan's own session material
// (sessionAuthHeaders — a JWT in SPA localStorage, or in a token-named cookie).
// That is deliberately the ONLY source. Stored request evidence has its
// Authorization header redacted by design (dumpRequest), so a discovered
// request can never hand this engine a live credential; a scan with no bearer
// token therefore sends nothing at all.
//
// A confirming differential is real proof of an authentication bypass: the
// server answered with the authenticated data to a token it must have rejected.
// The anonymous control is what keeps a public endpoint from being misreported
// — if the same data comes back with no credential at all, an invalid token
// proves nothing and no validation finding is made.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"reflect"
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
	jwtEngine = "jwt_validation"

	// jwtCategoryClaims / jwtCategoryHeader / jwtCategoryValidation separate the
	// finding families this one engine reports, so a report/UI can group them:
	// claims and header shape are offline observations about the token, while
	// validation is what the server did with a refused token.
	jwtCategoryClaims     = "claims"
	jwtCategoryHeader     = "header"
	jwtCategoryValidation = "validation"

	// maxJWTOrigins bounds the pass: one job per origin carrying a token.
	maxJWTOrigins = 10
	// maxJWTEndpointsPerOrigin bounds the authenticated-baseline search inside
	// one job. A page that does not return 200 to this session is not a usable
	// comparison point.
	maxJWTEndpointsPerOrigin = 3
	// jwtPriority runs among the cheap passive passes (higher number = earlier,
	// see the queue): its claims half is offline and its differential is four
	// GETs, so it belongs before the payload-bearing engines.
	jwtPriority = 34
	// jwtMaxTokenBytes caps what is decoded. A token larger than this is not a
	// credential worth parsing and is skipped rather than buffered.
	jwtMaxTokenBytes = 8192
	// jwtExcessiveLifetime is the hygiene ceiling for a token's total lifetime.
	jwtExcessiveLifetime = 30 * 24 * time.Hour
)

// Signal kinds. Stable strings so a report/UI can group them.
const (
	jwtKindMissingExp    = "jwt_missing_exp_claim"
	jwtKindExcessiveLife = "jwt_excessive_lifetime"
	jwtKindSensitive     = "jwt_sensitive_claim"
	jwtKindAlgNone       = "jwt_alg_none"
	jwtKindSigNotChecked = "jwt_signature_not_validated"
	jwtKindUnsignedTaken = "jwt_unsigned_token_accepted"
	// Key-source hygiene. Every one of these is an observation about the
	// token's header bytes, never a claim that the server acted on them.
	jwtKindKidPath        = "jwt_kid_path_reference"
	jwtKindKidInjection   = "jwt_kid_injection_shape"
	jwtKindKidURL         = "jwt_kid_url_reference"
	jwtKindUntrustedKey   = "jwt_untrusted_key_reference"
	jwtKindEmbeddedKey    = "jwt_header_embedded_key"
	jwtKindDuplicateParam = "jwt_duplicate_header_param"
)

// jwtSignal is one observed weakness. Its Key identifies the
// (origin, issuer, category, subject) tuple, so a second endpoint on the same
// origin absorbs into the same finding instead of adding a row.
type jwtSignal struct {
	Key         string            `json:"key"`
	Category    string            `json:"category"`
	Kind        string            `json:"kind"`
	Subject     string            `json:"subject"`
	Severity    domain.Severity   `json:"severity"`
	Confidence  domain.Confidence `json:"confidence"`
	Reason      string            `json:"reason"`
	Remediation string            `json:"remediation"`
	// Observed is a value-free summary (an algorithm, a lifetime, a claim
	// NAME). It never contains a signature, a claim VALUE or the token.
	Observed string `json:"observed,omitempty"`
	Title    string `json:"title"`
}

// jwtTokenSummary is the redaction-safe view of the inspected token that is
// persisted. It deliberately has no field that can hold the token, its
// signature or a claim value.
type jwtTokenSummary struct {
	// Fingerprint identifies the token across runs without being usable as
	// one: the first 16 hex characters of its SHA-256.
	Fingerprint  string `json:"fingerprint,omitempty"`
	Alg          string `json:"alg,omitempty"`
	Typ          string `json:"typ,omitempty"`
	Kid          string `json:"kid,omitempty"`
	HasSignature bool   `json:"has_signature"`
	// JKU / X5U are the key locations the header names, reduced to
	// scheme://host/path: userinfo, query and fragment are dropped so a signed
	// URL or an embedded credential can never be copied into a finding.
	JKU         string     `json:"jku,omitempty"`
	X5U         string     `json:"x5u,omitempty"`
	EmbeddedKey string     `json:"embedded_key,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	IssuedAt    *time.Time `json:"issued_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// LifetimeHours is exp-iat when iat is present, otherwise the time left
	// before exp at inspection time. 0 when exp is absent/unparseable.
	LifetimeHours float64  `json:"lifetime_hours,omitempty"`
	Claims        []string `json:"claims,omitempty"`
}

// jwtControlResult records one invalid-token control's outcome.
type jwtControlResult struct {
	Kind       string `json:"kind"`
	Status     int    `json:"status"`
	Rejected   bool   `json:"rejected"`
	Equivalent bool   `json:"equivalent,omitempty"`
	Note       string `json:"note,omitempty"`
}

// jwtValidationDetail records the read-only differential.
type jwtValidationDetail struct {
	EndpointURL       string             `json:"endpoint_url,omitempty"`
	BaselineStatus    int                `json:"baseline_status,omitempty"`
	AnonymousStatus   int                `json:"anonymous_status,omitempty"`
	AnonymousRejected bool               `json:"anonymous_rejected,omitempty"`
	AnonymousSameData bool               `json:"anonymous_same_data,omitempty"`
	Controls          []jwtControlResult `json:"controls,omitempty"`
	Note              string             `json:"note,omitempty"`
}

// jwtDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type jwtDetail struct {
	Engine      string               `json:"engine"`
	URL         string               `json:"url"`
	Origin      string               `json:"origin"`
	Issuer      string               `json:"issuer,omitempty"`
	Method      string               `json:"method"`
	DedupKey    string               `json:"dedup_key,omitempty"`
	Occurrences int                  `json:"occurrences,omitempty"`
	Verdict     domain.Verdict       `json:"verdict"`
	Severity    domain.Severity      `json:"severity,omitempty"`
	Confidence  domain.Confidence    `json:"confidence,omitempty"`
	Reason      string               `json:"reason,omitempty"`
	Token       *jwtTokenSummary     `json:"token,omitempty"`
	Validation  *jwtValidationDetail `json:"validation,omitempty"`
	Signals     []jwtSignal          `json:"signals,omitempty"`
	Throttled   bool                 `json:"throttled,omitempty"`
	Skipped     bool                 `json:"skipped,omitempty"`
	SkipReason  string               `json:"skip_reason,omitempty"`
	TestCaseIDs []domain.ID          `json:"test_case_ids,omitempty"`
	EvidenceIDs []domain.ID          `json:"evidence_ids,omitempty"`
}

// ---------------------------------------------------------------------------
// pure parsing / analysis
// ---------------------------------------------------------------------------

// jwtToken is the decoded, redaction-safe view of one compact JWS. The raw
// token, its signature and its claim VALUES are deliberately not fields: this
// value is what reaches the detail and the finding.
type jwtToken struct {
	fingerprint  string
	alg          string
	typ          string
	kid          string
	hasSignature bool
	// kidRaw is the header's kid exactly as decoded. kid is stored sanitized for
	// display, but the shape checks must see the bytes (a NUL or a control
	// character is part of what makes a kid file-shaped), and it is never
	// serialized.
	kidRaw string
	// jku / x5u are sanitized and length-bounded; they are analysed offline and
	// only ever stored as a scheme://host/path label.
	jku      string
	x5u      string
	hasJWK   bool
	x5cCount int
	// duplicateParams lists verification-relevant header parameters that the
	// header object repeats.
	duplicateParams []string
	issuer          string
	issuedAt        *time.Time
	notBefore       *time.Time
	expiresAt       *time.Time
	lifetime        time.Duration
	expMissing      bool
	claimNames      []string
	sensitiveKeys   []string
}

// jwtOrigin is the scheme://host[:port] identity of a URL — the same
// correlation unit the passive header pass uses (securityHeadersOrigin),
// reused verbatim so two origin-scoped engines can never disagree about what
// an origin is.
func jwtOrigin(raw string) string { return securityHeadersOrigin(raw) }

// jwtDedupKey is the finding identity: one row per origin, issuer, category
// (claims/validation) and subject (claim or control name).
func jwtDedupKey(origin, issuer, category, subject string) string {
	return jwtEngine + "\x00" + strings.ToLower(origin) + "\x00" + strings.ToLower(issuer) +
		"\x00" + category + "\x00" + strings.ToLower(subject)
}

// jwtOriginKey identifies the origin-level inspection recorded in a
// TestCase.Detail (the finding-level keys are the per-subject ones above).
func jwtOriginKey(origin string) string {
	return jwtEngine + "\x00" + strings.ToLower(origin)
}

// splitJWTParts accepts a compact JWS, with or without a "Bearer " prefix, and
// returns its three segments. The signature may be empty (alg=none).
func splitJWTParts(raw string) (header, payload, signature string, ok bool) {
	token := strings.TrimSpace(raw)
	if token == "" || len(token) > jwtMaxTokenBytes {
		return "", "", "", false
	}
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	if len(parts[2]) > jwtMaxTokenBytes {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// decodeJWTSegment decodes one base64url segment. Compact JWS uses unpadded
// base64url; padded input is tolerated because some issuers (and hand-written
// fixtures) pad it.
func decodeJWTSegment(seg string) ([]byte, bool) {
	if seg == "" || len(seg) > jwtMaxTokenBytes {
		return nil, false
	}
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	if b, err := base64.URLEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	return nil, false
}

// decodeJWTJSON decodes a segment as a JSON object, keeping numbers exact.
func decodeJWTJSON(raw []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, false
	}
	return m, true
}

// jwtFingerprint is a stable, non-reversible identifier for a token.
func jwtFingerprint(raw string) string {
	token := strings.TrimSpace(raw)
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// parseJWT decodes one Bearer credential. ok is false when the value is not a
// compact JWS we can reason about (an opaque API token, a JWE, malformed
// base64) — the caller then skips instead of guessing.
//
// now decides only the "time left before exp" fallback used when there is no
// iat claim to measure a total lifetime from.
func parseJWT(raw string, now time.Time) (*jwtToken, bool) {
	headerSeg, payloadSeg, sigSeg, ok := splitJWTParts(raw)
	if !ok {
		return nil, false
	}
	headerBytes, ok := decodeJWTSegment(headerSeg)
	if !ok {
		return nil, false
	}
	payloadBytes, ok := decodeJWTSegment(payloadSeg)
	if !ok {
		return nil, false
	}
	header, ok := decodeJWTJSON(headerBytes)
	if !ok {
		return nil, false
	}
	claims, ok := decodeJWTJSON(payloadBytes)
	if !ok {
		return nil, false
	}

	tok := &jwtToken{
		fingerprint:  jwtFingerprint(raw),
		alg:          jwtStringClaim(header, "alg", 32),
		typ:          jwtStringClaim(header, "typ", 32),
		kid:          jwtStringClaim(header, "kid", 128),
		hasSignature: strings.TrimSpace(sigSeg) != "",
		jku:          jwtStringClaim(header, "jku", 512),
		x5u:          jwtStringClaim(header, "x5u", 512),
		issuer:       jwtStringClaim(claims, "iss", 256),
	}
	// The kid shape checks must see the raw value, not the sanitized one: a NUL
	// or a control byte is part of what makes a kid look like a file path.
	if kid, ok := header["kid"].(string); ok {
		tok.kidRaw = kid
	}
	if _, ok := header["jwk"]; ok {
		tok.hasJWK = true
	}
	if chain, ok := header["x5c"].([]any); ok {
		tok.x5cCount = len(chain)
	}
	tok.duplicateParams = jwtDuplicateHeaderParams(headerBytes)
	if ts, ok := jwtTimeClaim(claims, "iat"); ok {
		tok.issuedAt = &ts
	}
	if ts, ok := jwtTimeClaim(claims, "nbf"); ok {
		tok.notBefore = &ts
	}
	if ts, ok := jwtTimeClaim(claims, "exp"); ok {
		tok.expiresAt = &ts
		switch {
		case tok.issuedAt != nil && ts.After(*tok.issuedAt):
			tok.lifetime = ts.Sub(*tok.issuedAt)
		case ts.After(now):
			tok.lifetime = ts.Sub(now)
		}
	} else {
		tok.expMissing = true
	}
	tok.claimNames = jwtClaimNames(claims)
	tok.sensitiveKeys = jwtSensitiveClaims(claims)
	return tok, true
}

// jwtStringClaim reads one string claim, bounded and control-character free so
// a hostile token cannot inject layout into a finding or a log line.
func jwtStringClaim(m map[string]any, key string, max int) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return sanitizeJWTText(v, max)
}

// sanitizeJWTText strips control characters and bounds the length.
func sanitizeJWTText(v string, max int) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(v))
	if len(v) > max {
		v = v[:max]
	}
	return v
}

// jwtTimeClaim reads a NumericDate claim (seconds since the epoch).
func jwtTimeClaim(m map[string]any, key string) (time.Time, bool) {
	sec, ok := jwtNumeric(m[key])
	if !ok || math.IsNaN(sec) || math.IsInf(sec, 0) || sec <= 0 || sec > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(int64(sec), 0).UTC(), true
}

func jwtNumeric(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	case float64:
		return n, true
	}
	return 0, false
}

// jwtClaimNames is the sorted list of ROOT claim names. Names only, never
// values.
func jwtClaimNames(claims map[string]any) []string {
	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, sanitizeJWTText(k, 64))
	}
	sort.Strings(names)
	return names
}

// jwtSensitiveClaimKeys are the claim names (and name tokens) that mean secret
// material is sitting in a base64url payload. Values are never read or kept —
// only the key is evidence.
var jwtSensitiveClaimKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true,
	"secret": true, "clientsecret": true, "client_secret": true,
	"apikey": true, "api_key": true, "api-key": true,
	"access_token": true, "access-token": true, "refreshtoken": true,
	"refresh_token": true, "refresh-token": true, "idtoken": true, "id_token": true,
	"private_key": true, "privatekey": true, "private-key": true,
	"ssn": true, "credit_card": true, "creditcard": true, "credit-card": true,
	"card_number": true, "cardnumber": true, "card-number": true,
	"cvv": true, "cvc": true, "pin": true, "session_id": true, "sessionid": true,
}

// jwtSensitiveClaimKey reports whether a claim NAME means secret material. It
// matches the whole normalised name (so "access_token" matches but
// "token_type" does not) and, for the unambiguous words, any name token (so
// "user_password" matches but "pinned" does not).
func jwtSensitiveClaimKey(key string) bool {
	full := strings.ToLower(strings.TrimSpace(key))
	if jwtSensitiveClaimKeys[full] {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(full)
	if jwtSensitiveClaimKeys[compact] {
		return true
	}
	for _, tok := range strings.FieldsFunc(full, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		switch tok {
		case "password", "passwd", "pwd", "secret", "ssn", "cvv", "cvc":
			return true
		}
	}
	return false
}

// jwtSensitiveClaims walks the payload (bounded depth, root first) and returns
// the PATH of every sensitive claim name. A value never leaves this function.
func jwtSensitiveClaims(claims map[string]any) []string {
	var out []string
	var walk func(m map[string]any, prefix string, depth int)
	walk = func(m map[string]any, prefix string, depth int) {
		if depth > 3 {
			return
		}
		for _, k := range sortedKeys(m) {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if jwtSensitiveClaimKey(k) {
				out = append(out, sanitizeJWTText(path, 128))
			}
			if child, ok := m[k].(map[string]any); ok {
				walk(child, path, depth+1)
			}
		}
	}
	walk(claims, "", 0)
	sort.Strings(out)
	return dedupeStrings(out)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// header hygiene: kid shape, key references, repeated parameters
// ---------------------------------------------------------------------------

// jwtGuardedHeaderParams are the JWS header parameters whose duplication can
// change how a token is verified. A duplicated extension parameter nobody reads
// is noise; a duplicated alg/kid/jku is a parser differential.
var jwtGuardedHeaderParams = map[string]bool{
	"alg": true, "kid": true, "jku": true, "x5u": true, "x5c": true, "jwk": true,
	"crit": true, "typ": true, "cty": true, "enc": true, "zip": true,
}

// jwtDuplicateHeaderParams reports the guarded parameters that appear more than
// once in the RAW header object. encoding/json keeps the last occurrence and
// discards the rest, while other JOSE stacks keep the first, so two layers can
// verify different headers from the same token. Pure: it walks the bytes it was
// given and never re-serializes them.
func jwtDuplicateHeaderParams(raw []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	counts := make(map[string]int)
	depth, expectKey := 1, true
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				depth++
				expectKey = false
			default:
				depth--
				if depth == 1 {
					// A container used as a value just closed: the next
					// depth-1 token is a key again.
					expectKey = true
				}
			}
		case string:
			if depth == 1 {
				if expectKey {
					counts[t]++
					expectKey = false
				} else {
					expectKey = true
				}
			}
		default:
			if depth == 1 && !expectKey {
				expectKey = true
			}
		}
	}
	var out []string
	for name, n := range counts {
		lower := strings.ToLower(name)
		if n > 1 && jwtGuardedHeaderParams[lower] {
			out = append(out, lower)
		}
	}
	sort.Strings(out)
	return out
}

// kid shape classes, in the order they are reported.
const (
	jwtKidClassPath      = "path"
	jwtKidClassInjection = "injection"
	jwtKidClassURL       = "url"
)

// jwtKidInjectionMarkers are sequences an opaque key identifier never needs:
// SQL, shell and template metacharacters. Base64url ids, hex thumbprints and
// UUIDs contain none of them, so a hit is a shape observation rather than a
// guess about intent.
var jwtKidInjectionMarkers = []string{
	"'", "\"", "`", "$(", "${", "{{", "}}", ";", "|", "/*", "*/",
	" or ", " union ", " and ", "\r", "\n",
}

// jwtKidIsDrivePath reports whether v starts with a Windows drive reference
// (C:, C:\). A forward slash after the letter is treated as a URL scheme
// instead (http://), so it is not a drive.
func jwtKidIsDrivePath(v string) bool {
	if len(v) < 2 || v[1] != ':' {
		return false
	}
	c := v[0] | 0x20
	if c < 'a' || c > 'z' {
		return false
	}
	return len(v) == 2 || v[2] == '\\'
}

// jwtKidClasses classifies a kid value by SHAPE only. It returns every class
// the value matches, in a fixed order; a URL-shaped kid yields just the URL
// class, because "remote key reference" is the dominant reading of it.
//
// This says nothing about whether the verifier uses kid as a path, a query
// fragment or a URL — only that the value has the shape those uses need.
func jwtKidClasses(kid string) []string {
	v := strings.TrimSpace(kid)
	if v == "" {
		return nil
	}
	lower := strings.ToLower(v)
	urlShape := (strings.Contains(v, "://") && !strings.HasPrefix(lower, "file:")) ||
		strings.HasPrefix(v, "//") || strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "data:")
	if urlShape {
		return []string{jwtKidClassURL}
	}
	pathShape := strings.Contains(lower, "../") || strings.Contains(lower, `..\`) ||
		strings.Contains(lower, "%2e%2e") || strings.Contains(lower, "..%2f") ||
		strings.Contains(lower, "..%5c") || strings.Contains(lower, "%00") ||
		strings.ContainsRune(v, 0) ||
		strings.HasPrefix(v, "/") || strings.HasPrefix(v, `\`) ||
		jwtKidIsDrivePath(v) || strings.HasPrefix(lower, "file:")
	injectionShape := false
	for _, marker := range jwtKidInjectionMarkers {
		if strings.Contains(lower, marker) {
			injectionShape = true
			break
		}
	}
	var classes []string
	if pathShape {
		classes = append(classes, jwtKidClassPath)
	}
	if injectionShape {
		classes = append(classes, jwtKidClassInjection)
	}
	return classes
}

// jwtKeyRefIssue is what is wrong with one jku/x5u reference. It carries the
// safe label that may be persisted, never the value's query or userinfo.
type jwtKeyRefIssue struct {
	Severity   domain.Severity
	Confidence domain.Confidence
	Observed   string
	Reason     string
}

// jwtKeyRefLabel renders a key reference for storage: scheme, host[:port] and
// path only. Userinfo, query and fragment are dropped, so an embedded
// credential or a signed URL can never be copied into a finding or the evidence
// store. A value that is not a parseable absolute URL is sanitized and bounded
// instead.
func jwtKeyRefLabel(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return sanitizeJWTText(raw, 96)
	}
	out := strings.ToLower(u.Scheme) + "://" + u.Host
	if p := u.EscapedPath(); p != "" && p != "/" {
		out += p
	}
	return sanitizeJWTText(out, 160)
}

// jwtTrustedKeyHosts returns the hosts a token's key reference may legitimately
// name: the origin the token was observed on, and the host of its issuer claim.
// Ports are ignored — a JWKS endpoint on another port of the same host is not a
// different trust domain, and treating it as one would only add noise.
func jwtTrustedKeyHosts(origin, issuer string) map[string]bool {
	hosts := make(map[string]bool, 2)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.ContainsAny(raw, " 	") {
			return
		}
		if !strings.Contains(raw, "://") {
			// An issuer is often a bare hostname; resolve it as one so a
			// self-hosted key set is not reported as foreign.
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return
		}
		hosts[strings.ToLower(u.Hostname())] = true
	}
	add(origin)
	add(issuer)
	return hosts
}

// jwtMaxSeverity returns the stronger of two severities.
func jwtMaxSeverity(a, b domain.Severity) domain.Severity {
	if jwtSeverityRank(b) > jwtSeverityRank(a) {
		return b
	}
	return a
}

// jwtKeyRefIssueFor inspects one jku/x5u value. ok is false when the header is
// absent, empty, or names a location both this application and the token's own
// issuer plausibly control over HTTPS — the normal self-hosted key set.
//
// Pure: it parses strings and compares hosts. It never contacts the reference.
func jwtKeyRefIssueFor(name, value string, trusted map[string]bool) (jwtKeyRefIssue, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return jwtKeyRefIssue{}, false
	}
	issue := jwtKeyRefIssue{Severity: domain.SeverityInfo, Confidence: domain.ConfidenceHigh}
	var problems []string
	// shape is true when the defect is visible in the value itself, which makes
	// the observation certain; a merely foreign host depends on the verifier's
	// allow-list and is reported at medium confidence.
	shape := false

	u, err := url.Parse(raw)
	switch {
	case err != nil || (u.Scheme == "" && u.Host == ""):
		problems = append(problems, "is not an absolute URL, so every verifier has to resolve it against a base of its own choosing")
		issue.Severity, shape = domain.SeverityMedium, true
	case u.Scheme == "":
		problems = append(problems, "is protocol-relative, so it inherits the scheme of whatever fetches it and can be downgraded to plain HTTP")
		issue.Severity, shape = domain.SeverityMedium, true
	default:
		switch scheme := strings.ToLower(u.Scheme); scheme {
		case "https":
		case "http":
			problems = append(problems, "is fetched over plain HTTP, so a network attacker can replace the key set and mint tokens the server would accept")
			issue.Severity = jwtMaxSeverity(issue.Severity, domain.SeverityMedium)
			shape = true
		default:
			problems = append(problems, fmt.Sprintf("uses the %q scheme, which a key-set fetch must never reach: a generic fetcher can be steered at local files or another protocol", scheme))
			issue.Severity = jwtMaxSeverity(issue.Severity, domain.SeverityHigh)
			shape = true
		}
		if u.User != nil {
			problems = append(problems, "embeds credentials in the URL")
			issue.Severity = jwtMaxSeverity(issue.Severity, domain.SeverityHigh)
			shape = true
		}
		host := strings.ToLower(u.Hostname())
		switch {
		case host == "":
			problems = append(problems, "names no host")
			issue.Severity = jwtMaxSeverity(issue.Severity, domain.SeverityMedium)
			shape = true
		case len(trusted) > 0 && !trusted[host]:
			problems = append(problems, fmt.Sprintf("names %s, which is neither the token issuer's host nor this application's host", host))
			issue.Severity = jwtMaxSeverity(issue.Severity, domain.SeverityLow)
		}
	}
	if len(problems) == 0 {
		return jwtKeyRefIssue{}, false
	}
	if !shape {
		issue.Confidence = domain.ConfidenceMedium
	}
	issue.Observed = jwtKeyRefLabel(raw)
	issue.Reason = fmt.Sprintf("the token header's %s %s. A verifier that follows a key location chosen by the token trusts whatever "+
		"that location serves, so whoever can influence the header controls the key its tokens are checked against; the token "+
		"alone does not show that this server fetches it", name, strings.Join(problems, " and "))
	return issue, true
}

// summary renders the persisted, redaction-safe token view.
func (t *jwtToken) summary() *jwtTokenSummary {
	s := &jwtTokenSummary{
		Fingerprint:   t.fingerprint,
		Alg:           t.alg,
		Typ:           t.typ,
		Kid:           t.kid,
		HasSignature:  t.hasSignature,
		JKU:           jwtKeyRefLabel(t.jku),
		X5U:           jwtKeyRefLabel(t.x5u),
		Issuer:        t.issuer,
		IssuedAt:      t.issuedAt,
		NotBefore:     t.notBefore,
		ExpiresAt:     t.expiresAt,
		LifetimeHours: math.Round(t.lifetime.Hours()*10) / 10,
		Claims:        t.claimNames,
	}
	var embedded []string
	if t.hasJWK {
		embedded = append(embedded, "jwk")
	}
	if t.x5cCount > 0 {
		embedded = append(embedded, "x5c")
	}
	s.EmbeddedKey = strings.Join(embedded, ",")
	return s
}

// analyzeJWTToken turns the decoded token into signals. It is pure: no clock,
// no I/O, no network. Order is fixed so the same token always yields the same
// signal list.
func analyzeJWTToken(origin string, tok *jwtToken) []jwtSignal {
	var signals []jwtSignal
	add := func(s jwtSignal) {
		s.Key = jwtDedupKey(origin, tok.issuer, s.Category, s.Subject)
		if s.Confidence == "" {
			s.Confidence = domain.ConfidenceHigh
		}
		signals = append(signals, s)
	}

	// 1. An unsigned token is not a token: any value can be minted for any
	// subject, so this outranks every other claim-level observation.
	if strings.EqualFold(tok.alg, "none") {
		add(jwtSignal{
			Category: jwtCategoryClaims, Kind: jwtKindAlgNone, Subject: "alg",
			Severity: domain.SeverityHigh, Observed: "alg=none",
			Reason: "the token header declares alg=none, an unverified algorithm: its payload is not signed at all, " +
				"so anyone who can write a claim set can mint a token the server may accept",
			Remediation: "Reject alg=none (and any algorithm not on an explicit allow-list) when the token is verified, " +
				"and issue tokens signed with a modern algorithm such as HS256/RS256/ES256.",
			Title: "JWT uses the unverified alg=none algorithm",
		})
	}

	// 2. Key-source hygiene: the header as a key-selection surface. Everything
	// here is read off the token's own bytes, so the observation is certain; the
	// exploitability is not (it depends on what the verifier does with the
	// value), which is why these carry medium confidence and the reasons say so.
	for _, class := range jwtKidClasses(tok.kidRaw) {
		s := jwtSignal{
			Category:   jwtCategoryHeader,
			Subject:    "kid/" + class,
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
			Observed:   fmt.Sprintf("kid=%q", sanitizeJWTText(tok.kidRaw, 64)),
		}
		switch class {
		case jwtKidClassPath:
			s.Kind, s.Title = jwtKindKidPath, "JWT header kid looks like a filesystem path"
			s.Reason = "the token header's kid is shaped like a file path: it carries a traversal sequence, an absolute path, a drive letter or a NUL byte. " +
				"kid is routinely used to select a key file or a keystore entry, so a value that can escape the intended directory is exactly the precondition " +
				"for loading a key the token's holder chose"
			s.Remediation = "Treat kid as an opaque identifier: resolve it through a fixed table of key ids, never concatenate it into a file path, and reject a kid that is not in that table."
		case jwtKidClassInjection:
			s.Kind, s.Title = jwtKindKidInjection, "JWT header kid carries injection metacharacters"
			s.Reason = "the token header's kid contains SQL, shell or template metacharacters, which an opaque key identifier never needs. " +
				"If the verifier interpolates kid into a query, a command or a template, those characters change the meaning of that statement"
			s.Remediation = "Never interpolate kid into a query, command or template; look it up as a value, and reject a kid that is not a plain identifier."
		case jwtKidClassURL:
			s.Kind, s.Title = jwtKindKidURL, "JWT header kid is a URL"
			s.Reason = "the token header's kid is a URL rather than an identifier, so a verifier that resolves it may fetch key material from a location the token names — " +
				"the same trust problem as an untrusted jku"
			s.Remediation = "Treat kid as a local identifier only; never fetch key material from a URL carried in kid."
		default:
			continue
		}
		add(s)
	}

	// 3. jku/x5u: where the header says the verification key lives. Only a
	// reference that is defective in shape, or foreign to both this application
	// and the token's issuer, is reported; a self-hosted HTTPS key set is normal.
	trustedKeyHosts := jwtTrustedKeyHosts(origin, tok.issuer)
	for _, ref := range []struct{ name, value string }{
		{"jku", tok.jku},
		{"x5u", tok.x5u},
	} {
		issue, ok := jwtKeyRefIssueFor(ref.name, ref.value, trustedKeyHosts)
		if !ok {
			continue
		}
		add(jwtSignal{
			Category: jwtCategoryHeader, Kind: jwtKindUntrustedKey, Subject: ref.name,
			Severity: issue.Severity, Confidence: issue.Confidence,
			Observed: ref.name + "=" + issue.Observed,
			Reason:   issue.Reason,
			Remediation: "Ignore jku and x5u unless the URL matches a fixed allow-list of key-set locations the issuer itself controls over HTTPS, " +
				"and never fetch verification keys from a URL the token supplies.",
			Title: fmt.Sprintf("JWT header points at an untrusted key location (%s)", ref.name),
		})
	}

	// 4. Header-embedded key material: the token names the key it is checked
	// with, which defeats the signature if the verifier honours it.
	for _, embedded := range []struct {
		name    string
		present bool
	}{
		{"jwk", tok.hasJWK},
		{"x5c", tok.x5cCount > 0},
	} {
		if !embedded.present {
			continue
		}
		add(jwtSignal{
			Category: jwtCategoryHeader, Kind: jwtKindEmbeddedKey, Subject: embedded.name,
			Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium,
			Observed: embedded.name + " present in the token header",
			Reason: fmt.Sprintf("the token header carries its own key material (%s), so a verifier that trusts a key named by the token accepts a token "+
				"signed by whoever minted that header — the signature then proves nothing", embedded.name),
			Remediation: "Verify tokens with keys from the server's own configured key store; ignore or reject jwk and x5c in a token header.",
			Title:       fmt.Sprintf("JWT header carries embedded key material (%s)", embedded.name),
		})
	}

	// 5. Repeated header parameters: JSON parsers disagree about which
	// occurrence wins, so two layers can verify different tokens.
	for _, name := range tok.duplicateParams {
		add(jwtSignal{
			Category: jwtCategoryHeader, Kind: jwtKindDuplicateParam, Subject: "header/" + name,
			Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh,
			Observed: fmt.Sprintf("%q appears more than once in the header object", name),
			Reason: fmt.Sprintf("the token's header JSON repeats the %q parameter. JSON parsers disagree about which occurrence wins, so a gateway and "+
				"the verifier can act on different values from the same token", name),
			Remediation: "Reject a JWS whose header object repeats a parameter name, and parse the header once with a strict decoder.",
			Title:       fmt.Sprintf("JWT header repeats the %s parameter", name),
		})
	}

	// 6. No expiry: the credential lives until the signing key is rotated.
	if tok.expMissing {
		add(jwtSignal{
			Category: jwtCategoryClaims, Kind: jwtKindMissingExp, Subject: "exp",
			Severity: domain.SeverityMedium, Observed: "no usable exp claim",
			Reason: "the token carries no usable exp claim (absent or not a NumericDate), so it never expires on its own: " +
				"a stolen or leaked token stays valid until the server rotates its signing key or the account is disabled",
			Remediation: "Issue access tokens with a short exp (minutes to hours) and a refresh token that can be revoked.",
			Title:       "JWT has no expiration claim",
		})
	} else if tok.lifetime > jwtExcessiveLifetime {
		days := math.Round(tok.lifetime.Hours() / 24)
		add(jwtSignal{
			Category: jwtCategoryClaims, Kind: jwtKindExcessiveLife, Subject: "exp",
			Severity: domain.SeverityLow, Observed: fmt.Sprintf("lifetime about %.0f days", days),
			Reason: fmt.Sprintf("the token's expiration is %d days away (the hygiene ceiling is %d days), so a leak "+
				"stays exploitable for a long window and a password change cannot shorten it",
				int(days), int(jwtExcessiveLifetime.Hours()/24)),
			Remediation: "Shorten the access-token lifetime (typically 5-60 minutes) and rely on a refresh token that the " +
				"server can revoke.",
			Title: "JWT expiration is longer than 30 days",
		})
	}

	// 7. Secret material inside the payload. A JWT payload is only base64url:
	// every party that sees the token can read it.
	for _, key := range tok.sensitiveKeys {
		add(jwtSignal{
			Category: jwtCategoryClaims, Kind: jwtKindSensitive, Subject: key,
			Severity: domain.SeverityHigh, Observed: "claim named " + key,
			Reason: fmt.Sprintf("the token payload carries a claim named %q; a JWT payload is only base64url-encoded, "+
				"so anyone who sees the token — its holder, a proxy log, a leaked HAR — reads that value", key),
			Remediation: "Remove secret material from the token payload; put only non-sensitive identifiers and claims in it.",
			Title:       fmt.Sprintf("JWT payload carries a sensitive claim (%s)", key),
		})
	}
	return signals
}

// jwtValidationSignals turns the differential's controls into signals. It is
// pure: every field it reads was recorded from a real response.
func jwtValidationSignals(origin, issuer string, v *jwtValidationDetail) []jwtSignal {
	if v == nil {
		return nil
	}
	if v.AnonymousSameData {
		// The endpoint hands the same data to a caller with no credential at
		// all, so an invalid token bought nothing: there is no authentication
		// boundary here to bypass. This is the classic false positive of a
		// token-validation check and it is deliberately not reported.
		return nil
	}
	var signals []jwtSignal
	for _, c := range v.Controls {
		if !c.Equivalent || c.Rejected {
			continue
		}
		kind, subject, reason, title := "", "", "", ""
		switch c.Kind {
		case "modified_signature":
			kind, subject = jwtKindSigNotChecked, "signature"
			reason = fmt.Sprintf("the server answered HTTP %d with the SAME data the authenticated baseline returned when "+
				"the token's signature was replaced with an invalid one, so the signature is not verified: a caller can "+
				"forge a token for any subject the claims name", c.Status)
			title = "JWT signature is not validated"
		case "alg_none":
			kind, subject = jwtKindUnsignedTaken, "alg"
			reason = fmt.Sprintf("the server answered HTTP %d with the SAME data the authenticated baseline returned when "+
				"the token header was changed to alg=none and the signature removed, so an unsigned token is accepted", c.Status)
			title = "Unsigned alg=none JWT is accepted"
		default:
			continue
		}
		s := jwtSignal{
			Key:      jwtDedupKey(origin, issuer, jwtCategoryValidation, subject),
			Category: jwtCategoryValidation, Kind: kind, Subject: subject,
			Severity: domain.SeverityCritical, Confidence: domain.ConfidenceHigh,
			Observed: fmt.Sprintf("HTTP %d with the authenticated response data", c.Status),
			Reason:   reason,
			Remediation: "Verify the token's signature before trusting any claim, pin the accepted algorithms to an " +
				"explicit allow-list (never none), and reject any request whose token fails verification with 401.",
			Title: title,
		}
		signals = append(signals, s)
	}
	return signals
}

// jwtResponseDataEquivalent reports whether two response bodies carry the same
// data: either byte-identical (after trimming surrounding whitespace) or the
// same decoded JSON value. Structural comparison keeps a re-serialised response
// (key order, whitespace) from hiding a bypass, while stopping short of a fuzzy
// similarity that could call two different pages "the same".
func jwtResponseDataEquivalent(a, b []byte) bool {
	ta, tb := bytes.TrimSpace(a), bytes.TrimSpace(b)
	if len(ta) == 0 || len(tb) == 0 {
		return false
	}
	if bytes.Equal(ta, tb) {
		return true
	}
	var va, vb any
	if json.Unmarshal(ta, &va) == nil && json.Unmarshal(tb, &vb) == nil {
		return reflect.DeepEqual(va, vb)
	}
	return false
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

type jwtExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
	// bearer reads the Authorization value the scan's own session would send
	// to a URL. nil (no bearer-carrying engine, e.g. an anonymous scan) means
	// the pass has nothing to inspect.
	bearer sessionBearerSource
}

func newJWTExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *jwtExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	e := &jwtExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
	if src, ok := eng.(sessionBearerSource); ok {
		e.bearer = src
	}
	return e
}

var _ worker.Handler = (*jwtExecutor)(nil)

// jwtExchange is one request/response pair worth persisting as evidence.
type jwtExchange struct {
	Note     string
	Request  *httpengine.Request
	Response *httpengine.Response
}

// Handle implements worker.Handler: decode the session's token, then run the
// bounded differential.
func (e *jwtExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, err := e.jwtTarget(ctx, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnJWT, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist jwt test case: %w", err)
	}

	origin := jwtOrigin(ep.URL)
	d := &jwtDetail{Engine: jwtEngine, URL: ep.URL, Origin: origin, Method: method, Verdict: domain.VerdictRejected}
	if origin == "" {
		return e.skip(ctx, tc, d, "the endpoint URL is not an absolute http(s) URL")
	}
	if reason, skip := e.jwtSkip(ep); skip {
		return e.skip(ctx, tc, d, reason)
	}
	d.DedupKey = jwtOriginKey(origin)

	// The scan's own bearer credential for this origin. No token (anonymous
	// scan, or the session changed since the job was queued) means there is
	// nothing to inspect — this is a skip, not an error.
	token := ""
	if e.bearer != nil {
		token = e.bearer.sessionBearerFor(ep.URL)
	}
	if token == "" {
		return e.skip(ctx, tc, d, "no bearer JWT was available for this origin")
	}
	tok, ok := parseJWT(token, started)
	if !ok {
		return e.skip(ctx, tc, d, "the bearer credential on this origin is not a JWT (not a decodable compact JWS)")
	}
	d.Token = tok.summary()
	d.Issuer = tok.issuer
	signals := analyzeJWTToken(origin, tok)

	// Bounded read-only differential. A 429/503 anywhere stops it: the target
	// asked for less traffic, and nothing about token validation can be judged
	// from a throttled or unavailable response.
	val, exchanges, throttled := e.jwtDifferential(ctx, job.ScanID, ep, origin, token)
	d.Validation = val
	if throttled {
		// The offline claims findings stand (they need no response); only the
		// differential is withheld.
		d.Throttled = true
	} else {
		signals = append(signals, jwtValidationSignals(origin, tok.issuer, val)...)
	}
	d.Signals = signals
	if d.Validation != nil && d.Validation.BaselineStatus != 0 {
		// The endpoint's status under the scan's OWN credential — the honest
		// baseline, not the last invalid-token control.
		tc.HTTPStatus = d.Validation.BaselineStatus
	} else if resp := firstResponse(exchanges); resp != nil {
		tc.HTTPStatus = resp.Status
	}
	e.persist(ctx, tc, exchanges)

	now := time.Now()
	tc.FinishedAt = &now
	tc.DurationMS = now.Sub(started).Milliseconds()
	note := "jwt validation: the token's claims are clean and the server rejected every invalid token"
	if d.Validation != nil && d.Validation.Note != "" {
		// Never claim the server rejected a token when the comparison could not
		// be made: say exactly which part did not run.
		note = "jwt validation: the token's claims are clean; the differential was inconclusive: " + d.Validation.Note
	}
	switch {
	case len(d.Signals) > 0:
		d.Severity, d.Confidence = jwtTopSeverity(d.Signals), domain.ConfidenceHigh
		d.Reason = jwtSummary(d.Signals)
		// A finding needs no verdict change when nothing was observed:
		// d.Verdict stays Rejected, which is this engine's negative result.
		d.Verdict = domain.VerdictConfirmed
		e.correlate(ctx, job, ep, tc, d)
		note = "jwt validation: " + d.Reason
		if throttled {
			// The offline claims findings stand; only the differential was
			// withheld, and the note must say so rather than implying the
			// server rejected every invalid token.
			note = "jwt validation: target throttled the differential; token claims were still inspected: " + d.Reason
		}
	case throttled:
		note = "jwt validation: target throttled the differential; the token's claims are clean"
	}
	return e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
}

// skip records a skipped test case: the pass had nothing it could inspect.
func (e *jwtExecutor) skip(ctx context.Context, tc *domain.TestCase, d *jwtDetail, reason string) error {
	d.Skipped, d.SkipReason = true, reason
	return e.finish(ctx, tc, d, domain.TestCaseSkipped, "jwt check skipped: "+reason)
}

// jwtTarget resolves the job's endpoint, tolerating an origin job that carries
// only a URL.
func (e *jwtExecutor) jwtTarget(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, error) {
	if job == nil {
		return nil, fmt.Errorf("nil job")
	}
	if !job.Target.EndpointID.Empty() {
		ep, _, _, err := resolveJobTarget(ctx, e.store, job)
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
	if jwtOrigin(raw) == "" {
		return nil, fmt.Errorf("job URL %q is not an absolute http(s) URL", raw)
	}
	return &domain.Endpoint{URL: raw, Method: domain.MethodGET, Source: domain.SourceUserProvided}, nil
}

// jwtSkip applies the read-only guards: the differential must never be the
// request that mutates a target.
func (e *jwtExecutor) jwtSkip(ep *domain.Endpoint) (string, bool) {
	if !isSafeMethod(ep.Method) {
		return fmt.Sprintf("%s is state-changing; the JWT validation differential only sends GET", ep.Method), true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

// jwtDifferential runs the bounded read-only comparison on ONE authenticated
// GET endpoint of this origin:
//
//	baseline  — the scan's own credential (added by the scoped engine)
//	anonymous — no credential at all (NoCookies)
//	control 1 — the same token with its signature replaced by an invalid one
//	control 2 — the same claims re-signed with alg=none and no signature
//
// The anonymous control is not decoration: it is what separates "the server
// verifies nothing" from "this endpoint is public", the classic false positive
// of a token-validation check.
func (e *jwtExecutor) jwtDifferential(ctx context.Context, scanID domain.ID, ep *domain.Endpoint, origin, token string) (*jwtValidationDetail, []jwtExchange, bool) {
	v := &jwtValidationDetail{}
	// A listing failure is not fatal: the job's own endpoint is always a
	// candidate, so the differential still runs on it.
	candidates, listErr := e.jwtCandidateEndpoints(ctx, scanID, ep, origin)

	var exchanges []jwtExchange
	var baseline *httpengine.Response
	for _, target := range candidates {
		// Token ONLY, no cookies: the baseline must prove this bearer token is
		// itself a working credential. A 200 that a session cookie produced
		// would make every control below meaningless (the cookie, not the
		// token, would explain the data coming back), so the token is attached
		// explicitly and the engine is told to send no session state at all.
		req := httpengine.GET(target.URL).WithHeader("Authorization", jwtBearerHeader(token))
		req.NoCookies = true
		resp, outcome := e.jwtDo(ctx, req)
		if resp == nil || outcome != domain.OutcomeSuccess {
			if outcome == domain.OutcomeCancelled {
				v.Note = "the differential was cancelled"
				return v, exchanges, false
			}
			continue
		}
		exchanges = append(exchanges, jwtExchange{Note: "baseline", Request: req, Response: resp})
		// Record what the token actually got, even when it is not a 200: an
		// operator reading the detail must see that the token-only baseline
		// was refused rather than guessing why the differential did not run.
		v.EndpointURL = target.URL
		v.BaselineStatus = resp.Status
		if isThrottleStatus(resp.Status) {
			v.Note = fmt.Sprintf("the target answered HTTP %d to the authenticated baseline", resp.Status)
			return v, exchanges, true
		}
		if resp.Status == http.StatusOK && len(bytes.TrimSpace(resp.Body)) > 0 {
			baseline = resp
			break
		}
	}
	if baseline == nil {
		if listErr != nil {
			v.Note = "the endpoints for this origin could not be listed, so only the job's own endpoint was tried"
		} else {
			v.Note = "no endpoint on this origin returned an authenticated 200 response, so the differential was not run"
		}
		return v, exchanges, false
	}

	// Anonymous control: no token, no cookies.
	anonReq := httpengine.GET(v.EndpointURL)
	anonReq.NoCookies = true
	anonResp, outcome := e.jwtDo(ctx, anonReq)
	if anonResp == nil || outcome != domain.OutcomeSuccess {
		v.Note = "the anonymous control did not complete, so an invalid-token response could not be attributed"
		return v, exchanges, false
	}
	exchanges = append(exchanges, jwtExchange{Note: "anonymous control", Request: anonReq, Response: anonResp})
	v.AnonymousStatus = anonResp.Status
	if isThrottleStatus(anonResp.Status) {
		v.Note = fmt.Sprintf("the target answered HTTP %d to the anonymous control", anonResp.Status)
		return v, exchanges, true
	}
	switch anonResp.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		v.AnonymousRejected = true
	default:
		if anonResp.Status == http.StatusOK && jwtResponseDataEquivalent(baseline.Body, anonResp.Body) {
			v.AnonymousSameData = true
		}
	}

	// Invalid-token controls.
	for _, c := range e.jwtControlRequests(v.EndpointURL, token) {
		resp, outcome := e.jwtDo(ctx, c.Request)
		if resp == nil || outcome != domain.OutcomeSuccess {
			v.Controls = append(v.Controls, jwtControlResult{Kind: c.Kind, Note: "the control request did not complete"})
			continue
		}
		exchanges = append(exchanges, jwtExchange{Note: c.Kind, Request: c.Request, Response: resp})
		result := jwtControlResult{Kind: c.Kind, Status: resp.Status}
		if isThrottleStatus(resp.Status) {
			v.Controls = append(v.Controls, result)
			v.Note = fmt.Sprintf("the target answered HTTP %d to the %s control", resp.Status, c.Kind)
			return v, exchanges, true
		}
		switch resp.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			result.Rejected = true
		default:
			if resp.Status >= 200 && resp.Status < 300 && jwtResponseDataEquivalent(baseline.Body, resp.Body) {
				result.Equivalent = true
			}
		}
		v.Controls = append(v.Controls, result)
	}
	if v.AnonymousSameData {
		v.Note = "the endpoint returns the same data with no credential at all, so an invalid token proves nothing here"
	}
	return v, exchanges, false
}

// jwtControl is one invalid-token request.
type jwtControl struct {
	Kind    string
	Request *httpengine.Request
}

// jwtBearerHeader returns value as a complete Authorization header value,
// adding the Bearer scheme when the stored credential lacks it.
func jwtBearerHeader(value string) string {
	v := strings.TrimSpace(value)
	if len(v) >= 7 && strings.EqualFold(v[:7], "bearer ") {
		return v
	}
	return "Bearer " + v
}

// jwtControlRequests builds the two invalid-token controls for one URL. Both
// carry an explicit Authorization header and NO cookies: the token must be the
// only credential on the request, or a 200 could not be attributed to it (an
// endpoint that authenticates by session cookie would look like a server that
// accepts forged tokens). The scoped engine hands an explicit Authorization
// through instead of substituting the session's own token.
func (e *jwtExecutor) jwtControlRequests(rawURL, token string) []jwtControl {
	var out []jwtControl
	if tampered, ok := jwtTamperedSignature(token); ok {
		out = append(out, jwtControl{
			Kind:    "modified_signature",
			Request: httpengine.GET(rawURL).WithHeader("Authorization", "Bearer "+tampered),
		})
	}
	if none, ok := jwtAlgNone(token); ok {
		out = append(out, jwtControl{
			Kind:    "alg_none",
			Request: httpengine.GET(rawURL).WithHeader("Authorization", "Bearer "+none),
		})
	}
	for i := range out {
		out[i].Request.NoCookies = true
	}
	return out
}

// jwtCandidateEndpoints returns the GET endpoints of this origin to try as the
// differential's baseline, the job's own endpoint first and the rest in URL
// order (deterministic), bounded by maxJWTEndpointsPerOrigin.
func (e *jwtExecutor) jwtCandidateEndpoints(ctx context.Context, scanID domain.ID, own *domain.Endpoint, origin string) ([]*domain.Endpoint, error) {
	out := []*domain.Endpoint{own}
	all, err := e.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return out, err
	}
	var rest []*domain.Endpoint
	for _, ep := range all {
		if ep == nil || ep.ID == own.ID || strings.TrimSpace(ep.URL) == "" {
			continue
		}
		if !isSafeMethod(ep.Method) || jwtOrigin(ep.URL) != origin {
			continue
		}
		if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
			continue
		}
		rest = append(rest, ep)
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].URL < rest[j].URL })
	for _, ep := range rest {
		if len(out) >= maxJWTEndpointsPerOrigin {
			break
		}
		out = append(out, ep)
	}
	if len(out) > maxJWTEndpointsPerOrigin {
		out = out[:maxJWTEndpointsPerOrigin]
	}
	return out, nil
}

// jwtDo sends one request with the executor's per-request timeout.
func (e *jwtExecutor) jwtDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled
	case isTimeout(err):
		return nil, domain.OutcomeTimeout
	default:
		return nil, domain.OutcomeError
	}
}

// jwtTamperedSignature returns the same token with its signature segment
// replaced by a same-length run of 'A' (base64url for zero bytes) — a signature
// no verifier can accept. The original signature is never copied anywhere.
func jwtTamperedSignature(raw string) (string, bool) {
	header, payload, sig, ok := splitJWTParts(raw)
	if !ok {
		return "", false
	}
	n := len(sig)
	if n == 0 {
		n = 4
	}
	return header + "." + payload + "." + strings.Repeat("A", n), true
}

// jwtAlgNone returns the same claims re-signed with alg=none and an empty
// signature: the canonical "unverified header algorithm" control.
func jwtAlgNone(raw string) (string, bool) {
	headerSeg, payloadSeg, _, ok := splitJWTParts(raw)
	if !ok {
		return "", false
	}
	headerBytes, ok := decodeJWTSegment(headerSeg)
	if !ok {
		return "", false
	}
	header, ok := decodeJWTJSON(headerBytes)
	if !ok {
		return "", false
	}
	if strings.EqualFold(jwtStringClaim(header, "alg", 32), "none") {
		// Already unsigned: the modified-signature control covers this token.
		return "", false
	}
	header["alg"] = "none"
	rewritten, err := json.Marshal(header)
	if err != nil {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(rewritten) + "." + payloadSeg + ".", true
}

// firstResponse returns the first response of the exchange list (the baseline,
// when one was made), so the test case records the status the scan's own
// credential received rather than a control's.
func firstResponse(exchanges []jwtExchange) *httpengine.Response {
	for _, x := range exchanges {
		if x.Response != nil {
			return x.Response
		}
	}
	return nil
}

// persist stores every request/response pair. dumpRequest redacts Authorization
// unconditionally, so a token (and a token-shaped cookie) can never turn the
// evidence store into a credential store.
func (e *jwtExecutor) persist(ctx context.Context, tc *domain.TestCase, exchanges []jwtExchange) {
	if e.evidence == nil || len(exchanges) == 0 {
		return
	}
	var ids []domain.ID
	for _, x := range exchanges {
		if x.Response == nil {
			continue
		}
		captured := capturedFrom(x.Request, x.Response)
		captured.Headers = captured.Headers.Clone()
		redacted := redactRequestCookieValues(captured.Headers)
		reqNote := "test_case=" + string(tc.ID) + " jwt " + x.Note + " request (authorization redacted)"
		if redacted {
			reqNote += " (cookie values redacted)"
		}
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(captured), reqNote); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("jwt: persist request evidence", "test_case", tc.ID, "err", err)
		}
		recorded := *x.Response
		recorded.Headers = x.Response.Headers.Clone()
		respNote := "test_case=" + string(tc.ID) + " jwt " + x.Note + " response"
		if redactSetCookieValues(recorded.Headers) {
			respNote += " (cookie values redacted)"
		}
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
			dumpResponse(&recorded), respNote); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("jwt: persist response evidence", "test_case", tc.ID, "err", err)
		}
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

// finish persists the test case.
func (e *jwtExecutor) finish(ctx context.Context, tc *domain.TestCase, d *jwtDetail, status domain.TestCaseStatus, note string) error {
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
		e.log.Warn("jwt: persist test case", "test_case", tc.ID, "err", err)
	}
	return nil
}

// correlate upserts one Finding per signal. The dedup key is
// (origin, issuer, category, subject), so a second endpoint on the same origin —
// or a resumed execution that re-runs the pass — absorbs into the same row and
// only unions evidence and the occurrence count.
func (e *jwtExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *jwtDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("jwt: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("jwt: list findings", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	// conclude() runs after correlation, so the IDs this attempt earned are
	// merged in here — a finding must never be created without its evidence or
	// without a link back to the test case that proved it.
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	byKey := make(map[string]*domain.Finding, len(existing))
	for _, f := range existing {
		if f.VulnClass != domain.VulnJWT {
			continue
		}
		var fd jwtDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
			continue
		}
		byKey[fd.DedupKey] = f
	}

	for _, s := range d.Signals {
		title := s.Title + ": " + originHostLabel(d.Origin)
		findingDetail := *d
		findingDetail.DedupKey = s.Key
		findingDetail.Severity, findingDetail.Confidence = s.Severity, s.Confidence
		findingDetail.Reason = s.Reason
		findingDetail.Signals = []jwtSignal{s}
		if findingDetail.Occurrences == 0 {
			findingDetail.Occurrences = 1
		}
		detail, _ := json.Marshal(&findingDetail)

		if f := byKey[s.Key]; f != nil {
			var fd jwtDetail
			if err := json.Unmarshal(f.Detail, &fd); err == nil {
				if fd.Occurrences == 0 {
					fd.Occurrences = 1
				}
				fd.Occurrences++
				if jwtSeverityRank(s.Severity) > jwtSeverityRank(fd.Severity) {
					fd.Severity, fd.Confidence = s.Severity, s.Confidence
					f.Severity, f.Confidence = s.Severity, s.Confidence
				}
				fd.Reason, fd.Signals = s.Reason, []jwtSignal{s}
				fd.Token, fd.Validation = findingDetail.Token, findingDetail.Validation
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
				e.log.Warn("jwt: update finding", "scan", job.ScanID, "err", err)
			}
			continue
		}

		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnJWT,
			Verdict: domain.VerdictConfirmed, Severity: s.Severity, Confidence: s.Confidence,
			Title: title, Summary: s.Reason, EndpointID: ep.ID,
			EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
			Provenance:  domain.Provenance{Engine: jwtEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
			Detail:      detail, CreatedAt: now, UpdatedAt: now,
		}
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.log.Warn("jwt: create finding", "scan", job.ScanID, "err", err)
			continue
		}
		byKey[s.Key] = f
	}
}

// jwtTopSeverity returns the strongest severity among the signals.
func jwtTopSeverity(signals []jwtSignal) domain.Severity {
	best := domain.SeverityInfo
	for _, s := range signals {
		if jwtSeverityRank(s.Severity) > jwtSeverityRank(best) {
			best = s.Severity
		}
	}
	return best
}

// jwtSeverityRank orders severities for comparison.
func jwtSeverityRank(s domain.Severity) int {
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

// jwtSummary is the one-line test-case/finding summary.
func jwtSummary(signals []jwtSignal) string {
	subjects := make([]string, 0, len(signals))
	for _, s := range signals {
		subjects = append(subjects, s.Kind+"("+s.Subject+")")
	}
	return fmt.Sprintf("%d JWT validation/hygiene issue(s) on this origin: %s",
		len(signals), strings.Join(subjects, ", "))
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueJWTProbes queues ONE JobJWT per origin that the scan's own session
// carries a Bearer JWT for. A scan with no bearer credential queues nothing at
// all: there is no token to inspect, so spending a job (and a skipped test
// case) per origin would only add noise.
func (c *Controller) enqueueJWTProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipJWT {
		return
	}
	headers := c.sessionAuthHeadersFor(ctx, sc)
	if len(headers) == 0 {
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
		if queued >= maxJWTOrigins {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" || !isSafeMethod(ep.Method) {
			continue
		}
		if sc.Config.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		if sc.Config.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
			continue
		}
		origin := jwtOrigin(ep.URL)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		// Only an origin this session actually authenticates with a bearer
		// token has anything to inspect.
		if sessionBearerFrom(headers, ep.URL) == "" {
			continue
		}
		seen[origin] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobJWT,
			State:       domain.JobQueued,
			Priority:    jwtPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("jwt: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("jwt validation probes: enqueued", "scan", scanID, "jobs", queued)
	}
}
