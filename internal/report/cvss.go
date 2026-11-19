package report

// Finding classification (CWE + CVSS v3.1) and reproducible curl PoCs.
//
// Two pure, deterministic helpers that turn a finding into the two fields every
// bug-bounty form and every client deliverable asks for:
//
//   - Classify       maps Indago's vulnerability class onto a CWE id and a
//                    canonical CVSS v3.1 base vector, with the base score
//                    COMPUTED from the vector (never hand-typed), so the number
//                    and the vector can never disagree.
//   - CurlPoC        renders stored HTTP request evidence as one runnable curl
//                    command. Credentials are parameterized by default (env
//                    vars, never the literal secret) and only emitted verbatim
//                    when the caller explicitly asks for it.
//
// Neither helper decides a verdict, touches the network, or reads a clock:
// the same input always produces byte-identical output. A CVSS vector is a
// class-level BASELINE, not a claim about a specific target's impact — adjust
// the impact metrics to what was actually observed before submitting (see
// ClassificationNote, which ships with every classification).

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// ---------------------------------------------------------------------------
// CVSS v3.1
// ---------------------------------------------------------------------------

// CVSS31Prefix is the only vector version this package scores. CVSS v3.0 used
// round-to-one-decimal; v3.1 introduced the Roundup function below, so mixing
// the two would silently produce a different base score for the same metrics.
const CVSS31Prefix = "CVSS:3.1"

// CVSSSeverity is the qualitative rating band of a base score.
type CVSSSeverity string

const (
	CVSSSeverityNone     CVSSSeverity = "none"
	CVSSSeverityLow      CVSSSeverity = "low"
	CVSSSeverityMedium   CVSSSeverity = "medium"
	CVSSSeverityHigh     CVSSSeverity = "high"
	CVSSSeverityCritical CVSSSeverity = "critical"
)

// SeverityForScore maps a base score onto its CVSS v3.1 qualitative rating.
func SeverityForScore(score float64) CVSSSeverity {
	switch {
	case score <= 0:
		return CVSSSeverityNone
	case score < 4.0:
		return CVSSSeverityLow
	case score < 7.0:
		return CVSSSeverityMedium
	case score < 9.0:
		return CVSSSeverityHigh
	default:
		return CVSSSeverityCritical
	}
}

// CVSS31Metrics is a parsed set of CVSS v3.1 base metrics. The eight fields are
// the specification's own abbreviations.
type CVSS31Metrics struct {
	AV string // Attack Vector: N A L P
	AC string // Attack Complexity: L H
	PR string // Privileges Required: N L H
	UI string // User Interaction: N R
	S  string // Scope: U C
	C  string // Confidentiality: H L N
	I  string // Integrity: H L N
	A  string // Availability: H L N
}

// CVSS v3.1 base-metric weights (specification §7.1).
var (
	cvssAVWeights   = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	cvssACWeights   = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUIWeights   = map[string]float64{"N": 0.85, "R": 0.62}
	cvssCIAWeights  = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	cvssPRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvssPRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// cvssBaseKeys is the canonical metric order used by Vector().
var cvssBaseKeys = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// Validate reports whether every metric carries a value the specification
// defines. A vector is never scored unless it validates.
func (m CVSS31Metrics) Validate() error {
	checks := []struct {
		name   string
		value  string
		labels map[string]float64
	}{
		{"AV", m.AV, cvssAVWeights},
		{"AC", m.AC, cvssACWeights},
		{"PR", m.PR, cvssPRUnchanged},
		{"UI", m.UI, cvssUIWeights},
		{"S", m.S, map[string]float64{"U": 0, "C": 0}},
		{"C", m.C, cvssCIAWeights},
		{"I", m.I, cvssCIAWeights},
		{"A", m.A, cvssCIAWeights},
	}
	for _, c := range checks {
		if _, ok := c.labels[c.value]; !ok {
			return fmt.Errorf("report: invalid CVSS metric %s:%q", c.name, c.value)
		}
	}
	return nil
}

// Vector renders the canonical vector string for these metrics.
func (m CVSS31Metrics) Vector() string {
	values := map[string]string{"AV": m.AV, "AC": m.AC, "PR": m.PR, "UI": m.UI, "S": m.S, "C": m.C, "I": m.I, "A": m.A}
	parts := make([]string, 0, len(cvssBaseKeys)+1)
	parts = append(parts, CVSS31Prefix)
	for _, k := range cvssBaseKeys {
		parts = append(parts, k+":"+values[k])
	}
	return strings.Join(parts, "/")
}

// BaseScore computes the CVSS v3.1 base score for these metrics.
//
//	ISS  = 1 - [(1-C)(1-I)(1-A)]
//	Impact      = 6.42 x ISS                          (S:U)
//	            = 7.52x(ISS-0.029) - 3.25x(ISS-0.02)^15 (S:C)
//	Exploitab.  = 8.22 x AV x AC x PR x UI
//	Base        = Roundup(min(Impact+Exploitability, 10))          (S:U)
//	            = Roundup(min(1.08x(Impact+Exploitability), 10))   (S:C)
func (m CVSS31Metrics) BaseScore() float64 {
	if err := m.Validate(); err != nil {
		return 0
	}
	scopeChanged := m.S == "C"
	iss := 1 - (1-cvssCIAWeights[m.C])*(1-cvssCIAWeights[m.I])*(1-cvssCIAWeights[m.A])

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}

	pr := cvssPRUnchanged[m.PR]
	if scopeChanged {
		pr = cvssPRChanged[m.PR]
	}
	exploitability := 8.22 * cvssAVWeights[m.AV] * cvssACWeights[m.AC] * pr * cvssUIWeights[m.UI]

	if scopeChanged {
		return cvssRoundup(math.Min(1.08*(impact+exploitability), 10))
	}
	return cvssRoundup(math.Min(impact+exploitability, 10))
}

// Severity is the qualitative rating of this metric set's base score.
func (m CVSS31Metrics) Severity() CVSSSeverity { return SeverityForScore(m.BaseScore()) }

// cvssRoundup is the CVSS v3.1 Appendix-A Roundup function: always round up to
// one decimal, so 4.02 becomes 4.1 while an exact one-decimal value is kept.
func cvssRoundup(input float64) float64 {
	const precision = 100000
	intInput := int(math.Round(input * precision))
	if intInput%10000 == 0 {
		return float64(intInput) / precision
	}
	return float64(intInput/10000+1) * 10000 / precision
}

// ParseCVSS31 parses a CVSS v3.1 base vector. It requires the CVSS:3.1 prefix,
// all eight base metrics exactly once, and a defined value for each; anything
// else is an error rather than a silent zero score.
func ParseCVSS31(vector string) (CVSS31Metrics, error) {
	raw := strings.TrimSpace(vector)
	if raw == "" {
		return CVSS31Metrics{}, errors.New("report: empty CVSS vector")
	}
	parts := strings.Split(raw, "/")
	if parts[0] != CVSS31Prefix {
		return CVSS31Metrics{}, fmt.Errorf("report: CVSS vector %q must start with %q", vector, CVSS31Prefix)
	}
	seen := make(map[string]string, len(cvssBaseKeys))
	for _, part := range parts[1:] {
		if strings.TrimSpace(part) == "" {
			return CVSS31Metrics{}, fmt.Errorf("report: CVSS vector %q has an empty metric", vector)
		}
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			return CVSS31Metrics{}, fmt.Errorf("report: CVSS metric %q is not key:value", part)
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		value = strings.ToUpper(strings.TrimSpace(value))
		if !cvssBaseMetric(key) {
			return CVSS31Metrics{}, fmt.Errorf("report: CVSS vector %q carries unknown metric %q", vector, key)
		}
		if _, dup := seen[key]; dup {
			return CVSS31Metrics{}, fmt.Errorf("report: CVSS vector %q repeats metric %q", vector, key)
		}
		seen[key] = value
	}
	for _, key := range cvssBaseKeys {
		if _, ok := seen[key]; !ok {
			return CVSS31Metrics{}, fmt.Errorf("report: CVSS vector %q is missing metric %q", vector, key)
		}
	}
	m := CVSS31Metrics{
		AV: seen["AV"], AC: seen["AC"], PR: seen["PR"], UI: seen["UI"],
		S: seen["S"], C: seen["C"], I: seen["I"], A: seen["A"],
	}
	if err := m.Validate(); err != nil {
		return CVSS31Metrics{}, err
	}
	return m, nil
}

func cvssBaseMetric(key string) bool {
	for _, k := range cvssBaseKeys {
		if k == key {
			return true
		}
	}
	return false
}

// CVSS31 is a scored vector: the canonical string, its base score and the
// qualitative rating. Build one with NewCVSS31 so the number always matches the
// vector.
type CVSS31 struct {
	Vector    string       `json:"vector"`
	BaseScore float64      `json:"base_score"`
	Severity  CVSSSeverity `json:"severity"`
}

// NewCVSS31 parses vector and computes its base score.
func NewCVSS31(vector string) (CVSS31, error) {
	m, err := ParseCVSS31(vector)
	if err != nil {
		return CVSS31{}, err
	}
	return CVSS31{Vector: m.Vector(), BaseScore: m.BaseScore(), Severity: m.Severity()}, nil
}

// mustCVSS31 is used only for the fixed table below; a malformed table entry is
// a programming error.
func mustCVSS31(vector string) CVSS31 {
	c, err := NewCVSS31(vector)
	if err != nil {
		panic("report: invalid built-in CVSS vector: " + err.Error())
	}
	return c
}

// Score formats the base score the way every CVSS vector is written: one
// decimal place.
func (c CVSS31) Score() string { return strconv.FormatFloat(c.BaseScore, 'f', 1, 64) }

// String renders the vector and its score, e.g.
// "CVSS:3.1/AV:N/... (6.1 medium)".
func (c CVSS31) String() string {
	return fmt.Sprintf("%s (%s %s)", c.Vector, c.Score(), c.Severity)
}

// ---------------------------------------------------------------------------
// CWE
// ---------------------------------------------------------------------------

// CWE is one Common Weakness Enumeration entry.
type CWE struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// String renders "CWE-79: <name>".
func (c CWE) String() string { return fmt.Sprintf("CWE-%d: %s", c.ID, c.Name) }

// URL is the entry's canonical MITRE page.
func (c CWE) URL() string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", c.ID)
}

// ---------------------------------------------------------------------------
// classification table
// ---------------------------------------------------------------------------

// ClassificationNote ships with every classification. A CVSS vector is only
// meaningful against a stated impact, and a class-level baseline cannot know
// what an individual target exposed.
const ClassificationNote = "class-level baseline vector; adjust the impact metrics to the impact actually observed before submitting"

// Classification is one vulnerability class's CWE and CVSS v3.1 baseline.
type Classification struct {
	Class domain.VulnClass `json:"class"`
	CWE   CWE              `json:"cwe"`
	CVSS  CVSS31           `json:"cvss"`
	Note  string           `json:"note,omitempty"`
}

// String renders the one-line classification a report or bug-bounty form shows.
func (c Classification) String() string {
	return fmt.Sprintf("%s · %s", c.CWE, c.CVSS.String())
}

// Classification-only classes.
//
// SSRF, CORS and GraphQL were first recognized HERE so a future engine's
// finding could be classified without this table changing; they are
// deliberately not added to internal/domain by this package (that model is
// owned by the engine slices, and this package must not extend it).
const (
	ClassSSRF    domain.VulnClass = "ssrf"
	ClassCORS    domain.VulnClass = "cors"
	ClassGraphQL domain.VulnClass = "graphql"
)

// CWE names are the official MITRE titles.
var (
	cweXSS              = CWE{79, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"}
	cweCommandInjection = CWE{78, "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"}
	cweXXE              = CWE{611, "Improper Restriction of XML External Entity Reference"}
	cweSSRF             = CWE{918, "Server-Side Request Forgery (SSRF)"}
	cweIDOR             = CWE{639, "Authorization Bypass Through User-Controlled Key"}
	cweAccessControl    = CWE{862, "Missing Authorization"}
	cweOpenRedirect     = CWE{601, "URL Redirection to Untrusted Site ('Open Redirect')"}
	cwePathTraversal    = CWE{22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"}
	cweDisclosure       = CWE{200, "Exposure of Sensitive Information to an Unauthorized Actor"}
	cweCORS             = CWE{942, "Permissive Cross-domain Policy with Untrusted Domains"}
	cweSSTI             = CWE{1336, "Improper Neutralization of Special Elements Used in a Template Engine"}
	cweSQLi             = CWE{89, "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"}
	cweSecurityHeaders  = CWE{693, "Protection Mechanism Failure"}
	cweCookiePolicy     = CWE{614, "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"}
	cweJWT              = CWE{347, "Improper Verification of Cryptographic Signature"}
)

// classTable is the deterministic mapping. Order is documentation order and is
// also the order Classes() returns.
var classTable = []Classification{
	// Reflected, stored and DOM XSS are all CWE-79: script executes in the
	// victim's browser with the site's origin. UI:R because a victim must load
	// the crafted page; S:C because the payload runs in the browser context.
	{Class: domain.VulnReflectedXSS, CWE: cweXSS, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Note: ClassificationNote},
	{Class: domain.VulnStoredXSS, CWE: cweXSS, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Note: ClassificationNote},
	{Class: domain.VulnDOMXSS, CWE: cweXSS, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Note: ClassificationNote},

	// Server-side template injection and OS command injection both hand the
	// attacker code execution on the server: unauthenticated, no interaction,
	// high on all three impact metrics.
	{Class: domain.VulnSSTI, CWE: cweSSTI, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Note: ClassificationNote},
	{Class: domain.VulnCommandInjection, CWE: cweCommandInjection, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Note: ClassificationNote},

	// SQL injection reaches the database directly: the attacker reads and
	// writes stored data, so all three impact metrics are high and no victim
	// interaction is needed.
	{Class: domain.VulnSQLi, CWE: cweSQLi, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Note: ClassificationNote},

	// XXE as a file-read/SSRF primitive: high confidentiality, no integrity or
	// availability impact.
	{Class: domain.VulnXXE, CWE: cweXXE, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), Note: ClassificationNote},

	// Path traversal / LFI is also a file-read primitive: the attacker reads
	// files outside the intended directory, so confidentiality is high while
	// the engine's read-only probes leave integrity and availability untouched.
	// Raise I/A only if the same parameter is shown to write or delete.
	{Class: domain.VulnPathTraversal, CWE: cwePathTraversal, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), Note: ClassificationNote},

	// Missing/weak response security headers remove a browser-side defence
	// (downgrade protection, MIME-sniffing, framing). They are enablers, not a
	// vulnerability on their own, so the baseline is deliberately modest and
	// needs a victim interaction; raise it when the finding is chained with a
	// concrete injection or clickjacking payload.
	{Class: domain.VulnSecurityHeaders, CWE: cweSecurityHeaders, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"), Note: ClassificationNote},

	// A cookie set without Secure/HttpOnly/SameSite exposes a session to
	// network interception or script access; the attacker still has to reach
	// the cookie, so the baseline is low with a high attack complexity.
	{Class: domain.VulnCookiePolicy, CWE: cweCookiePolicy, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"), Note: ClassificationNote},

	// A server that accepts a modified signature or an unsigned alg=none
	// token has no authentication boundary left: any caller can mint a token
	// naming any subject, so confidentiality and integrity are high with no
	// privileges or interaction required. Lower it when the finding is only a
	// claim-level hygiene issue (missing exp, long lifetime, sensitive claim).
	{Class: domain.VulnJWT, CWE: cweJWT, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"), Note: ClassificationNote},

	// SSRF reaches internal services the attacker cannot address directly, so
	// the security scope changes (S:C).
	{Class: ClassSSRF, CWE: cweSSRF, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"), Note: ClassificationNote},

	// Object-level authorization bypass: an authenticated low-privileged user
	// reads another principal's object. Raise I/A if the same key also writes.
	{Class: domain.VulnIDOR, CWE: cweIDOR, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), Note: ClassificationNote},

	// Function/role-level authorization: a low-privileged user reaches
	// privileged functionality, so integrity is impacted too.
	{Class: domain.VulnAccessControl, CWE: cweAccessControl, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"), Note: ClassificationNote},

	// A permissive cross-origin policy lets an attacker's page read
	// authenticated responses: confidentiality only, and the victim must visit
	// the attacker's page.
	{Class: ClassCORS, CWE: cweCORS, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"), Note: ClassificationNote},

	// Open redirect: no confidentiality or availability impact; integrity of
	// the navigation decision only, and the victim must follow the link.
	{Class: domain.VulnOpenRedirect, CWE: cweOpenRedirect, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"), Note: ClassificationNote},

	// GraphQL introspection / field-level exposure: unauthenticated metadata
	// read, confidentiality only.
	{Class: ClassGraphQL, CWE: cweDisclosure, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"), Note: ClassificationNote},

	// Debug pages, exposed source/VCS artefacts: unauthenticated, high
	// confidentiality.
	{Class: domain.VulnInfoDisclosure, CWE: cweDisclosure, CVSS: mustCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), Note: ClassificationNote},
}

// Classify returns the CWE and CVSS v3.1 baseline for a vulnerability class.
// ok is false for a class this table does not know: the caller must render
// "not classified" rather than invent a weakness or a score.
func Classify(class domain.VulnClass) (Classification, bool) {
	for _, c := range classTable {
		if c.Class == class {
			return c, true
		}
	}
	return Classification{}, false
}

// Classes returns every class this table classifies, in table order.
func Classes() []domain.VulnClass {
	out := make([]domain.VulnClass, 0, len(classTable))
	for _, c := range classTable {
		out = append(out, c.Class)
	}
	return out
}

// ---------------------------------------------------------------------------
// curl PoC
// ---------------------------------------------------------------------------

// HTTPHeader is one request header exactly as it appeared on the wire.
type HTTPHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HTTPRequestEvidence is the minimal, transport-independent shape of a stored
// HTTP request. URL is absolute: a parser resolves an origin-form request line
// against the Host header, and a caller building this by hand supplies a full
// URL.
type HTTPRequestEvidence struct {
	Method  string       `json:"method"`
	URL     string       `json:"url"`
	Headers []HTTPHeader `json:"headers,omitempty"`
	Body    string       `json:"body,omitempty"`
}

// Value returns the first value of a header, case-insensitively.
func (r HTTPRequestEvidence) Value(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(strings.TrimSpace(h.Name), strings.TrimSpace(name)) {
			return h.Value
		}
	}
	return ""
}

// curlSensitiveHeaders are the auth-bearing headers whose values are
// parameterized unless the caller explicitly opts in to verbatim credentials.
var curlSensitiveHeaders = map[string]bool{
	"authorization":        true,
	"proxy-authorization":  true,
	"cookie":               true,
	"x-api-key":            true,
	"api-key":              true,
	"x-auth-token":         true,
	"x-access-token":       true,
	"x-api-token":          true,
	"x-session-token":      true,
	"x-amz-security-token": true,
}

// curlSkipHeaders are headers curl sets itself, or hop-by-hop fields that would
// make the reproduced request differ from the stored one.
var curlSkipHeaders = map[string]bool{
	"host":              true,
	"content-length":    true,
	"connection":        true,
	"transfer-encoding": true,
	"expect":            true,
	"proxy-connection":  true,
	"upgrade":           true,
}

// CurlOptions tunes the generated command. The zero value is the safe default:
// credentials are parameterized as shell environment variables, redirects are
// NOT followed (so the response the evidence recorded is the response curl
// shows), and the request times out after 30 seconds.
type CurlOptions struct {
	// IncludeCredentials emits the literal Authorization/Cookie/API-key values
	// instead of $INDAGO_TOKEN / $INDAGO_COOKIE. Only use it for a throwaway
	// lab session; a report or ticket must never carry a real secret.
	IncludeCredentials bool
	// CookieVar and TokenVar name the shell variables a redacted command
	// reads. Defaults: INDAGO_COOKIE, INDAGO_TOKEN.
	CookieVar string
	TokenVar  string
	// SensitiveHeaders adds header names whose values are treated as secrets.
	SensitiveHeaders []string
	// Note is rendered as a leading "# ..." comment (single line).
	Note string
	// MaxTimeSeconds bounds the request; default 30.
	MaxTimeSeconds int
	// FollowRedirects adds -L. Off by default so the recorded status is what
	// the operator sees.
	FollowRedirects bool
	// Insecure adds -k (lab targets with a self-signed certificate).
	Insecure bool
	// Scheme is used by CurlPoCFromEvidence when the request target is
	// origin-form and no X-Forwarded-Proto/Scheme header states one.
	// Default https.
	Scheme string
}

func (o CurlOptions) withDefaults() CurlOptions {
	if strings.TrimSpace(o.CookieVar) == "" {
		o.CookieVar = "INDAGO_COOKIE"
	}
	if strings.TrimSpace(o.TokenVar) == "" {
		o.TokenVar = "INDAGO_TOKEN"
	}
	if o.MaxTimeSeconds <= 0 {
		o.MaxTimeSeconds = 30
	}
	return o
}

// CurlPoC renders req as one runnable curl command.
//
// The output is deterministic: headers are emitted in evidence order, no map is
// iterated, and no clock or environment value is read. Every literal is
// single-quoted for POSIX shells; every credential is a double-quoted shell
// variable expansion unless IncludeCredentials is set.
func CurlPoC(req HTTPRequestEvidence, opts CurlOptions) (string, error) {
	o := opts.withDefaults()
	if err := req.validate(); err != nil {
		return "", err
	}
	sensitive := make(map[string]bool, len(curlSensitiveHeaders)+len(o.SensitiveHeaders))
	for name := range curlSensitiveHeaders {
		sensitive[name] = true
	}
	for _, name := range o.SensitiveHeaders {
		sensitive[strings.ToLower(strings.TrimSpace(name))] = true
	}

	first := "curl -sS -i"
	if o.Insecure {
		first += " -k"
	}
	first += " -X " + strings.ToUpper(strings.TrimSpace(req.Method))
	first += " " + curlQuote(singleLine(req.URL))

	segments := []string{first, fmt.Sprintf("--max-time %d", o.MaxTimeSeconds)}
	if o.FollowRedirects {
		segments = append(segments, "-L")
	}

	for _, h := range req.Headers {
		name := strings.TrimSpace(h.Name)
		lower := strings.ToLower(name)
		if name == "" || curlSkipHeaders[lower] {
			continue
		}
		value := singleLine(h.Value)
		switch {
		case lower == "cookie":
			if o.IncludeCredentials {
				segments = append(segments, "-b "+curlQuote(value))
			} else {
				segments = append(segments, `-b "$`+o.CookieVar+`"`)
			}
		case sensitive[lower]:
			if o.IncludeCredentials {
				segments = append(segments, "-H "+curlQuote(curlHeaderField(name, value)))
				continue
			}
			segments = append(segments, `-H "`+name+": "+curlTokenPlaceholder(value, o.TokenVar)+`"`)
		default:
			segments = append(segments, "-H "+curlQuote(curlHeaderField(name, value)))
		}
	}

	if req.Body != "" {
		segments = append(segments, "--data-raw "+curlQuote(req.Body))
	}

	out := strings.Join(segments, " \\\n  ")
	if note := singleLine(o.Note); note != "" {
		out = "# " + note + "\n" + out
	}
	return out, nil
}

// CurlPoCFromEvidence parses a stored request dump (the .http message every
// executor writes as evidence) and renders the curl command in one call.
func CurlPoCFromEvidence(raw []byte, opts CurlOptions) (string, error) {
	req, err := ParseHTTPRequestEvidenceWithScheme(raw, opts.Scheme)
	if err != nil {
		return "", err
	}
	return CurlPoC(req, opts)
}

// curlHeaderField renders "Name: value", or curl's "Name;" form for an empty
// value (which asks curl to send the header with no value).
func curlHeaderField(name, value string) string {
	if value == "" {
		return name + ";"
	}
	return name + ": " + value
}

// curlTokenPlaceholder keeps the authentication scheme ("Bearer", "Basic") and
// replaces only the secret with a shell variable.
func curlTokenPlaceholder(value, tokenVar string) string {
	scheme, _ := splitAuthScheme(value)
	if scheme == "" {
		return "$" + tokenVar
	}
	return scheme + " $" + tokenVar
}

// splitAuthScheme splits "Bearer abc.def" into ("Bearer", "abc.def"). A value
// with no scheme returns ("", value).
func splitAuthScheme(value string) (scheme, secret string) {
	trimmed := strings.TrimSpace(value)
	scheme, secret, ok := strings.Cut(trimmed, " ")
	if !ok || !curlTokenWord(scheme) {
		return "", trimmed
	}
	return scheme, strings.TrimSpace(secret)
}

// curlTokenWord reports whether s is a short HTTP token, safe to place inside a
// double-quoted shell string without escaping.
func curlTokenWord(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '+', r == '/':
		default:
			return false
		}
	}
	return true
}

// curlQuote wraps s in single quotes, escaping embedded single quotes for POSIX
// shells.
func curlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// singleLine replaces CR, LF and NUL so a value can never break the generated
// command's line structure.
func singleLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\x00", " ")
	return strings.TrimSpace(s)
}

// validate refuses evidence that could not be reproduced as one shell command.
func (r HTTPRequestEvidence) validate() error {
	method := strings.TrimSpace(r.Method)
	if !curlTokenWord(method) {
		return fmt.Errorf("report: %q is not a valid HTTP method", r.Method)
	}
	rawURL := strings.TrimSpace(r.URL)
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("report: HTTP request evidence has no absolute URL (%q)", r.URL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("report: URL scheme %q is not http(s)", u.Scheme)
	}
	if strings.ContainsAny(rawURL, "\r\n\x00") {
		return errors.New("report: the request URL contains a control character")
	}
	for _, h := range r.Headers {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			return errors.New("report: HTTP request evidence has an empty header name")
		}
		for _, c := range name {
			if c <= ' ' || c >= 0x7f || c == ':' {
				return fmt.Errorf("report: %q is not a valid HTTP header name", h.Name)
			}
		}
		if strings.ContainsAny(h.Value, "\r\n\x00") {
			return fmt.Errorf("report: header %q contains a control character", name)
		}
	}
	if strings.IndexByte(r.Body, 0) >= 0 {
		return errors.New("report: a body containing NUL cannot be rendered as a shell argument")
	}
	return nil
}

// ParseHTTPRequestEvidence parses a stored HTTP/1.1 request message (the
// message/http evidence blob every executor writes). The scheme for an
// origin-form target is taken from X-Forwarded-Proto / X-Forwarded-Scheme when
// present, otherwise https.
func ParseHTTPRequestEvidence(raw []byte) (HTTPRequestEvidence, error) {
	return ParseHTTPRequestEvidenceWithScheme(raw, "")
}

// ParseHTTPRequestEvidenceWithScheme is ParseHTTPRequestEvidence with an
// explicit fallback scheme ("http" for a plain-HTTP lab target).
func ParseHTTPRequestEvidenceWithScheme(raw []byte, scheme string) (HTTPRequestEvidence, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return HTTPRequestEvidence{}, errors.New("report: empty HTTP request evidence")
	}
	head, body := splitHTTPMessage(raw)
	lines := httpMessageLines(head)
	if len(lines) == 0 {
		return HTTPRequestEvidence{}, errors.New("report: HTTP request evidence has no request line")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return HTTPRequestEvidence{}, fmt.Errorf("report: malformed request line %q", lines[0])
	}
	method, target := fields[0], fields[1]
	if len(fields) > 2 && !strings.HasPrefix(strings.ToUpper(fields[2]), "HTTP/") {
		return HTTPRequestEvidence{}, fmt.Errorf("report: malformed request line %q", lines[0])
	}

	headers := make([]HTTPHeader, 0, len(lines)-1)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return HTTPRequestEvidence{}, fmt.Errorf("report: malformed header line %q", line)
		}
		headers = append(headers, HTTPHeader{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}

	req := HTTPRequestEvidence{Method: method, URL: target, Headers: headers, Body: string(body)}
	if !isAbsoluteHTTPURL(target) {
		host := req.Value("Host")
		if host == "" {
			return HTTPRequestEvidence{}, errors.New("report: request evidence has no Host header and a relative target")
		}
		s := strings.ToLower(strings.TrimSpace(scheme))
		if s != "http" && s != "https" {
			s = evidenceScheme(headers)
		}
		if s == "" {
			s = "https"
		}
		req.URL = s + "://" + host + target
	}
	if err := req.validate(); err != nil {
		return HTTPRequestEvidence{}, err
	}
	return req, nil
}

// evidenceScheme reads a client-side scheme from the forwarding headers an
// interception proxy or reverse proxy leaves in the stored request.
func evidenceScheme(headers []HTTPHeader) string {
	for _, name := range []string{"X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Original-Scheme"} {
		for _, h := range headers {
			if !strings.EqualFold(strings.TrimSpace(h.Name), name) {
				continue
			}
			value := strings.ToLower(strings.TrimSpace(strings.Split(h.Value, ",")[0]))
			if value == "http" || value == "https" {
				return value
			}
		}
	}
	return ""
}

// splitHTTPMessage splits a message into its header block and its body,
// accepting both CRLF and bare-LF line endings.
func splitHTTPMessage(raw []byte) (head, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, nil
}

// httpMessageLines returns the header block's lines, dropping CR and unfolding
// obsolete line continuations.
func httpMessageLines(head []byte) []string {
	raw := strings.Split(string(head), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if len(out) > 0 {
				out[len(out)-1] += " " + strings.TrimSpace(line)
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func isAbsoluteHTTPURL(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}
