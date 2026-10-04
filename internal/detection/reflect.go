package detection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// This file implements the first real Reflected XSS detection step: injecting a
// unique, deterministic marker into one injection point and analysing whether —
// and how — it is reflected in the response. It makes NO verdict: it records
// reflection, location, surrounding context, and how the marker's canary was
// transformed (encoded/stripped/raw). Confirming XSS is a later phase.
//
// The analysis here is pure (bytes in, report out); the scan executor performs
// the HTTP requests and persists the ReflectionReport into TestCase.Detail.

// Probe is a unique, deterministic reflection marker for one injection point.
//
// The injected value is Token + Canary + Tail:
//
//   - Token and Tail are alphanumeric sentinels (hex), so they survive HTML/URL/
//     JS encoders unchanged and can always be located. Bracketing the canary
//     between two sentinels makes transformation analysis robust: the bytes
//     strictly between a Token and its following Tail are exactly what the target
//     did to the canary, with no ambiguity from surrounding markup.
//   - Canary is a small, fixed set of HTML-significant characters. Observing how
//     they come back is reflection analysis (required: "record transformations/
//     encoding applied to the marker"); it is NOT an exploit payload — no script,
//     event handler, or scheme is ever generated.
type Probe struct {
	Token  string `json:"token"`
	Canary string `json:"canary"`
	Tail   string `json:"tail"`
}

// canaryChars is the fixed detection canary: the HTML-significant characters
// whose encoding determines reflection context. Not an exploit payload.
const canaryChars = `<>"'`

// NewProbe derives a deterministic, per-injection-point probe. The same scan +
// injection point always yields the same probe (reproducible re-runs); different
// injection points yield different, non-colliding sentinels.
func NewProbe(scanID, injectionPointID domain.ID) Probe {
	sum := sha256.Sum256([]byte(string(scanID) + "\x00" + string(injectionPointID)))
	core := hex.EncodeToString(sum[:8]) // 16 hex chars
	return Probe{
		Token:  "ind" + core,
		Canary: canaryChars,
		Tail:   "end" + core,
	}
}

// Value is the string to inject into the selected injection point.
func (p Probe) Value() string { return p.Token + p.Canary + p.Tail }

// Encoding classifications for how the canary came back.
const (
	EncNone     = "none"     // reflected verbatim (unencoded)
	EncHTML     = "html"     // HTML entity-encoded
	EncURL      = "url"      // percent-encoded
	EncJS       = "js"       // backslash-escaped
	EncStripped = "stripped" // removed
	EncMixed    = "mixed"    // more than one of the above
	EncUnknown  = "unknown"  // tail sentinel not found near the token
)

// ResponseSummary is a light comparison record for a response.
type ResponseSummary struct {
	Status  int `json:"status"`
	BodyLen int `json:"body_len"`
}

// ReflectionLocation is one site where the marker's token was reflected.
type ReflectionLocation struct {
	Offset     int               `json:"offset"`                // byte offset of the token in the mutated body
	TailOffset int               `json:"tail_offset,omitempty"` // byte offset of the tail sentinel (0 = not found)
	Before     string            `json:"before"`                // bounded context before the token
	Segment    string            `json:"segment"`               // bytes between token and tail (the transformed canary)
	After      string            `json:"after"`                 // bounded context after the tail
	Encoding   string            `json:"encoding"`              // none|html|url|js|stripped|mixed|unknown
	PerChar    map[string]string `json:"per_char,omitempty"`    // canary char -> raw|html|url|js|stripped

	// Context is the deterministic context classification of this site, set by
	// ClassifyContexts. nil on reports produced before context analysis.
	Context *ContextAnalysis `json:"context,omitempty"`
}

// ReflectionEvidence ties a report to the stored evidence it was derived from, so
// every site offset can be resolved to an exact byte in the evidence blob.
//
// Offsets in ReflectionLocation/ContextAnalysis are relative to the mutated
// response BODY. The mutated-response evidence blob is an HTTP/1.1 message
// (status line + headers + blank line + body), so the blob offset of a site is
// MutatedBodyOffset + Offset.
type ReflectionEvidence struct {
	BaselineRequest   domain.ID `json:"baseline_request,omitempty"`
	BaselineResponse  domain.ID `json:"baseline_response,omitempty"`
	MutatedRequest    domain.ID `json:"mutated_request,omitempty"`
	MutatedResponse   domain.ID `json:"mutated_response,omitempty"`
	MutatedBodyOffset int       `json:"mutated_body_offset,omitempty"`
}

// BlobOffset converts a body-relative offset into an offset within the
// mutated-response evidence blob.
func (e ReflectionEvidence) BlobOffset(bodyOffset int) int { return e.MutatedBodyOffset + bodyOffset }

// ReflectionReport is the persisted result of the reflection step. It is stored
// (JSON) in TestCase.Detail. It is intentionally descriptive, not a verdict.
type ReflectionReport struct {
	Engine          string               `json:"engine"`
	Probe           Probe                `json:"probe"`
	Parameter       string               `json:"parameter"`
	Location        domain.ParamLocation `json:"location"`
	Reflected       bool                 `json:"reflected"`
	Count           int                  `json:"count"` // number of reflection sites
	Truncated       bool                 `json:"truncated,omitempty"`
	TokenInBaseline bool                 `json:"token_in_baseline"` // sanity: should be false
	Locations       []ReflectionLocation `json:"locations,omitempty"`
	Baseline        ResponseSummary      `json:"baseline"`
	Mutated         ResponseSummary      `json:"mutated"`
	ContentType     string               `json:"content_type,omitempty"` // mutated response Content-Type
	Evidence        ReflectionEvidence   `json:"evidence,omitempty"`

	// Plan is the deterministic candidate plan derived from the sites above, set
	// by PlanCandidates. nil on reports produced before candidate planning. The
	// candidates are data for a later, separately-gated execution phase; recording
	// them here is not a verdict and sends nothing.
	Plan *CandidatePlan `json:"plan,omitempty"`

	// Candidate is set when this report is the RE-ANALYSIS of a sent candidate
	// (the candidate-execution phase) rather than the initial reflection step. It
	// records which candidate (and its source — builtin/llm) produced this
	// response. Candidate reports carry no Plan: candidates are not re-planned.
	Candidate *Candidate `json:"candidate,omitempty"`
}

// Tuning for the analysis.
const (
	maxReflectionLocations = 25  // cap recorded sites
	contextWindow          = 48  // bytes of before/after context
	tailSearchWindow       = 512 // how far after a token to look for the tail
)

// AnalyzeReflection locates the probe's token in the mutated body and classifies
// how the canary was transformed at each site. baselineBody is used only for the
// token-absence sanity check and comparison.
func AnalyzeReflection(p Probe, baselineBody, mutatedBody []byte) ReflectionReport {
	rep := ReflectionReport{
		Engine:          "reflected-xss",
		Probe:           p,
		TokenInBaseline: bytes.Contains(baselineBody, []byte(p.Token)),
	}

	token := []byte(p.Token)
	tail := []byte(p.Tail)
	for off := 0; ; {
		i := bytes.Index(mutatedBody[off:], token)
		if i < 0 {
			break
		}
		abs := off + i
		rep.Count++
		if len(rep.Locations) < maxReflectionLocations {
			rep.Locations = append(rep.Locations, locationAt(mutatedBody, abs, token, tail, p.Canary))
		} else {
			rep.Truncated = true
		}
		off = abs + len(token) // overlapping tokens are not expected; advance past it
	}
	rep.Reflected = rep.Count > 0
	return rep
}

func locationAt(body []byte, tokenOff int, token, tail []byte, canary string) ReflectionLocation {
	tokenEnd := tokenOff + len(token)
	loc := ReflectionLocation{
		Offset: tokenOff,
		Before: excerpt(body, tokenOff-contextWindow, tokenOff),
	}

	// Find the tail sentinel in a bounded window after the token; the bytes
	// between are exactly what the target did to the canary.
	searchEnd := tokenEnd + tailSearchWindow
	if searchEnd > len(body) {
		searchEnd = len(body)
	}
	rel := bytes.Index(body[tokenEnd:searchEnd], tail)
	if rel < 0 {
		loc.Encoding = EncUnknown
		loc.After = excerpt(body, tokenEnd, tokenEnd+contextWindow)
		return loc
	}
	segStart := tokenEnd
	segEnd := tokenEnd + rel
	seg := body[segStart:segEnd]
	loc.TailOffset = segEnd
	loc.Segment = toValid(seg)
	loc.After = excerpt(body, segEnd+len(tail), segEnd+len(tail)+contextWindow)
	loc.Encoding, loc.PerChar = classifyCanary(seg, canary)
	return loc
}

// classifyCanary determines, within the exact segment between the sentinels, how
// each canary character was represented, and summarizes.
func classifyCanary(seg []byte, canary string) (string, map[string]string) {
	low := bytes.ToLower(seg)
	perChar := make(map[string]string, len(canary))
	forms := map[string]bool{}
	pos := 0
	for i := 0; i < len(canary); i++ {
		ch := canary[i]
		form, adv := matchCanaryChar(seg, low, pos, ch)
		perChar[string(ch)] = form
		forms[form] = true
		pos += adv
	}
	return summarize(forms), perChar
}

func matchCanaryChar(seg, low []byte, pos int, ch byte) (form string, advance int) {
	if pos >= len(seg) {
		return EncStripped, 0
	}
	if seg[pos] == ch {
		return EncNone, 1 // raw
	}
	for _, cand := range canaryEncodings(ch) {
		if hasPrefixAt(low, pos, cand.enc) {
			return cand.form, len(cand.enc)
		}
	}
	return EncStripped, 0 // present-but-unrecognized stays where it is
}

type canaryEnc struct {
	enc  string // lowercased
	form string
}

func canaryEncodings(ch byte) []canaryEnc {
	switch ch {
	case '<':
		return []canaryEnc{{"&lt;", EncHTML}, {"&#60;", EncHTML}, {"&#x3c;", EncHTML}, {"%3c", EncURL}, {"\\x3c", EncJS}, {"\\u003c", EncJS}}
	case '>':
		return []canaryEnc{{"&gt;", EncHTML}, {"&#62;", EncHTML}, {"&#x3e;", EncHTML}, {"%3e", EncURL}, {"\\x3e", EncJS}, {"\\u003e", EncJS}}
	case '"':
		return []canaryEnc{{"&quot;", EncHTML}, {"&#34;", EncHTML}, {"&#x22;", EncHTML}, {"%22", EncURL}, {"\\\"", EncJS}, {"\\u0022", EncJS}}
	case '\'':
		return []canaryEnc{{"&#39;", EncHTML}, {"&#x27;", EncHTML}, {"&apos;", EncHTML}, {"%27", EncURL}, {"\\'", EncJS}, {"\\u0027", EncJS}}
	default:
		return nil
	}
}

func hasPrefixAt(low []byte, pos int, prefix string) bool {
	if pos+len(prefix) > len(low) {
		return false
	}
	return string(low[pos:pos+len(prefix)]) == prefix
}

// summarize reduces the set of per-character forms to one label.
func summarize(forms map[string]bool) string {
	delete(forms, "") // defensive
	switch len(forms) {
	case 0:
		return EncUnknown
	case 1:
		for f := range forms {
			return f
		}
	}
	// Multiple distinct forms. All-raw was length 1 (EncNone); here it is mixed.
	return EncMixed
}

func excerpt(b []byte, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(b) {
		end = len(b)
	}
	if start >= end {
		return ""
	}
	return toValid(b[start:end])
}

func toValid(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// ParseReflection decodes a ReflectionReport from TestCase.Detail. It returns
// (nil, nil) for empty detail so callers can treat "no reflection data" simply.
func ParseReflection(detail []byte) (*ReflectionReport, error) {
	if len(detail) == 0 {
		return nil, nil
	}
	var r ReflectionReport
	if err := json.Unmarshal(detail, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
