package report

// The finding view model shared by every report format AND the web API's
// finding endpoints, so a finding is presented the same way everywhere.
//
// It is pure derivation from a stored Finding, its opaque Detail blob, and
// evidence metadata: it computes no verdict and fabricates nothing. The
// "verified candidate" is simply the stored attempt whose recorded verdict is
// Confirmed — the verdict itself was decided earlier, by the browser
// verifier's deterministic signal, and is only echoed here. Like the other
// generators it reads Detail through a small local shape rather than importing
// internal/scan or internal/detection.

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
)

// Section is where a finding belongs in a report: confirmed vulnerabilities
// first, then findings that still need review, then diagnostics — attempts
// that were rejected and are NOT vulnerabilities.
type Section string

const (
	SectionConfirmed   Section = "confirmed"
	SectionNeedsReview Section = "needs_review"
	SectionDiagnostic  Section = "diagnostic"
)

var sectionOrder = []Section{SectionConfirmed, SectionNeedsReview, SectionDiagnostic}

func (s Section) rank() int {
	for i, x := range sectionOrder {
		if x == s {
			return i
		}
	}
	return len(sectionOrder)
}

// Title is the human heading for the section.
func (s Section) Title() string {
	switch s {
	case SectionConfirmed:
		return "Confirmed vulnerabilities"
	case SectionNeedsReview:
		return "Unconfirmed — needs review"
	default:
		return "Diagnostics — rejected attempts (not vulnerabilities)"
	}
}

// SectionOf maps a stored verdict to its report section, with no finding
// context — see FindingSection for the context-aware version every call site
// in this package actually uses. Kept exported for compatibility with any
// caller that only has a bare Verdict.
func SectionOf(v domain.Verdict) Section {
	switch v {
	case domain.VerdictConfirmed:
		return SectionConfirmed
	case domain.VerdictRejected:
		return SectionDiagnostic
	default: // pending, inconclusive
		return SectionNeedsReview
	}
}

// SeverityLabel and VerifiedAtLabel name a finding's severity and
// verification-time fields. Only a confirmed finding is a vulnerability: for
// any other verdict the severity is what it WOULD be if confirmed, and the
// timestamp is when verification ran, not when anything was verified — a
// plain "Severity: high" / "Verified: <time>" on a rejected finding reads as
// a confirmed one at a glance.
func SeverityLabel(v domain.Verdict) string {
	if v == domain.VerdictConfirmed {
		return "Severity"
	}
	return "Severity (if confirmed)"
}

// VerifiedAtLabel: see SeverityLabel.
func VerifiedAtLabel(v domain.Verdict) string {
	if v == domain.VerdictConfirmed {
		return "Verified"
	}
	return "Verification run"
}

// CVSSLabel names a finding's CVSS line. The vector is a CLASS-LEVEL baseline
// either way (see Classification), but on a finding that was not confirmed it
// must not read as the score of a confirmed vulnerability — the same reason
// SeverityLabel qualifies its own label.
func CVSSLabel(v domain.Verdict) string {
	if v == domain.VerdictConfirmed {
		return "CVSS v3.1 (class baseline)"
	}
	return "CVSS v3.1 (class baseline — this finding is NOT confirmed)"
}

// EvidenceView is evidence METADATA with its role — never content or the blob
// path. Baseline evidence is the unmodified request/response kept for
// comparison; it is labelled so a value in it (q=hello) is never mistaken for
// a payload.
type EvidenceView struct {
	ID        domain.ID           `json:"id"`
	Kind      domain.EvidenceKind `json:"kind"`
	Role      domain.EvidenceRole `json:"role"`
	MediaType string              `json:"media_type,omitempty"`
	Size      int64               `json:"size"`
	SHA256    string              `json:"sha256,omitempty"`
	CreatedAt time.Time           `json:"created_at"`
}

// CandidateView is one candidate that reflected at the finding's location.
type CandidateView struct {
	Source         string `json:"source,omitempty"`
	Category       string `json:"category,omitempty"`
	Context        string `json:"context,omitempty"`
	ContextSub     string `json:"context_sub,omitempty"`
	Value          string `json:"value"`
	Trigger        string `json:"trigger,omitempty"`
	Technique      string `json:"technique,omitempty"`
	Transformation string `json:"transformation,omitempty"`
	Rationale      string `json:"rationale,omitempty"`
	// Combined/ParameterB/ValueB describe a COMBINED (multi-parameter)
	// candidate's SECOND half — see docs/reflection-candidates.md "Combined
	// (multi-parameter) candidates". Empty/false for every ordinary
	// single-parameter candidate.
	Combined   bool   `json:"combined,omitempty"`
	ParameterB string `json:"parameter_b,omitempty"`
	ValueB     string `json:"value_b,omitempty"`
}

// AttemptView is one browser-verification attempt: the candidate replayed, that
// attempt's OWN verdict, and the evidence it produced.
type AttemptView struct {
	CandidateValue string `json:"candidate_value"`
	// URL is the exact URL this attempt navigated to (candidate value
	// already substituted into its injection point) — a ready, copy-paste
	// manual proof-of-concept, most useful for an interaction-only
	// candidate (onmouseover, javascript: href, …) the passive verifier can
	// reflect-but-never-confirm itself; see ReviewInteractionOnly below.
	// Empty when the attempt never actually navigated (unsupported body
	// representation, invalid/oversized JSON, or a state-changing request
	// without AllowStateChanging).
	URL              string            `json:"url,omitempty"`
	Verdict          domain.Verdict    `json:"verdict"`
	Confidence       domain.Confidence `json:"confidence,omitempty"`
	Notes            string            `json:"notes,omitempty"`
	VerifyTestCaseID domain.ID         `json:"verify_test_case_id,omitempty"`
	At               time.Time         `json:"at"`
	Evidence         []EvidenceView    `json:"evidence,omitempty"`
}

// FindingPoC is one runnable curl command reproduced from the finding's own
// stored HTTP request evidence. It exists so a reader can copy the exact
// request out of a report instead of rebuilding it by hand.
//
// The credential rule is not optional: the command carries auth values as shell
// variables ($INDAGO_TOKEN / $INDAGO_COOKIE), so a report, ticket or bug-bounty
// form can be shared without leaking the session it was tested with. See
// CurlOptions.IncludeCredentials for the explicit (and deliberately unused
// here) opt-out.
type FindingPoC struct {
	// EvidenceID names the stored request the command was reproduced from, so
	// the reader can open the exact artifact.
	EvidenceID domain.ID `json:"evidence_id"`
	// Command is the curl invocation (may span lines for readability).
	Command string `json:"curl"`
	// Note is a one-line caveat rendered with the command, e.g. that the
	// credentials are shell variables the reader must export first.
	Note string `json:"note,omitempty"`
}

// ClassIntelView is the class-level context that accompanies a finding in the
// human-facing formats: what the class is called, the impact it normally has,
// and the remediation that class is fixed with. It is reference material from
// the built-in class table — never a claim about what this target exposed —
// and is nil only for a class the table does not know.
type ClassIntelView struct {
	Name        string   `json:"name"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

// FindingView is a finding as presented: its section, the candidate whose
// browser verification succeeded (confirmed findings only), every attempt kept
// as a child diagnostic, and role-ordered evidence.
type FindingView struct {
	Section   Section `json:"section"`
	Method    string  `json:"method,omitempty"`
	ParamName string  `json:"parameter_name,omitempty"`
	// Classification is this finding's class-level CWE + CVSS v3.1 baseline
	// (see Classify), nil for a class the table does not know — an unknown
	// class is reported as unclassified, never given an invented weakness or
	// score. The vector is a documented BASELINE, not a measurement of this
	// target's impact; Classification.Note says so and ships with it.
	Classification *Classification `json:"classification,omitempty"`
	// Intel is the class-level name/impact/remediation rendered with the
	// finding, so every export format (technical Markdown/HTML, JSON and
	// SARIF) carries the same context instead of leaving it to one template.
	// Nil for an unknown class, which is reported as unclassified rather
	// than given invented text.
	Intel *ClassIntelView `json:"class_intel,omitempty"`
	// CurlPoC reproduces the finding's stored HTTP request evidence as one
	// runnable curl command with credentials redacted to shell variables.
	// Nil when the caller supplied no request blob content (Data.
	// RequestEvidence) or the finding has no request evidence of its own —
	// a PoC is never synthesized from a response or a candidate value.
	CurlPoC *FindingPoC `json:"curl_poc,omitempty"`
	// ReviewReason is set only when Section is needs_review BECAUSE a Rejected
	// verdict's own candidates give reason to doubt the negative is clean (see
	// findingReviewReason) — empty for every other case, including the
	// ordinary pending/inconclusive needs-review section.
	ReviewReason      ReviewReason `json:"review_reason,omitempty"`
	ReviewReasonLabel string       `json:"review_reason_label,omitempty"`
	// Combined/ParamNameB mark a finding that required TWO parameters
	// mutated together in the SAME request — see
	// docs/reflection-candidates.md "Combined (multi-parameter)
	// candidates". Empty/false for every ordinary single-parameter finding.
	Combined   bool   `json:"combined,omitempty"`
	ParamNameB string `json:"parameter_b_name,omitempty"`
	// Verified is the confirming attempt (nil unless the finding is confirmed).
	Verified   *AttemptView    `json:"verified_candidate,omitempty"`
	Candidates []CandidateView `json:"candidates,omitempty"`
	Attempts   []AttemptView   `json:"attempts,omitempty"`
	Evidence   []EvidenceView  `json:"evidence,omitempty"`
}

// detailShape is the part of Finding.Detail this view reads (by JSON field
// name; mirrors scan.findingDetail).
type detailShape struct {
	Method        string `json:"method,omitempty"`
	ParameterName string `json:"parameter_name,omitempty"`
	// BlockSuspected/BlockDetail mirror scan.findingDetail's fields of the
	// same name — see upsertBlockFinding. Set only on a diagnostic Finding
	// for a possible WAF/rate-limit/maintenance block seen during testing.
	BlockSuspected bool   `json:"block_suspected,omitempty"`
	BlockDetail    string `json:"block_detail,omitempty"`
	// Throttled is the sticky per-point backpressure flag: once this point
	// answered 429/503, BlockDetail may later show a 403 (it tracks the latest
	// status change) while the point stays ineligible for the bounded pass.
	Throttled        bool   `json:"throttled,omitempty"`
	CaptchaSuspected bool   `json:"captcha_suspected,omitempty"`
	CaptchaLabel     string `json:"captcha_label,omitempty"`
	// Combined/ParameterBName mirror scan.findingDetail's fields of the
	// same name — see docs/reflection-candidates.md "Combined
	// (multi-parameter) candidates".
	Combined       bool   `json:"combined,omitempty"`
	ParameterBName string `json:"parameter_b_name,omitempty"`
	Candidates     []struct {
		Source         string `json:"source"`
		Category       string `json:"category"`
		Context        string `json:"context"`
		ContextSub     string `json:"context_sub"`
		Value          string `json:"value"`
		Trigger        string `json:"trigger"`
		Technique      string `json:"technique"`
		Transformation string `json:"transformation"`
		Rationale      string `json:"rationale"`
		Combined       bool   `json:"combined"`
		ParameterB     string `json:"parameter_b"`
		ValueB         string `json:"value_b"`
	} `json:"candidates"`
	Attempts []struct {
		CandidateValue   string            `json:"candidate_value"`
		URL              string            `json:"url"`
		VerifyTestCaseID domain.ID         `json:"verify_test_case_id"`
		Verdict          domain.Verdict    `json:"verdict"`
		Confidence       domain.Confidence `json:"confidence"`
		Notes            string            `json:"notes"`
		EvidenceIDs      []domain.ID       `json:"evidence_ids"`
		At               time.Time         `json:"at"`
	} `json:"attempts"`
}

// decodeDetail is the one place Finding.Detail is unmarshaled into
// detailShape, so FindingSection and NewFindingView never disagree about what
// it contains.
func decodeDetail(b []byte) detailShape {
	var d detailShape
	if len(b) > 0 {
		_ = json.Unmarshal(b, &d)
	}
	return d
}

// ReviewReason identifies a limitation of the recorded evidence or verdict.
type ReviewReason string

const (
	// ReviewInteractionOnly: the candidate that survived unescaped needs an
	// action beyond page load. The verifier dispatches one declared activation
	// for a closed, recognized set; this reason remains when the action is not
	// recognized or still produced no marker signal, so it may be exploitable.
	ReviewInteractionOnly ReviewReason = "interaction_required"
	// ReviewAllCandidatesFiltered: every candidate this site's context offered
	// was encoded/stripped by the target (none survived raw). The finding may
	// list a bounded automatic Technique fallback as well as canonical shapes;
	// either way, any differently-shaped payload outside the recorded attempts
	// remains untested rather than ruled out.
	ReviewAllCandidatesFiltered ReviewReason = "all_candidates_filtered"
	// ReviewPossibleBlock: a request during testing came back with a
	// suspicious status-code change from baseline (403/429/503) — the real
	// test may never have reached the application at all. Set on the
	// dedicated diagnostic Finding upsertBlockFinding creates (verdict
	// always Inconclusive), never inferred from a Rejected finding's
	// candidates the way the other two reasons are.
	ReviewPossibleBlock ReviewReason = "possible_block"
	// ReviewCaptchaDetected: a CAPTCHA/bot-challenge page newly appeared for
	// the mutated/candidate request during testing — detect-only (AGENTS.md
	// §2.2), set on its own dedicated diagnostic Finding the same way
	// ReviewPossibleBlock is.
	ReviewCaptchaDetected ReviewReason = "captcha_detected"
	// ReviewThrottledPoint: the same diagnostic row, but this point answered
	// 429/503 at some time during testing (sticky). It stays a block
	// diagnostic, yet the bounded fallback is NOT escalated here, so it must
	// not borrow the 403 wording that promises the pass.
	ReviewThrottledPoint           ReviewReason = "throttled_point"
	ReviewBrowserArtifactsWithheld ReviewReason = "browser_artifacts_withheld"
)

// Label is the human-readable explanation of a ReviewReason.
func (r ReviewReason) Label() string {
	switch r {
	case ReviewBrowserArtifactsWithheld:
		return "Indago recorded a browser verdict. Raw browser artifacts were withheld for privacy, so the saved record has limited evidence for independent review."
	case ReviewInteractionOnly:
		return "a candidate reflected unescaped and needs an action beyond page load; for a recognized declared mechanism the verifier dispatches one declared activation, and no marker signal was observed. Unsupported or page-specific actions may still need manual review, so this is not ruled out"
	case ReviewAllCandidatesFiltered:
		return "every candidate recorded at this site was encoded or stripped by the target; bounded alternate technique shapes may also have been tried (and are listed above when present), but a differently-shaped payload outside the recorded attempts remains untested, not ruled out"
	case ReviewPossibleBlock:
		return "a request during testing came back with a suspicious status-code change from the baseline (e.g. 403/429/503) — this may be a WAF/filter, rate-limit or maintenance block, not a clean negative; the diagnostic itself does not retry, any bounded fallback is separately gated by evidence and never bypasses a CAPTCHA, and a 429/503 point is NOT escalated at all because that is backpressure rather than a filter decision on the payload (a 403 filter rejection can still get the bounded pass; see AGENTS.md §2.2)"
	case ReviewThrottledPoint:
		return "this point answered 429 (rate limit) or 503 (unavailable/maintenance) at some time during testing — that is backpressure or downtime, not a filter decision on the payload, so the bounded bypass fallback is NOT escalated here and no CAPTCHA is ever bypassed (see AGENTS.md §2.2). The status change shown is the LATEST one recorded; an earlier 429/503 keeps the point ineligible even when the latest answer was a 403."
	case ReviewCaptchaDetected:
		return "a response during testing matched a known CAPTCHA/bot-challenge pattern (reCAPTCHA/hCaptcha/Cloudflare challenge) that was not present in the baseline response — Indago only detects this, it never attempts to solve or bypass a CAPTCHA (see AGENTS.md §2.2)"
	default:
		return string(r)
	}
}

// findingReviewReason inspects a Rejected finding's own candidates and reports
// the review reason, if any, that means "rejected" should not read as "ruled
// out safe" here. Returns ("", false) for every other verdict, or when a
// Rejected finding's candidates give no reason to doubt the negative. A
// candidate whose Transformation was never recorded (""  — e.g. a
// hand-built test fixture, never a real scan's candidate.go output, which
// always sets "raw" or a specific encoding) is treated as UNKNOWN, not as
// evidence of filtering, so this never fires on data that simply didn't say.
func findingReviewReason(verdict domain.Verdict, d detailShape) (ReviewReason, bool) {
	if d.BlockSuspected {
		// The label follows the STICKY flag, not the latest status in
		// BlockDetail: a 403 that arrives after a 429 is still a throttled
		// point, and telling the operator it can get the bounded pass would
		// be wrong.
		if d.Throttled {
			return ReviewThrottledPoint, true
		}
		return ReviewPossibleBlock, true
	}
	if d.CaptchaSuspected {
		return ReviewCaptchaDetected, true
	}
	if verdict != domain.VerdictRejected || len(d.Candidates) == 0 {
		return "", false
	}
	sawKnownFiltered, allKnownFiltered := false, true
	for _, c := range d.Candidates {
		if c.Trigger == "interaction" && c.Transformation == "raw" {
			return ReviewInteractionOnly, true
		}
		switch c.Transformation {
		case "raw":
			allKnownFiltered = false
		case "html", "url", "js", "stripped", "mixed":
			sawKnownFiltered = true
		default: // "" / unrecognized: unknown, not evidence of filtering
			allKnownFiltered = false
		}
	}
	if sawKnownFiltered && allKnownFiltered {
		return ReviewAllCandidatesFiltered, true
	}
	return "", false
}

// FindingSection is the context-aware section a finding belongs in: it starts
// from its Verdict (see SectionOf) but moves a Rejected finding into
// needs-review when findingReviewReason says the negative is not a clean one.
// Every section-determining call in this package uses this, not SectionOf
// directly, so a finding can never be sorted into one section while its
// FindingView claims another.
func FindingSection(f *domain.Finding) Section {
	sec := SectionOf(f.Verdict)
	if sec != SectionDiagnostic {
		return sec
	}
	if _, ok := findingReviewReason(f.Verdict, decodeDetail(f.Detail)); ok {
		return SectionNeedsReview
	}
	return sec
}

// NewFindingView derives the presentation of f. evidence resolves evidence IDs
// to their metadata; an ID that does not resolve is skipped, never invented.
//
// It cannot render a curl PoC: that needs the stored request BLOB content,
// which this package never reads itself. Callers holding the blobs use
// NewFindingViewWithRequests instead.
func NewFindingView(f *domain.Finding, evidence map[domain.ID]*domain.Evidence) FindingView {
	return newFindingView(f, evidence, nil)
}

// NewFindingViewWithRequests is NewFindingView plus the stored HTTP request
// messages (message/http blobs, keyed by evidence ID) the PoC is reproduced
// from. Passing nil requests is exactly NewFindingView.
//
// The map is data the caller already holds, so this stays a pure derivation:
// no I/O, no network, no clock. A blob that is missing, unparseable or not
// actually a request is skipped — the view then simply carries no PoC rather
// than a made-up one.
func NewFindingViewWithRequests(f *domain.Finding, evidence map[domain.ID]*domain.Evidence, requests map[domain.ID][]byte) FindingView {
	return newFindingView(f, evidence, requests)
}

func newFindingView(f *domain.Finding, evidence map[domain.ID]*domain.Evidence, requests map[domain.ID][]byte) FindingView {
	d := decodeDetail(f.Detail)
	v := FindingView{Section: FindingSection(f), Method: d.Method, ParamName: d.ParameterName, Combined: d.Combined, ParamNameB: d.ParameterBName}
	if c, ok := Classify(f.VulnClass); ok {
		v.Classification = &c
		in := intelFor(f.VulnClass)
		if in.CWE != "n/a" {
			v.Intel = &ClassIntelView{Name: in.Name, Impact: in.Impact, Remediation: in.Remediation, References: in.References}
		}
	}
	if reason, ok := findingReviewReason(f.Verdict, d); ok {
		v.ReviewReason = reason
		v.ReviewReasonLabel = reason.Label()
	}
	if f.Verdict == domain.VerdictConfirmed && browserArtifactsWithheld(f, evidence) {
		v.ReviewReason = ReviewBrowserArtifactsWithheld
		v.ReviewReasonLabel = v.ReviewReason.Label()
	}

	for _, c := range d.Candidates {
		v.Candidates = append(v.Candidates, CandidateView{
			Source: c.Source, Category: c.Category, Context: c.Context, ContextSub: c.ContextSub,
			Value: c.Value, Trigger: c.Trigger, Technique: c.Technique, Transformation: c.Transformation, Rationale: c.Rationale,
			Combined: c.Combined, ParameterB: c.ParameterB, ValueB: c.ValueB,
		})
	}

	evidenceFor := func(ids []domain.ID) []EvidenceView {
		var out []EvidenceView
		seen := map[domain.ID]bool{}
		for _, id := range ids {
			ev := evidence[id]
			if ev == nil || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, EvidenceView{ID: ev.ID, Kind: ev.Kind, Role: ev.Role(), MediaType: ev.MediaType,
				Size: ev.Size, SHA256: ev.SHA256, CreatedAt: ev.CreatedAt})
		}
		sortEvidence(out)
		return out
	}

	for _, a := range d.Attempts {
		v.Attempts = append(v.Attempts, AttemptView{
			CandidateValue: a.CandidateValue, URL: a.URL, Verdict: a.Verdict, Confidence: a.Confidence, Notes: a.Notes,
			VerifyTestCaseID: a.VerifyTestCaseID, At: a.At, Evidence: evidenceFor(a.EvidenceIDs),
		})
	}
	// Chronological, with the verify TestCase ID as tiebreak: concurrent
	// verifications complete in no fixed order, so storage order is not stable.
	sort.SliceStable(v.Attempts, func(i, j int) bool {
		a, b := v.Attempts[i], v.Attempts[j]
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		return a.VerifyTestCaseID < b.VerifyTestCaseID
	})
	if f.Verdict == domain.VerdictConfirmed {
		for i := range v.Attempts {
			if v.Attempts[i].Verdict == domain.VerdictConfirmed {
				a := v.Attempts[i] // earliest confirming attempt
				v.Verified = &a
				break
			}
		}
	}
	v.Evidence = evidenceFor(f.EvidenceIDs)
	v.CurlPoC = curlPoCFor(v, requests)
	return v
}

// curlPoCFor reproduces the finding's stored HTTP request evidence as one curl
// command, or returns nil when no request blob was supplied.
//
// Preference order is what makes the command a PoC for THIS finding: the
// verified attempt's own request first (the exact request the browser
// replayed), then another attempt's, then the finding's remaining evidence.
// Baseline evidence is excluded on purpose — it is the UNMODIFIED request, so a
// command reproduced from it would not reproduce the finding.
func curlPoCFor(v FindingView, requests map[domain.ID][]byte) *FindingPoC {
	if len(requests) == 0 {
		return nil
	}
	for _, id := range pocRequestIDs(v) {
		raw, ok := requests[id]
		if !ok || len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		// Default options: credentials are shell variables, never literal
		// secrets, and redirects are not followed so the reader sees the
		// response the evidence recorded.
		opts := CurlOptions{Scheme: pocScheme(v)}
		cmd, err := CurlPoCFromEvidence(raw, opts)
		if err != nil {
			// Not a reproducible request: try the next candidate rather
			// than emit a broken command.
			continue
		}
		note := ""
		defaults := opts.withDefaults()
		if strings.Contains(cmd, "$"+defaults.TokenVar) || strings.Contains(cmd, "$"+defaults.CookieVar) {
			note = "credentials are shell variables ($" + defaults.TokenVar + " / $" + defaults.CookieVar + ") — export them before running; no literal secret is stored in this report"
		}
		if note != "" {
			cmd = "# " + note + "\n" + cmd
		}
		return &FindingPoC{EvidenceID: id, Command: cmd, Note: note}
	}
	return nil
}

// pocRequestIDs lists the request-kind evidence IDs to try, most specific
// first, skipping the baseline reference (see curlPoCFor).
func pocRequestIDs(v FindingView) []domain.ID {
	var out []domain.ID
	seen := map[domain.ID]bool{}
	add := func(evs []EvidenceView) {
		for _, e := range evs {
			if e.Kind != domain.EvidenceRequest || e.Role == domain.RoleBaseline || seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			out = append(out, e.ID)
		}
	}
	if v.Verified != nil {
		add(v.Verified.Evidence)
	}
	for _, a := range v.Attempts {
		add(a.Evidence)
	}
	add(v.Evidence)
	return out
}

// pocScheme is the scheme to assume for a stored request whose target is
// origin-form: the scheme of any absolute URL this finding recorded, else
// https. Without it a plain-HTTP lab target would get a https command that
// cannot connect.
func pocScheme(v FindingView) string {
	urls := []string{}
	if v.Verified != nil {
		urls = append(urls, v.Verified.URL)
	}
	for _, a := range v.Attempts {
		urls = append(urls, a.URL)
	}
	for _, u := range urls {
		if strings.HasPrefix(strings.ToLower(u), "http://") {
			return "http"
		}
	}
	return "https"
}

// sortEvidence orders by what matters when reading a finding: the browser
// verification artifacts first, then the request/response of the candidate that
// was sent, and the baseline (reference) last.
func sortEvidence(evs []EvidenceView) {
	roleRank := map[domain.EvidenceRole]int{domain.RoleBrowser: 0, domain.RoleCandidate: 1, domain.RoleBaseline: 2}
	kindRank := map[domain.EvidenceKind]int{
		domain.EvidenceScreenshot: 0, domain.EvidenceDOM: 1, domain.EvidenceBrowserLog: 2,
		domain.EvidenceRequest: 3, domain.EvidenceResponse: 4,
	}
	rk := func(m map[domain.EvidenceRole]int, r domain.EvidenceRole) int {
		if n, ok := m[r]; ok {
			return n
		}
		return len(m)
	}
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i], evs[j]
		if ra, rb := rk(roleRank, a.Role), rk(roleRank, b.Role); ra != rb {
			return ra < rb
		}
		ka, oka := kindRank[a.Kind]
		kb, okb := kindRank[b.Kind]
		if !oka {
			ka = len(kindRank)
		}
		if !okb {
			kb = len(kindRank)
		}
		if ka != kb {
			return ka < kb
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	})
}

// Prioritized returns a copy of findings ordered for presentation: confirmed
// first, then needs-review, then diagnostics; within a section by
// (CreatedAt, ID). Deterministic regardless of the input order.
func Prioritized(findings []*domain.Finding) []*domain.Finding {
	out := append([]*domain.Finding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := FindingSection(out[i]).rank(), FindingSection(out[j]).rank()
		if si != sj {
			return si < sj
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// EvidenceIndex builds the lookup NewFindingView takes from a metadata slice.
func EvidenceIndex(evs []*domain.Evidence) map[domain.ID]*domain.Evidence {
	m := make(map[domain.ID]*domain.Evidence, len(evs))
	for _, e := range evs {
		if e != nil {
			m[e.ID] = e
		}
	}
	return m
}
