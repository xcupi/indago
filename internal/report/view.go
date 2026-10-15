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
	"encoding/json"
	"sort"
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
}

// AttemptView is one browser-verification attempt: the candidate replayed, that
// attempt's OWN verdict, and the evidence it produced.
type AttemptView struct {
	CandidateValue   string            `json:"candidate_value"`
	Verdict          domain.Verdict    `json:"verdict"`
	Confidence       domain.Confidence `json:"confidence,omitempty"`
	Notes            string            `json:"notes,omitempty"`
	VerifyTestCaseID domain.ID         `json:"verify_test_case_id,omitempty"`
	At               time.Time         `json:"at"`
	Evidence         []EvidenceView    `json:"evidence,omitempty"`
}

// FindingView is a finding as presented: its section, the candidate whose
// browser verification succeeded (confirmed findings only), every attempt kept
// as a child diagnostic, and role-ordered evidence.
type FindingView struct {
	Section   Section `json:"section"`
	Method    string  `json:"method,omitempty"`
	ParamName string  `json:"parameter_name,omitempty"`
	// ReviewReason is set only when Section is needs_review BECAUSE a Rejected
	// verdict's own candidates give reason to doubt the negative is clean (see
	// findingReviewReason) — empty for every other case, including the
	// ordinary pending/inconclusive needs-review section.
	ReviewReason      ReviewReason `json:"review_reason,omitempty"`
	ReviewReasonLabel string       `json:"review_reason_label,omitempty"`
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
	Candidates    []struct {
		Source         string `json:"source"`
		Category       string `json:"category"`
		Context        string `json:"context"`
		ContextSub     string `json:"context_sub"`
		Value          string `json:"value"`
		Trigger        string `json:"trigger"`
		Technique      string `json:"technique"`
		Transformation string `json:"transformation"`
		Rationale      string `json:"rationale"`
	} `json:"candidates"`
	Attempts []struct {
		CandidateValue   string            `json:"candidate_value"`
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

// ReviewReason explains why a Rejected finding was placed in needs-review
// instead of diagnostics — a distinction "rejected" alone cannot make: a
// rejected VERDICT always means "no execution signal was observed", but that
// covers two operator-meaningfully-different situations this type separates.
type ReviewReason string

const (
	// ReviewInteractionOnly: the candidate that survived unescaped needs a user
	// action (click/hover/navigation) the verifier deliberately never simulates
	// (AGENTS.md §3) — it may be genuinely exploitable; passive verification
	// simply could never confirm it either way.
	ReviewInteractionOnly ReviewReason = "interaction_required"
	// ReviewAllCandidatesFiltered: every candidate this site's context offered
	// was encoded/stripped by the target (none survived raw). Indago tries only
	// the small, canonical breakout(s) for that context — never alternate
	// shapes/evasion variants (AGENTS.md §2.2) — so a DIFFERENTLY shaped
	// breakout bypassing this specific filter is simply untested, not ruled out.
	ReviewAllCandidatesFiltered ReviewReason = "all_candidates_filtered"
)

// Label is the human-readable explanation of a ReviewReason.
func (r ReviewReason) Label() string {
	switch r {
	case ReviewInteractionOnly:
		return "a candidate reflected unescaped but requires a user action (click/hover/navigation) that passive browser verification deliberately never simulates — it may still be exploitable; this was never actually confirmed OR ruled out"
	case ReviewAllCandidatesFiltered:
		return "every candidate tried at this site was encoded or stripped by the target; Indago only tries the small, canonical breakout(s) for this context (never alternate shapes or evasion variants), so a differently-shaped payload bypassing this specific filter is untested, not ruled out"
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
func NewFindingView(f *domain.Finding, evidence map[domain.ID]*domain.Evidence) FindingView {
	d := decodeDetail(f.Detail)
	v := FindingView{Section: FindingSection(f), Method: d.Method, ParamName: d.ParameterName}
	if reason, ok := findingReviewReason(f.Verdict, d); ok {
		v.ReviewReason = reason
		v.ReviewReasonLabel = reason.Label()
	}

	for _, c := range d.Candidates {
		v.Candidates = append(v.Candidates, CandidateView{
			Source: c.Source, Category: c.Category, Context: c.Context, ContextSub: c.ContextSub,
			Value: c.Value, Trigger: c.Trigger, Technique: c.Technique, Transformation: c.Transformation, Rationale: c.Rationale,
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
			CandidateValue: a.CandidateValue, Verdict: a.Verdict, Confidence: a.Confidence, Notes: a.Notes,
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
	return v
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
