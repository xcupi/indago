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

// SectionOf maps a stored verdict to its report section.
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

// NewFindingView derives the presentation of f. evidence resolves evidence IDs
// to their metadata; an ID that does not resolve is skipped, never invented.
func NewFindingView(f *domain.Finding, evidence map[domain.ID]*domain.Evidence) FindingView {
	var d detailShape
	if len(f.Detail) > 0 {
		_ = json.Unmarshal(f.Detail, &d)
	}
	v := FindingView{Section: SectionOf(f.Verdict), Method: d.Method, ParamName: d.ParameterName}

	for _, c := range d.Candidates {
		v.Candidates = append(v.Candidates, CandidateView{
			Source: c.Source, Category: c.Category, Context: c.Context, ContextSub: c.ContextSub,
			Value: c.Value, Trigger: c.Trigger, Transformation: c.Transformation, Rationale: c.Rationale,
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
		si, sj := SectionOf(out[i].Verdict).rank(), SectionOf(out[j].Verdict).rank()
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
