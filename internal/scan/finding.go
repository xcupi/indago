package scan

// This file is the Finding correlation layer: it turns a reflected candidate
// into a Finding (Pending), and a browser-verification result into that
// Finding's Confirmed/Rejected/Inconclusive promotion — without ever
// multiplying near-duplicate Finding rows for the same underlying site, and
// without ever discarding the raw evidence a correlated attempt produced.
//
// Boundaries (see AGENTS.md §2):
//   - Only verification's own Verdict ever reaches the Finding (correlate
//     never invents or overrides it); the ONE rule this file adds is that a
//     Finding's verdict only ever moves UP the pending→inconclusive/
//     rejected→confirmed lattice — a later, weaker result at the same
//     correlated site never downgrades an already-confirmed finding.
//   - Correlation is keyed on meaningful differences only: injection point
//     (= scan+endpoint+parameter) and the reflection's category+context. A
//     different parameter or a different context is a different Finding.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/verification"
)

// findingDetail is Finding.Detail's engine-specific payload for Reflected XSS:
// the correlation key, every distinct candidate that correlated into this
// finding (raw evidence of what was actually tried, preserved even when
// merged), and the TestCase IDs that back it end to end.
type findingDetail struct {
	Method        domain.HTTPMethod     `json:"method,omitempty"`
	ParameterName string                `json:"parameter_name,omitempty"`
	DedupKey      string                `json:"dedup_key"`
	Occurrences   int                   `json:"occurrences"`
	TestCaseIDs   []domain.ID           `json:"test_case_ids,omitempty"`
	Candidates    []detection.Candidate `json:"candidates,omitempty"`
	// Attempts records every browser-verification attempt correlated into this
	// finding with its OWN verdict and evidence. The Finding's Verdict is the
	// ratcheted maximum across attempts (see verdictRank); this keeps the
	// per-candidate outcomes that produced it — a confirming attempt and a
	// later rejected one both stay visible instead of collapsing into one value.
	Attempts []verificationAttempt `json:"attempts,omitempty"`

	// BlockSuspected/BlockDetail: see upsertBlockFinding. Set only on a
	// diagnostic Finding recording a possible WAF/rate-limit/maintenance
	// block seen during testing — never on a real reflected-XSS candidate
	// finding (the two use disjoint dedup keys, see blockFindingDedupKey, so
	// they never share a row).
	BlockSuspected bool   `json:"block_suspected,omitempty"`
	BlockDetail    string `json:"block_detail,omitempty"`

	// CaptchaSuspected/CaptchaLabel: see upsertCaptchaFinding. Set only on a
	// diagnostic Finding recording a CAPTCHA/bot-challenge that newly
	// appeared during testing — detect-only (AGENTS.md §2.2), disjoint dedup
	// key from both the real candidate findings and the block diagnostic.
	CaptchaSuspected bool   `json:"captcha_suspected,omitempty"`
	CaptchaLabel     string `json:"captcha_label,omitempty"`

	// Combined marks a finding that required TWO parameters mutated
	// together in the SAME request to produce this candidate — see
	// docs/reflection-candidates.md "Combined (multi-parameter)
	// candidates". Never set on an ordinary single-parameter finding.
	// ParameterBName names the second parameter so a report can show both
	// without decoding Candidates[0] itself.
	Combined       bool   `json:"combined,omitempty"`
	ParameterBName string `json:"parameter_b_name,omitempty"`
}

// verificationAttempt is one browser-verification attempt correlated into a
// Finding: which candidate was replayed, what verification decided for that
// candidate, and the evidence that attempt (plus its candidate request/
// response) produced.
type verificationAttempt struct {
	CandidateValue      string    `json:"candidate_value"`
	CandidateDedupKey   string    `json:"candidate_dedup_key,omitempty"`
	CandidateTestCaseID domain.ID `json:"candidate_test_case_id,omitempty"`
	VerifyTestCaseID    domain.ID `json:"verify_test_case_id"`
	// URL is the exact URL this attempt navigated to — the candidate value
	// already substituted into its injection point. Surfaced so an operator
	// can copy-paste it into their own browser to manually exercise a
	// candidate the passive verifier can never confirm itself (an
	// interaction-only trigger: onmouseover, javascript: href, …) — see
	// ReviewInteractionOnly in internal/report/view.go. Empty for a
	// non-GET-navigable attempt (unsupported body representation, invalid or
	// oversized POST/JSON, or state-changing without the operator's
	// AllowStateChanging opt-in) that never actually navigated.
	URL         string            `json:"url,omitempty"`
	Verdict     domain.Verdict    `json:"verdict"`
	Confidence  domain.Confidence `json:"confidence,omitempty"`
	Notes       string            `json:"notes,omitempty"`
	EvidenceIDs []domain.ID       `json:"evidence_ids,omitempty"`
	At          time.Time         `json:"at"`
}

func decodeFindingDetail(b []byte) findingDetail {
	var d findingDetail
	if len(b) > 0 {
		_ = json.Unmarshal(b, &d)
	}
	return d
}

func (d findingDetail) encode() []byte {
	b, _ := json.Marshal(d)
	return b
}

// findingDedupKey is the correlation key for a reflected candidate: the SAME
// injection point (scan+endpoint+parameter) producing the SAME candidate
// category at the SAME reflection context is one underlying site, however many
// distinct candidates or attempts confirm it. A different injection point, or
// the same injection point reflecting into a genuinely different context
// (e.g. one site in html_text, another in js_string), is a different finding.
//
// A COMBINED (multi-parameter) candidate gets its own, disjoint identity:
// BOTH injection point IDs plus a "combined" tag plus category+context, so a
// combined finding for (paramX, paramY) can never collide with — or absorb
// into — either paramX's or paramY's own single-parameter finding, nor with
// a DIFFERENT combined pair that happens to share paramX and the same
// category+context but pairs it with a different second parameter.
func findingDedupKey(injectionPointID domain.ID, cand detection.Candidate) string {
	if cand.Combined {
		return string(injectionPointID) + "\x00" + string(cand.InjectionPointBID) + "\x00combined\x00" + string(cand.Category) + "\x00" + string(cand.Context)
	}
	return string(injectionPointID) + "\x00" + string(cand.Category) + "\x00" + string(cand.Context)
}

// severityFor rates a reflected candidate by how directly its category reaches
// code execution. This is a prioritization aid for the PENDING finding, not a
// verdict — only verification decides confirmed/rejected/inconclusive.
func severityFor(cand detection.Candidate) domain.Severity {
	switch cand.Category {
	case detection.CatHTMLText, detection.CatHTMLAttr, detection.CatJS:
		return domain.SeverityHigh
	case detection.CatCSS, detection.CatURL:
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}

// findingTitle names a finding by everything its dedup key distinguishes that
// an operator can see: parameter, reflection context, and endpoint (method +
// path + the parameter-name set that keys an endpoint in discovery). Naming
// it by candidate category alone made distinct findings indistinguishable —
// every html_text reflection of "q" on any endpoint shared one title, as did
// js_string and js_code reflections (both category "javascript").
//
// A COMBINED (multi-parameter) candidate names BOTH parameters and says so
// explicitly ("combined, ...") — an operator must see at a glance that this
// is not a single-parameter bug, since the fix and the report both differ.
// The literal substring "Reflected XSS candidate in" is kept at the front
// either way so confirmedTitle's plain string replace keeps working
// unchanged for a combined finding too.
func findingTitle(cand detection.Candidate, focus *domain.Parameter, ep *domain.Endpoint) string {
	if cand.Combined && cand.ParameterB != "" {
		return fmt.Sprintf("Reflected XSS candidate in parameters %q + %q (combined, %s) at %s %s", focus.Name, cand.ParameterB, cand.Context, ep.Method, endpointLabel(ep.URL))
	}
	return fmt.Sprintf("Reflected XSS candidate in parameter %q (%s) at %s %s", focus.Name, cand.Context, ep.Method, endpointLabel(ep.URL))
}

// confirmedTitle drops "candidate" from a finding's title once browser
// verification has confirmed it: a verified vulnerability is not a candidate.
// Everything else the title says (parameter, context, endpoint) is unchanged,
// and an unconfirmed finding keeps its "candidate" wording.
func confirmedTitle(title string) string {
	return strings.Replace(title, "Reflected XSS candidate in", "Reflected XSS in", 1)
}

// verifiedAttempt returns the attempt that confirmed the finding — the
// candidate whose browser verification produced the deterministic execution
// signal — or nil if none did. With several confirming attempts the earliest
// (then lowest verify TestCase ID) wins, so the choice never depends on the
// order concurrent verifications happened to complete in.
func (d findingDetail) verifiedAttempt() *verificationAttempt {
	var best *verificationAttempt
	for i := range d.Attempts {
		a := &d.Attempts[i]
		if a.Verdict != domain.VerdictConfirmed {
			continue
		}
		if best == nil || a.At.Before(best.At) || (a.At.Equal(best.At) && a.VerifyTestCaseID < best.VerifyTestCaseID) {
			best = a
		}
	}
	return best
}

// endpointLabel is path plus sorted query-parameter NAMES (values dropped),
// mirroring discovery's endpoint identity so two endpoints that differ only
// by their parameter set are told apart.
func endpointLabel(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	label := u.EscapedPath()
	if label == "" {
		label = "/"
	}
	q := u.Query()
	if len(q) == 0 {
		return label
	}
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	return label + "?" + strings.Join(names, "&")
}

// upsertPendingFinding returns the Finding a reflected candidate correlates
// into. An existing finding at the same dedup key (see findingDedupKey)
// absorbs this candidate — its own TestCase ID and candidate value are
// recorded, and its occurrence count bumped, but its Verdict is left to
// verification alone. Otherwise a new Finding is created at VerdictPending,
// carrying full provenance: scan, endpoint, parameter, injection point, the
// candidate, and the endpoint's own discovery source.
func upsertPendingFinding(ctx context.Context, st store.Store, scanID domain.ID, ep *domain.Endpoint, injectionPointID domain.ID, focus *domain.Parameter, cand detection.Candidate, candTestCaseID domain.ID) (*domain.Finding, error) {
	key := findingDedupKey(injectionPointID, cand)

	existing, err := st.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings for correlation: %w", err)
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		d := decodeFindingDetail(f.Detail)
		if d.DedupKey != key {
			continue
		}
		d.Occurrences++
		d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, candTestCaseID)
		d.Candidates = appendUniqueCandidate(d.Candidates, cand)
		f.Detail = d.encode()
		f.UpdatedAt = time.Now()
		if err := st.Findings().Update(ctx, f); err != nil {
			return nil, fmt.Errorf("update correlated finding: %w", err)
		}
		return f, nil
	}

	sc, err := st.Scans().Get(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("load scan: %w", err)
	}
	now := time.Now()
	d := findingDetail{
		Method: ep.Method, ParameterName: focus.Name, DedupKey: key, Occurrences: 1,
		TestCaseIDs: []domain.ID{candTestCaseID}, Candidates: []detection.Candidate{cand},
	}
	if cand.Combined {
		d.Combined = true
		d.ParameterBName = cand.ParameterB
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictPending, Severity: severityFor(cand), Confidence: domain.ConfidenceLow,
		Title:            findingTitle(cand, focus, ep),
		Summary:          cand.Rationale,
		EndpointID:       ep.ID,
		InjectionPointID: injectionPointID,
		ParameterID:      focus.ID,
		Location:         focus.Location,
		Provenance:       domain.Provenance{Engine: "reflected-xss", DiscoverySource: ep.Source, DetectedAt: now, AIAssisted: false},
		Detail:           d.encode(),
		CreatedAt:        now, UpdatedAt: now,
	}
	if err := st.Findings().Create(ctx, f); err != nil {
		return nil, fmt.Errorf("create finding: %w", err)
	}
	return f, nil
}

// blockFindingDedupKey distinguishes a possible-block diagnostic from a real
// candidate finding at the same injection point: "\x00block" never collides
// with findingDedupKey's "\x00<category>\x00<context>" shape (detection never
// emits an empty category or context), so a real reflected-XSS finding and a
// block diagnostic for the same parameter are always two separate rows.
func blockFindingDedupKey(injectionPointID domain.ID) string {
	return string(injectionPointID) + "\x00block"
}

// upsertBlockFinding records (or bumps the occurrence count of) a diagnostic
// Finding for a "not reflected" result whose status-code change from
// baseline looks like a WAF/rate-limit/maintenance block rather than a clean
// negative (see possibleBlockNote in executor.go). Before this existed, that
// signal only ever reached a raw TestCase note — invisible on every report
// surface (markdown/html/CLI/web UI) unless an operator went digging through
// individual test-case rows.
//
// Verdict is always Inconclusive: a possible block means the real test may
// never have reached the application at all, which is strictly less
// informative than a confirmed negative (see verdictRank) — never Rejected,
// which would read as a clean "tried and didn't execute". Severity is always
// Info: this is a testing-coverage diagnostic about Indago's OWN probe, never
// itself a vulnerability. Like upsertPendingFinding, repeated blocks at the
// same injection point absorb into one Finding (occurrence count bumped)
// rather than multiplying rows.
func upsertBlockFinding(ctx context.Context, st store.Store, scanID domain.ID, ep *domain.Endpoint, injectionPointID domain.ID, focus *domain.Parameter, baselineStatus, mutatedStatus int, testCaseID domain.ID) (*domain.Finding, error) {
	key := blockFindingDedupKey(injectionPointID)
	detail := fmt.Sprintf("status changed %d -> %d from baseline while testing this parameter", baselineStatus, mutatedStatus)

	existing, err := st.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings for block correlation: %w", err)
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		d := decodeFindingDetail(f.Detail)
		if d.DedupKey != key {
			continue
		}
		d.Occurrences++
		d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, testCaseID)
		d.BlockDetail = detail
		f.Detail = d.encode()
		f.UpdatedAt = time.Now()
		if err := st.Findings().Update(ctx, f); err != nil {
			return nil, fmt.Errorf("update block finding: %w", err)
		}
		return f, nil
	}

	sc, err := st.Scans().Get(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("load scan: %w", err)
	}
	now := time.Now()
	d := findingDetail{
		Method: ep.Method, ParameterName: focus.Name, DedupKey: key, Occurrences: 1,
		TestCaseIDs: []domain.ID{testCaseID}, BlockSuspected: true, BlockDetail: detail,
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictInconclusive, Severity: domain.SeverityInfo, Confidence: domain.ConfidenceMedium,
		Title:            fmt.Sprintf("Possible block/filter while testing parameter %q (%s) at %s %s", focus.Name, focus.Location, ep.Method, endpointLabel(ep.URL)),
		Summary:          detail + " — this may not be a clean negative; Indago does not retry or evade (AGENTS.md §2.2)",
		EndpointID:       ep.ID,
		InjectionPointID: injectionPointID,
		ParameterID:      focus.ID,
		Location:         focus.Location,
		Provenance:       domain.Provenance{Engine: "reflected-xss", DiscoverySource: ep.Source, DetectedAt: now, AIAssisted: false},
		Detail:           d.encode(),
		CreatedAt:        now, UpdatedAt: now,
	}
	if err := st.Findings().Create(ctx, f); err != nil {
		return nil, fmt.Errorf("create block finding: %w", err)
	}
	return f, nil
}

// captchaFindingDedupKey distinguishes a CAPTCHA diagnostic from both a real
// candidate finding and the status-code block diagnostic at the same
// injection point — see blockFindingDedupKey for why a disjoint suffix is
// enough to guarantee no collision.
func captchaFindingDedupKey(injectionPointID domain.ID) string {
	return string(injectionPointID) + "\x00captcha"
}

// upsertCaptchaFinding records (or bumps the occurrence count of) a
// diagnostic Finding for a CAPTCHA/bot-challenge that newly appeared during
// testing (see detection.CaptchaSuspected). Detect-only: Indago never
// attempts to solve or bypass a CAPTCHA (AGENTS.md §2.2) — this exists so
// the operator sees the signal on the report instead of only in a raw
// TestCase note. Same Verdict/Severity contract as upsertBlockFinding
// (Inconclusive/Info: a coverage diagnostic, never itself a vulnerability),
// and the same correlate-by-dedup-key-or-create shape.
func upsertCaptchaFinding(ctx context.Context, st store.Store, scanID domain.ID, ep *domain.Endpoint, injectionPointID domain.ID, focus *domain.Parameter, label string, testCaseID domain.ID) (*domain.Finding, error) {
	key := captchaFindingDedupKey(injectionPointID)
	detail := fmt.Sprintf("%s challenge newly appeared for this parameter's test request (not present on the baseline response)", label)

	existing, err := st.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings for captcha correlation: %w", err)
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		d := decodeFindingDetail(f.Detail)
		if d.DedupKey != key {
			continue
		}
		d.Occurrences++
		d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, testCaseID)
		d.CaptchaLabel = label
		f.Detail = d.encode()
		f.UpdatedAt = time.Now()
		if err := st.Findings().Update(ctx, f); err != nil {
			return nil, fmt.Errorf("update captcha finding: %w", err)
		}
		return f, nil
	}

	sc, err := st.Scans().Get(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("load scan: %w", err)
	}
	now := time.Now()
	d := findingDetail{
		Method: ep.Method, ParameterName: focus.Name, DedupKey: key, Occurrences: 1,
		TestCaseIDs: []domain.ID{testCaseID}, CaptchaSuspected: true, CaptchaLabel: label,
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictInconclusive, Severity: domain.SeverityInfo, Confidence: domain.ConfidenceMedium,
		Title:            fmt.Sprintf("Possible %s challenge triggered while testing parameter %q (%s) at %s %s", label, focus.Name, focus.Location, ep.Method, endpointLabel(ep.URL)),
		Summary:          detail + " — detect-only; Indago never attempts to solve or bypass a CAPTCHA (AGENTS.md §2.2)",
		EndpointID:       ep.ID,
		InjectionPointID: injectionPointID,
		ParameterID:      focus.ID,
		Location:         focus.Location,
		Provenance:       domain.Provenance{Engine: "reflected-xss", DiscoverySource: ep.Source, DetectedAt: now, AIAssisted: false},
		Detail:           d.encode(),
		CreatedAt:        now, UpdatedAt: now,
	}
	if err := st.Findings().Create(ctx, f); err != nil {
		return nil, fmt.Errorf("create captcha finding: %w", err)
	}
	return f, nil
}

// verdictRank orders verdicts for the monotonic-confirmation rule: Pending <
// Inconclusive < Rejected < Confirmed. Rejected outranks Inconclusive because
// it is itself a high-confidence negative (the candidate WAS observed, just
// did not execute), while Inconclusive means the candidate could not even be
// re-observed — strictly less informative.
func verdictRank(v domain.Verdict) int {
	switch v {
	case domain.VerdictConfirmed:
		return 3
	case domain.VerdictRejected:
		return 2
	case domain.VerdictInconclusive:
		return 1
	default: // Pending or unset
		return 0
	}
}

// correlateVerification merges one completed verification attempt into the
// Finding it targets. The verdict only ever moves up verdictRank — a finding
// already Confirmed stays Confirmed regardless of what a later, correlated
// attempt finds — but evidence (this attempt's browser evidence AND the
// original candidate's own request/response evidence) and the contributing
// TestCase IDs are unioned in every time, so correlating never discards raw
// evidence. It is the only place a Finding's Verdict leaves Pending.
func (e *verifyExecutor) correlateVerification(ctx context.Context, findingID domain.ID, cand detection.Candidate, candTestCaseID domain.ID, vres *verification.Result, verifyTestCaseID domain.ID, newEvidenceIDs []domain.ID, verifiedURL string) {
	// Serialized: two verify jobs for the same correlated finding (two
	// candidates at the same site) can complete at the same time on different
	// browser workers, and this is a plain Get-mutate-Update — without the
	// lock, the second Update to commit would silently overwrite the first's
	// evidence/verdict rather than merge with it.
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	f, err := e.store.Findings().Get(ctx, findingID)
	if err != nil {
		e.log.Warn("load finding for verification update", "finding", findingID, "err", err)
		return
	}

	now := time.Now()
	if verdictRank(vres.Verdict) > verdictRank(f.Verdict) {
		f.Verdict = vres.Verdict
		f.Confidence = vres.Confidence
		if vres.Notes != "" {
			f.Summary = vres.Notes
		}
		if f.Verdict == domain.VerdictConfirmed {
			f.Title = confirmedTitle(f.Title)
		}
	}

	// Include request, response, browser event, DOM/screenshot evidence where
	// available: newEvidenceIDs is this attempt's browser evidence (screenshot/
	// DOM/browser log); the candidate TestCase's own evidence is its HTTP
	// request/response.
	all := append([]domain.ID(nil), newEvidenceIDs...)
	if !candTestCaseID.Empty() {
		if candTC, err := e.store.TestCases().Get(ctx, candTestCaseID); err == nil {
			all = append(all, candTC.EvidenceIDs...)
		}
	}
	f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, all)

	d := decodeFindingDetail(f.Detail)
	d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, verifyTestCaseID)
	d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, candTestCaseID)
	d.Attempts = appendAttempt(d.Attempts, verificationAttempt{
		CandidateValue: cand.Value, CandidateDedupKey: cand.DedupKey,
		CandidateTestCaseID: candTestCaseID, VerifyTestCaseID: verifyTestCaseID,
		URL:     verifiedURL,
		Verdict: vres.Verdict, Confidence: vres.Confidence, Notes: vres.Notes,
		EvidenceIDs: appendUniqueIDs(nil, all), At: now,
	})
	f.Detail = d.encode()

	f.Provenance.VerifiedAt = &now
	f.UpdatedAt = now
	if err := e.store.Findings().Update(ctx, f); err != nil {
		e.log.Warn("persist finding verification result", "finding", findingID, "err", err)
	}
}

func appendUniqueID(ids []domain.ID, id domain.ID) []domain.ID {
	if id.Empty() {
		return ids
	}
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

// appendAttempt records a verification attempt once per verify TestCase, so a
// re-delivered correlation for the same attempt does not double-count it.
func appendAttempt(attempts []verificationAttempt, a verificationAttempt) []verificationAttempt {
	for _, x := range attempts {
		if x.VerifyTestCaseID == a.VerifyTestCaseID {
			return attempts
		}
	}
	return append(attempts, a)
}

func appendUniqueIDs(existing, add []domain.ID) []domain.ID {
	for _, id := range add {
		existing = appendUniqueID(existing, id)
	}
	return existing
}

// appendUniqueCandidate records a correlated candidate only once (by its own
// dedup key + value), so repeated confirmations of the SAME candidate do not
// bloat the finding's raw-evidence list — but every genuinely DISTINCT
// candidate that reached this site is kept.
func appendUniqueCandidate(cands []detection.Candidate, c detection.Candidate) []detection.Candidate {
	for _, x := range cands {
		if x.DedupKey == c.DedupKey && x.Value == c.Value {
			return cands
		}
	}
	return append(cands, c)
}
