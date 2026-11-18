package scan

// Privacy tests for browser-evidence persistence: an authenticated scan must
// never write the raw screenshot, rendered DOM or browser log into the
// evidence store, on either verification persistence path (Reflected XSS and
// DOM XSS). The deterministic verdict, the verification report and a minimal
// non-sensitive summary must survive.
//
// Every fixture here is inert dummy data. Nothing in this file opens a target,
// launches a browser, or carries an exploit payload.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

const (
	// Distinct sentinels: each may only ever appear inside a raw artifact that
	// the privacy gate is expected to drop.
	dummyScreenshotSecret = "INERT-DUMMY-SCREENSHOT-BYTES"
	dummyDOMSecret        = "inert-dummy-dom-secret"
	dummyBrowserLogSecret = "inert-dummy-console-secret"
	dummySessionStatePath = "/tmp/indago-dummy-session-state.json"
)

// createSession writes the scan's session row the way Controller.CreateScan
// does (a controller-created scan always has exactly one, anonymous included)
// and links it from the scan.
func (e *scanEnv) createSession(t *testing.T, mode domain.AuthMode, statePath string) *domain.Session {
	t.Helper()
	now := time.Now()
	sess := &domain.Session{
		ID: domain.NewID(), ScanID: e.scanID, Mode: mode, State: domain.SessionActive,
		StatePath: statePath, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.st.Sessions().Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	e.sc.SessionID = sess.ID
	if err := e.st.Scans().Update(context.Background(), e.sc); err != nil {
		t.Fatal(err)
	}
	return sess
}

func dummyArtifacts() verification.ResultEvidence {
	return verification.ResultEvidence{
		Screenshot: []byte(dummyScreenshotSecret),
		DOMHTML:    "<html><body>" + dummyDOMSecret + "</body></html>",
		BrowserLog: []string{dummyBrowserLogSecret},
	}
}

// assertNoRawBrowserArtifacts fails if any screenshot, DOM or browser-log row
// was persisted for the scan.
func assertNoRawBrowserArtifacts(t *testing.T, env *scanEnv) {
	t.Helper()
	rows, err := env.st.Evidence().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		switch row.Kind {
		case domain.EvidenceScreenshot, domain.EvidenceDOM, domain.EvidenceBrowserLog:
			t.Fatalf("raw %s evidence was persisted for an authenticated scan: %+v", row.Kind, row)
		}
	}
}

// assertWithheldSummary checks the only artifact that may remain: one
// non-sensitive JSON summary that names what was captured but carries none of
// it.
func assertWithheldSummary(t *testing.T, env *scanEnv, ids []domain.ID, note, wantReason string) {
	t.Helper()
	if len(ids) != 1 {
		t.Fatalf("evidence ids = %v, want exactly 1 non-sensitive summary", ids)
	}
	if !strings.Contains(note, "withheld") {
		t.Fatalf("test-case note does not record the withholding: %q", note)
	}
	row, body := env.evidenceBlob(ids[0])
	if row.Kind != domain.EvidenceOther {
		t.Fatalf("summary kind = %s, want %s", row.Kind, domain.EvidenceOther)
	}
	if row.MediaType != "application/json" {
		t.Fatalf("summary media type = %q, want application/json", row.MediaType)
	}
	for _, secret := range []string{dummyScreenshotSecret, dummyDOMSecret, dummyBrowserLogSecret} {
		if strings.Contains(body, secret) {
			t.Fatalf("raw artifact content %q leaked into the summary: %s", secret, body)
		}
	}
	var summary browserEvidenceSummary
	if err := json.Unmarshal([]byte(body), &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v (%s)", err, body)
	}
	if !summary.RawArtifactsWithheld || summary.Reason != wantReason {
		t.Fatalf("summary = %+v, want raw_artifacts_withheld with reason %q", summary, wantReason)
	}
	if !summary.ScreenshotCaptured || !summary.DOMCaptured || summary.BrowserLogEntries != 1 {
		t.Fatalf("summary lost the capture metadata: %+v", summary)
	}
	assertNoRawBrowserArtifacts(t, env)
}

// --- Reflected XSS verification persistence path ---

func TestVerificationEvidenceWithheldForAuthenticatedScan(t *testing.T) {
	env := newScanEnv(t)
	env.createSession(t, domain.AuthExisting, dummySessionStatePath)

	vx := env.verifyExec(&fakeVerifier{}, openScope(), ExecutorConfig{})
	ids, note := vx.persistVerificationEvidence(context.Background(), env.scanID, domain.NewID(), dummyArtifacts())

	assertWithheldSummary(t, env, ids, note, browserEvidenceWithheldAuthenticated)
}

func TestVerificationEvidencePersistedForAnonymousScan(t *testing.T) {
	env := newScanEnv(t)
	env.createSession(t, domain.AuthAnonymous, "")

	vx := env.verifyExec(&fakeVerifier{}, openScope(), ExecutorConfig{})
	ids, note := vx.persistVerificationEvidence(context.Background(), env.scanID, domain.NewID(), dummyArtifacts())

	if note != "" {
		t.Fatalf("anonymous scan must not report a withholding: %q", note)
	}
	if len(ids) != 3 {
		t.Fatalf("evidence ids = %v, want 3 (screenshot/dom/log)", ids)
	}
	got := map[domain.EvidenceKind]string{}
	for _, id := range ids {
		row, body := env.evidenceBlob(id)
		got[row.Kind] = body
	}
	if got[domain.EvidenceScreenshot] != dummyScreenshotSecret {
		t.Fatalf("screenshot evidence changed: %q", got[domain.EvidenceScreenshot])
	}
	if !strings.Contains(got[domain.EvidenceDOM], dummyDOMSecret) {
		t.Fatalf("rendered DOM evidence changed: %q", got[domain.EvidenceDOM])
	}
	if !strings.Contains(got[domain.EvidenceBrowserLog], dummyBrowserLogSecret) {
		t.Fatalf("browser log evidence changed: %q", got[domain.EvidenceBrowserLog])
	}
}

// A scan that records a session dependency whose metadata is gone must fail
// CLOSED: unknown auth state is treated as authenticated, never as public.
func TestVerificationEvidenceWithheldWhenSessionMetadataMissing(t *testing.T) {
	env := newScanEnv(t)
	env.sc.SessionID = domain.NewID()
	if err := env.st.Scans().Update(context.Background(), env.sc); err != nil {
		t.Fatal(err)
	}

	vx := env.verifyExec(&fakeVerifier{}, openScope(), ExecutorConfig{})
	ids, note := vx.persistVerificationEvidence(context.Background(), env.scanID, domain.NewID(), dummyArtifacts())

	assertWithheldSummary(t, env, ids, note, browserEvidenceWithheldUnknownAuth)
}

// --- DOM XSS verification persistence path ---

func TestDOMXSSEvidenceWithheldForAuthenticatedScan(t *testing.T) {
	env := newScanEnv(t)
	env.createSession(t, domain.AuthPassword, dummySessionStatePath)

	ex := &domXSSExecutor{store: env.st, evidence: env.ev, log: execLog()}
	art := dummyArtifacts()
	ids, note := ex.persistDOMXSSEvidence(context.Background(), env.scanID, domain.NewID(), art.Screenshot, art.DOMHTML, art.BrowserLog)

	assertWithheldSummary(t, env, ids, note, browserEvidenceWithheldAuthenticated)
}

// --- the end-to-end contract: verdict and report survive the withholding ---

func TestVerifyHandleKeepsVerdictWhenEvidenceWithheld(t *testing.T) {
	env := newScanEnv(t)
	env.createSession(t, domain.AuthExisting, dummySessionStatePath)
	ep := env.endpoint("https://app.example.test/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	art := dummyArtifacts()
	fv := &fakeVerifier{result: &verification.Result{
		Verdict: domain.VerdictConfirmed, Confidence: domain.ConfidenceHigh, Notes: "execution verified",
		Report:   &verification.Report{Engine: "browser-verification", Signal: verification.SignalPageError},
		Evidence: art,
	}}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.only()
	if tc.Outcome != domain.OutcomeSuccess || tc.Status != domain.TestCaseCompleted {
		t.Fatalf("test case outcome/status = %s/%s, want success/completed", tc.Outcome, tc.Status)
	}
	var report verification.Report
	if err := json.Unmarshal(tc.Detail, &report); err != nil {
		t.Fatalf("verification report not preserved in Detail: %v (%s)", err, tc.Detail)
	}
	if report.Signal != verification.SignalPageError {
		t.Fatalf("verification report signal = %q, want page_error", report.Signal)
	}
	if !strings.Contains(tc.Note, "withheld") {
		t.Fatalf("test-case note does not record the withholding: %q", tc.Note)
	}
	if len(tc.EvidenceIDs) != 1 {
		t.Fatalf("test-case evidence ids = %v, want 1 summary", tc.EvidenceIDs)
	}

	got, err := env.st.Findings().Get(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != domain.VerdictConfirmed || got.Confidence != domain.ConfidenceHigh {
		t.Fatalf("finding verdict was not preserved: %+v", got)
	}
	if got.Provenance.VerifiedAt == nil {
		t.Fatal("finding verification provenance was lost")
	}
	assertNoRawBrowserArtifacts(t, env)
}

// --- the persisted verification report: page-derived fields are withheld ---

const (
	dummyDOMExcerpt = "INERT-DUMMY-DOM-EXCERPT-PAGE-CONTENT"
	dummySignalText = "INERT-DUMMY-SIGNAL-TEXT-ReferenceError: inert-dummy-marker is not defined"
	dummyDialogText = "INERT-DUMMY-DIALOG-MESSAGE"
)

// dummyReportResult mirrors what the real BrowserVerifier returns: a
// page-derived DOM window and the browser's own error text, plus every field a
// verdict, a report consumer and the finding correlation actually need.
func dummyReportResult() *verification.Result {
	return &verification.Result{
		Verdict: domain.VerdictConfirmed, Confidence: domain.ConfidenceHigh, Notes: "execution verified",
		Report: &verification.Report{
			Engine: "browser-verification", Signal: verification.SignalPageError,
			SignalText: dummySignalText, MarkerInDOM: true, DOMExcerpt: dummyDOMExcerpt,
			FinalURL: "https://app.example.test/s",
		},
		Evidence: dummyArtifacts(),
	}
}

// assertReportFieldsWithheld asserts the persisted report carries neither
// page-derived free-text field, and returns it decoded so the caller can check
// that the non-sensitive fields survived.
func assertReportFieldsWithheld(t *testing.T, detail []byte) verification.Report {
	t.Helper()
	if len(detail) == 0 {
		t.Fatal("verification report was not persisted")
	}
	body := string(detail)
	for _, secret := range []string{dummyDOMExcerpt, dummySignalText} {
		if strings.Contains(body, secret) {
			t.Fatalf("page-derived report content %q leaked into TestCase.Detail: %s", secret, body)
		}
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(detail, &raw); err != nil {
		t.Fatalf("persisted report is not valid JSON: %v (%s)", err, body)
	}
	for _, field := range []string{"dom_excerpt", "signal_text"} {
		if _, ok := raw[field]; ok {
			t.Fatalf("%s must be omitted from an authenticated scan's persisted report: %s", field, body)
		}
	}
	var report verification.Report
	if err := json.Unmarshal(detail, &report); err != nil {
		t.Fatalf("persisted report does not decode: %v", err)
	}
	return report
}

func TestVerificationReportWithheldForAuthenticatedScan(t *testing.T) {
	env := newScanEnv(t)
	env.createSession(t, domain.AuthExisting, dummySessionStatePath)
	ep := env.endpoint("https://app.example.test/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	vx := env.verifyExec(&fakeVerifier{result: dummyReportResult()}, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.only()
	report := assertReportFieldsWithheld(t, tc.Detail)
	// The verdict's own signal must survive verbatim: only free text is
	// page-derived, the Signal enum is not.
	if report.Signal != verification.SignalPageError {
		t.Fatalf("report signal = %q, want page_error", report.Signal)
	}
	if !report.MarkerInDOM || report.FinalURL != "https://app.example.test/s" {
		t.Fatalf("non-sensitive report fields were lost: %+v", report)
	}
	if !strings.Contains(tc.Note, "page-derived verification report fields withheld") {
		t.Fatalf("test-case note does not record the report withholding: %q", tc.Note)
	}
	for _, secret := range []string{dummyDOMExcerpt, dummySignalText} {
		if strings.Contains(tc.Note, secret) {
			t.Fatalf("page-derived report content %q leaked into the note: %q", secret, tc.Note)
		}
	}

	got, err := env.st.Findings().Get(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != domain.VerdictConfirmed || got.Confidence != domain.ConfidenceHigh {
		t.Fatalf("finding verdict was not preserved: %+v", got)
	}
}

// The report gate must not depend on an evidence store: a scan with no
// evidence configured still persists TestCase.Detail.
func TestVerificationReportWithheldWithoutEvidenceStore(t *testing.T) {
	env := newScanEnv(t)
	env.createSession(t, domain.AuthPassword, "")
	ep := env.endpoint("https://app.example.test/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	vx := newVerifyExecutor(env.st, nil, &fakeVerifier{result: dummyReportResult()}, nil, nil,
		openScope(), ExecutorConfig{}, execLog(), nil, nil, nil, nil)
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.only()
	report := assertReportFieldsWithheld(t, tc.Detail)
	if report.Signal != verification.SignalPageError {
		t.Fatalf("report signal = %q, want page_error", report.Signal)
	}
	if len(tc.EvidenceIDs) != 0 {
		t.Fatalf("no evidence store is configured, got evidence ids %v", tc.EvidenceIDs)
	}
	if !strings.Contains(tc.Note, "page-derived verification report fields withheld") {
		t.Fatalf("test-case note does not record the report withholding: %q", tc.Note)
	}
}

// An anonymous scan is unchanged: its report keeps the full observations.
func TestVerificationReportKeptForAnonymousScan(t *testing.T) {
	env := newScanEnv(t)
	env.createSession(t, domain.AuthAnonymous, "")
	ep := env.endpoint("https://app.example.test/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	vx := env.verifyExec(&fakeVerifier{result: dummyReportResult()}, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.only()
	if !strings.Contains(string(tc.Detail), dummyDOMExcerpt) || !strings.Contains(string(tc.Detail), dummySignalText) {
		t.Fatalf("anonymous scan report lost its page-derived fields: %s", tc.Detail)
	}
	var report verification.Report
	if err := json.Unmarshal(tc.Detail, &report); err != nil {
		t.Fatalf("verification report not preserved in Detail: %v", err)
	}
	if report.Signal != verification.SignalPageError {
		t.Fatalf("report signal = %q, want page_error", report.Signal)
	}
}

// DOM XSS persists no verification.Report; its note carries the equivalent
// page-derived signal/dialog text, which the same gate must replace.
func TestDOMXSSNotePageDerivedTextWithheld(t *testing.T) {
	const reason = browserEvidenceWithheldAuthenticated

	if got := domXSSSignalTextNote(dummySignalText, false, reason); !strings.Contains(got, dummySignalText) {
		t.Fatalf("anonymous signal note lost the observed text: %q", got)
	}
	got := domXSSSignalTextNote(dummySignalText, true, reason)
	if strings.Contains(got, dummySignalText) || !strings.Contains(got, "withheld") {
		t.Fatalf("authenticated signal note leaked page text: %q", got)
	}
	if domXSSSignalTextNote("", true, reason) != "" {
		t.Fatal("an empty signal text must stay empty")
	}

	if got := domXSSDialogTextNote(dummyDialogText, false, reason); got != dummyDialogText {
		t.Fatalf("anonymous dialog note changed: %q", got)
	}
	got = domXSSDialogTextNote(dummyDialogText, true, reason)
	if strings.Contains(got, dummyDialogText) || !strings.Contains(got, "withheld") {
		t.Fatalf("authenticated dialog note leaked page text: %q", got)
	}
}

// --- the auth decision itself: fail closed on every unknown state ---

func TestScanUsesAuthenticatedSessionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name           string
		mode           domain.AuthMode
		statePath      string
		noSession      bool
		claimSessionID bool
		want           bool
	}{
		{name: "explicit anonymous", mode: domain.AuthAnonymous, want: false},
		{name: "password session without state path", mode: domain.AuthPassword, want: true},
		{name: "existing session with state path", mode: domain.AuthExisting, statePath: dummySessionStatePath, want: true},
		{name: "unknown mode without state path", mode: "", want: true},
		{name: "anonymous mode but session material present", mode: domain.AuthAnonymous, statePath: dummySessionStatePath, want: true},
		{name: "missing session metadata with a recorded dependency", noSession: true, claimSessionID: true, want: true},
		{name: "no session record at all", noSession: true, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newScanEnv(t)
			if tc.noSession {
				if tc.claimSessionID {
					env.sc.SessionID = domain.NewID()
					if err := env.st.Scans().Update(context.Background(), env.sc); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				env.createSession(t, tc.mode, tc.statePath)
			}
			got, reason := scanUsesAuthenticatedSession(context.Background(), env.st, env.scanID)
			if got != tc.want {
				t.Fatalf("authenticated = %t, want %t (reason %q)", got, tc.want, reason)
			}
			if got && reason == "" {
				t.Fatal("a withholding decision must carry a reason")
			}
		})
	}
}
