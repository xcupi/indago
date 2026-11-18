package scan

// Raw browser artifacts are page-derived: a screenshot, the rendered DOM and
// the browser's own console/page log can each contain authenticated,
// session-scoped content that the target only renders for a logged-in user.
// Persisting them for an authenticated scan copies that content out of the
// target and into Indago's evidence store, where it outlives the scan and is
// readable by anyone with evidence access.
//
// Both browser-verification persistence paths — Reflected XSS
// (verifyExecutor.persistVerificationEvidence) and DOM XSS
// (domXSSExecutor.persistDOMXSSEvidence) — therefore go through this file.
// For an anonymous scan nothing changes: the artifacts are stored exactly as
// before. For a scan that runs with a non-anonymous session only a small,
// non-sensitive summary is stored: no image bytes, no HTML and no console
// text. The verdict, the verification Report and the Finding correlation are
// untouched — they never carried the page body.
//
// The Reflected XSS Report is page-derived too: DOMExcerpt is a window of the
// rendered DOM and SignalText is the browser's own error text. Both are
// removed from the report BEFORE it is marshalled into TestCase.Detail for an
// authenticated (or unknown-auth) scan, whether or not an evidence store is
// configured (verificationReportForPersistence). The DOM XSS engine persists no
// such Report, but its verification note records the equivalent page-derived
// signal/dialog text, which is replaced by a fixed placeholder under the same
// gate (domXSSSignalTextNote / domXSSDialogTextNote).
//
// The auth decision fails CLOSED. A scan that records a session dependency
// whose metadata cannot be read is treated as authenticated, because losing a
// screenshot is preferable to persisting authenticated page content.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/verification"
)

const (
	browserEvidenceWithheldAuthenticated = "authenticated scan"
	browserEvidenceWithheldUnknownAuth   = "scan authentication state unavailable"
	// browserEvidenceSummaryNote is the human-readable explanation stored
	// alongside the summary so "withheld" can never be mistaken for "nothing
	// was captured".
	browserEvidenceSummaryNote = "verdict, verification report and finding correlation are stored on the test case and finding; page-derived artifacts are intentionally not stored"
	// browserReportWithheldNote is the TestCase note suffix recorded when the
	// persisted verification report's page-derived free text is omitted. It
	// names the two fields so a reader can tell an intentional omission apart
	// from a report that never had them.
	browserReportWithheldNote = "; page-derived verification report fields withheld (%s): dom_excerpt=%t, signal_text=%t"
)

// browserArtifacts is the raw, page-derived material one verification attempt
// captured. It exists only so both persistence paths pass the same shape to
// the same gate.
type browserArtifacts struct {
	Screenshot []byte
	DOMHTML    string
	BrowserLog []string
}

// browserEvidenceSummary is the only artifact persisted for an authenticated
// scan. It deliberately contains no page content — no image bytes, no HTML, no
// console text — just which artifact classes were captured and why they were
// withheld, so a reviewer can tell an intentional withholding apart from a
// verification that captured nothing.
type browserEvidenceSummary struct {
	RawArtifactsWithheld bool   `json:"raw_artifacts_withheld"`
	Reason               string `json:"reason"`
	ScreenshotCaptured   bool   `json:"screenshot_captured"`
	DOMCaptured          bool   `json:"dom_captured"`
	BrowserLogEntries    int    `json:"browser_log_entries"`
	Note                 string `json:"note"`
}

// scanUsesAuthenticatedSession reports whether a scan's browser evidence must
// be withheld, plus the reason to record. It fails CLOSED: any state that
// cannot be established counts as authenticated.
//
// The session record, not the caller-supplied AuthMode, is authoritative: a
// controller-created scan always gets exactly one Session row (anonymous scans
// included), so a non-anonymous mode — or any session material at all — is
// what distinguishes a logged-in run.
func scanUsesAuthenticatedSession(ctx context.Context, st store.Store, scanID domain.ID) (bool, string) {
	if st == nil {
		return true, browserEvidenceWithheldUnknownAuth
	}
	sc, err := st.Scans().Get(ctx, scanID)
	if err != nil {
		return true, browserEvidenceWithheldUnknownAuth
	}
	sess, err := st.Sessions().GetByScan(ctx, scanID)
	switch {
	case errors.Is(err, store.ErrNotFound) || sess == nil:
		// No session metadata at all. A scan that still records a session
		// dependency is unknown, not public.
		if !sc.SessionID.Empty() {
			return true, browserEvidenceWithheldUnknownAuth
		}
		return false, ""
	case err != nil:
		return true, browserEvidenceWithheldUnknownAuth
	}
	if sess.StatePath != "" {
		return true, browserEvidenceWithheldAuthenticated
	}
	switch sess.Mode {
	case domain.AuthAnonymous:
		return false, ""
	case domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA, domain.AuthExisting:
		return true, browserEvidenceWithheldAuthenticated
	default:
		// A session row whose mode is missing or unrecognized, and which
		// carries no state path: the auth state cannot be established.
		return true, browserEvidenceWithheldUnknownAuth
	}
}

// verificationReportForPersistence returns the report that may be marshalled
// into TestCase.Detail. The report carries two page-derived free-text fields —
// DOMExcerpt (a window of the rendered DOM around the marker) and SignalText
// (the browser's own error text) — which can contain authenticated,
// session-scoped content exactly like the screenshot/DOM/log artifacts. For a
// scan whose session is authenticated (or cannot be established) both are
// removed; everything a verdict, a report consumer or the finding correlation
// relies on is kept verbatim: the Signal enum, MarkerInDOM, provenance, the
// candidate, URLs, status, activation and timestamps. The input report is
// never mutated, so the in-memory Result keeps the observations it was given.
// The second return value reports whether anything was actually removed.
func verificationReportForPersistence(r *verification.Report, withhold bool) (*verification.Report, bool) {
	if r == nil || !withhold || (r.DOMExcerpt == "" && r.SignalText == "") {
		return r, false
	}
	cp := *r
	cp.DOMExcerpt, cp.SignalText = "", ""
	return &cp, true
}

// domXSSSignalTextNote returns the note fragment recorded after a matched
// DOM-XSS execution signal: the browser's own text for an anonymous scan, and
// a fixed placeholder when the scan's page-derived material is withheld. The
// DOM engine has no verification.Report, so its verification note (and the
// finding attempt note built from it) is the field equivalent to the reflected
// report's SignalText.
func domXSSSignalTextNote(sigText string, withhold bool, reason string) string {
	if sigText == "" {
		return ""
	}
	if withhold {
		return "; page-derived signal text withheld (" + reason + ")"
	}
	return " (" + sigText + ")"
}

// domXSSDialogTextNote returns the page-derived dialog message a confirmed
// sandbox_escape note records: the observed message for an anonymous scan, and
// a fixed placeholder when the scan's page-derived material is withheld.
func domXSSDialogTextNote(msg string, withhold bool, reason string) string {
	if !withhold {
		return msg
	}
	return "page-derived dialog message withheld (" + reason + ")"
}

// persistBrowserArtifacts stores one verification attempt's browser artifacts.
// It returns the evidence IDs plus a TestCase note suffix when the raw
// artifacts were withheld (empty otherwise). warnPrefix preserves each
// executor's own log context ("" for Reflected XSS, "dom-xss: " for DOM XSS).
func persistBrowserArtifacts(ctx context.Context, st store.Store, ev evidence.Store, log *slog.Logger, scanID, tcID domain.ID, a browserArtifacts, warnPrefix string) ([]domain.ID, string) {
	if st == nil || ev == nil {
		return nil, ""
	}
	if log == nil {
		log = slog.Default()
	}
	if withhold, reason := scanUsesAuthenticatedSession(ctx, st, scanID); withhold {
		ids := persistBrowserEvidenceSummary(ctx, st, ev, log, scanID, tcID, a, reason, warnPrefix)
		return ids, fmt.Sprintf("; raw browser artifacts withheld (%s): screenshot=%t, rendered_dom=%t, browser_log_entries=%d",
			reason, len(a.Screenshot) > 0, a.DOMHTML != "", len(a.BrowserLog))
	}

	var ids []domain.ID
	note := "test_case=" + string(tcID)
	if len(a.Screenshot) > 0 {
		if id, err := putEvidenceBlob(ctx, st, ev, scanID, domain.EvidenceScreenshot, ".png", "image/png", a.Screenshot, note+" screenshot"); err == nil {
			ids = append(ids, id)
		} else {
			log.Warn(warnPrefix+"persist screenshot evidence", "err", err)
		}
	}
	if a.DOMHTML != "" {
		if id, err := putEvidenceBlob(ctx, st, ev, scanID, domain.EvidenceDOM, ".html", "text/html", []byte(a.DOMHTML), note+" rendered DOM"); err == nil {
			ids = append(ids, id)
		} else {
			log.Warn(warnPrefix+"persist DOM evidence", "err", err)
		}
	}
	if len(a.BrowserLog) > 0 {
		data := []byte(joinLines(a.BrowserLog))
		if id, err := putEvidenceBlob(ctx, st, ev, scanID, domain.EvidenceBrowserLog, ".log", "text/plain", data, note+" browser log"); err == nil {
			ids = append(ids, id)
		} else {
			log.Warn(warnPrefix+"persist browser log evidence", "err", err)
		}
	}
	return ids, ""
}

// persistBrowserEvidenceSummary writes the non-sensitive record that stands in
// for the raw artifacts. It uses EvidenceOther so it can never be mistaken for
// a screenshot/DOM/log blob by a reader that renders those kinds.
func persistBrowserEvidenceSummary(ctx context.Context, st store.Store, ev evidence.Store, log *slog.Logger, scanID, tcID domain.ID, a browserArtifacts, reason, warnPrefix string) []domain.ID {
	summary := browserEvidenceSummary{
		RawArtifactsWithheld: true,
		Reason:               reason,
		ScreenshotCaptured:   len(a.Screenshot) > 0,
		DOMCaptured:          a.DOMHTML != "",
		BrowserLogEntries:    len(a.BrowserLog),
		Note:                 browserEvidenceSummaryNote,
	}
	data, err := json.Marshal(summary)
	if err != nil {
		log.Warn(warnPrefix+"marshal browser evidence summary", "err", err)
		return nil
	}
	id, err := putEvidenceBlob(ctx, st, ev, scanID, domain.EvidenceOther, ".json", "application/json", data,
		"test_case="+string(tcID)+" browser artifacts withheld ("+reason+")")
	if err != nil {
		log.Warn(warnPrefix+"persist browser evidence summary", "err", err)
		return nil
	}
	return []domain.ID{id}
}
