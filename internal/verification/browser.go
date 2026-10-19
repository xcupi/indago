package verification

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"strings"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// This file is the real, Chromium-backed Verifier. It loads the EXACT candidate
// that already reflected (no new payloads, nothing re-chosen here) in a real,
// optionally-authenticated browser context, and observes whether the marker
// token reaches a position the JavaScript engine evaluates — see signal.go for
// why only a marker-specific unresolved-identifier ReferenceError is a
// deterministic, non-timing signal rather than a heuristic.
//
// Boundaries preserved here:
//   - No payload generation: Input.Candidate.Value is sent byte-for-byte.
//   - No anti-bot/WAF evasion: one navigation, one scope-gated context, no
//     fingerprint spoofing.
//   - No DOM XSS: this observes the SAME marker the candidate step already sent;
//     it does not crawl the DOM for new sinks or client-side-only inputs.
//   - No LLM: the verdict in decide() is a pure function of the observations.

// Report is the structured, persisted record of one browser-verification
// attempt. The caller marshals it into TestCase.Detail, mirroring how
// detection.ReflectionReport is persisted.
type Report struct {
	Provenance  browser.RuntimeObservations `json:"provenance"`
	Engine      string                      `json:"engine"` // "browser-verification"
	Candidate   detection.Candidate         `json:"candidate"`
	FinalURL    string                      `json:"final_url"`
	Status      int                         `json:"status,omitempty"`
	Signal      Signal                      `json:"signal"`
	SignalText  string                      `json:"signal_text,omitempty"`
	MarkerInDOM bool                        `json:"marker_in_dom"`
	DOMExcerpt  string                      `json:"dom_excerpt,omitempty"`
	NavigatedAt time.Time                   `json:"navigated_at"`
	ObservedAt  time.Time                   `json:"observed_at"`
}

// BrowserVerifierConfig tunes the verifier.
type BrowserVerifierConfig struct {
	// NavigationTimeout bounds one navigation (default 30s; 0 uses the browser
	// Manager's own default).
	NavigationTimeout time.Duration
	// DOMExcerptWindow bounds the bytes of context captured around the marker in
	// the DOM evidence (default 80).
	DOMExcerptWindow int
}

func (c BrowserVerifierConfig) withDefaults() BrowserVerifierConfig {
	if c.DOMExcerptWindow <= 0 {
		c.DOMExcerptWindow = 80
	}
	return c
}

// BrowserVerifier is the real Verifier: it drives browser.Manager.
type BrowserVerifier struct {
	manager *browser.Manager
	cfg     BrowserVerifierConfig
}

// NewBrowserVerifier builds a verifier over an already-running browser Manager
// (the same Manager instance discovery and the rest of the scan use).
func NewBrowserVerifier(m *browser.Manager, cfg BrowserVerifierConfig) *BrowserVerifier {
	return &BrowserVerifier{manager: m, cfg: cfg.withDefaults()}
}

var _ Verifier = (*BrowserVerifier)(nil)

// Verify implements Verifier. It returns a non-nil error only when verification
// could not be ATTEMPTED or completed (unsupported method, context deadline,
// cancellation, or a browser/navigation failure); ctx cancellation surfaces as
// context.Canceled and a navigation timeout as context.DeadlineExceeded, so the
// caller can classify them exactly like the HTTP executor does. A completed
// attempt — including one where the marker was reflected but did not execute —
// returns (*Result, nil) with the decided Verdict.
func (v *BrowserVerifier) Verify(ctx context.Context, in Input) (*Result, error) {
	if v.manager == nil {
		return nil, ErrNotImplemented
	}
	method := in.Method
	if method == "" {
		method = "GET"
	}
	isFormPost := method == "POST" && in.Location == domain.LocationForm && in.FormValues != nil
	isJSONPost := method == "POST" && in.Location == domain.LocationJSON && validJSONPost(in.JSONBody, in.ContentType)
	if method != "GET" && method != "HEAD" && !isFormPost && !isJSONPost {
		return nil, ErrUnsupportedMethod
	}
	if in.URL == "" {
		return nil, errors.New("verification: empty URL")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	allow := func(u string) bool { return in.Scope.Permits(u).Allowed }
	if !allow(in.URL) {
		return nil, errOutOfScope
	}

	bctx, err := v.manager.NewContext(ctx, browser.ContextOptions{
		AllowRequest:     allow,
		StorageStatePath: in.SessionStatePath,
		ProxyServer:      in.ProxyServer,
		ExtraHeaders:     in.ExtraHeaders,
	})
	if err != nil {
		return nil, classifyBrowserErr(ctx, err)
	}
	defer bctx.Close()

	// A Cookie-location candidate's override must reach the browser BEFORE
	// navigation (see Input.ExtraCookies) — appended as its own cookie,
	// never replacing or removing any cookie the session's own storage
	// state already seeded this context with.
	if len(in.ExtraCookies) > 0 {
		cks := make([]browser.Cookie, 0, len(in.ExtraCookies))
		for _, ck := range in.ExtraCookies {
			if ck == nil {
				continue
			}
			cks = append(cks, browser.Cookie{Name: ck.Name, Value: ck.Value, URL: in.URL})
		}
		if len(cks) > 0 {
			if err := bctx.SetCookies(ctx, cks); err != nil {
				return nil, classifyBrowserErr(ctx, err)
			}
		}
	}

	page, err := bctx.NewPage(ctx)
	if err != nil {
		return nil, classifyBrowserErr(ctx, err)
	}
	defer page.Close()
	provenanceErr := page.EnableRuntimeProvenance(in.Marker, "")

	// Baseline the page's own observation channels BEFORE navigating, so the
	// signal below is attributable to THIS navigation only. A page is brand new
	// here (one page per Verify call, never reused across attempts), so these
	// are normally empty — but this makes that an enforced property, not an
	// assumption: nothing observed on the pre-navigation page (e.g. any
	// pre-existing/early error) can be mistaken for this candidate's signal.
	baseConsole := len(page.ConsoleMessages())
	basePageErrs := len(page.PageErrors())
	baseDialogs := len(page.DialogMessages())

	navigatedAt := time.Now()
	var nav *browser.NavResult
	if isFormPost {
		nav, err = page.NavigateForm(ctx, method, in.URL, in.FormValues, browser.NavOptions{
			WaitUntil: browser.WaitLoad,
			Timeout:   v.cfg.NavigationTimeout,
			Limiter:   in.Limiter,
		})
	} else if isJSONPost {
		nav, err = page.NavigateJSON(ctx, in.URL, in.JSONBody, in.ContentType, browser.NavOptions{
			WaitUntil: browser.WaitLoad,
			Timeout:   v.cfg.NavigationTimeout,
			Limiter:   in.Limiter,
		})
	} else {
		nav, err = page.Navigate(ctx, in.URL, browser.NavOptions{
			WaitUntil: browser.WaitLoad,
			Timeout:   v.cfg.NavigationTimeout,
			Limiter:   in.Limiter,
		})
	}
	if err != nil {
		return nil, classifyBrowserErr(ctx, err)
	}

	html, err := page.Content(ctx)
	if err != nil {
		return nil, classifyBrowserErr(ctx, err)
	}
	observedAt := time.Now()

	var consoleErrs []string
	for _, cm := range sinceIndex(page.ConsoleMessages(), baseConsole) {
		if cm.Type == "error" {
			consoleErrs = append(consoleErrs, cm.Text)
		}
	}
	pageErrs := sinceIndex(page.PageErrors(), basePageErrs)
	dialogs := sinceIndex(page.DialogMessages(), baseDialogs)

	token := in.Marker
	provenance := page.RuntimeObservations()
	sig, sigText, matched := MatchRuntimeExecution(token, provenance)
	markerInDOM := containsToken(html, token)

	verdict, confidence, notes := DecideWithProvenance(token, matched, markerInDOM, provenance)
	if provenanceErr != nil {
		verdict, confidence = domain.VerdictInconclusive, domain.ConfidenceLow
		notes = "execution provenance could not be enabled: " + provenanceErr.Error() + "; replay manually"
	}

	rep := &Report{
		Provenance:  provenance,
		Engine:      "browser-verification",
		Candidate:   in.Candidate,
		FinalURL:    nav.FinalURL,
		Status:      nav.Status,
		Signal:      sig,
		SignalText:  sigText,
		MarkerInDOM: markerInDOM,
		DOMExcerpt:  domExcerpt(html, token, v.cfg.DOMExcerptWindow),
		NavigatedAt: navigatedAt,
		ObservedAt:  observedAt,
	}

	var shot []byte
	if s, err := page.Screenshot(ctx, browser.ScreenshotOptions{}); err == nil {
		shot = s
	} // a screenshot failure is not fatal to verification; evidence stays partial

	return &Result{
		Verdict:    verdict,
		Confidence: confidence,
		Notes:      notes,
		Report:     rep,
		Evidence: ResultEvidence{
			Screenshot: shot,
			DOMHTML:    html,
			BrowserLog: append(append(append([]string(nil), consoleErrs...), pageErrs...), dialogs...),
		},
	}, nil
}

func validJSONPost(body []byte, contentType string) bool {
	if len(body) == 0 || len(body) > browser.MaxJSONNavigationBodyBytes || !json.Valid(body) {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return false
	}
	var fields map[string]json.RawMessage
	return json.Unmarshal(body, &fields) == nil && len(fields) > 0
}

// containsToken reports whether the rendered HTML contains the marker token.
func containsToken(html, token string) bool {
	return token != "" && strings.Contains(html, token)
}

// sinceIndex returns the elements observed after baseline (a count taken
// before navigation), so pre-navigation noise is never attributed to the
// candidate just navigated to. A baseline beyond the current length (should
// never happen — these only grow) safely yields nothing.
func sinceIndex[T any](all []T, baseline int) []T {
	if baseline >= len(all) {
		return nil
	}
	return all[baseline:]
}

// decide is the deterministic verdict rule — the one place a candidate is
// promoted to confirmed. No LLM, no heuristic scoring: exactly three cases.
func decide(matched, markerInDOM bool) (domain.Verdict, domain.Confidence, string) {
	switch {
	case matched:
		return domain.VerdictConfirmed, domain.ConfidenceHigh,
			"the browser reported the marker as an unresolved JavaScript identifier: the candidate reached an executable position"
	case markerInDOM:
		return domain.VerdictRejected, domain.ConfidenceHigh,
			"the candidate was reflected in the rendered page but no execution signal was observed"
	default:
		return domain.VerdictInconclusive, domain.ConfidenceLow,
			"the marker was not found in the rendered page during verification; confirmation could not be attempted"
	}
}

// Decide is decide's exported form — see "The three-way decision" in
// docs/browser-verification.md. Reused by DOM XSS payload verification
// (internal/scan/domxss.go) so a DOM-XSS verdict is produced by the
// IDENTICAL deterministic rule Reflected XSS verification already uses,
// never a separately-invented one.
func Decide(matched, markerInDOM bool) (domain.Verdict, domain.Confidence, string) {
	return decide(matched, markerInDOM)
}

// errOutOfScope is returned when the navigation URL itself fails the scope gate
// (defense in depth: the caller should never hand verification an out-of-scope
// URL, since the candidate step already ran it through the scope-enforcing
// engine, but verification fails closed too).
var errOutOfScope = errors.New("verification: navigation target is out of scope")

// classifyBrowserErr normalizes a browser/navigation error so the caller's
// existing timeout/cancellation classification (ctx.Err / errors.Is(...,
// context.DeadlineExceeded)) applies uniformly, whether the error came from the
// HTTP engine or the browser (Playwright's own TimeoutError, via
// browser.IsTimeout — see that doc comment for why Playwright stays confined to
// the browser package).
func classifyBrowserErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if browser.IsTimeout(err) {
		return context.DeadlineExceeded
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}
