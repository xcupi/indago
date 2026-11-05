package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// This file is the SAME-ORIGIN EXTERNAL SCRIPT layer for the DOM-XSS static
// pass. It exists because the taint pass could only see inline <script>
// bodies: a page whose sink lives in `/app.js` produced
// DOMXSSFlowNoTaintedPath, which reads as "this page has no sink" even though
// the page's own external script contains one. The measured lab page is
// exactly that shape (see docs/dom-xss.md, "Same-origin external scripts").
//
// Three properties are deliberate:
//
//   - PURE. Nothing here performs I/O. A caller supplies a DOMXSSScriptFetcher;
//     in the pipeline that fetcher reads the script THROUGH the already-loaded
//     page, so the scan's own session, proxy, rate limiter and scope gate
//     apply exactly as they do to every other browser request. No new network
//     path exists.
//   - BOUNDED. Per file, per page and per scan (loader) byte/count ceilings are
//     constants below and are enforced here, once, so no caller can widen them
//     accidentally. A file over the size cap is SKIPPED WHOLE and recorded —
//     never truncated: half a minified bundle parses into nonsense, and a
//     nonsense answer is worse than an explicit "not analysed".
//   - CACHED BY CONTENT. The same script referenced by several pages is fetched
//     once (URL cache), identical content under different URLs is not fetched
//     twice (content-hash cache), and within one page identical content is
//     parsed once.
//
// Absence is never fabricated: a reference that is out of origin, over a cap,
// unfetchable or unparsable is recorded as a skip with a reason, and the
// static pass turns that into DOMXSSFlowUnresolved rather than a negative.

const (
	// DOMXSSScriptScanByteBudget bounds the total script bytes ONE loader (one
	// scan) will hand to the analyser. Four mebibytes at a 256 KiB per-file cap
	// is sixteen full-size scripts; a scan that reads more than that has
	// visited a lot of pages, and the remaining scripts are recorded as
	// budget-refused instead of being analysed.
	DOMXSSScriptScanByteBudget = 4 << 20
)

// Skip reasons recorded for a reference that was not analysed. They are stable
// strings because they are persisted in TestCase notes and asserted by tests.
const (
	DOMXSSScriptSkipForeign     = "not same-origin"
	DOMXSSScriptSkipPerPageCap  = "per-page script cap reached"
	DOMXSSScriptSkipTooLarge    = "exceeds the per-file size cap"
	DOMXSSScriptSkipFetchFailed = "fetch failed"
	DOMXSSScriptSkipBudget      = "per-scan byte budget exhausted"
	DOMXSSScriptSkipNotFetched  = "not fetched"
	DOMXSSScriptSkipParseFailed = "could not be parsed"
)

// ErrDOMXSSScriptTooLarge is what a DOMXSSScriptFetcher returns when the body
// it read exceeds DOMXSSScriptByteLimit. The loader records the reference as
// skipped rather than handing a truncated body to the parser.
var ErrDOMXSSScriptTooLarge = errors.New("dom-xss: script exceeds the analysis size cap")

// DOMXSSScriptFetcher reads one already-resolved, same-origin script body.
// Implementations MUST enforce the same scope/session/proxy policy as the rest
// of their scan; this package never does network I/O itself. Returning an error
// (including ErrDOMXSSScriptTooLarge) means the body is unavailable, which is
// recorded — never silently treated as "this script contains no sink".
type DOMXSSScriptFetcher interface {
	FetchDOMXSSScript(url string) (string, error)
}

// DOMXSSScriptFetcherFunc adapts a plain function to DOMXSSScriptFetcher.
type DOMXSSScriptFetcherFunc func(url string) (string, error)

// FetchDOMXSSScript implements DOMXSSScriptFetcher.
func (f DOMXSSScriptFetcherFunc) FetchDOMXSSScript(url string) (string, error) { return f(url) }

// DOMXSSExternalScript is one <script src=...> reference and, when it could be
// read, its body. It is the unit the static pass analyses and the provenance
// carrier a report needs: URL is the resolved, same-origin script URL that a
// sink found in this body is attributed to.
type DOMXSSExternalScript struct {
	// Src is the raw attribute value as written in the page.
	Src string `json:"src,omitempty"`
	// URL is the resolved same-origin URL, empty when it did not resolve.
	URL string `json:"url,omitempty"`
	// Body is the script source. Empty when Err is set.
	Body string `json:"-"`
	// Hash is the hex SHA-256 of Body, the content-cache key.
	Hash string `json:"hash,omitempty"`
	// Bytes is len(Body).
	Bytes int `json:"bytes,omitempty"`
	// Err is the reason the body is unavailable, one of the DOMXSSScriptSkip*
	// values (plus the fetcher's own message for a transport failure). A
	// non-empty Err is recorded by the static pass as an unresolved script.
	Err string `json:"error,omitempty"`
}

// Unavailable reports whether this reference has no analysable body.
func (s DOMXSSExternalScript) Unavailable() bool { return s.Err != "" || s.Body == "" }

// DOMXSSScriptStats is the deterministic counter set one scan's loader
// exposes. Tests assert the caps from it; operator-facing notes quote it.
type DOMXSSScriptStats struct {
	Pages          int `json:"pages"`
	Refs           int `json:"refs"`
	Fetches        int `json:"fetches"`
	CacheHits      int `json:"cache_hits"`
	HashHits       int `json:"hash_hits"`
	BytesRead      int `json:"bytes_read"`
	PerPageSkipped int `json:"per_page_skipped"`
	TooLarge       int `json:"too_large"`
	Failed         int `json:"failed"`
	BudgetRefused  int `json:"budget_refused"`
	Foreign        int `json:"foreign"`
	// Bodies is the number of DISTINCT script bodies available for analysis
	// (the content-hash cache size): two URLs serving identical bytes count
	// once.
	Bodies int `json:"bodies"`
}

// DOMXSSScriptLoader is the per-scan, bounded, content-addressed script cache.
// It is safe for concurrent use: DOM-XSS probes for several endpoints can run
// on different workers at the same time and must share one byte budget.
type DOMXSSScriptLoader struct {
	mu     sync.Mutex
	byURL  map[string]DOMXSSExternalScript
	byHash map[string]DOMXSSExternalScript
	bytes  int
	stats  DOMXSSScriptStats
}

// NewDOMXSSScriptLoader returns an empty per-scan loader.
func NewDOMXSSScriptLoader() *DOMXSSScriptLoader {
	return &DOMXSSScriptLoader{
		byURL:  make(map[string]DOMXSSExternalScript),
		byHash: make(map[string]DOMXSSExternalScript),
	}
}

// Stats returns a snapshot of the loader's counters.
func (l *DOMXSSScriptLoader) Stats() DOMXSSScriptStats {
	if l == nil {
		return DOMXSSScriptStats{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Bodies = len(l.byHash)
	return s
}

// ScriptsFor resolves refs (raw src attribute values from ONE page at pageURL),
// keeps only same-origin references, and returns one entry per reference the
// static pass should consider — including the skipped ones, each with a reason.
// The returned slice preserves reference order, so provenance stays
// deterministic.
//
// Caps: at most DOMXSSScriptFetchLimit script FILES are fetched per page (the
// rest are returned with a skip reason), each body at most
// DOMXSSScriptByteLimit (a larger body is skipped whole, never truncated), and
// at most DOMXSSScriptScanByteBudget NEW bytes are read across the loader's
// lifetime. References already cached by URL, or whose content hash is already
// known, cost no fetch and no budget.
func (l *DOMXSSScriptLoader) ScriptsFor(f DOMXSSScriptFetcher, pageURL string, refs []string) []DOMXSSExternalScript {
	if l == nil || len(refs) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stats.Pages++

	out := make([]DOMXSSExternalScript, 0, len(refs))
	seen := make(map[string]bool, len(refs))
	files := 0
	for _, raw := range refs {
		l.stats.Refs++
		resolved, sameOrigin := DOMXSSSameOriginScriptURL(raw, pageURL)
		if !sameOrigin {
			l.stats.Foreign++
			out = append(out, DOMXSSExternalScript{Src: raw, Err: DOMXSSScriptSkipForeign})
			continue
		}
		if seen[resolved] {
			continue // the same URL twice on one page is one reference
		}
		seen[resolved] = true

		if cached, ok := l.byURL[resolved]; ok {
			l.stats.CacheHits++
			files++
			out = append(out, cached)
			continue
		}
		if files >= DOMXSSScriptFetchLimit {
			l.stats.PerPageSkipped++
			out = append(out, DOMXSSExternalScript{Src: raw, URL: resolved, Err: DOMXSSScriptSkipPerPageCap})
			continue
		}
		if l.bytes >= DOMXSSScriptScanByteBudget {
			l.stats.BudgetRefused++
			out = append(out, DOMXSSExternalScript{Src: raw, URL: resolved, Err: DOMXSSScriptSkipBudget})
			continue
		}

		body, err := f.FetchDOMXSSScript(resolved)
		files++
		if errors.Is(err, ErrDOMXSSScriptTooLarge) {
			l.stats.TooLarge++
			out = append(out, DOMXSSExternalScript{Src: raw, URL: resolved, Err: DOMXSSScriptSkipTooLarge})
			continue
		}
		if err != nil {
			l.stats.Failed++
			out = append(out, DOMXSSExternalScript{Src: raw, URL: resolved, Err: DOMXSSScriptSkipFetchFailed + ": " + err.Error()})
			continue
		}
		if len(body) > DOMXSSScriptByteLimit {
			// Defensive: a fetcher that ignores the cap cannot smuggle a
			// truncated body into the parser.
			l.stats.TooLarge++
			out = append(out, DOMXSSExternalScript{Src: raw, URL: resolved, Err: DOMXSSScriptSkipTooLarge})
			continue
		}

		hash := domXSSContentHash(body)
		if known, ok := l.byHash[hash]; ok {
			// Same CONTENT under a different URL: nothing new to fetch, and
			// nothing new to charge to the byte budget. The body is still
			// handed to the caller (analysis is per page, see
			// dxsPageScriptBodies' within-page hash dedupe).
			l.stats.HashHits++
			out = append(out, DOMXSSExternalScript{Src: raw, URL: resolved, Body: body, Hash: hash, Bytes: known.Bytes})
			continue
		}

		l.stats.Fetches++
		l.stats.BytesRead += len(body)
		l.bytes += len(body)
		entry := DOMXSSExternalScript{Src: raw, URL: resolved, Body: body, Hash: hash, Bytes: len(body)}
		l.byHash[hash] = entry
		l.byURL[resolved] = entry
		out = append(out, entry)
	}
	return out
}

// domXSSContentHash is the content-cache key for one script body.
func domXSSContentHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// DOMXSSSameOriginScriptURL resolves raw against base and reports whether it
// stays on the SAME origin (scheme + host + port). Only those are read: a
// third-party bundle is not this page's script, and tainting a name or sink
// from it would attribute someone else's code to the target.
func DOMXSSSameOriginScriptURL(raw, base string) (string, bool) {
	b, err := url.Parse(strings.TrimSpace(base))
	if err != nil || b.Host == "" {
		return "", false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	r, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(r.Scheme) {
	case "data", "blob", "javascript", "mailto", "about":
		return "", false
	}
	u := b.ResolveReference(r)
	if u.Scheme != b.Scheme || !strings.EqualFold(u.Hostname(), b.Hostname()) || domXSSEffectivePort(u) != domXSSEffectivePort(b) {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	// An explicit default port is the same origin; normalise it away so the
	// provenance a report prints is stable.
	if p := u.Port(); p != "" && p == domXSSDefaultPort(u.Scheme) {
		u.Host = u.Hostname()
	}
	u.Fragment = ""
	return u.String(), true
}

// domXSSEffectivePort is the port the URL actually connects to, with the
// scheme's default filled in, so `https://h/x` and `https://h:443/x` compare
// equal. Any other port difference is a different origin.
func domXSSEffectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return domXSSDefaultPort(u.Scheme)
}

func domXSSDefaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// DOMXSSScriptProblem is one <script src> the static pass could not analyse.
// It is reported for exactly the same reason DOMXSSUnresolvedFlow is: so an
// unknown is never read as an absence.
type DOMXSSScriptProblem struct {
	Src    string `json:"src,omitempty"`
	URL    string `json:"url,omitempty"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Describe renders one line for a TestCase note or a report.
func (p DOMXSSScriptProblem) Describe() string {
	target := p.URL
	if target == "" {
		target = p.Src
	}
	if p.Detail != "" {
		return fmt.Sprintf("%s (%s: %s)", target, p.Reason, p.Detail)
	}
	return fmt.Sprintf("%s (%s)", target, p.Reason)
}
