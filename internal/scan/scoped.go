package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// maxScopedRedirects bounds the redirect chain followed by scopedEngine.
const maxScopedRedirects = 10

// scopedEngine wraps an httpengine.Engine so that NO request leaves the scan's
// scope — including requests caused by redirects.
//
// The HTTP engine deliberately performs no scope checks (scope enforcement lives
// outside that module). The controller therefore enforces it here, at the
// boundary where discovery obtains its engine:
//
//  1. every request URL is checked against scope (fail closed) before it is sent;
//  2. redirects are followed MANUALLY, re-checking scope on every hop, so an
//     in-scope page cannot bounce the crawler to an out-of-scope host.
//
// For (2) to hold, the wrapped engine MUST be configured with
// FollowRedirects=false; otherwise it would follow redirects itself, bypassing
// the per-hop check. cmd/indago builds its client that way.
type scopedEngine struct {
	inner httpengine.Engine
	scope domain.Scope
	// cookies are added to every request this engine sends, on top of whatever
	// the caller set — see WithSessionCookies. nil for most scans (anonymous
	// auth, or no browser storage state).
	cookies []*http.Cookie
}

var _ httpengine.Engine = (*scopedEngine)(nil)

func newScopedEngine(inner httpengine.Engine, scope domain.Scope) *scopedEngine {
	return &scopedEngine{inner: inner, scope: scope}
}

// WithSessionCookies attaches cookies to every request this engine sends, so
// the scan's authenticated session (established for browser verification) is
// ALSO carried by the plain HTTP-level reflection/candidate testing — without
// it, a cookie-gated endpoint would never even show its reflection to the HTTP
// executor, and nothing downstream would ever reach verification. Returns the
// same engine for chaining. Each scopedEngine instance is scan-scoped (built
// fresh per launch), so this never leaks one scan's cookies into another's
// requests even though the underlying transport (c.opts.HTTP) is shared.
func (s *scopedEngine) WithSessionCookies(cookies []*http.Cookie) *scopedEngine {
	s.cookies = cookies
	return s
}

// Do implements httpengine.Engine.
func (s *scopedEngine) Do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", httpengine.ErrInvalidRequest)
	}
	cur := *req // never mutate the caller's request
	if len(s.cookies) > 0 {
		cur.Cookies = append(append([]*http.Cookie(nil), req.Cookies...), s.cookies...)
	}
	var chain []string

	for hop := 0; ; hop++ {
		if d := s.scope.Permits(cur.URL); !d.Allowed {
			return nil, fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
		}
		resp, err := s.inner.Do(ctx, &cur)
		if err != nil {
			return nil, err
		}
		if !isRedirectStatus(resp.Status) {
			resp.RedirectChain = chain
			resp.FinalURL = cur.URL
			return resp, nil
		}

		loc := resp.Headers.Get("Location")
		if loc == "" {
			resp.RedirectChain = chain
			resp.FinalURL = cur.URL
			return resp, nil // redirect without a target: hand the 3xx back
		}
		next, err := resolveRedirect(cur.URL, loc)
		if err != nil {
			return nil, fmt.Errorf("%w: bad redirect Location %q", httpengine.ErrInvalidRequest, loc)
		}
		if hop >= maxScopedRedirects {
			return nil, httpengine.ErrTooManyRedirects
		}
		chain = append(chain, next)
		cur.URL = next
		// Per RFC 9110, 301/302/303 turn a non-GET/HEAD into GET and drop the body;
		// 307/308 preserve method and body.
		if resp.Status == 301 || resp.Status == 302 || resp.Status == 303 {
			if cur.Method != "" && cur.Method != http.MethodGet && cur.Method != http.MethodHead {
				cur.Method = http.MethodGet
				cur.Body = nil
				cur.ContentType = ""
			}
		}
	}
}

func isRedirectStatus(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// sessionCookies reads a browser storage-state file (the JSON format
// browser.Context.SaveStorageState writes: {"cookies":[...], "origins":[...]})
// and returns the cookies whose domain matches host, for WithSessionCookies.
// It never errors — a missing/unreadable/malformed file, or no browser
// session having been saved at all, simply yields no cookies; HTTP-level
// testing then proceeds unauthenticated, exactly as it always has.
func sessionCookies(statePath, host string) []*http.Cookie {
	if statePath == "" {
		return nil
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil
	}
	var state struct {
		Cookies []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Domain string `json:"domain"`
		} `json:"cookies"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	host = strings.ToLower(host)
	var out []*http.Cookie
	for _, c := range state.Cookies {
		// Playwright's storage state does not record whether a cookie was
		// host-only or had an explicit Domain (no such flag is written), so
		// every stored cookie is treated as domain-scoped: it applies to its
		// domain and that domain's subdomains, with or without a leading dot.
		d := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
		if d == "" || d == host || strings.HasSuffix(host, "."+d) {
			out = append(out, &http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	return out
}

func resolveRedirect(base, loc string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	return bu.ResolveReference(lu).String(), nil
}
