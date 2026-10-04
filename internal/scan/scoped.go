package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

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
}

var _ httpengine.Engine = (*scopedEngine)(nil)

func newScopedEngine(inner httpengine.Engine, scope domain.Scope) *scopedEngine {
	return &scopedEngine{inner: inner, scope: scope}
}

// Do implements httpengine.Engine.
func (s *scopedEngine) Do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", httpengine.ErrInvalidRequest)
	}
	cur := *req // never mutate the caller's request
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
