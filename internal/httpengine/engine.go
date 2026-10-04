// Package httpengine performs HTTP exchanges with a target. It supports GET and
// POST (form and JSON) requests, custom headers and cookies, redirect control,
// per-request timeouts, proxying, full request/response capture for evidence,
// and context cancellation.
//
// Scope enforcement is intentionally OUT of scope for this package: callers
// (e.g. the scan controller) must validate a URL against the scan's scope before
// invoking the engine. The engine also performs no payload generation or
// vulnerability detection — it is a neutral transport.
package httpengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// Errors returned by the engine.
var (
	// ErrNotImplemented is returned by the Stub engine (no traffic).
	ErrNotImplemented = errors.New("httpengine: not implemented")
	// ErrInvalidRequest indicates a malformed request (bad method/URL/scheme).
	ErrInvalidRequest = errors.New("httpengine: invalid request")
	// ErrTooManyRedirects indicates the redirect limit was exceeded.
	ErrTooManyRedirects = errors.New("httpengine: too many redirects")
)

// Request describes a single HTTP request. It is a plain data value so it can be
// persisted and captured as evidence.
type Request struct {
	Method  string            // defaults to GET when empty
	URL     string            // absolute http(s) URL
	Headers map[string]string // request headers (single value each)
	Cookies []*http.Cookie    // request-scoped cookies (in addition to any jar)
	Body    []byte            // raw request body
	// ContentType, when set and no explicit Content-Type header is present, is
	// used as the request's Content-Type. The POSTForm/POSTJSON constructors set
	// it for you.
	ContentType string
}

// NewRequest returns a request with the given method and URL.
func NewRequest(method, rawURL string) *Request {
	return &Request{Method: method, URL: rawURL}
}

// GET returns a GET request for rawURL.
func GET(rawURL string) *Request {
	return &Request{Method: http.MethodGet, URL: rawURL}
}

// POSTForm returns a POST request with a url-encoded form body and the
// application/x-www-form-urlencoded content type.
func POSTForm(rawURL string, form url.Values) *Request {
	return &Request{
		Method:      http.MethodPost,
		URL:         rawURL,
		Body:        []byte(form.Encode()),
		ContentType: "application/x-www-form-urlencoded",
	}
}

// POSTJSON returns a POST request whose body is the JSON encoding of v, with the
// application/json content type.
func POSTJSON(rawURL string, v any) (*Request, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &Request{
		Method:      http.MethodPost,
		URL:         rawURL,
		Body:        b,
		ContentType: "application/json",
	}, nil
}

// WithHeader sets a header and returns the request for chaining.
func (r *Request) WithHeader(key, value string) *Request {
	if r.Headers == nil {
		r.Headers = make(map[string]string)
	}
	r.Headers[key] = value
	return r
}

// WithCookie adds a cookie and returns the request for chaining.
func (r *Request) WithCookie(name, value string) *Request {
	r.Cookies = append(r.Cookies, &http.Cookie{Name: name, Value: value})
	return r
}

// CapturedRequest records what was actually sent, for evidence/reproducibility.
// Note: cookies added by a shared cookie jar are applied by the transport and
// may not appear in Headers; request-scoped cookies do.
type CapturedRequest struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body,omitempty"`
}

// Response captures an HTTP response plus timing and provenance for evidence.
type Response struct {
	Status        int              `json:"status"`
	StatusText    string           `json:"status_text"`
	Proto         string           `json:"proto"`
	Headers       http.Header      `json:"headers"`
	Body          []byte           `json:"body,omitempty"`
	Truncated     bool             `json:"truncated"`      // body hit MaxBodyBytes
	ContentLength int64            `json:"content_length"` // as reported (-1 if unknown)
	FinalURL      string           `json:"final_url"`      // after redirects
	RedirectChain []string         `json:"redirect_chain,omitempty"`
	Duration      time.Duration    `json:"duration"`
	ReceivedAt    time.Time        `json:"received_at"`
	Request       *CapturedRequest `json:"request,omitempty"`
}

// Engine performs HTTP exchanges with a target.
//
// Implementations do NOT enforce scope — the caller must ensure the request URL
// is in scope before calling Do.
type Engine interface {
	Do(ctx context.Context, req *Request) (*Response, error)
}

// Stub is a no-op engine. Every call returns ErrNotImplemented so no target
// traffic is generated. Useful in tests and where the real engine is not wired.
type Stub struct{}

// Do implements Engine.
func (Stub) Do(context.Context, *Request) (*Response, error) { return nil, ErrNotImplemented }

var _ Engine = Stub{}
