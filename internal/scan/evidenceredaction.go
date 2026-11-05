package scan

// Cookie-value redaction at the access-control persistence boundary.
//
// persistPair already redacts Cookie and Set-Cookie HEADER values. That leaves
// the other half of the same credential problem: a target is free to reflect
// the cookie value it received — or the one it just issued — into the HTML or
// JavaScript it returns, so the value also travels inside the stored response
// body, and body-derived data (an action's href, for instance) reaches the
// TestCase and Finding detail. Evidence has to stay reproducible without
// becoming a credential store.
//
// cookieRedactor collects, per job, the cookie values the scan has ALREADY seen
// on the wire — the values in a captured request's Cookie header and in a
// response's Set-Cookie headers — and rewrites those exact values to
// "<redacted>" in the copy that is persisted. It never reads a body looking for
// "secrets" to remember, and the redactor itself is never persisted: it exists
// only as a context value for the duration of one Handle call, so one job's
// values can neither outlive it nor redact another job's evidence.
//
// Values are matched as exact byte strings (plus their URL-encoded form, since a
// target may echo a value into a query string). EVERY observed non-empty value
// is rewritten, including one- and two-byte values: "sid=abc" or "role=1" is
// still credential and authorization state, and evidence fidelity is secondary
// to not persisting it. Short values that also read as ordinary prose are
// therefore over-redacted; that is the accepted cost (see HANDOFF.md).

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/indago/indago/internal/httpengine"
)

const (
	// redactedCookieValue is what a matched value becomes. It is the same
	// marker the header redaction uses, so a reader sees one convention.
	redactedCookieValue = "<redacted>"

	// redactionSentinel stands in for a value while the remaining values are
	// processed. It must contain no byte a cookie value can contain: a
	// one-character value such as "e" would otherwise rewrite the marker
	// itself ("<redacted>" contains "e"), producing a corrupted marker or a
	// recursive replacement. Cookie-octet values are printable US-ASCII, so a
	// control-byte sequence is safe.
	redactionSentinel = "\x00\x01\x00"
)

// cookieRedactor holds the cookie values one job has seen so far.
type cookieRedactor struct {
	mu     sync.Mutex
	values []string
	seen   map[string]struct{}
}

func newCookieRedactor() *cookieRedactor {
	return &cookieRedactor{seen: make(map[string]struct{})}
}

type cookieRedactorKey struct{}

// withCookieRedaction attaches a fresh, job-local redactor to ctx and returns
// it. Handle calls this once per job.
func withCookieRedaction(ctx context.Context) (context.Context, *cookieRedactor) {
	r := newCookieRedactor()
	return context.WithValue(ctx, cookieRedactorKey{}, r), r
}

// cookieRedactorFrom returns the redactor attached to ctx, or nil. Every method
// tolerates a nil receiver, so call sites do not branch.
func cookieRedactorFrom(ctx context.Context) *cookieRedactor {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(cookieRedactorKey{}).(*cookieRedactor)
	return r
}

// observe records the cookie values carried by one request/response pair:
// every value in the captured request's Cookie header(s) and every value in the
// response's Set-Cookie header(s). Both are already part of the pair this job
// is about to persist, so nothing new is discovered — only remembered for the
// duration of the job.
func (r *cookieRedactor) observe(resp *httpengine.Response) {
	if r == nil || resp == nil {
		return
	}
	if resp.Request != nil {
		for _, line := range resp.Request.Headers.Values("Cookie") {
			for _, part := range strings.Split(line, ";") {
				if _, value, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
					r.add(value)
				}
			}
		}
	}
	for _, line := range resp.Headers.Values("Set-Cookie") {
		name, rest, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		if i := strings.IndexByte(rest, ';'); i >= 0 {
			rest = rest[:i]
		}
		r.add(rest)
	}
}

func (r *cookieRedactor) add(value string) {
	value = strings.TrimSpace(value)
	if r == nil || value == "" || value == redactedCookieValue {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.seen[value]; dup {
		return
	}
	r.seen[value] = struct{}{}
	r.values = append(r.values, value)
	// Longest first, so a value that contains another one is rewritten whole.
	sort.SliceStable(r.values, func(i, j int) bool { return len(r.values[i]) > len(r.values[j]) })
}

// redact returns s with every known cookie value rewritten. It is a no-op on a
// nil redactor (a flow that never attached one).
func (r *cookieRedactor) redact(s string) string {
	if r == nil || s == "" {
		return s
	}
	r.mu.Lock()
	values := append([]string(nil), r.values...)
	r.mu.Unlock()
	for _, value := range values {
		s = strings.ReplaceAll(s, value, redactionSentinel)
		// The same value can reach a stored blob in an encoded form: the
		// detail record is JSON (where "&", "<" and ">" are escaped) and a
		// target may HTML-encode what it echoes back into a page.
		for _, encoded := range []string{url.QueryEscape(value), jsonStringForm(value), html.EscapeString(value)} {
			if encoded != "" && encoded != value {
				s = strings.ReplaceAll(s, encoded, redactionSentinel)
			}
		}
	}
	// Resolve the sentinels only after every value has been matched, so a
	// short value can never rewrite (or recursively match) the marker.
	return strings.ReplaceAll(s, redactionSentinel, redactedCookieValue)
}

// jsonStringForm renders value the way encoding/json renders a string's
// contents (HTML escaping included), so a value that json.Marshal escaped is
// still matched inside a serialised detail record.
func jsonStringForm(value string) string {
	b, err := json.Marshal(value)
	if err != nil || len(b) < 2 {
		return ""
	}
	return string(b[1 : len(b)-1])
}

// redactBytes is redact for a serialised evidence blob or detail record.
func (r *cookieRedactor) redactBytes(b []byte) []byte {
	if r == nil || len(b) == 0 {
		return b
	}
	return []byte(r.redact(string(b)))
}

// redactJSON is redactBytes for a serialised JSON detail record. Replacing
// bytes across the whole record would corrupt independent structure — a
// one-digit cookie value "1" turns {"attempt":1} into {"attempt":<redacted>} —
// so the record is decoded and only string VALUES are redacted; numbers (kept
// verbatim via json.Number), booleans, null, object keys, unknown fields and
// structure pass through unchanged. Input that is not a single valid JSON
// value falls back to strict byte redaction.
func (r *cookieRedactor) redactJSON(b []byte) []byte {
	if r == nil || len(b) == 0 {
		return b
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return r.redactBytes(b)
	}
	if _, err := dec.Token(); err != io.EOF {
		return r.redactBytes(b)
	}
	// HTML escaping stays off so the "<redacted>" marker remains readable in
	// the stored record; the JSON it encodes is semantically identical.
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r.redactStrings(v)); err != nil {
		return r.redactBytes(b)
	}
	return bytes.TrimRight(out.Bytes(), "\n")
}

func (r *cookieRedactor) redactStrings(v any) any {
	switch x := v.(type) {
	case string:
		return r.redact(x)
	case []any:
		for i := range x {
			x[i] = r.redactStrings(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = r.redactStrings(x[k])
		}
	}
	return v
}
