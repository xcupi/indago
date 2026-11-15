package oast

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Poll API.
//
// A collaborator answers one question — did the target call back? — but the
// engines that ask it (internal/scan/ssrf.go, xxe.go, commandinjection.go)
// cannot read the Manager's in-process state: each was written against an
// external webhook service and polls a URL for the marker it planted. Rather
// than bend three engines around a new interface, the Manager publishes exactly
// that: a read API whose body lists every recorded interaction, raw host, path
// and query included, so `strings.Contains(body, marker)` keeps working while
// the listener, the token correlation and the bounded retention all come from
// one component.
//
// Boundaries kept on purpose:
//
//   - The poll listener ALWAYS binds loopback, whatever Config.ListenAddr says.
//     A hit list must never be reachable from a target, even when the callback
//     listener is published through a tunnel.
//   - The path carries a per-process random secret, so another local process
//     cannot enumerate it by guessing; every other path is a 404.
//   - The response is bounded (pollMaxInteractions, each field capped and
//     stripped of control characters) so a flooded listener cannot turn a poll
//     into a memory or terminal-escape amplifier.
//   - It lists interactions only. It never sends anything, and a listed hit is
//     evidence, not a verdict: deciding what a hit means stays with the
//     engine's own deterministic rules (AGENTS.md §2.5).
//
// Poll traffic never touches the callback listener, so a poll can never be
// recorded as an interaction and inflate the evidence it reports on.

const (
	// pollListenAddr is the poll API's own bind address. Not configurable:
	// there is no legitimate reason for a hit list to be reachable off-host.
	pollListenAddr = "127.0.0.1:0"

	// pollMaxInteractions caps how many interactions one response lists. An
	// engine only looks for its own marker, and the oldest interactions are
	// the ones already examined, so the newest N are enough.
	pollMaxInteractions = 512
	// pollFieldMax caps one rendered field (path, query, host, ...).
	pollFieldMax = 512

	pollPathPrefix = "/poll/"
)

// pollServer is the loopback read API: one listener, one unguessable path.
type pollServer struct {
	mgr    *Manager
	secret string
	url    string
	srv    *http.Server
}

// PollURL returns the URL of the loopback-only read API that lists this
// manager's recorded interactions (newest last), starting the API on first
// call. Repeated calls return the same URL; a start failure is remembered and
// returned every time rather than retried per call.
//
// The body is plain text, one line per interaction, carrying the raw host, path
// and query a callback used, so an engine that planted a correlation marker
// finds it with a substring search. See this file's header for what the API
// deliberately refuses to expose.
func (m *Manager) PollURL() (string, error) {
	select {
	case <-m.closed:
		return "", ErrClosed
	default:
	}
	m.pollOnce.Do(func() {
		ps, err := m.startPollServer()
		if err != nil {
			m.pollErr = err
			return
		}
		m.pollSrvMu.Lock()
		m.poll = ps
		m.pollSrvMu.Unlock()
	})
	if m.pollErr != nil {
		return "", m.pollErr
	}
	return m.pollURL, nil
}

func (m *Manager) startPollServer() (*pollServer, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", pollListenAddr)
	if err != nil {
		return nil, fmt.Errorf("oast: poll listener: %w", err)
	}
	ps := &pollServer{mgr: m, secret: newToken()}
	// A Close that raced with this first call must not leave a listener behind.
	select {
	case <-m.closed:
		_ = ln.Close()
		return nil, ErrClosed
	default:
	}
	ps.url = "http://" + displayAddr(ln.Addr()) + pollPathPrefix + ps.secret
	ps.srv = &http.Server{
		Handler:           http.HandlerFunc(ps.serve),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() {
		if serr := ps.srv.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) && m.log != nil {
			m.log.Warn("oast: poll listener stopped", "addr", ln.Addr().String(), "err", serr)
		}
	}()
	// Record the URL only after the listener exists, so a caller that sees a
	// URL can rely on it answering.
	m.pollURL = ps.url
	return ps, nil
}

func (ps *pollServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !pollPathMatches(r.URL.Path, ps.secret) {
		// Same answer for a wrong secret and for a wrong path: a prober learns
		// nothing about whether the API exists.
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	body := ps.mgr.pollBody()
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, body)
}

// pollPathMatches reports whether path is exactly the API's own path, compared
// in constant time so a prober cannot learn the secret byte by byte.
func pollPathMatches(path, secret string) bool {
	if !strings.HasPrefix(path, pollPathPrefix) {
		return false
	}
	given := strings.TrimPrefix(path, pollPathPrefix)
	if len(given) != len(secret) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(secret)) == 1
}

// pollBody renders the retained interactions, oldest first. It copies what it
// needs under the lock and formats outside it: a poll must never hold up a
// callback being recorded.
func (m *Manager) pollBody() string {
	m.mu.Lock()
	total := m.interactions.len()
	start := 0
	if total > pollMaxInteractions {
		start = total - pollMaxInteractions
	}
	kept := make([]Interaction, 0, total-start)
	for i := start; i < total; i++ {
		kept = append(kept, cloneInteraction(m.interactions.at(i)))
	}
	m.mu.Unlock()

	matched := 0
	for _, it := range kept {
		if it.Token != "" {
			matched++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "indago-oast poll: %d interaction(s), %d correlated\n", len(kept), matched)
	for _, it := range kept {
		target := it.Host + it.Path
		if it.Query != "" {
			target += "?" + it.Query
		}
		b.WriteString(it.ReceivedAt.UTC().Format(time.RFC3339Nano))
		b.WriteByte(' ')
		b.WriteString(pollField(it.Protocol))
		b.WriteByte(' ')
		b.WriteString(pollField(it.Method))
		b.WriteByte(' ')
		b.WriteString(pollField(target))
		if it.Token != "" {
			b.WriteString(" token=")
			b.WriteString(pollField(it.Token))
		}
		if it.ProbeID != "" {
			b.WriteString(" probe=")
			b.WriteString(pollField(it.ProbeID))
		}
		if it.Tag != "" {
			b.WriteString(" tag=")
			b.WriteString(pollField(it.Tag))
		}
		if it.RemoteIP != "" {
			b.WriteString(" remote=")
			b.WriteString(pollField(it.RemoteIP))
		}
		b.WriteString(" source=")
		b.WriteString(pollField(it.Source))
		b.WriteByte('\n')
	}
	return b.String()
}

// pollField makes one value safe to embed in a line-oriented body: control
// characters (a callback path can hold almost anything) become '.', so a target
// cannot forge lines, split a marker invisibly, or page through the reader's
// terminal. Printable bytes are untouched, so a marker present in the raw
// request stays present verbatim.
func pollField(s string) string {
	if s == "" {
		return "-"
	}
	if len(s) > pollFieldMax {
		s = s[:pollFieldMax]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			b.WriteByte('.')
			continue
		}
		b.WriteByte(c)
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// closePoll stops the poll API, if it was ever started.
func (m *Manager) closePoll() error {
	m.pollSrvMu.Lock()
	poll := m.poll
	m.pollSrvMu.Unlock()
	if poll == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := poll.srv.Shutdown(ctx); err != nil {
		_ = poll.srv.Close()
		return err
	}
	return nil
}
