// Package oast implements Indago's out-of-band application security testing
// (OAST) manager.
//
// A scan needs a collaborator it can point a payload at, and then one question
// answered: did the target actually call back? Until now that question was
// answered ad hoc: the XXE and command-injection engines each take an
// operator-supplied callback URL plus a separate poll URL and search the polled
// body for a marker (internal/scan/xxe.go, internal/scan/commandinjection.go).
// That works against one specific webhook service, duplicates polling code in
// every engine, and leaves correlation — which probe caused this hit? — to
// string matching against an arbitrary document.
//
// This package replaces that with one component:
//
//   - Local mode (the default) runs a built-in HTTP listener. Every probe gets
//     a unique URL containing a crypto-random token. Inbound requests are
//     recorded with timestamp, source IP, method, path, query, headers and a
//     bounded body, and the listener answers with a fixed inert canary. A
//     DNS-style bridge (an operator's wildcard DNS, tunnel or proxy forwarding
//     hits) feeds the same correlated records through RecordHit with
//     Protocol "dns".
//   - Interactsh mode registers with any interactsh-compatible server,
//     generates a unique per-probe subdomain, polls on demand, decrypts the
//     server's RSA/AES payloads and records the resulting interactions.
//
// Safety properties, which are load-bearing rather than incidental:
//
//   - The manager never sends a request to the target. It only listens, or
//     polls the operator's own OAST server. Scope enforcement stays in the scan
//     layer; nothing here can widen what may be targeted.
//   - The canary response is constant. Nothing from the request (path, query,
//     headers, body) is echoed, so the listener cannot become an injection
//     source of its own.
//   - Inbound data is bounded before it is stored: body size, header count,
//     header value length and the number of retained interactions all have
//     hard ceilings, and Config validation rejects absurd values.
//   - There are no vendor or lab constants. Local mode is built in; interactsh
//     mode requires an explicit server. Nothing defaults to a public service.
//   - A recorded interaction is evidence that a callback arrived, not a
//     verdict. Whether that means a vulnerability stays with the calling
//     engine's own deterministic rules (AGENTS.md §2.5).
//
// A Manager is safe for concurrent use: one Manager is shared by every worker
// of a scan, like the rate limiter and the scope-enforcing engine.
package oast

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultListenAddr binds the built-in listener to an ephemeral loopback
	// port. Local mode is loopback-only unless the operator explicitly allows
	// anything else through AllowExternalBind.
	DefaultListenAddr = "127.0.0.1:0"

	// DefaultCanaryBody is the fixed response the local listener returns. It
	// carries no information and never reflects input.
	DefaultCanaryBody = "ok"

	// DefaultMaxBodyBytes caps how much of an inbound body is retained.
	DefaultMaxBodyBytes int64 = 8 << 10
	// DefaultMaxHeaders caps how many request header keys are retained.
	DefaultMaxHeaders = 64
	// DefaultMaxInteractions caps how many interactions are retained; the
	// oldest are evicted first so a flooded listener cannot exhaust memory.
	DefaultMaxInteractions = 4096

	// MaxAllowedBodyBytes is the hard ceiling Config.MaxBodyBytes may not
	// exceed. A callback body is a marker or a short exfil string, not a file.
	MaxAllowedBodyBytes int64 = 1 << 20
	// MaxAllowedInteractions is the hard ceiling Config.MaxInteractions may not
	// exceed.
	MaxAllowedInteractions = 100_000
	// MaxAllowedHeaders is the hard ceiling Config.MaxHeaders may not exceed.
	MaxAllowedHeaders = 512

	maxHeaderValueBytes = 1 << 10
	tokenBytes          = 13 // 104 bits, base32-encoded to 21 DNS-safe chars
)

// ErrClosed is returned by operations that need a live manager (Poll,
// WaitForHit) after Close.
var ErrClosed = errors.New("oast: manager is closed")

// Mode selects where callback URLs point and where interactions come from.
type Mode string

const (
	// ModeLocal uses the built-in HTTP listener. It needs no third-party
	// account and no outbound dependency, which is the right default for a
	// local-first tool.
	ModeLocal Mode = "local"
	// ModeInteractsh uses an interactsh-compatible server: register once,
	// generate per-probe subdomains, then Poll for interactions.
	ModeInteractsh Mode = "interactsh"
)

// Config configures a Manager. The zero value is a working local listener on
// an ephemeral loopback port.
type Config struct {
	// Mode is ModeLocal (default) or ModeInteractsh.
	Mode Mode

	// ListenAddr is the local listener address (host:port). Default
	// DefaultListenAddr. A non-loopback address (including an empty host, which
	// binds every interface) requires AllowExternalBind.
	ListenAddr string
	// AllowExternalBind acknowledges that ListenAddr exposes the listener
	// beyond loopback. It is never implied.
	AllowExternalBind bool

	// PublicBaseURL is the URL a target can actually reach when the listener is
	// published through a tunnel or reverse proxy (for example
	// https://abc.example-tunnel.net). Empty means the listener's own address
	// is used, which is only reachable from the scanning host.
	PublicBaseURL string

	// CanaryBody is the constant response body of the local listener.
	CanaryBody string

	// MaxBodyBytes, MaxHeaders and MaxInteractions bound retained data.
	MaxBodyBytes    int64
	MaxHeaders      int
	MaxInteractions int

	// TrustProxyHeaders makes RecordHit trust X-Forwarded-For / X-Real-IP for
	// the source IP. Off by default: those headers are attacker-controlled on a
	// listener reachable from the internet, so RemoteAddr is the honest source
	// unless a trusted proxy is known to rewrite them.
	TrustProxyHeaders bool

	// InteractshServer is the base URL of an interactsh-compatible server,
	// e.g. https://oast.example.net. Required in ModeInteractsh; there is no
	// built-in public default.
	InteractshServer string
	// InteractshToken is sent as the Authorization header when the server
	// requires a registration token. Optional.
	InteractshToken string

	// HTTPClient is used for interactsh registration and polling. Defaults to a
	// client with a 30s timeout that refuses redirects.
	HTTPClient *http.Client
	// Logger receives rare lifecycle warnings. Optional.
	Logger *slog.Logger
	// Now overrides the clock; tests only.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Mode == "" {
		c.Mode = ModeLocal
	}
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}
	if c.CanaryBody == "" {
		c.CanaryBody = DefaultCanaryBody
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.MaxHeaders <= 0 {
		c.MaxHeaders = DefaultMaxHeaders
	}
	if c.MaxInteractions <= 0 {
		c.MaxInteractions = DefaultMaxInteractions
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.HTTPClient == nil {
		c.HTTPClient = defaultHTTPClient()
	}
	return c
}

func (c Config) validate() error {
	switch c.Mode {
	case ModeLocal:
		if err := validateListenAddr(c.ListenAddr, c.AllowExternalBind); err != nil {
			return err
		}
	case ModeInteractsh:
		if _, err := parseServerURL(c.InteractshServer); err != nil {
			return err
		}
	default:
		return fmt.Errorf("oast: unknown mode %q (want %q or %q)", c.Mode, ModeLocal, ModeInteractsh)
	}
	if c.PublicBaseURL != "" {
		if _, err := parseServerURL(c.PublicBaseURL); err != nil {
			return fmt.Errorf("oast: public base URL: %w", err)
		}
	}
	if c.MaxBodyBytes <= 0 || c.MaxBodyBytes > MaxAllowedBodyBytes {
		return fmt.Errorf("oast: max body bytes must be within 1..%d", MaxAllowedBodyBytes)
	}
	if c.MaxHeaders <= 0 || c.MaxHeaders > MaxAllowedHeaders {
		return fmt.Errorf("oast: max headers must be within 1..%d", MaxAllowedHeaders)
	}
	if c.MaxInteractions <= 0 || c.MaxInteractions > MaxAllowedInteractions {
		return fmt.Errorf("oast: max interactions must be within 1..%d", MaxAllowedInteractions)
	}
	return nil
}

// Hit is one inbound out-of-band interaction as captured by a listener or a
// bridge, before it is correlated with a probe.
type Hit struct {
	// Protocol is "http", "https", "dns", "smtp", ... Default "http".
	Protocol string
	Method   string
	// Host is the request host, or the queried name for a DNS-style hit.
	Host string
	Path string
	// Query is the raw query string, without the leading '?'.
	Query   string
	QType   string
	Headers http.Header
	Body    []byte
	// Truncated reports whether Body was cut to Config.MaxBodyBytes.
	Truncated bool
	// RemoteAddr is the observed peer address ("ip:port").
	RemoteAddr string
	// Source labels where the hit came from: "local", "interactsh" or
	// "bridge". Empty means "bridge".
	Source     string
	ReceivedAt time.Time
}

// Interaction is a recorded, correlated out-of-band callback. It is evidence,
// never a verdict.
type Interaction struct {
	// Token is the correlation token the manager issued for this probe. Empty
	// when the hit did not match any issued token (it is still recorded).
	Token string `json:"token,omitempty"`
	// ProbeID and Tag echo the caller's callback identity.
	ProbeID string `json:"probe_id,omitempty"`
	Tag     string `json:"tag,omitempty"`

	Protocol string              `json:"protocol"`
	Method   string              `json:"method,omitempty"`
	Host     string              `json:"host,omitempty"`
	Path     string              `json:"path,omitempty"`
	Query    string              `json:"query,omitempty"`
	Headers  map[string][]string `json:"headers,omitempty"`
	Body     string              `json:"body,omitempty"`
	// Truncated reports whether Body hit the configured cap.
	Truncated bool `json:"truncated,omitempty"`

	// RemoteIP is the callback source address, without the port.
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`

	ReceivedAt time.Time `json:"received_at"`
	// Source is "local", "interactsh" or "bridge".
	Source string `json:"source"`

	// UniqueID, QType, RawRequest and RawResponse carry what an external OAST
	// server reported, when it reported anything.
	UniqueID    string `json:"unique_id,omitempty"`
	QType       string `json:"qtype,omitempty"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`

	// fingerprintKey is the external server's dedupe fingerprint, kept so the
	// dedupe set can be rebuilt from retained interactions. Not exported and
	// not serialized: it is bookkeeping, not evidence.
	fingerprintKey string
}

// Client is the transport-neutral OAST surface scan engines use. The concrete
// implementation is *Manager.
type Client interface {
	// GeneratePayloadURL returns a callback URL carrying a correlation token
	// unique to (probeID, tag) and that token. Repeated calls with the same
	// (probeID, tag) return the same token, so a probe's retries and its
	// pending verification all correlate to one identity.
	GeneratePayloadURL(probeID, tag string) (url string, token string)
	// RecordHit stores an inbound interaction. The bool reports whether it
	// correlated with an issued token.
	RecordHit(hit Hit) (Interaction, bool)
	// Poll fetches new interactions from an external OAST server. Local mode
	// has nothing to fetch and returns (0, nil). The int is how many new
	// interactions were recorded.
	Poll(ctx context.Context) (int, error)
	// HasHit returns the earliest interaction recorded for token.
	HasHit(token string) (Interaction, bool)
	// WaitForHit blocks until token has a hit, the timeout elapses (<= 0 waits
	// for the context), or ctx is done.
	WaitForHit(ctx context.Context, token string, timeout time.Duration) (Interaction, bool)

	// Interactions returns every retained interaction, oldest first.
	Interactions() []Interaction
	// InteractionsFor returns every retained interaction for token.
	InteractionsFor(token string) []Interaction
	// BaseURL is the local listener base or the configured OAST server.
	BaseURL() string
	// Close stops the listener. It is idempotent.
	Close() error
}

// probe is one issued callback identity.
type probe struct {
	token     string
	probeID   string
	tag       string
	createdAt time.Time
}

// interactionRing retains the newest max interactions without shifting the
// whole window on every callback. A listener exposed to the internet can be
// flooded; an O(n) copy per hit would turn that flood into a CPU amplifier.
type interactionRing struct {
	buf  []Interaction
	head int // index of the oldest interaction once buf is full
}

func newInteractionRing(max int) interactionRing {
	return interactionRing{buf: make([]Interaction, 0, max)}
}

func (r *interactionRing) len() int { return len(r.buf) }

// at returns the i-th oldest interaction.
func (r *interactionRing) at(i int) Interaction {
	if len(r.buf) < cap(r.buf) {
		return r.buf[i]
	}
	return r.buf[(r.head+i)%len(r.buf)]
}

// push stores it and reports whether the oldest interaction was evicted.
func (r *interactionRing) push(it Interaction) bool {
	if len(r.buf) < cap(r.buf) {
		r.buf = append(r.buf, it)
		return false
	}
	r.buf[r.head] = it
	r.head = (r.head + 1) % len(r.buf)
	return true
}

// Manager is the default Client implementation.
type Manager struct {
	cfg  Config
	mode Mode
	log  *slog.Logger
	now  func() time.Time

	mu           sync.Mutex
	probes       map[string]*probe // key: probeKey(probeID, tag)
	tokens       map[string]*probe // key: lowercased token
	interactions interactionRing
	seen         map[string]struct{} // dedupe fingerprints from external polls
	dropped      uint64
	changed      chan struct{} // closed and replaced on every new interaction

	pollMu sync.Mutex // serializes external polls

	listener net.Listener
	server   *http.Server
	baseURL  string

	httpClient   *http.Client
	serverURL    string
	serverParsed *url.URL
	correlation  string
	secretKey    *rsa.PrivateKey
	secretKeyB64 string

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

var _ Client = (*Manager)(nil)

// New validates cfg and starts the selected mode. In interactsh mode it
// registers immediately, so a bad server, a rejected registration or a
// redirect surfaces here rather than on the first probe.
func New(ctx context.Context, cfg Config) (*Manager, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:          cfg,
		mode:         cfg.Mode,
		log:          cfg.Logger,
		now:          cfg.Now,
		probes:       make(map[string]*probe),
		tokens:       make(map[string]*probe),
		interactions: newInteractionRing(cfg.MaxInteractions),
		seen:         make(map[string]struct{}),
		changed:      make(chan struct{}),
		closed:       make(chan struct{}),
		httpClient:   cfg.HTTPClient,
	}
	switch cfg.Mode {
	case ModeLocal:
		if err := m.startLocal(ctx); err != nil {
			return nil, err
		}
	case ModeInteractsh:
		if err := m.startInteractsh(ctx); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("oast: unknown mode %q", cfg.Mode)
	}
	return m, nil
}

func (m *Manager) startLocal(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("oast: listen on %s: %w", m.cfg.ListenAddr, err)
	}
	m.listener = ln
	if m.cfg.PublicBaseURL != "" {
		m.baseURL = strings.TrimRight(m.cfg.PublicBaseURL, "/")
	} else {
		m.baseURL = "http://" + displayAddr(ln.Addr())
	}
	m.server = &http.Server{
		Handler:           m.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		if serr := m.server.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) && m.log != nil {
			m.log.Warn("oast: local listener stopped", "addr", m.cfg.ListenAddr, "err", serr)
		}
	}()
	return nil
}

func (m *Manager) startInteractsh(ctx context.Context) error {
	u, err := parseServerURL(m.cfg.InteractshServer)
	if err != nil {
		return err
	}
	m.serverParsed = u
	m.serverURL = strings.TrimRight(m.cfg.InteractshServer, "/")
	if err := m.register(ctx); err != nil {
		return err
	}
	m.baseURL = m.serverURL
	return nil
}

// ---------------------------------------------------------------- payloads

// GeneratePayloadURL implements Client. The token is random (104 bits) and
// DNS-safe, so it works as a path segment in local mode and as a subdomain
// label in interactsh mode.
func (m *Manager) GeneratePayloadURL(probeID, tag string) (string, string) {
	probeID = strings.TrimSpace(probeID)
	tag = strings.TrimSpace(tag)
	fresh := newToken()

	m.mu.Lock()
	var p *probe
	if probeID == "" {
		// An unnamed probe is a one-off: give it its own identity rather than
		// letting every anonymous caller share one token.
		p = &probe{token: fresh, tag: tag, createdAt: m.now()}
		m.probes["anon:"+fresh] = p
	} else {
		key := probeKey(probeID, tag)
		p = m.probes[key]
		if p == nil {
			p = &probe{token: fresh, probeID: probeID, tag: tag, createdAt: m.now()}
			m.probes[key] = p
		}
	}
	m.tokens[p.token] = p
	base := m.baseURL
	m.mu.Unlock()

	switch m.mode {
	case ModeInteractsh:
		return m.interactshURL(p.token), p.token
	default:
		return strings.TrimRight(base, "/") + "/p/" + p.token, p.token
	}
}

func (m *Manager) interactshURL(token string) string {
	u := m.serverParsed
	path := strings.TrimRight(u.Path, "/")
	if path == "/" {
		path = ""
	}
	return fmt.Sprintf("%s://%s%s/", u.Scheme, token+"."+u.Host, path)
}

func probeKey(probeID, tag string) string {
	return probeID + "\x00" + tag
}

var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newToken returns a lowercase base32 token (letters a-z and digits 2-7): a
// valid DNS label as well as a valid URL path segment.
func newToken() string {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand guarantees success or process panic; there is no
		// meaningful fallback for a correlation token.
		panic("oast: crypto/rand failed: " + err.Error())
	}
	return strings.ToLower(tokenEncoding.EncodeToString(buf))
}

// ----------------------------------------------------------------- listener

// Handler returns the HTTP handler that records hits and serves the canary. It
// is exported so an operator can mount the same listener behind an existing
// server or tunnel. In interactsh mode it answers 404: there is no local
// listener, and a bridge should call RecordHit instead.
func (m *Manager) Handler() http.Handler {
	if m.mode != ModeLocal {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
	return http.HandlerFunc(m.serveHTTP)
}

func (m *Manager) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, truncated, err := readBounded(r.Body, m.cfg.MaxBodyBytes)
	if r.Body != nil {
		_ = r.Body.Close()
	}
	if err != nil && m.log != nil {
		m.log.Warn("oast: read callback body", "err", err)
	}
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	m.RecordHit(Hit{
		Protocol:   proto,
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Headers:    r.Header,
		Body:       body,
		Truncated:  truncated,
		RemoteAddr: r.RemoteAddr,
		Source:     string(ModeLocal),
		ReceivedAt: m.now(),
	})

	// Fixed, inert canary. Nothing from the request is written back: a
	// collaborator that echoed its input would be an injection source itself.
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, m.cfg.CanaryBody)
}

// RecordHit implements Client. Hits that match no issued token are still
// recorded (with an empty Token): the traffic is real evidence, and hiding it
// would make a noisy target look quiet.
func (m *Manager) RecordHit(hit Hit) (Interaction, bool) {
	it := m.interactionFromHit(hit)
	recorded, matched, _ := m.record(it, "")
	return recorded, matched
}

func (m *Manager) interactionFromHit(h Hit) Interaction {
	at := h.ReceivedAt
	if at.IsZero() {
		at = m.now()
	}
	src := strings.TrimSpace(h.Source)
	if src == "" {
		src = "bridge"
	}
	proto := strings.ToLower(strings.TrimSpace(h.Protocol))
	if proto == "" {
		proto = "http"
	}
	body, truncated := h.Body, h.Truncated
	// A bridge can hand over anything; bound it here too, so RecordHit is
	// never a way around Config.MaxBodyBytes.
	if int64(len(body)) > m.cfg.MaxBodyBytes {
		body = body[:m.cfg.MaxBodyBytes]
		truncated = true
	}
	it := Interaction{
		Protocol:   proto,
		Method:     strings.ToUpper(strings.TrimSpace(h.Method)),
		Host:       strings.TrimSpace(h.Host),
		Path:       h.Path,
		Query:      strings.TrimPrefix(h.Query, "?"),
		QType:      strings.TrimSpace(h.QType),
		Headers:    cloneHeaders(h.Headers, m.cfg.MaxHeaders),
		Body:       string(body),
		Truncated:  truncated,
		RemoteAddr: strings.TrimSpace(h.RemoteAddr),
		RemoteIP:   remoteIP(h.RemoteAddr),
		ReceivedAt: at.UTC(),
		Source:     src,
	}
	if m.cfg.TrustProxyHeaders {
		if ip := forwardedIP(h.Headers); ip != "" {
			it.RemoteIP = ip
		}
	}
	return it
}

// record appends a normalized interaction, correlates it with an issued token
// and bounds retention. dedupe, when non-empty, suppresses a repeated external
// interaction (servers re-deliver until acknowledged). added reports whether
// the interaction was actually stored; matched whether it belongs to an issued
// probe.
func (m *Manager) record(it Interaction, dedupe string) (out Interaction, matched, added bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if dedupe != "" {
		if _, ok := m.seen[dedupe]; ok {
			return Interaction{}, false, false
		}
		m.seen[dedupe] = struct{}{}
		it.fingerprintKey = dedupe
	}
	if p, ok := m.matchTokenLocked(it); ok {
		it.Token = p.token
		it.ProbeID = p.probeID
		it.Tag = p.tag
		matched = true
	}
	if m.interactions.push(it) {
		m.dropped++
	}
	if len(m.seen) > 4*m.cfg.MaxInteractions {
		// The fingerprint set only needs to cover retained interactions;
		// rebuilding from what is still kept keeps it bounded too.
		m.seen = make(map[string]struct{}, m.interactions.len())
		for i := 0; i < m.interactions.len(); i++ {
			if fp := m.interactions.at(i).fingerprintKey; fp != "" {
				m.seen[fp] = struct{}{}
			}
		}
	}
	m.notifyLocked()
	return cloneInteraction(it), matched, true
}

func (m *Manager) notifyLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

// matchTokenLocked looks for an issued token in the hit: exact matches in the
// query, path or host labels first, then a subdomain prefix (interactsh appends
// a per-request nonce to the registered id).
func (m *Manager) matchTokenLocked(it Interaction) (*probe, bool) {
	for _, cand := range tokenCandidates(it) {
		if p := m.tokens[strings.ToLower(cand)]; p != nil {
			return p, true
		}
	}
	hosts := hostCandidates(it)
	for _, h := range hosts {
		for _, label := range strings.Split(h, ".") {
			if p := m.tokens[strings.ToLower(label)]; p != nil {
				return p, true
			}
		}
	}
	var best *probe
	for _, h := range hosts {
		for tok, p := range m.tokens {
			if !strings.HasPrefix(h, tok) {
				continue
			}
			if best == nil || len(tok) > len(best.token) {
				best = p
			}
		}
	}
	if best != nil {
		return best, true
	}
	return nil, false
}

func tokenCandidates(it Interaction) []string {
	var out []string
	if it.Query != "" {
		if q, err := url.ParseQuery(it.Query); err == nil {
			for _, key := range []string{"id", "token", "probe"} {
				if v := strings.TrimSpace(q.Get(key)); v != "" {
					out = append(out, v)
				}
			}
		}
	}
	for _, seg := range strings.Split(it.Path, "/") {
		if seg = strings.TrimSpace(seg); seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

func hostCandidates(it Interaction) []string {
	var out []string
	if h := hostWithoutPort(it.Host); h != "" {
		out = append(out, strings.ToLower(h))
	}
	if it.UniqueID != "" {
		if h := hostWithoutPort(it.UniqueID); h != "" {
			out = append(out, strings.ToLower(h))
		}
	}
	return out
}

// ------------------------------------------------------------------ queries

// HasHit returns the earliest interaction for token.
func (m *Manager) HasHit(token string) (Interaction, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Interaction{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var best Interaction
	found := false
	for i := 0; i < m.interactions.len(); i++ {
		it := m.interactions.at(i)
		if !strings.EqualFold(it.Token, token) {
			continue
		}
		if !found || it.ReceivedAt.Before(best.ReceivedAt) {
			best, found = it, true
		}
	}
	if !found {
		return Interaction{}, false
	}
	return cloneInteraction(best), true
}

// WaitForHit blocks until token has a hit, the timeout elapses (a timeout <= 0
// waits until ctx is done), or the manager is closed. It reacts to new
// interactions immediately: no polling interval, no arbitrary sleep.
func (m *Manager) WaitForHit(ctx context.Context, token string, timeout time.Duration) (Interaction, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Interaction{}, false
	}
	var deadline <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}
	for {
		if it, ok := m.HasHit(token); ok {
			return it, true
		}
		m.mu.Lock()
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return Interaction{}, false
		case <-deadline:
			return Interaction{}, false
		case <-m.closed:
			return Interaction{}, false
		case <-changed:
		}
	}
}

// Interactions returns every retained interaction, oldest first.
func (m *Manager) Interactions() []Interaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Interaction, 0, m.interactions.len())
	for i := 0; i < m.interactions.len(); i++ {
		out = append(out, cloneInteraction(m.interactions.at(i)))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ReceivedAt.Before(out[j].ReceivedAt) })
	return out
}

// InteractionsFor returns every retained interaction for token, oldest first.
func (m *Manager) InteractionsFor(token string) []Interaction {
	token = strings.TrimSpace(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Interaction
	for i := 0; i < m.interactions.len(); i++ {
		it := m.interactions.at(i)
		if strings.EqualFold(it.Token, token) {
			out = append(out, cloneInteraction(it))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ReceivedAt.Before(out[j].ReceivedAt) })
	return out
}

// Dropped reports how many interactions were evicted by MaxInteractions.
func (m *Manager) Dropped() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped
}

// BaseURL is the local listener base URL, or the configured OAST server.
func (m *Manager) BaseURL() string { return m.baseURL }

// Close stops the local listener (gracefully, for in-flight callbacks) and is
// idempotent.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		close(m.closed)
		if m.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := m.server.Shutdown(ctx); err != nil {
				m.closeErr = err
				_ = m.server.Close()
			}
		}
		if m.httpClient != nil {
			m.httpClient.CloseIdleConnections()
		}
	})
	return m.closeErr
}

// --------------------------------------------------------------- interactsh

type registrationResponse struct {
	Message       string `json:"message"`
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

type pollResponse struct {
	Data    []string `json:"data"`
	AESKey  string   `json:"aes_key"`
	TLDData []string `json:"tlddata"`
}

// interactshInteraction is the decrypted per-interaction payload the server
// publishes. Field names are the wire names, not Indago's.
type interactshInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	QType         string    `json:"q-type"`
	RawRequest    string    `json:"raw-request"`
	RawResponse   string    `json:"raw-response"`
	SMTPFrom      string    `json:"smtp-from"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

func (m *Manager) register(ctx context.Context) error {
	endpoint := m.serverURL + "/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("oast: interactsh register: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if tok := strings.TrimSpace(m.cfg.InteractshToken); tok != "" {
		req.Header.Set("Authorization", tok)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("oast: interactsh register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oast: interactsh register: server returned %s", resp.Status)
	}
	var rr registrationResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rr); err != nil {
		return fmt.Errorf("oast: interactsh register: decode response: %w", err)
	}
	if strings.TrimSpace(rr.CorrelationID) == "" || strings.TrimSpace(rr.SecretKey) == "" {
		return errors.New("oast: interactsh register: server returned an incomplete registration")
	}
	key, err := parseSecretKey(rr.SecretKey)
	if err != nil {
		return err
	}
	m.correlation = rr.CorrelationID
	m.secretKey = key
	m.secretKeyB64 = rr.SecretKey
	return nil
}

// Poll implements Client. Local mode has no remote queue and returns (0, nil).
func (m *Manager) Poll(ctx context.Context) (int, error) {
	select {
	case <-m.closed:
		return 0, ErrClosed
	default:
	}
	if m.mode != ModeInteractsh {
		return 0, nil
	}
	// One poll at a time: concurrent polls would race on dedupe and could
	// double-record the same server payload.
	m.pollMu.Lock()
	defer m.pollMu.Unlock()
	return m.pollInteractsh(ctx)
}

func (m *Manager) pollInteractsh(ctx context.Context) (int, error) {
	m.mu.Lock()
	correlation, secret, key := m.correlation, m.secretKeyB64, m.secretKey
	m.mu.Unlock()
	if correlation == "" || key == nil {
		return 0, errors.New("oast: interactsh: client is not registered")
	}

	q := url.Values{}
	q.Set("id", correlation)
	q.Set("secret", secret)
	endpoint := m.serverURL + "/poll?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("oast: interactsh poll: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("oast: interactsh poll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("oast: interactsh poll: server returned %s", resp.Status)
	}
	var pr pollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&pr); err != nil {
		return 0, fmt.Errorf("oast: interactsh poll: decode response: %w", err)
	}
	if len(pr.Data) == 0 {
		return 0, nil
	}
	aesKey, err := decryptAESKey(key, pr.AESKey)
	if err != nil {
		return 0, err
	}

	recorded := 0
	failures := 0
	var firstErr error
	for _, item := range pr.Data {
		plain, derr := decryptPayload(aesKey, item)
		if derr != nil {
			failures++
			if firstErr == nil {
				firstErr = derr
			}
			continue
		}
		var ii interactshInteraction
		if derr := json.Unmarshal(plain, &ii); derr != nil {
			failures++
			if firstErr == nil {
				firstErr = derr
			}
			continue
		}
		it := m.interactionFromInteractsh(ii)
		if _, _, added := m.record(it, ii.fingerprint()); added {
			recorded++
		}
	}
	if failures > 0 {
		return recorded, fmt.Errorf("oast: interactsh poll: %d of %d interactions could not be decoded: %w", failures, len(pr.Data), firstErr)
	}
	return recorded, nil
}

func (m *Manager) interactionFromInteractsh(ii interactshInteraction) Interaction {
	at := ii.Timestamp
	if at.IsZero() {
		at = m.now()
	}
	proto := strings.ToLower(strings.TrimSpace(ii.Protocol))
	if proto == "" {
		proto = "http"
	}
	host := strings.TrimSpace(ii.FullID)
	if host == "" {
		host = strings.TrimSpace(ii.UniqueID)
	}
	it := Interaction{
		Protocol:   proto,
		Host:       host,
		UniqueID:   strings.TrimSpace(ii.UniqueID),
		QType:      strings.TrimSpace(ii.QType),
		RemoteAddr: strings.TrimSpace(ii.RemoteAddress),
		RemoteIP:   remoteIP(ii.RemoteAddress),
		ReceivedAt: at.UTC(),
		Source:     string(ModeInteractsh),
	}
	if raw := ii.RawRequest; raw != "" {
		it.RawRequest = truncate(raw, int(m.cfg.MaxBodyBytes)+4096)
	}
	if raw := ii.RawResponse; raw != "" {
		it.RawResponse = truncate(raw, int(m.cfg.MaxBodyBytes)+4096)
	}
	if proto == "http" || proto == "https" {
		method, path, query, headers, body, truncated := parseRawRequest(it.RawRequest, m.cfg.MaxBodyBytes)
		it.Method = method
		it.Path = path
		it.Query = query
		it.Headers = cloneHeaders(http.Header(headers), m.cfg.MaxHeaders)
		it.Body = body
		it.Truncated = truncated
	}
	return it
}

// fingerprint identifies a server-side interaction so a re-delivered payload is
// recorded once.
func (ii interactshInteraction) fingerprint() string {
	h := sha256.New()
	for _, part := range []string{ii.Protocol, ii.UniqueID, ii.FullID, ii.RemoteAddress,
		ii.Timestamp.UTC().Format(time.RFC3339Nano), ii.RawRequest, ii.RawResponse} {
		_, _ = io.WriteString(h, part)
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// decryptAESKey unwraps the per-poll AES key with the registration private key.
// interactsh uses PKCS#1 v1.5; OAEP-SHA256 is accepted as a fallback for
// compatible servers.
func decryptAESKey(priv *rsa.PrivateKey, encoded string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("oast: interactsh poll: decode aes key: %w", err)
	}
	if len(ct) == 0 {
		return nil, errors.New("oast: interactsh poll: server returned an empty aes key")
	}
	if k, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ct); err == nil && len(k) > 0 {
		return k, nil
	}
	if k, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ct, nil); err == nil && len(k) > 0 {
		return k, nil
	}
	return nil, errors.New("oast: interactsh poll: cannot decrypt aes key")
}

// decryptPayload reverses interactsh's AES-CTR framing: base64(iv || ciphertext).
func decryptPayload(key []byte, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("oast: interactsh poll: decode interaction: %w", err)
	}
	if len(raw) <= aes.BlockSize {
		return nil, errors.New("oast: interactsh poll: interaction payload is too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("oast: interactsh poll: aes cipher: %w", err)
	}
	iv, body := raw[:aes.BlockSize], raw[aes.BlockSize:]
	out := make([]byte, len(body))
	cipher.NewCTR(block, iv).XORKeyStream(out, body)
	return out, nil
}

func parseSecretKey(encoded string) (*rsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("oast: interactsh register: decode secret key: %w", err)
		}
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("oast: interactsh register: secret key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if key, ok := parsed.(*rsa.PrivateKey); ok {
			return key, nil
		}
	}
	return nil, errors.New("oast: interactsh register: secret key is not an RSA private key")
}

// ------------------------------------------------------------------ helpers

func parseServerURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("oast: interactsh server URL is required (for example https://oast.example.net)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("oast: server URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("oast: server URL %q must be absolute http(s)", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("oast: server URL %q has no host", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("oast: server URL %q must not embed credentials", raw)
	}
	return u, nil
}

func validateListenAddr(addr string, allowExternal bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("oast: listen address %q must be host:port: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("oast: listen address %q has no port", addr)
	}
	if host == "" {
		if !allowExternal {
			return fmt.Errorf("oast: listen address %q binds every interface; set Config.AllowExternalBind to do that deliberately", addr)
		}
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if !allowExternal {
			return fmt.Errorf("oast: listen address %q is not loopback; set Config.AllowExternalBind to publish the listener deliberately", addr)
		}
		return nil
	}
	if ip.IsLoopback() {
		return nil
	}
	if !allowExternal {
		return fmt.Errorf("oast: listen address %q is not loopback; set Config.AllowExternalBind to publish the listener deliberately", addr)
	}
	return nil
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		// Registration and polling are fixed endpoints; a redirect is a
		// misconfiguration or an attempt to move the API token elsewhere.
		// Refuse it rather than follow.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func displayAddr(a net.Addr) string {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func readBounded(r io.Reader, max int64) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r, max+1))
	truncated := false
	if int64(len(buf)) > max {
		buf = buf[:max]
		truncated = true
	}
	return buf, truncated, err
}

func cloneHeaders(h http.Header, maxKeys int) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic when a cap drops keys
	if len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	out := make(map[string][]string, len(keys))
	for _, k := range keys {
		vals := make([]string, 0, len(h[k]))
		for _, v := range h[k] {
			vals = append(vals, truncate(v, maxHeaderValueBytes))
		}
		out[k] = vals
	}
	return out
}

func cloneInteraction(it Interaction) Interaction {
	if it.Headers != nil {
		cp := make(map[string][]string, len(it.Headers))
		for k, v := range it.Headers {
			cp[k] = append([]string(nil), v...)
		}
		it.Headers = cp
	}
	return it
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

func remoteIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

func forwardedIP(h http.Header) string {
	if h == nil {
		return ""
	}
	for _, raw := range []string{
		strings.TrimSpace(strings.Split(h.Get("X-Forwarded-For"), ",")[0]),
		strings.TrimSpace(h.Get("X-Real-IP")),
	} {
		if raw == "" {
			continue
		}
		// Only accept something that is actually an IP: a proxy or a target can
		// put arbitrary text in these headers, and evidence should not record
		// attacker-chosen junk as a source address.
		if ip := net.ParseIP(remoteIP(raw)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func hostWithoutPort(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.Trim(h, "[]"), ".")
}

// parseRawRequest extracts what a scan engine cares about from the raw request
// text an interactsh server reports.
func parseRawRequest(raw string, maxBody int64) (method, path, query string, headers map[string][]string, body string, truncated bool) {
	if raw == "" {
		return "", "", "", nil, "", false
	}
	head := raw
	rest := ""
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head, rest = raw[:i], raw[i+4:]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, rest = raw[:i], raw[i+2:]
	}
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return "", "", "", nil, "", false
	}
	parts := strings.SplitN(strings.TrimRight(lines[0], "\r"), " ", 3)
	if len(parts) >= 2 {
		method = strings.ToUpper(parts[0])
		target := parts[1]
		if u, err := url.Parse(target); err == nil && (u.Path != "" || u.RawQuery != "") {
			path, query = u.Path, u.RawQuery
		} else {
			if i := strings.Index(target, "?"); i >= 0 {
				path, query = target[:i], target[i+1:]
			} else {
				path = target
			}
		}
	}
	if len(lines) > 1 {
		headers = make(map[string][]string)
		for _, line := range lines[1:] {
			line = strings.TrimRight(line, "\r")
			if line == "" {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			headers[http.CanonicalHeaderKey(k)] = append(headers[http.CanonicalHeaderKey(k)], truncate(strings.TrimSpace(v), maxHeaderValueBytes))
		}
		if len(headers) == 0 {
			headers = nil
		}
	}
	body = truncate(rest, int(maxBody))
	truncated = int64(len(rest)) > maxBody
	return method, path, query, headers, body, truncated
}
