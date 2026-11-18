// Package scopeproxy is a loopback-only HTTP forward proxy that refuses to
// connect to any host:port its caller did not explicitly permit.
//
// Why it exists. Indago's browser scope gate aborts out-of-scope *requests*
// before network dispatch, but Chromium still opens a TCP connection — and, for
// https, sends a TLS ClientHello carrying the name in the SNI — to a navigation
// target before that abort can happen (docs/browser-scope-boundary.md, "Known
// gap: connections"). A proxy the browser cannot bypass moves the decision one
// layer earlier: the browser connects to 127.0.0.1, the proxy decides, and only
// an allowed authority is ever dialled. This package is that primitive and
// nothing else; it is intentionally independent of internal/browser and
// internal/domain so it can be wired in (or tested) without touching either.
//
// Deliberate boundaries:
//   - Loopback listener only. New refuses to serve anything else.
//   - Fail closed. A missing policy, a panicking policy, a malformed authority,
//     an unsupported request form, an unresolvable name and a failed dial all
//     deny. Denial happens BEFORE any DNS query or TCP connect for that
//     destination, so a refused request cannot leak a name either.
//   - DNS is gated. The proxy resolves a name itself, after the policy says
//     yes, and dials the literal address it resolved (never re-resolving at
//     dial time), so a policy cannot be satisfied by one answer and connected
//     to another.
//   - Operator-proxy chaining is refused, not silently ignored
//     (ErrUpstreamProxyUnsupported): this process cannot vouch for DNS another
//     proxy performs, so the combination is not offered as if it were verified.
//   - No TLS interception. https is CONNECT-tunnelled end to end, so the proxy
//     sees no plaintext, no credentials and no cookies.
//   - It is not an OS-wide firewall. It constrains only processes configured to
//     use it; see ChromiumArgs for the switches that point Chromium at it.
package scopeproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Errors returned by New and the request path.
var (
	// ErrNoPolicy is returned when Config.Policy is nil. A proxy without a
	// policy would be an open relay, so its absence is a construction error
	// rather than "allow everything".
	ErrNoPolicy = errors.New("scopeproxy: a policy is required (fail closed)")
	// ErrNonLoopbackListener is returned when the listener is not bound to a
	// loopback address. The proxy must never be reachable from the network.
	ErrNonLoopbackListener = errors.New("scopeproxy: the listener must be bound to a loopback address")
	// ErrUpstreamProxyUnsupported is returned when Config.UpstreamProxy is set.
	//
	// Chaining is refused on purpose. The scope decision would still be made
	// here (the CONNECT authority or absolute-form target is checked before
	// anything is dialled), but the DESTINATION NAME would then be resolved by
	// the operator's proxy, on the operator's host, outside this process. That
	// means this package can no longer promise "the name that was allowed is
	// the only name ever looked up", and it cannot apply PermitAddress to the
	// answer. Rather than ship a mode whose DNS guarantee is unverifiable, the
	// combination fails closed with this error until a separate, explicitly
	// validated design exists.
	ErrUpstreamProxyUnsupported = errors.New("scopeproxy: operator-proxy chaining is not supported: DNS for the destination would be performed by the upstream proxy, outside this process, so the DNS gate and PermitAddress cannot be guaranteed; run the operator proxy as the only egress path or use a direct connection")
)

// Audit event kinds and denial reasons. They are stable strings so a caller can
// assert on them (and so evidence can record why a destination was refused).
const (
	KindConnect = "connect"
	KindForward = "forward"
)

const (
	ReasonAllowed            = "allowed"
	ReasonPolicyDenied       = "policy_denied"
	ReasonPolicyPanic        = "policy_panic"
	ReasonMalformedTarget    = "malformed_target"
	ReasonOriginForm         = "origin_form"
	ReasonHTTPSAbsoluteForm  = "https_absolute_form"
	ReasonAuthorityMismatch  = "authority_mismatch"
	ReasonResolveFailed      = "resolve_failed"
	ReasonNoPermittedAddress = "no_permitted_address"
	ReasonDialFailed         = "dial_failed"
	ReasonConnectionLimit    = "connection_limit"
	ReasonDialTargetMismatch = "dial_target_mismatch"
)

// Policy decides whether a destination may be contacted. host is lower-case
// (IPv6 unbracketed) and port is concrete (a default port is already applied),
// so the policy never has to guess. A nil Policy is a construction error, and a
// Policy that panics denies (see policyAllows).
type Policy interface {
	Permit(host string, port int) bool
}

// PolicyFunc adapts a function to Policy. A nil PolicyFunc denies everything.
type PolicyFunc func(host string, port int) bool

// Permit implements Policy.
func (f PolicyFunc) Permit(host string, port int) bool { return f != nil && f(host, port) }

// Resolver is the DNS lookup this proxy performs, and the only one it performs.
// *net.Resolver satisfies it; tests inject a recording implementation to prove
// that a denied destination is never looked up.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Dialer is the TCP dial this proxy performs. *net.Dialer satisfies it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Event is one audited proxy decision. Events are emitted for allowed and
// denied requests alike, before any connection is made for the former.
type Event struct {
	At        time.Time
	Kind      string
	Authority string // the bytes the client sent
	Host      string // validated, lower-case ("" when unparseable)
	Port      int
	Allowed   bool
	Reason    string
}

// Config configures a Server.
type Config struct {
	// Policy is required. It is the allowlist; everything it does not permit
	// is denied.
	Policy Policy
	// ListenAddr is where the proxy listens. It must resolve to a loopback
	// address; the default is "127.0.0.1:0" (an ephemeral port).
	ListenAddr string
	// Resolver performs DNS. nil uses net.DefaultResolver. It is called only
	// after the policy allows an authority.
	Resolver Resolver
	// Dialer performs the TCP dial. nil uses a net.Dialer with DialTimeout.
	Dialer Dialer
	// PermitAddress, when non-nil, is applied to every resolved address (and to
	// literal IP destinations) before dialling. It is the hook for an IP-level
	// policy such as "never contact link-local/private ranges"; an address it
	// refuses is skipped, and if no address survives the dial fails closed.
	PermitAddress func(net.IP) bool
	// Observer, when non-nil, receives every decision synchronously. It must be
	// fast and must not block; it is for logging/evidence, never for policy.
	Observer func(Event)
	// UpstreamProxy is refused: see ErrUpstreamProxyUnsupported. It exists so an
	// attempt to combine the two is an explicit error, not a silently ignored
	// field.
	UpstreamProxy string
	// MaxConnections bounds concurrently served requests/tunnels (default 64).
	// Beyond it a request is refused with 503 rather than queued.
	MaxConnections int
	// HeaderTimeout bounds reading a request header (default 10s).
	HeaderTimeout time.Duration
	// DialTimeout bounds one dial (default 10s).
	DialTimeout time.Duration
	// TunnelTimeout bounds a CONNECT tunnel's whole lifetime (default 10m). A
	// tunnel is closed when it elapses even if active: an unbounded tunnel is a
	// resource leak, and Chromium reconnects its own streams.
	TunnelTimeout time.Duration
	// IdleTimeout bounds an idle keep-alive connection on the forward path
	// (default 60s).
	IdleTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:0"
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 64
	}
	if c.HeaderTimeout <= 0 {
		c.HeaderTimeout = 10 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.TunnelTimeout <= 0 {
		c.TunnelTimeout = 10 * time.Minute
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 60 * time.Second
	}
	return c
}

// Stats is a snapshot of the proxy's counters.
type Stats struct {
	Requests  int64 // requests handled (both kinds)
	Allowed   int64 // destinations the policy permitted
	Denied    int64 // destinations refused for any reason
	Tunnels   int64 // CONNECT tunnels established
	Forwarded int64 // absolute-form requests forwarded to an origin
	Active    int64 // requests/tunnels in flight
}

// Server is the local scope proxy. It is safe for concurrent use.
type Server struct {
	cfg Config
	ln  net.Listener
	srv *http.Server
	tr  *http.Transport
	log *log.Logger

	requests, allowed, denied, tunnelCount, forwarded atomic.Int64
	active                                            atomic.Int64

	mu          sync.Mutex
	liveTunnels map[net.Conn]struct{}
	closed      bool
}

// New binds the loopback listener, starts serving, and returns the proxy. The
// listener is bound here (not on first request) so a caller can hand the URL to
// a browser with no window in which the browser could miss it.
func New(cfg Config) (*Server, error) {
	if cfg.Policy == nil {
		return nil, ErrNoPolicy
	}
	if strings.TrimSpace(cfg.UpstreamProxy) != "" {
		return nil, ErrUpstreamProxyUnsupported
	}
	cfg = cfg.withDefaults()
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{Timeout: cfg.DialTimeout}
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("scopeproxy: listen: %w", err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.IP == nil || !addr.IP.IsLoopback() {
		_ = ln.Close()
		return nil, fmt.Errorf("%w (got %s)", ErrNonLoopbackListener, ln.Addr())
	}

	s := &Server{
		cfg:         cfg,
		ln:          ln,
		log:         log.New(io.Discard, "", 0),
		liveTunnels: make(map[net.Conn]struct{}),
	}
	// No proxy of our own, no transparent decompression (the origin's bytes
	// must reach the browser unchanged), and every dial goes through the
	// validated-target check in dialFromContext.
	s.tr = &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     cfg.IdleTimeout,
		DialContext:         s.dialFromContext,
	}
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: cfg.HeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0), // a malformed request is denied by policy, not logged as noise
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Only reachable after an unexpected listener failure. Requests
			// then fail closed (no listener), which is the safe direction.
			s.log.Printf("scopeproxy: serve stopped: %v", err)
		}
	}()
	return s, nil
}

// Addr is the bound listener address (a loopback IP and port).
func (s *Server) Addr() string { return s.ln.Addr().String() }

// ProxyURL is the value to hand a browser (and ChromiumArgs): the HTTP proxy
// URL for this listener.
func (s *Server) ProxyURL() string { return "http://" + s.ln.Addr().String() }

// Stats returns a counter snapshot.
func (s *Server) Stats() Stats {
	return Stats{
		Requests:  s.requests.Load(),
		Allowed:   s.allowed.Load(),
		Denied:    s.denied.Load(),
		Tunnels:   s.tunnelCount.Load(),
		Forwarded: s.forwarded.Load(),
		Active:    s.active.Load(),
	}
}

// Close stops accepting, closes active tunnels, and waits for the listener.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	tunnels := make([]net.Conn, 0, len(s.liveTunnels))
	for c := range s.liveTunnels {
		tunnels = append(tunnels, c)
	}
	s.mu.Unlock()

	for _, c := range tunnels {
		_ = c.Close()
	}
	err := s.srv.Close()
	s.tr.CloseIdleConnections()
	return err
}

func (s *Server) emit(ev Event) {
	// The authority field is client-controlled bytes. An event ends up in logs
	// and evidence, so bound it and strip control characters: a refusal must not
	// be able to forge a log line or bloat a record.
	ev.Authority = sanitizeForAudit(ev.Authority)
	if s.cfg.Observer != nil {
		s.cfg.Observer(ev)
	}
}

// maxAuditedAuthorityBytes bounds the client-supplied authority kept in an
// audit event (the parser's own limit plus room for a rejected shape).
const maxAuditedAuthorityBytes = 512

func sanitizeForAudit(raw string) string {
	if len(raw) > maxAuditedAuthorityBytes {
		raw = raw[:maxAuditedAuthorityBytes]
	}
	b := []byte(raw)
	for i := 0; i < len(b); i++ {
		if b[i] <= 0x20 || b[i] == 0x7f {
			b[i] = '?'
		}
	}
	return string(b)
}

// record counts and audits one decision. allowed is the single source of truth
// for the counters, so a denial cannot be counted as anything else.
func (s *Server) record(kind, raw string, a authority, allowed bool, reason string) {
	ev := Event{At: time.Now(), Kind: kind, Authority: raw, Host: a.host, Port: a.port, Allowed: allowed, Reason: reason}
	if allowed {
		s.allowed.Add(1)
	} else {
		s.denied.Add(1)
	}
	s.emit(ev)
}

// recordDialFailure audits an allowed destination whose connection could not be
// established. It counts as a denial: nothing was reached through this proxy.
func (s *Server) recordDialFailure(kind, raw string, a authority, reason string) {
	s.denied.Add(1)
	s.emit(Event{At: time.Now(), Kind: kind, Authority: raw, Host: a.host, Port: a.port, Allowed: false, Reason: reason})
}

// denyRecorded audits a request refused before a parseable authority existed.
func (s *Server) denyUnparsed(kind, raw, reason string) {
	s.denied.Add(1)
	s.emit(Event{At: time.Now(), Kind: kind, Authority: raw, Allowed: false, Reason: reason})
}

// policyAllows applies the policy and fails closed on a panic. A policy is
// caller code; a bug in it must deny this request, not take the proxy down or
// let the request through.
func (s *Server) policyAllows(a authority) (allowed bool, reason string) {
	defer func() {
		if r := recover(); r != nil {
			allowed, reason = false, ReasonPolicyPanic
		}
	}()
	if s.cfg.Policy.Permit(a.host, a.port) {
		return true, ReasonAllowed
	}
	return false, ReasonPolicyDenied
}

// ServeHTTP implements http.Handler. Every path through it either denies
// without touching the network or dials exactly the authority that was checked.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	n := s.active.Add(1)
	defer s.active.Add(-1)
	if n > int64(s.cfg.MaxConnections) {
		s.denyUnparsed(kindOf(r), r.RequestURI, ReasonConnectionLimit)
		deny(w, http.StatusServiceUnavailable, ReasonConnectionLimit)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleForward(w, r)
}

func kindOf(r *http.Request) string {
	if r.Method == http.MethodConnect {
		return KindConnect
	}
	return KindForward
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	raw := r.RequestURI
	// net/http fills r.Host for authority-form; a disagreement means the two
	// readings of the same bytes differ, so there is no single authority to
	// authorize.
	if r.Host != "" && r.Host != raw {
		s.denyUnparsed(KindConnect, raw, ReasonAuthorityMismatch)
		deny(w, http.StatusBadRequest, ReasonAuthorityMismatch)
		return
	}
	// CONNECT carries no scheme, so a port is mandatory: a default would have to
	// assume 443 for every method that happens to be CONNECT.
	a, err := parseAuthority(raw, 0)
	if err != nil {
		s.denyUnparsed(KindConnect, raw, ReasonMalformedTarget)
		deny(w, http.StatusBadRequest, ReasonMalformedTarget)
		return
	}
	allowed, reason := s.policyAllows(a)
	s.record(KindConnect, raw, a, allowed, reason)
	if !allowed {
		deny(w, http.StatusForbidden, reason)
		return
	}

	ctx := r.Context()
	up, err := s.dialValidated(ctx, a)
	if err != nil {
		s.recordDialFailure(KindConnect, raw, a, dialReason(err))
		deny(w, http.StatusBadGateway, dialReason(err))
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		deny(w, http.StatusInternalServerError, "hijack_unsupported")
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	s.mu.Lock()
	if s.closed {
		// Close began between the handler entry and the hijack: the server's
		// own Close no longer tracks a hijacked connection, so it must be
		// closed here rather than left until TunnelTimeout.
		s.mu.Unlock()
		_ = client.Close()
		_ = up.Close()
		return
	}
	s.liveTunnels[client] = struct{}{}
	s.mu.Unlock()
	s.tunnelCount.Add(1)
	defer func() {
		s.mu.Lock()
		delete(s.liveTunnels, client)
		s.mu.Unlock()
		_ = client.Close()
		_ = up.Close()
	}()

	deadline := time.Now().Add(s.cfg.TunnelTimeout)
	_ = client.SetDeadline(deadline)
	_ = up.SetDeadline(deadline)

	// The tunnel response is written only now: the policy allowed this authority
	// and the upstream connection exists, so a client never receives a 200 for a
	// destination that was neither authorized nor reachable.
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// One direction carries the bytes net/http already buffered (brw) and then
	// the rest of the client stream; the other carries the destination's.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, brw)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, up)
		done <- struct{}{}
	}()
	<-done
	// Closing both ends unblocks the other direction, which may be waiting on a
	// peer that will never send again.
	_ = client.Close()
	_ = up.Close()
	<-done
}

func (s *Server) handleForward(w http.ResponseWriter, r *http.Request) {
	raw := r.RequestURI
	auth, rest, err := splitAbsoluteTarget(raw)
	if err != nil {
		reason := ReasonMalformedTarget
		switch {
		case errors.Is(err, errTargetNotAbsolute):
			reason = ReasonOriginForm
		case errors.Is(err, errHTTPSAbsoluteForm):
			reason = ReasonHTTPSAbsoluteForm
		}
		s.denyUnparsed(KindForward, raw, reason)
		status := http.StatusBadRequest
		if reason == ReasonHTTPSAbsoluteForm {
			status = http.StatusNotImplemented
		}
		deny(w, status, reason)
		return
	}
	a, err := parseAuthority(auth, 80)
	if err != nil {
		s.denyUnparsed(KindForward, raw, ReasonMalformedTarget)
		deny(w, http.StatusBadRequest, ReasonMalformedTarget)
		return
	}
	// RFC 7230 §5.4 says a proxy must ignore the received Host header in
	// absolute-form and use the request-target's authority; net/http applies
	// that before the handler runs, so r.Host already equals the target's
	// authority. This comparison is a guard, not the enforcement: if a future
	// net/http stopped replacing it, the header's claim would be forwarded to
	// the origin while the policy checked the request-target, so refuse the
	// disagreement instead. TestForwardOriginFormAndHTTPSAbsoluteFormFailClosed
	// asserts the origin sees the checked authority.
	if r.Host != "" {
		if hostOnly, port, err := net.SplitHostPort(r.Host); err == nil {
			if p, err := strconv.Atoi(port); err != nil || !strings.EqualFold(hostOnly, a.host) || p != a.port {
				s.denyUnparsed(KindForward, raw, ReasonAuthorityMismatch)
				deny(w, http.StatusBadRequest, ReasonAuthorityMismatch)
				return
			}
		} else if !strings.EqualFold(strings.TrimSuffix(strings.TrimPrefix(r.Host, "["), "]"), a.host) {
			s.denyUnparsed(KindForward, raw, ReasonAuthorityMismatch)
			deny(w, http.StatusBadRequest, ReasonAuthorityMismatch)
			return
		}
	}

	allowed, reason := s.policyAllows(a)
	s.record(KindForward, raw, a, allowed, reason)
	if !allowed {
		deny(w, http.StatusForbidden, reason)
		return
	}
	if r.URL == nil || r.URL.Scheme != "http" || !strings.EqualFold(r.URL.Host, auth) {
		// Should be unreachable: net/http parses the absolute-form it accepted.
		// If it is reachable, the bytes the policy checked and the bytes that
		// would be forwarded disagree, so nothing is forwarded.
		s.denyUnparsed(KindForward, raw, ReasonAuthorityMismatch)
		deny(w, http.StatusBadRequest, ReasonAuthorityMismatch)
		return
	}

	outURL := &url.URL{
		Scheme:     "http",
		Host:       a.String(),
		Path:       r.URL.Path,
		RawPath:    r.URL.RawPath,
		RawQuery:   r.URL.RawQuery,
		ForceQuery: r.URL.ForceQuery,
	}
	outReq := r.Clone(context.WithValue(r.Context(), targetKey{}, a))
	if got := outURL.RequestURI(); got != rest {
		// The suffix cut from the raw request-target and the suffix net/http
		// would forward disagree; one of the two parsers is reading the bytes
		// differently, so nothing is forwarded.
		s.denyUnparsed(KindForward, raw, ReasonMalformedTarget)
		deny(w, http.StatusBadRequest, ReasonMalformedTarget)
		return
	}
	outReq.URL = outURL
	outReq.RequestURI = "" // a client request must not carry one
	outReq.Host = r.Host   // preserve the vhost the client asked for
	outReq.Body = r.Body
	outReq.ContentLength = r.ContentLength
	outReq.Header = r.Header.Clone()
	removeHopByHop(outReq.Header)

	resp, err := s.tr.RoundTrip(outReq)
	if err != nil {
		s.recordDialFailure(KindForward, raw, a, dialReason(err))
		deny(w, http.StatusBadGateway, dialReason(err))
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	s.forwarded.Add(1)

	copyHeader(w.Header(), resp.Header)
	removeHopByHop(w.Header())
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		// The client went away; the origin connection is returned to the pool
		// only when the body is fully read, so drain a bounded amount first.
		_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
	}
}

// targetKey carries the validated authority from the request handler to the
// transport's dialler, so a dial can be matched against what was authorized.
type targetKey struct{}

func (s *Server) dialFromContext(ctx context.Context, network, addr string) (net.Conn, error) {
	a, ok := ctx.Value(targetKey{}).(authority)
	if !ok {
		return nil, errors.New("scopeproxy: dial without a validated target (fail closed)")
	}
	if !sameTarget(addr, a) {
		s.denyUnparsed(KindForward, addr, ReasonDialTargetMismatch)
		return nil, fmt.Errorf("%w: refusing to dial %q for validated target %q", errDialTargetMismatch, addr, a.String())
	}
	return s.dialValidated(ctx, a)
}

// dialValidated resolves (only when needed) and dials the literal address it
// resolved. A name is never re-resolved by the dial itself, so the address
// PermitAddress approves is the address connected to.
func (s *Server) dialValidated(ctx context.Context, a authority) (net.Conn, error) {
	port := strconv.Itoa(a.port)
	if a.isIPLiteral() {
		ip := net.ParseIP(a.host)
		if s.cfg.PermitAddress != nil && !s.cfg.PermitAddress(ip) {
			return nil, fmt.Errorf("%w: address %s refused by PermitAddress", errNoPermittedAddress, a.host)
		}
		return s.cfg.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(a.host, port))
	}
	addrs, err := s.cfg.Resolver.LookupIPAddr(ctx, a.host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResolveFailed, err)
	}
	var lastErr error
	for _, addr := range addrs {
		if s.cfg.PermitAddress != nil && !s.cfg.PermitAddress(addr.IP) {
			lastErr = fmt.Errorf("%w: address %s refused by PermitAddress", errNoPermittedAddress, addr.IP)
			continue
		}
		c, err := s.cfg.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: %q resolved to no address", errNoPermittedAddress, a.host)
	}
	return nil, lastErr
}

var (
	errResolveFailed      = errors.New("scopeproxy: resolve failed")
	errNoPermittedAddress = errors.New("scopeproxy: no permitted address")
)

// dialReason maps a dial error to a stable reason without leaking addresses
// into counters. The error text still reaches the log/caller through the event.
func dialReason(err error) string {
	switch {
	case errors.Is(err, errResolveFailed):
		return ReasonResolveFailed
	case errors.Is(err, errNoPermittedAddress):
		return ReasonNoPermittedAddress
	case errors.Is(err, errDialTargetMismatch):
		return ReasonDialTargetMismatch
	default:
		return ReasonDialFailed
	}
}

var errDialTargetMismatch = errors.New("scopeproxy: dial target mismatch")

// deny writes a short, non-committal refusal. It names the reason class (which
// is already visible to the browser as a failed request) but never the policy
// internals.
func deny(w http.ResponseWriter, status int, reason string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Indago-Scope-Proxy", "denied")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "indago scope proxy: denied ("+reason+")\n")
}

// hopHeaders are never forwarded in either direction: they describe the
// connection, not the message, and the origin must not learn the proxy exists.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if name := strings.TrimSpace(f); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

var _ http.Handler = (*Server)(nil)
var _ Resolver = (*net.Resolver)(nil)
var _ Dialer = (*net.Dialer)(nil)
