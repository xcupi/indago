package oast_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/oast"
)

// ---------------------------------------------------------------- helpers

func newLocal(t *testing.T, mutate func(*oast.Config)) *oast.Manager {
	t.Helper()
	cfg := oast.Config{}
	if mutate != nil {
		mutate(&cfg)
	}
	mgr, err := oast.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(local): %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

func client() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func mustRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}

var dnsLabel = regexp.MustCompile(`^[a-z2-7]{21}$`)

// ------------------------------------------------------------ local mode

func TestNewLocalDefaults(t *testing.T) {
	mgr := newLocal(t, nil)
	if !strings.HasPrefix(mgr.BaseURL(), "http://127.0.0.1:") {
		t.Fatalf("default base URL = %q, want loopback listener", mgr.BaseURL())
	}
	if mgr.Handler() == nil {
		t.Fatal("Handler() is nil")
	}
	if n, err := mgr.Poll(context.Background()); n != 0 || err != nil {
		t.Fatalf("Poll(local) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestGeneratePayloadURLStabilityAndUniqueness(t *testing.T) {
	mgr := newLocal(t, nil)

	u1, tok1 := mgr.GeneratePayloadURL("probe-1", "cmdi")
	_, tok2 := mgr.GeneratePayloadURL("probe-2", "cmdi")
	u1b, tok1b := mgr.GeneratePayloadURL("probe-1", "cmdi")
	_, tok3 := mgr.GeneratePayloadURL("probe-1", "xxe")

	if tok1 == tok2 {
		t.Fatalf("distinct probes share token %q", tok1)
	}
	if tok1 == tok3 {
		t.Fatalf("distinct tags share token %q", tok1)
	}
	if u1 != u1b || tok1 != tok1b {
		t.Fatalf("same (probe, tag) is not stable: %q/%q vs %q/%q", u1, tok1, u1b, tok1b)
	}
	if !dnsLabel.MatchString(tok1) {
		t.Fatalf("token %q is not a 21-char lowercase base32 DNS label", tok1)
	}
	want := mgr.BaseURL() + "/p/" + tok1
	if u1 != want {
		t.Fatalf("payload URL = %q, want %q", u1, want)
	}
}

func TestGeneratePayloadURLAnonymousProbe(t *testing.T) {
	mgr := newLocal(t, nil)
	_, a := mgr.GeneratePayloadURL("", "cmdi")
	_, b := mgr.GeneratePayloadURL("", "cmdi")
	if a == b {
		t.Fatalf("anonymous probes share token %q", a)
	}
	if _, ok := mgr.HasHit(a); ok {
		t.Fatal("fresh token already has a hit")
	}
}

func TestLocalListenerRecordsHTTPHit(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) { c.MaxBodyBytes = 4096 })
	payload, tok := mgr.GeneratePayloadURL("probe-42", "cmdi")

	req := mustRequest(t, http.MethodPost, payload+"?marker=abc", "payload-body")
	req.Header.Set("X-Indago-Test", "yes")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	started := time.Now()
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != oast.DefaultCanaryBody {
		t.Fatalf("canary body = %q, want %q", body, oast.DefaultCanaryBody)
	}

	it, ok := mgr.HasHit(tok)
	if !ok {
		t.Fatal("HasHit = false after a callback")
	}
	if it.Token != tok || it.ProbeID != "probe-42" || it.Tag != "cmdi" {
		t.Fatalf("correlation = token %q probe %q tag %q", it.Token, it.ProbeID, it.Tag)
	}
	if it.Protocol != "http" || it.Method != http.MethodPost {
		t.Fatalf("protocol/method = %q/%q", it.Protocol, it.Method)
	}
	if it.Path != "/p/"+tok || it.Query != "marker=abc" {
		t.Fatalf("path/query = %q/%q", it.Path, it.Query)
	}
	if got := it.Headers["X-Indago-Test"]; len(got) != 1 || got[0] != "yes" {
		t.Fatalf("X-Indago-Test header = %v", got)
	}
	if it.Body != "payload-body" {
		t.Fatalf("body = %q", it.Body)
	}
	if it.Source != "local" {
		t.Fatalf("source = %q, want local", it.Source)
	}
	if it.RemoteIP != "127.0.0.1" {
		t.Fatalf("remote IP = %q, want the peer address 127.0.0.1", it.RemoteIP)
	}
	if !strings.Contains(it.RemoteAddr, ":") {
		t.Fatalf("remote addr = %q, want host:port", it.RemoteAddr)
	}
	if it.ReceivedAt.Location() != time.UTC {
		t.Fatalf("received_at location = %v, want UTC", it.ReceivedAt.Location())
	}
	if d := it.ReceivedAt.Sub(started); d < -2*time.Second || d > 5*time.Second {
		t.Fatalf("received_at %v is not near %v", it.ReceivedAt, started)
	}
	// X-Forwarded-For is spoofable, so it must not be trusted by default.
	if it.RemoteIP == "203.0.113.7" {
		t.Fatal("untrusted X-Forwarded-For was used as the source IP")
	}
}

func TestLocalListenerTruncatesBodyAndHeaders(t *testing.T) {
	const maxBody = 64
	mgr := newLocal(t, func(c *oast.Config) {
		c.MaxBodyBytes = maxBody
		c.MaxHeaders = 2
	})
	payload, tok := mgr.GeneratePayloadURL("probe-big", "cmdi")

	req := mustRequest(t, http.MethodPost, payload, strings.Repeat("A", 4096))
	req.Header.Set("X-One", "1")
	req.Header.Set("X-Two", "2")
	req.Header.Set("X-Three", "3")
	if _, body := do(t, req); body != oast.DefaultCanaryBody {
		t.Fatalf("canary body = %q", body)
	}

	it, ok := mgr.HasHit(tok)
	if !ok {
		t.Fatal("no hit recorded")
	}
	if len(it.Body) != maxBody || !it.Truncated {
		t.Fatalf("body len=%d truncated=%v, want len=%d truncated=true", len(it.Body), it.Truncated, maxBody)
	}
	if len(it.Headers) > 2 {
		t.Fatalf("retained %d header keys, want <= 2", len(it.Headers))
	}
}

func TestCanaryNeverReflectsInput(t *testing.T) {
	mgr := newLocal(t, nil)
	payload, tok := mgr.GeneratePayloadURL("probe-xss", "reflected")

	evil := `<script>alert("indago")</script>`
	req := mustRequest(t, http.MethodPost, payload+"?q="+url.QueryEscape(evil), evil)
	req.Header.Set("Referer", "javascript:alert(1)")
	resp, body := do(t, req)

	if body != oast.DefaultCanaryBody {
		t.Fatalf("canary body = %q, want the constant %q", body, oast.DefaultCanaryBody)
	}
	for _, needle := range []string{"script", "alert", "javascript"} {
		if strings.Contains(strings.ToLower(body), needle) {
			t.Fatalf("canary reflected input (%q found in %q)", needle, body)
		}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", ct)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options: nosniff")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing Cache-Control: no-store")
	}
	if _, ok := mgr.HasHit(tok); !ok {
		t.Fatal("the hit was not recorded")
	}
}

func TestLocalListenerCorrelatesQueryToken(t *testing.T) {
	mgr := newLocal(t, nil)
	_, tok := mgr.GeneratePayloadURL("probe-query", "ssrf")

	if _, ok := mgr.RecordHit(oast.Hit{Path: "/", Query: "id=" + tok, Host: "oast.test"}); !ok {
		t.Fatal("query token was not correlated")
	}
	it, ok := mgr.HasHit(tok)
	if !ok || it.ProbeID != "probe-query" {
		t.Fatalf("HasHit = (%+v, %v)", it, ok)
	}
	if it.Source != "bridge" {
		t.Fatalf("source = %q, want bridge", it.Source)
	}
}

func TestDNSBridgeHitCorrelates(t *testing.T) {
	mgr := newLocal(t, nil)
	_, tok := mgr.GeneratePayloadURL("probe-dns", "ssrf")

	it, ok := mgr.RecordHit(oast.Hit{
		Protocol:   "dns",
		Host:       tok + ".oast.example",
		QType:      "A",
		RemoteAddr: "198.51.100.9:5353",
		ReceivedAt: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
	})
	if !ok {
		t.Fatal("DNS-style host did not correlate")
	}
	if it.Token != tok || it.ProbeID != "probe-dns" {
		t.Fatalf("correlation = token %q probe %q", it.Token, it.ProbeID)
	}
	if it.Protocol != "dns" || it.QType != "A" {
		t.Fatalf("protocol/qtype = %q/%q", it.Protocol, it.QType)
	}
	if it.RemoteIP != "198.51.100.9" {
		t.Fatalf("remote IP = %q", it.RemoteIP)
	}
	if !it.ReceivedAt.Equal(time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Fatalf("received_at = %v", it.ReceivedAt)
	}
}

func TestUnknownHitRecordedWithoutCorrelation(t *testing.T) {
	mgr := newLocal(t, nil)
	it, ok := mgr.RecordHit(oast.Hit{Path: "/p/not-a-real-token", Host: "127.0.0.1"})
	if ok {
		t.Fatal("unknown token reported as correlated")
	}
	if it.Token != "" || it.ProbeID != "" {
		t.Fatalf("unknown hit carries identity: %+v", it)
	}
	if got := len(mgr.Interactions()); got != 1 {
		t.Fatalf("retained %d interactions, want 1 (unknown hits are evidence too)", got)
	}
	if _, ok := mgr.HasHit("not-a-real-token"); ok {
		t.Fatal("HasHit matched an unknown token")
	}
	if _, ok := mgr.HasHit(""); ok {
		t.Fatal("HasHit matched an empty token")
	}
}

func TestHasHitReturnsEarliestHit(t *testing.T) {
	mgr := newLocal(t, nil)
	_, tok := mgr.GeneratePayloadURL("probe-order", "cmdi")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	mgr.RecordHit(oast.Hit{Path: "/p/" + tok, ReceivedAt: base.Add(2 * time.Second)})
	mgr.RecordHit(oast.Hit{Path: "/p/" + tok, ReceivedAt: base})
	mgr.RecordHit(oast.Hit{Path: "/p/unrelated", ReceivedAt: base.Add(time.Second)})

	it, ok := mgr.HasHit(tok)
	if !ok || !it.ReceivedAt.Equal(base) {
		t.Fatalf("HasHit = (%v, %v), want the earliest hit at %v", it.ReceivedAt, ok, base)
	}
	if got := len(mgr.InteractionsFor(tok)); got != 2 {
		t.Fatalf("InteractionsFor = %d, want 2", got)
	}
	all := mgr.Interactions()
	if len(all) != 3 {
		t.Fatalf("Interactions = %d, want 3", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].ReceivedAt.Before(all[i-1].ReceivedAt) {
			t.Fatalf("Interactions() is not oldest-first: %v then %v", all[i-1].ReceivedAt, all[i].ReceivedAt)
		}
	}
}

func TestWaitForHit(t *testing.T) {
	mgr := newLocal(t, nil)
	payload, tok := mgr.GeneratePayloadURL("probe-wait", "cmdi")

	fired := make(chan struct{})
	go func() {
		defer close(fired)
		time.Sleep(75 * time.Millisecond)
		resp, err := client().Get(payload)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	it, ok := mgr.WaitForHit(context.Background(), tok, 5*time.Second)
	if !ok || it.Token != tok {
		t.Fatalf("WaitForHit = (%+v, %v)", it, ok)
	}
	<-fired

	started := time.Now()
	if _, ok := mgr.WaitForHit(context.Background(), tok+"-never", 100*time.Millisecond); ok {
		t.Fatal("WaitForHit reported a hit for a token that never called back")
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("timeout path took %v", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := mgr.WaitForHit(ctx, tok+"-other", 0); ok {
		t.Fatal("WaitForHit ignored a cancelled context")
	}
}

func TestTrustProxyHeaders(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) { c.TrustProxyHeaders = true })
	payload, tok := mgr.GeneratePayloadURL("probe-proxy", "cmdi")

	req := mustRequest(t, http.MethodGet, payload, "")
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if _, body := do(t, req); body != oast.DefaultCanaryBody {
		t.Fatalf("canary body = %q", body)
	}
	it, ok := mgr.HasHit(tok)
	if !ok {
		t.Fatal("no hit recorded")
	}
	if it.RemoteIP != "203.0.113.7" {
		t.Fatalf("remote IP = %q, want the forwarded client 203.0.113.7", it.RemoteIP)
	}
}

func TestBridgeHitIsBounded(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) {
		c.MaxBodyBytes = 32
		c.MaxHeaders = 1
	})
	it, _ := mgr.RecordHit(oast.Hit{
		Path:    "/",
		Body:    []byte(strings.Repeat("B", 4096)),
		Headers: http.Header{"X-A": {"1"}, "X-B": {"2"}},
	})
	if len(it.Body) != 32 || !it.Truncated {
		t.Fatalf("bridged body len=%d truncated=%v, want 32/true", len(it.Body), it.Truncated)
	}
	if len(it.Headers) != 1 {
		t.Fatalf("bridged hit retained %d header keys, want 1", len(it.Headers))
	}
}

func TestTrustProxyHeadersRejectsNonIP(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) { c.TrustProxyHeaders = true })

	payload, tok := mgr.GeneratePayloadURL("probe-proxy-junk", "cmdi")
	req := mustRequest(t, http.MethodGet, payload, "")
	req.Header.Set("X-Forwarded-For", "not-an-ip, 203.0.113.7")
	req.Header.Set("X-Real-IP", "also-not-an-ip")
	do(t, req)

	it, ok := mgr.HasHit(tok)
	if !ok {
		t.Fatal("no hit recorded")
	}
	if it.RemoteIP != "127.0.0.1" {
		t.Fatalf("remote IP = %q, want the peer address when forwarded values are not IPs", it.RemoteIP)
	}

	payload2, tok2 := mgr.GeneratePayloadURL("probe-proxy-real", "cmdi")
	req2 := mustRequest(t, http.MethodGet, payload2, "")
	req2.Header.Set("X-Forwarded-For", "not-an-ip")
	req2.Header.Set("X-Real-IP", "198.51.100.5")
	do(t, req2)
	it2, ok := mgr.HasHit(tok2)
	if !ok || it2.RemoteIP != "198.51.100.5" {
		t.Fatalf("remote IP = %q, want the valid X-Real-IP fallback", it2.RemoteIP)
	}
}

func TestConcurrentUse(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) { c.MaxInteractions = 4096 })

	const workers, perWorker = 16, 20
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				payload, tok := mgr.GeneratePayloadURL(fmt.Sprintf("probe-%d", w), "cmdi")
				if !strings.Contains(payload, tok) {
					t.Errorf("payload %q does not carry token %q", payload, tok)
					return
				}
				mgr.RecordHit(oast.Hit{Path: "/p/" + tok, Method: "GET", RemoteAddr: "127.0.0.1:1234"})
				if _, ok := mgr.HasHit(tok); !ok {
					t.Errorf("token %q lost its hit", tok)
					return
				}
				_ = mgr.Interactions()
				_ = mgr.InteractionsFor(tok)
			}
		}(w)
	}
	wg.Wait()

	if got, want := len(mgr.Interactions()), workers*perWorker; got != want {
		t.Fatalf("retained %d interactions, want %d", got, want)
	}
}

func TestEvictionBoundsRetention(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) { c.MaxInteractions = 5 })
	for i := 0; i < 12; i++ {
		mgr.RecordHit(oast.Hit{Path: fmt.Sprintf("/p/hit-%d", i)})
	}
	if got := len(mgr.Interactions()); got != 5 {
		t.Fatalf("retained %d interactions, want the 5 newest", got)
	}
	if got, want := mgr.Dropped(), uint64(7); got != want {
		t.Fatalf("Dropped() = %d, want %d", got, want)
	}
	last := mgr.Interactions()[4]
	if last.Path != "/p/hit-11" {
		t.Fatalf("newest interaction = %q, want /p/hit-11", last.Path)
	}
}

func TestRingWrapKeepsNewestInOrder(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) { c.MaxInteractions = 3 })
	base := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	for i := 0; i < 7; i++ {
		mgr.RecordHit(oast.Hit{Path: fmt.Sprintf("/p/hit-%d", i), ReceivedAt: base.Add(time.Duration(i) * time.Second)})
	}
	all := mgr.Interactions()
	if len(all) != 3 {
		t.Fatalf("retained %d interactions, want 3", len(all))
	}
	for i, want := range []string{"/p/hit-4", "/p/hit-5", "/p/hit-6"} {
		if all[i].Path != want {
			t.Fatalf("interaction %d = %q, want %q (all: %v)", i, all[i].Path, want, all)
		}
	}
	if got := mgr.Dropped(); got != 4 {
		t.Fatalf("Dropped() = %d, want 4", got)
	}
}

func TestSingleInteractionCap(t *testing.T) {
	mgr := newLocal(t, func(c *oast.Config) { c.MaxInteractions = 1 })
	mgr.RecordHit(oast.Hit{Path: "/p/first"})
	mgr.RecordHit(oast.Hit{Path: "/p/second"})
	all := mgr.Interactions()
	if len(all) != 1 || all[0].Path != "/p/second" {
		t.Fatalf("retained %v, want only /p/second", all)
	}
}

func TestCloseStopsListenerAndIsIdempotent(t *testing.T) {
	mgr, err := oast.New(context.Background(), oast.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	payload, tok := mgr.GeneratePayloadURL("probe-close", "cmdi")
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	resp, err := client().Get(payload)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("listener still accepts connections after Close")
	}
	if _, err := mgr.Poll(context.Background()); !errors.Is(err, oast.ErrClosed) {
		t.Fatalf("Poll after Close = %v, want ErrClosed", err)
	}
	if _, ok := mgr.WaitForHit(context.Background(), tok, 10*time.Millisecond); ok {
		t.Fatal("WaitForHit reported a hit after Close")
	}
}

func TestHandlerServesCanaryWhenMounted(t *testing.T) {
	mgr := newLocal(t, nil)
	ts := httptest.NewServer(mgr.Handler())
	defer ts.Close()

	_, tok := mgr.GeneratePayloadURL("probe-mounted", "cmdi")
	resp, err := client().Get(ts.URL + "/p/" + tok)
	if err != nil {
		t.Fatalf("GET mounted handler: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != oast.DefaultCanaryBody {
		t.Fatalf("mounted canary body = %q", body)
	}
	it, ok := mgr.HasHit(tok)
	if !ok || it.Path != "/p/"+tok {
		t.Fatalf("mounted handler hit = (%+v, %v)", it, ok)
	}
}

func TestInteractionJSONRoundTrip(t *testing.T) {
	mgr := newLocal(t, nil)
	payload, tok := mgr.GeneratePayloadURL("probe-json", "cmdi")
	req := mustRequest(t, http.MethodGet, payload, "")
	req.Header.Set("X-Marker", "json")
	do(t, req)

	it, ok := mgr.HasHit(tok)
	if !ok {
		t.Fatal("no hit")
	}
	blob, err := json.Marshal(it)
	if err != nil {
		t.Fatalf("marshal interaction: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal interaction: %v", err)
	}
	for _, key := range []string{"token", "probe_id", "tag", "protocol", "method", "path", "headers", "remote_ip", "received_at", "source"} {
		if _, ok := back[key]; !ok {
			t.Fatalf("serialized interaction is missing %q: %s", key, blob)
		}
	}
}

// -------------------------------------------------------- interactsh mode

// fakeInteraction mirrors the server's wire contract, deliberately declared
// here rather than reusing the package's own type.
type fakeInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	QType         string    `json:"q-type,omitempty"`
	RawRequest    string    `json:"raw-request,omitempty"`
	RawResponse   string    `json:"raw-response,omitempty"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

type fakeInteractsh struct {
	t         *testing.T
	server    *httptest.Server
	correlID  string
	mu        sync.Mutex
	priv      *rsa.PrivateKey
	secretB64 string
	items     []fakeInteraction
	rawData   []string

	requireToken  string
	registerCode  int
	pollCode      int
	incompleteReg bool
	omitAESKey    bool

	registerCalls  int
	pollCalls      int
	lastPollID     string
	lastPollSecret string
}

func newFakeInteractsh(t *testing.T) *fakeInteractsh {
	t.Helper()
	f := &fakeInteractsh{t: t, correlID: "corr-0123456789abcdef"}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", f.handleRegister)
	mux.HandleFunc("/poll", f.handlePoll)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeInteractsh) add(ii fakeInteraction) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = append(f.items, ii)
}

func (f *fakeInteractsh) handleRegister(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registerCalls++
	if f.requireToken != "" && r.Header.Get("Authorization") != f.requireToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.registerCode != 0 {
		w.WriteHeader(f.registerCode)
		return
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Errorf("generate key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.priv = priv
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		f.t.Errorf("marshal public key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	f.secretB64 = base64.StdEncoding.EncodeToString(privPEM)
	if f.incompleteReg {
		writeJSON(f.t, w, map[string]string{"message": "registration successful", "correlation-id": f.correlID})
		return
	}
	writeJSON(f.t, w, map[string]string{
		"message":        "registration successful",
		"public-key":     base64.StdEncoding.EncodeToString(pubPEM),
		"secret-key":     f.secretB64,
		"correlation-id": f.correlID,
	})
}

func (f *fakeInteractsh) handlePoll(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollCalls++
	f.lastPollID = r.URL.Query().Get("id")
	f.lastPollSecret = r.URL.Query().Get("secret")
	if f.pollCode != 0 {
		w.WriteHeader(f.pollCode)
		return
	}
	if f.lastPollID != f.correlID {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if f.priv == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.t.Errorf("rand: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var data []string
	if f.rawData != nil {
		data = f.rawData
	} else {
		for _, ii := range f.items {
			plain, err := json.Marshal(ii)
			if err != nil {
				f.t.Errorf("marshal interaction: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			enc, err := encryptPayload(key, plain)
			if err != nil {
				f.t.Errorf("encrypt interaction: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			data = append(data, enc)
		}
	}
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, &f.priv.PublicKey, key)
	if err != nil {
		f.t.Errorf("encrypt aes key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := map[string]any{"data": data, "tlddata": []string{}}
	if !f.omitAESKey {
		resp["aes_key"] = base64.StdEncoding.EncodeToString(encKey)
	}
	writeJSON(f.t, w, resp)
}

func encryptPayload(key, plain []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	out := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(out, plain)
	return base64.StdEncoding.EncodeToString(append(iv, out...)), nil
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestInteractshModeRegistersAndPolls(t *testing.T) {
	f := newFakeInteractsh(t)
	mgr, err := oast.New(context.Background(), oast.Config{
		Mode:             oast.ModeInteractsh,
		InteractshServer: f.server.URL,
	})
	if err != nil {
		t.Fatalf("New(interactsh): %v", err)
	}
	defer mgr.Close()

	if mgr.BaseURL() != f.server.URL {
		t.Fatalf("BaseURL = %q, want %q", mgr.BaseURL(), f.server.URL)
	}
	payload, tok := mgr.GeneratePayloadURL("probe-1", "cmdi")
	want := "http://" + tok + "." + strings.TrimPrefix(f.server.URL, "http://") + "/"
	if payload != want {
		t.Fatalf("payload URL = %q, want %q", payload, want)
	}
	if !dnsLabel.MatchString(tok) {
		t.Fatalf("interactsh token %q is not a DNS label", tok)
	}

	ctx := context.Background()
	if n, err := mgr.Poll(ctx); n != 0 || err != nil {
		t.Fatalf("empty Poll = (%d, %v), want (0, nil)", n, err)
	}

	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	f.add(fakeInteraction{
		Protocol:      "http",
		UniqueID:      tok + "nonce123",
		FullID:        tok + "nonce123",
		RawRequest:    "GET /login?user=1 HTTP/1.1\r\nHost: " + tok + "nonce123.oast.example\r\nUser-Agent: curl/8.5.0\r\nX-Probe: live\r\n\r\n",
		RemoteAddress: "203.0.113.9:51000",
		Timestamp:     now,
	})
	f.add(fakeInteraction{
		Protocol:      "dns",
		UniqueID:      tok + "nonce456",
		FullID:        tok + "nonce456.oast.example",
		QType:         "A",
		RemoteAddress: "198.51.100.4:5353",
		Timestamp:     now.Add(time.Second),
	})

	n, err := mgr.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if n != 2 {
		t.Fatalf("Poll recorded %d interactions, want 2", n)
	}

	f.mu.Lock()
	lastID, lastSecret, registeredSecret := f.lastPollID, f.lastPollSecret, f.secretB64
	f.mu.Unlock()
	if lastID != f.correlID {
		t.Fatalf("poll id = %q, want %q", lastID, f.correlID)
	}
	if lastSecret == "" || lastSecret != registeredSecret {
		t.Fatal("poll did not carry the registration secret verbatim")
	}

	it, ok := mgr.HasHit(tok)
	if !ok {
		t.Fatal("HasHit = false after polling interactions")
	}
	if it.Token != tok || it.ProbeID != "probe-1" || it.Tag != "cmdi" {
		t.Fatalf("correlation = token %q probe %q tag %q", it.Token, it.ProbeID, it.Tag)
	}
	if it.Source != "interactsh" {
		t.Fatalf("source = %q, want interactsh", it.Source)
	}
	if it.Protocol != "http" || it.Method != "GET" || it.Path != "/login" || it.Query != "user=1" {
		t.Fatalf("http interaction = %+v", it)
	}
	if got := it.Headers["User-Agent"]; len(got) != 1 || got[0] != "curl/8.5.0" {
		t.Fatalf("user-agent header = %v", got)
	}
	if it.RemoteIP != "203.0.113.9" {
		t.Fatalf("remote IP = %q", it.RemoteIP)
	}
	if !it.ReceivedAt.Equal(now) {
		t.Fatalf("received_at = %v, want %v", it.ReceivedAt, now)
	}

	all := mgr.InteractionsFor(tok)
	if len(all) != 2 {
		t.Fatalf("InteractionsFor = %d, want 2", len(all))
	}
	var dns *oast.Interaction
	for i := range all {
		if all[i].Protocol == "dns" {
			dns = &all[i]
		}
	}
	if dns == nil {
		t.Fatal("DNS interaction missing")
	}
	if dns.QType != "A" || dns.RemoteIP != "198.51.100.4" || dns.Host != tok+"nonce456.oast.example" {
		t.Fatalf("dns interaction = %+v", *dns)
	}

	// The server re-delivers until acknowledged; a second poll must not
	// duplicate what is already recorded.
	if n, err := mgr.Poll(ctx); n != 0 || err != nil {
		t.Fatalf("second Poll = (%d, %v), want (0, nil)", n, err)
	}
	if got := len(mgr.Interactions()); got != 2 {
		t.Fatalf("retained %d interactions after re-poll, want 2", got)
	}
}

func TestInteractshUsesExplicitAuthorizationToken(t *testing.T) {
	f := newFakeInteractsh(t)
	f.requireToken = "api-token-123"

	if _, err := oast.New(context.Background(), oast.Config{
		Mode:             oast.ModeInteractsh,
		InteractshServer: f.server.URL,
	}); err == nil {
		t.Fatal("registration succeeded without the required token")
	}

	mgr, err := oast.New(context.Background(), oast.Config{
		Mode:             oast.ModeInteractsh,
		InteractshServer: f.server.URL,
		InteractshToken:  "api-token-123",
	})
	if err != nil {
		t.Fatalf("New with token: %v", err)
	}
	defer mgr.Close()

	f.mu.Lock()
	calls := f.registerCalls
	f.mu.Unlock()
	if calls != 2 {
		t.Fatalf("register calls = %d, want 2 (one rejected, one accepted)", calls)
	}
}

func TestInteractshRegistrationFailures(t *testing.T) {
	t.Run("server error", func(t *testing.T) {
		f := newFakeInteractsh(t)
		f.registerCode = http.StatusInternalServerError
		if _, err := oast.New(context.Background(), oast.Config{
			Mode: oast.ModeInteractsh, InteractshServer: f.server.URL,
		}); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("New = %v, want a 500 registration error", err)
		}
	})

	t.Run("incomplete registration", func(t *testing.T) {
		f := newFakeInteractsh(t)
		f.incompleteReg = true
		if _, err := oast.New(context.Background(), oast.Config{
			Mode: oast.ModeInteractsh, InteractshServer: f.server.URL,
		}); err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("New = %v, want an incomplete-registration error", err)
		}
	})

	t.Run("redirect refused", func(t *testing.T) {
		var target *httptest.Server
		target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
		}))
		defer target.Close()
		if _, err := oast.New(context.Background(), oast.Config{
			Mode: oast.ModeInteractsh, InteractshServer: target.URL,
		}); err == nil || !strings.Contains(err.Error(), "302") {
			t.Fatalf("New = %v, want the redirect to be refused by status", err)
		}
	})
}

func TestInteractshPollFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("server error", func(t *testing.T) {
		f := newFakeInteractsh(t)
		mgr, err := oast.New(ctx, oast.Config{Mode: oast.ModeInteractsh, InteractshServer: f.server.URL})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer mgr.Close()
		f.mu.Lock()
		f.pollCode = http.StatusInternalServerError
		f.mu.Unlock()
		if _, err := mgr.Poll(ctx); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("Poll = %v, want a 500 error", err)
		}
	})

	t.Run("undecodable interaction", func(t *testing.T) {
		f := newFakeInteractsh(t)
		f.rawData = []string{"!!! not base64 !!!"}
		mgr, err := oast.New(ctx, oast.Config{Mode: oast.ModeInteractsh, InteractshServer: f.server.URL})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer mgr.Close()
		n, err := mgr.Poll(ctx)
		if err == nil {
			t.Fatal("Poll accepted an undecodable interaction")
		}
		if n != 0 {
			t.Fatalf("Poll recorded %d interactions, want 0", n)
		}
	})

	t.Run("missing aes key", func(t *testing.T) {
		f := newFakeInteractsh(t)
		f.omitAESKey = true
		f.add(fakeInteraction{Protocol: "dns", FullID: "x.oast.example", RemoteAddress: "192.0.2.1:53"})
		mgr, err := oast.New(ctx, oast.Config{Mode: oast.ModeInteractsh, InteractshServer: f.server.URL})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer mgr.Close()
		if _, err := mgr.Poll(ctx); err == nil {
			t.Fatal("Poll accepted a response without an AES key")
		}
	})
}

// ------------------------------------------------------------- validation

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  oast.Config
		want string
	}{
		{"unknown mode", oast.Config{Mode: "carrier-pigeon"}, "unknown mode"},
		{"interactsh without server", oast.Config{Mode: oast.ModeInteractsh}, "required"},
		{"interactsh relative server", oast.Config{Mode: oast.ModeInteractsh, InteractshServer: "oast.example.net"}, "absolute"},
		{"interactsh credentialed server", oast.Config{Mode: oast.ModeInteractsh, InteractshServer: "https://user:pass@oast.example.net"}, "credentials"},
		{"listen without port", oast.Config{ListenAddr: "127.0.0.1"}, "host:port"},
		{"bind all interfaces", oast.Config{ListenAddr: ":0"}, "AllowExternalBind"},
		{"bind wildcard", oast.Config{ListenAddr: "0.0.0.0:0"}, "AllowExternalBind"},
		{"public base relative", oast.Config{PublicBaseURL: "/oast"}, "absolute"},
		{"body cap too large", oast.Config{MaxBodyBytes: oast.MaxAllowedBodyBytes + 1}, "max body bytes"},
		{"header cap too large", oast.Config{MaxHeaders: oast.MaxAllowedHeaders + 1}, "max headers"},
		{"interaction cap too large", oast.Config{MaxInteractions: oast.MaxAllowedInteractions + 1}, "max interactions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr, err := oast.New(context.Background(), tc.cfg)
			if err == nil {
				_ = mgr.Close()
				t.Fatalf("New(%+v) succeeded, want an error mentioning %q", tc.cfg, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestConfigAllowsExplicitExternalBindAndPublicBase(t *testing.T) {
	mgr, err := oast.New(context.Background(), oast.Config{
		ListenAddr:        "127.0.0.1:0",
		AllowExternalBind: true,
		PublicBaseURL:     "https://tunnel.example.net/oast/",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer mgr.Close()

	payload, tok := mgr.GeneratePayloadURL("probe-public", "cmdi")
	want := "https://tunnel.example.net/oast/p/" + tok
	if payload != want {
		t.Fatalf("payload URL = %q, want %q", payload, want)
	}
}
