package discovery_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

// rawQueryConfig returns a discovery config with the raw-query capability in
// the requested mode. Discovery-level defaults are otherwise untouched.
func rawQueryConfig(mode discovery.RawQueryMode) discovery.Config {
	cfg := discovery.DefaultConfig()
	cfg.RawQueryInjection = mode
	return cfg
}

// rawParams returns the endpoint's parameters whose Location is raw_query.
func rawParams(t *testing.T, st *memory.Store, ctx context.Context, endpointID domain.ID) []*domain.Parameter {
	t.Helper()
	ps, err := st.Parameters().ListByEndpoint(ctx, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	var out []*domain.Parameter
	for _, p := range ps {
		if p.Location == domain.LocationRawQuery {
			out = append(out, p)
		}
	}
	return out
}

func newMemoryPair() (*memory.Store, *queue.Memory) { return memory.New(), queue.NewMemory() }

func TestParseRawQueryMode(t *testing.T) {
	cases := map[string]discovery.RawQueryMode{
		"":       discovery.RawQueryOff,
		"off":    discovery.RawQueryOff,
		" OFF ":  discovery.RawQueryOff,
		"true":   discovery.RawQueryAuto,
		"on":     discovery.RawQueryAuto,
		"auto":   discovery.RawQueryAuto,
		"always": discovery.RawQueryAlways,
	}
	for in, want := range cases {
		got, err := discovery.ParseRawQueryMode(in)
		if err != nil || got != want {
			t.Errorf("ParseRawQueryMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := discovery.ParseRawQueryMode("sometimes"); err == nil {
		t.Fatal("an unknown mode must be rejected, not silently defaulted")
	}
}

func TestRawQueryShapeQueryString(t *testing.T) {
	bare, ok := discovery.RawQueryQueryString(discovery.RawQueryBareName, `"><svg onload=M>`, "")
	if !ok {
		t.Fatal("bare shape not recognised")
	}
	wantBare := url.QueryEscape(`"><svg onload=M>`)
	if bare != wantBare {
		t.Fatalf("bare query = %q, want %q", bare, wantBare)
	}
	named, ok := discovery.RawQueryQueryString(discovery.RawQueryNamedName, `"><svg onload=M>`, "")
	if !ok || named != "x="+wantBare {
		t.Fatalf("named query = %q (ok=%v), want %q", named, ok, "x="+wantBare)
	}
	if _, ok := discovery.RawQueryQueryString("q", "v", ""); ok {
		t.Fatal("an ordinary parameter name must not be treated as a raw-query shape")
	}
	// Append shape: the payload follows the endpoint's own query, which is what
	// an endpoint that requires one of its parameters needs (measured on lab 12:
	// "/?<payload>" and "/?x=<payload>" are both 400, "/?postId=1&<payload>"
	// reflects).
	appended, ok := discovery.RawQueryQueryString(discovery.RawQueryAppendName, `<payload>`, "postId=1")
	if !ok || appended != "postId=1&"+url.QueryEscape(`<payload>`) {
		t.Fatalf("append query = %q (ok=%v), want %q", appended, ok, "postId=1&"+url.QueryEscape(`<payload>`))
	}
	if _, ok := discovery.RawQueryQueryString(discovery.RawQueryAppendName, `<payload>`, ""); ok {
		t.Fatal("the append shape must not be sent when the endpoint has no query of its own")
	}
}

// The default (off) must be indistinguishable from before the capability
// existed: no raw-query parameter, injection point, or job.
func TestRawQueryInjectionOffRegistersNothing(t *testing.T) {
	c, st, q, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/", Method: domain.MethodGET, Source: domain.SourceCrawler,
	})
	if err != nil || id == "" {
		t.Fatalf("AddEndpoint: id=%q err=%v", id, err)
	}
	if got := rawParams(t, st, ctx, id); len(got) != 0 {
		t.Fatalf("off mode registered %d raw-query parameter(s); want 0", len(got))
	}
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	for _, ip := range ips {
		if ip.Location == domain.LocationRawQuery {
			t.Fatalf("off mode persisted a raw-query injection point: %+v", ip)
		}
	}
	// Jobs: the endpoint's own job plus its header injection points (a normal
	// part of discovery), but never a job for a raw-query probe.
	if n := countRawQueryJobs(t, q, scanID, ips); n != 0 {
		t.Fatalf("off mode enqueued %d raw-query job(s); want 0", n)
	}
}

// countRawQueryJobs counts jobs whose injection point is a raw-query probe.
func countRawQueryJobs(t *testing.T, q *queue.Memory, scanID domain.ID, ips []*domain.InjectionPoint) int {
	t.Helper()
	raw := map[domain.ID]bool{}
	for _, ip := range ips {
		if ip.Location == domain.LocationRawQuery {
			raw[ip.ID] = true
		}
	}
	jobs, err := q.Jobs(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, j := range jobs {
		if raw[j.Target.InjectionPointID] {
			n++
		}
	}
	return n
}

// auto = only GET endpoints with no named query parameters. always = also
// endpoints that do have them (their named pipeline is separate and stays).
func TestRawQueryInjectionModes(t *testing.T) {
	ctx := context.Background()

	t.Run("auto registers only the append shape on a named-parameter endpoint", func(t *testing.T) {
		c, st, _, _ := newCollector(t, rawQueryConfig(discovery.RawQueryAuto))
		id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
			URL: "http://example.com/search?q=hi", Method: domain.MethodGET, Source: domain.SourceCrawler,
		})
		if err != nil || id == "" {
			t.Fatalf("AddEndpoint: id=%q err=%v", id, err)
		}
		got := rawParams(t, st, ctx, id)
		// The endpoint's own query is what makes it reflect; bare/named would
		// replace it, so only the append shape is registered here. The executor
		// still skips its probe when a canonical parameter already reflected.
		if len(got) != 1 || got[0].Name != discovery.RawQueryAppendName {
			t.Fatalf("auto registered %v; want only the append shape %q", names(got), discovery.RawQueryAppendName)
		}
	})

	t.Run("auto covers a bare endpoint", func(t *testing.T) {
		c, st, _, _ := newCollector(t, rawQueryConfig(discovery.RawQueryAuto))
		id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
			URL: "http://example.com/", Method: domain.MethodGET, Source: domain.SourceCrawler,
		})
		if err != nil || id == "" {
			t.Fatalf("AddEndpoint: id=%q err=%v", id, err)
		}
		got := rawParams(t, st, ctx, id)
		// An endpoint with no query of its own gets bare + named: the append
		// shape would be byte-identical to bare there.
		if len(got) != 2 {
			t.Fatalf("auto registered %d raw-query parameter(s); want 2", len(got))
		}
		for _, p := range got {
			if p.Location != domain.LocationRawQuery {
				t.Fatalf("raw-query parameter has location %q, want %q", p.Location, domain.LocationRawQuery)
			}
			if _, ok := discovery.RawQueryPrefix(p.Name); !ok {
				t.Fatalf("parameter %q is not a reserved raw-query shape name", p.Name)
			}
		}
	})

	t.Run("always adds to a named-parameter endpoint", func(t *testing.T) {
		c, st, _, _ := newCollector(t, rawQueryConfig(discovery.RawQueryAlways))
		id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
			URL: "http://example.com/search?q=hi", Method: domain.MethodGET, Source: domain.SourceCrawler,
		})
		if err != nil || id == "" {
			t.Fatalf("AddEndpoint: id=%q err=%v", id, err)
		}
		ps, _ := st.Parameters().ListByEndpoint(ctx, id)
		var named, raw int
		for _, p := range ps {
			switch p.Location {
			case domain.LocationQuery:
				named++
			case domain.LocationRawQuery:
				raw++
			}
		}
		if named != 1 || raw != discovery.MaxRawQueryShapesPerEndpoint {
			t.Fatalf("always registered named=%d raw=%d; want named=1 raw=%d", named, raw, discovery.MaxRawQueryShapesPerEndpoint)
		}
	})
}

// POST endpoints are out of scope for this GET-only capability.
func TestRawQueryInjectionIgnoresNonGET(t *testing.T) {
	c, st, _, _ := newCollector(t, rawQueryConfig(discovery.RawQueryAlways))
	ctx := context.Background()
	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/api", Method: domain.MethodPOST, Source: domain.SourceUserProvided,
	})
	if err != nil || id == "" {
		t.Fatalf("AddEndpoint: id=%q err=%v", id, err)
	}
	if got := rawParams(t, st, ctx, id); len(got) != 0 {
		t.Fatalf("a POST endpoint got %d raw-query parameter(s); want 0", len(got))
	}
}

// The hard bounds: 2 shapes per endpoint and 40 probes per scan, each probe
// being exactly one extra reflection request. 25 bare endpoints would yield 50
// probes unbounded; exactly 40 are registered (the first 20 endpoints).
func TestRawQueryInjectionCaps(t *testing.T) {
	c, st, q, scanID := newCollector(t, rawQueryConfig(discovery.RawQueryAlways))
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
			URL: fmt.Sprintf("http://example.com/page%d", i), Method: domain.MethodGET, Source: domain.SourceCrawler,
		})
		if err != nil || id == "" {
			t.Fatalf("AddEndpoint %d: id=%q err=%v", i, id, err)
		}
		got := rawParams(t, st, ctx, id)
		if len(got) > discovery.MaxRawQueryShapesPerEndpoint {
			t.Fatalf("endpoint %d registered %d raw-query parameters; per-endpoint cap is %d",
				i, len(got), discovery.MaxRawQueryShapesPerEndpoint)
		}
	}

	ps, _ := st.Parameters().ListByScan(ctx, scanID)
	raw := 0
	for _, p := range ps {
		if p.Location == domain.LocationRawQuery {
			raw++
		}
	}
	if raw != discovery.MaxRawQueryProbesPerScan {
		t.Fatalf("scan registered %d raw-query probes; want exactly the cap %d", raw, discovery.MaxRawQueryProbesPerScan)
	}

	// One injection point (and therefore one mutated reflection request) per
	// probe, and no more.
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	rawIPs := 0
	for _, ip := range ips {
		if ip.Location == domain.LocationRawQuery {
			rawIPs++
		}
	}
	if rawIPs != discovery.MaxRawQueryProbesPerScan {
		t.Fatalf("scan persisted %d raw-query injection points; want %d", rawIPs, discovery.MaxRawQueryProbesPerScan)
	}

	// Jobs: exactly one per raw-query probe. Other injection points (headers)
	// are unrelated and are not counted here.
	if n := countRawQueryJobs(t, q, scanID, ips); n != discovery.MaxRawQueryProbesPerScan {
		t.Fatalf("scan enqueued %d raw-query jobs; want %d (one per probe)", n, discovery.MaxRawQueryProbesPerScan)
	}
}

// Resuming a scan must not reset or overshoot the per-scan budget: the budget
// is restored from the persisted rows, and a newly discovered endpoint is still
// capped.
func TestRawQueryInjectionCapSurvivesHydrate(t *testing.T) {
	ctx := context.Background()
	st, q := newMemoryPair()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	cfg := rawQueryConfig(discovery.RawQueryAlways)

	c := discovery.NewCollector(st, q, scanID, scope, false, cfg, quiet())
	for i := 0; i < 20; i++ { // exactly the 40-probe budget: 2 per endpoint
		if _, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
			URL: fmt.Sprintf("http://example.com/a%d", i), Method: domain.MethodGET, Source: domain.SourceCrawler,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Simulate a restart: a fresh collector hydrates from the store.
	c2 := discovery.NewCollector(st, q, scanID, scope, false, cfg, quiet())
	if err := c2.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := c2.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/late", Method: domain.MethodGET, Source: domain.SourceCrawler,
	})
	if err != nil || id == "" {
		t.Fatalf("AddEndpoint after hydrate: id=%q err=%v", id, err)
	}
	if got := rawParams(t, st, ctx, id); len(got) != 0 {
		t.Fatalf("a resumed scan exceeded its raw-query cap: late endpoint got %d probe(s)", len(got))
	}
	ps, _ := st.Parameters().ListByScan(ctx, scanID)
	raw := 0
	for _, p := range ps {
		if p.Location == domain.LocationRawQuery {
			raw++
		}
	}
	if raw != discovery.MaxRawQueryProbesPerScan {
		t.Fatalf("after resume: %d raw-query probes persisted; want %d", raw, discovery.MaxRawQueryProbesPerScan)
	}
}

func names(ps []*domain.Parameter) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name+" ("+string(p.Location)+")")
	}
	return out
}
