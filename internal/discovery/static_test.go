package discovery_test

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

func TestStaticAssetPathsAreRecognized(t *testing.T) {
	static := []string{
		"/dist/app.css", "/js/app.js", "/img/logo.svg", "/favicon.ico",
		"/fonts/x.woff2", "/photo.webp", "/manual.pdf", "/robots.txt",
	}
	for _, p := range static {
		if !discovery.IsStaticAssetPath(p) {
			t.Errorf("IsStaticAssetPath(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/", "/pricing", "/blog/why-vpn", "/api/v1/users"} {
		if discovery.IsStaticAssetPath(p) {
			t.Errorf("IsStaticAssetPath(%q) = true, want false", p)
		}
	}
}

func TestCollectorSkipsGlobalsAndStaticAssetsWhenConfigured(t *testing.T) {
	cfg := discovery.DefaultConfig()
	cfg.SkipGlobalInjection = true
	cfg.SkipStaticAssets = true
	c, st, _, scanID := newCollector(t, cfg)
	ctx := context.Background()

	if id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/assets/app.js?v=1", Method: domain.MethodGET, Source: domain.SourceCrawler,
	}); err != nil || id != "" {
		t.Fatalf("static crawler endpoint = %q, err=%v; want skipped", id, err)
	}
	if id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/pricing", Method: domain.MethodGET, Source: domain.SourceCrawler,
	}); err != nil || id == "" {
		t.Fatalf("HTML crawler endpoint = %q, err=%v; want registered", id, err)
	}
	params, err := st.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range params {
		if p.Location == domain.LocationHeader || p.Location == domain.LocationCookie {
			t.Fatalf("global injection point registered despite SkipGlobalInjection: %+v", p)
		}
	}
}
