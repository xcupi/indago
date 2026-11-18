package discovery

import (
	"context"
	"net/http"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

type batchHashBrowser struct {
	renderCalls int
	batchCalls  int
	lastFrags   []string
	pages       map[string]*browser.RenderResult
}

func (b *batchHashBrowser) Render(_ context.Context, url string, _ browser.RenderOptions) (*browser.RenderResult, error) {
	b.renderCalls++
	if res, ok := b.pages[url]; ok {
		return res, nil
	}
	return &browser.RenderResult{FinalURL: url, Status: 200}, nil
}

func (b *batchHashBrowser) RenderHashRoutes(_ context.Context, baseURL string, fragments []string, _ browser.RenderOptions) ([]*browser.RenderResult, error) {
	b.batchCalls++
	b.lastFrags = append([]string(nil), fragments...)
	out := make([]*browser.RenderResult, len(fragments))
	for i, frag := range fragments {
		u := baseURL + frag
		if res, ok := b.pages[u]; ok {
			out[i] = res
		} else {
			out[i] = &browser.RenderResult{FinalURL: u, Status: 200}
		}
	}
	return out, nil
}

func (b *batchHashBrowser) Close() error { return nil }

func TestNetworkSourceBatchesHashRoutesAndHarvestsNestedSPA(t *testing.T) {
	base := "http://app.test"
	b := &batchHashBrowser{
		pages: map[string]*browser.RenderResult{
			base + "/welcome.mvc": {
				FinalURL: base + "/welcome.mvc",
				Status:   200,
				HTML:     `<a href="/start.mvc">Start</a>`,
			},
			base + "/start.mvc": {
				FinalURL: base + "/start.mvc",
				Status:   200,
				HTML:     `<a href="#lesson/One.lesson">1</a><a href="#lesson/Two.lesson">2</a>`,
			},
			base + "/start.mvc#lesson/One.lesson": {
				FinalURL: base + "/start.mvc#lesson/One.lesson",
				Status:   200,
				Network:  []browser.NetworkEvent{{URL: base + "/LessonOne/attack", Method: "POST"}},
			},
			base + "/start.mvc#lesson/Two.lesson": {
				FinalURL: base + "/start.mvc#lesson/Two.lesson",
				Status:   200,
				HTML:     `<form method="POST" action="/LessonTwo/attack"><input name="x"></form>`,
			},
		},
	}

	scope := domain.Scope{IncludeHosts: []string{"app.test"}}
	eng := &stubHydrateEngine{responses: map[string]*httpengine.Response{
		base + "/LessonOne/attack": {Status: 200, Headers: http.Header{}},
	}}

	src := NewNetworkSourceWithEngine(b, eng, Config{})
	sink := &formTestSink{}
	err := src.Run(context.Background(), Input{
		Scope:    scope,
		SeedURLs: []string{base + "/welcome.mvc"},
	}, sink)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if b.batchCalls != 1 {
		t.Fatalf("batchCalls = %d, want 1 (got frags %v)", b.batchCalls, b.lastFrags)
	}
	if len(b.lastFrags) != 2 {
		t.Fatalf("lastFrags = %v, want 2 hash routes", b.lastFrags)
	}
	hasEndpoint := func(method domain.HTTPMethod, u string) bool {
		for _, ep := range sink.endpoints {
			if ep.Method == method && ep.URL == u {
				return true
			}
		}
		return false
	}
	if !hasEndpoint(domain.MethodPOST, base+"/LessonOne/attack") {
		t.Fatalf("missing LessonOne/attack endpoint; got %+v", sink.endpoints)
	}
	if !hasEndpoint(domain.MethodPOST, base+"/LessonTwo/attack") {
		t.Fatalf("missing LessonTwo/attack endpoint; got %+v", sink.endpoints)
	}
}
