package discovery

import (
	"context"
	"net/http"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

type stubHydrateEngine struct {
	responses map[string]*httpengine.Response
}

func (e *stubHydrateEngine) Do(_ context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	if resp, ok := e.responses[req.URL]; ok {
		return resp, nil
	}
	return &httpengine.Response{Status: 404, Headers: http.Header{}}, nil
}

func TestHydratePlaceholderEndpoints(t *testing.T) {
	sc := domain.Scope{IncludeHosts: []string{"app.test"}}
	eng := &stubHydrateEngine{
		responses: map[string]*httpengine.Response{
			"http://app.test/workshop/api/shop/orders/all?limit=30&offset=0": {
				Status:  200,
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"orders":[{"id":6,"quantity":1}]}`),
			},
			"http://app.test/workshop/api/shop/orders/6": {
				Status:  200,
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"id":6,"status":"delivered"}`),
			},
			"http://app.test/community/api/v2/community/posts/recent": {
				Status:  200,
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"posts":[{"id":"abc123","title":"hi"}]}`),
			},
			"http://app.test/community/api/v2/community/posts/abc123": {
				Status:  200,
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"id":"abc123"}`),
			},
			"http://app.test/workshop/api/mechanic/list": {
				Status:  200,
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"reports":[{"report_id":42}]}`),
			},
			"http://app.test/workshop/api/mechanic/mechanic_report?report_id=42": {
				Status:  200,
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"report_id":42}`),
			},
		},
	}
	n := &networkSource{engine: eng}
	sink := &formTestSink{}
	in := Input{Scope: sc}
	observed := map[string]struct{}{
		"http://app.test/workshop/api/shop/orders/null":                   {},
		"http://app.test/workshop/api/shop/orders/all?limit=30&offset=0":  {},
		"http://app.test/community/api/v2/community/posts/null":           {},
		"http://app.test/community/api/v2/community/posts/recent":         {},
		"http://app.test/workshop/api/mechanic/mechanic_report?report_id=null": {},
		"http://app.test/workshop/api/mechanic/list":                      {},
		"http://app.test/identity/api/v2/user/videos/undefined":           {},
	}

	if err := n.hydratePlaceholderEndpoints(context.Background(), in, sink, observed); err != nil {
		t.Fatalf("hydratePlaceholderEndpoints: %v", err)
	}

	want := map[string]bool{
		"http://app.test/workshop/api/shop/orders/6":                         false,
		"http://app.test/community/api/v2/community/posts/abc123":            false,
		"http://app.test/workshop/api/mechanic/mechanic_report?report_id=42": false,
	}
	for _, ep := range sink.endpoints {
		if _, ok := want[ep.URL]; ok && ep.Method == domain.MethodGET {
			want[ep.URL] = true
		}
	}
	for u, found := range want {
		if !found {
			t.Errorf("expected hydrated endpoint %s to be registered", u)
		}
	}
}
