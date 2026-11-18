package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

type formTestSink struct {
	endpoints []EndpointCandidate
	params    []ParamCandidate
}

func (s *formTestSink) AddEndpoint(_ context.Context, ep EndpointCandidate) (domain.ID, error) {
	s.endpoints = append(s.endpoints, ep)
	return domain.NewID(), nil
}
func (s *formTestSink) AddParameter(_ context.Context, p ParamCandidate) error {
	s.params = append(s.params, p)
	return nil
}

func TestEmitFormsFromRenderedHTML(t *testing.T) {
	sink := &formTestSink{}
	n := &networkSource{}
	body := `<form action="/save" method="post"><input name="q" value="hello"></form>`
	if err := n.emitForms(context.Background(), Input{
		Scope: domain.Scope{IncludeHosts: []string{"example.test"}},
	}, sink, "http://example.test/page", body); err != nil {
		t.Fatal(err)
	}
	if len(sink.endpoints) != 1 || sink.endpoints[0].URL != "http://example.test/save" ||
		sink.endpoints[0].Method != domain.MethodPOST {
		t.Fatalf("endpoints = %+v", sink.endpoints)
	}
	if len(sink.params) != 1 || sink.params[0].Name != "q" || sink.params[0].Location != domain.LocationForm {
		t.Fatalf("params = %+v", sink.params)
	}
}

func TestEmitNetworkExtractsFormsFromHTMLFragmentGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/SqlInjection.lesson.lesson" {
			w.Header().Set("Content-Type", "text/html;charset=UTF-8")
			_, _ = w.Write([]byte(`<html><form action="/SqlInjection/attack2" method="POST"><input name="query" value="SELECT 1"></form></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := httpengine.New(httpengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sink := &formTestSink{}
	n := &networkSource{engine: eng}
	in := Input{Scope: domain.Scope{IncludeHosts: []string{u.Hostname()}}}
	seenHTML := make(map[string]struct{})
	network := []browser.NetworkEvent{{
		Method: "GET",
		URL:    srv.URL + "/SqlInjection.lesson.lesson",
	}}
	if err := n.emitNetworkWithHTML(context.Background(), in, sink, network, seenHTML); err != nil {
		t.Fatal(err)
	}
	if len(sink.endpoints) != 2 {
		t.Fatalf("endpoints = %+v, want 2 (fragment + form action)", sink.endpoints)
	}
	if sink.endpoints[1].URL != srv.URL+"/SqlInjection/attack2" || sink.endpoints[1].Method != domain.MethodPOST {
		t.Fatalf("form endpoint = %+v, want POST /SqlInjection/attack2", sink.endpoints[1])
	}
	if len(sink.params) != 1 || sink.params[0].Name != "query" || sink.params[0].Location != domain.LocationForm {
		t.Fatalf("params = %+v, want form param query", sink.params)
	}
}
