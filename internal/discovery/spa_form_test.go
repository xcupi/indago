package discovery

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/domain"
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
