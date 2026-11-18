package discovery

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// recordingSink captures what a source registers, without a store.
type recordingSink struct {
	endpoints []EndpointCandidate
	params    []ParamCandidate
}

func (s *recordingSink) AddEndpoint(_ context.Context, ep EndpointCandidate) (domain.ID, error) {
	s.endpoints = append(s.endpoints, ep)
	return domain.NewID(), nil
}

func (s *recordingSink) AddParameter(_ context.Context, p ParamCandidate) error {
	s.params = append(s.params, p)
	return nil
}

// A request declared in a page's own inline script must reach the sink with its
// method, content type and literal body — that body is the only reason the XXE
// engine can probe such an endpoint at all. An out-of-scope declaration is
// dropped, and no request is ever sent by this path.
func TestEmitScriptDeclaredRequestsRegistersBodyEndpoint(t *testing.T) {
	sink := &recordingSink{}
	html := `<script>
var x = new XMLHttpRequest();
x.open("POST", "xxe-2.php", true);
x.setRequestHeader("Content-Type", "text/xml");
x.send("<reset><login>bee</login></reset>");
var y = new XMLHttpRequest();
y.open("POST", "http://other.example/collect");
y.send("a=1");
</script>`
	in := Input{Scope: domain.Scope{IncludeHosts: []string{"example.test"}}}
	if err := emitScriptDeclaredRequests(context.Background(), in, sink, "http://example.test/xxe-1.php", html); err != nil {
		t.Fatal(err)
	}
	if len(sink.endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want 1 (out-of-scope declaration dropped)", sink.endpoints)
	}
	ep := sink.endpoints[0]
	if ep.URL != "http://example.test/xxe-2.php" || ep.Method != domain.MethodPOST {
		t.Fatalf("endpoint = %+v", ep)
	}
	if ep.ContentType != "text/xml" || ep.RequestBody == "" {
		t.Fatalf("endpoint lost its declared body/content type: %+v", ep)
	}
	if ep.Source != domain.SourceScriptLiteral {
		t.Fatalf("source = %q, want %q", ep.Source, domain.SourceScriptLiteral)
	}
	if len(sink.params) != 0 {
		t.Fatalf("XML declaration produced parameters: %+v", sink.params)
	}
}

// The answer to "is a body-carrying method allowed" still belongs to the
// existing guards: a sink that refuses the fetch must not see the endpoint.
func TestEmitScriptDeclaredRequestsHonoursFetchGuard(t *testing.T) {
	sink := &guardedSink{}
	html := `<script>
var x = new XMLHttpRequest();
x.open("GET", "/delete?id=1");
</script>`
	in := Input{Scope: domain.Scope{IncludeHosts: []string{"example.test"}}}
	if err := emitScriptDeclaredRequests(context.Background(), in, sink, "http://example.test/page", html); err != nil {
		t.Fatal(err)
	}
	if len(sink.endpoints) != 0 {
		t.Fatalf("guarded declaration was registered: %+v", sink.endpoints)
	}
}

type guardedSink struct{ recordingSink }

func (s *guardedSink) AllowFetch(string, domain.DiscoverySource, domain.HTTPMethod) bool {
	return false
}
