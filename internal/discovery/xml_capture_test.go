package discovery

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// The XXE engine can only probe a body discovery actually captured, so an XML
// request body observed from XHR/fetch must be persisted verbatim on the
// endpoint (and must not be mistaken for a JSON parameter map).
func TestEmitNetworkCapturesXMLRequestBody(t *testing.T) {
	const (
		stockBody = `<stockCheck><productId>1</productId></stockCheck>`
		orderBody = `<order><id>7</id></order>`
		soapBody  = `<soap:Envelope><soap:Body/></soap:Envelope>`
	)
	sink := &formTestSink{}
	n := &networkSource{}
	in := Input{Scope: domain.Scope{IncludeHosts: []string{"example.test"}}}
	network := []browser.NetworkEvent{
		{URL: "http://example.test/api/stock", Method: "POST", ResourceType: "fetch",
			ContentType: "application/xml", PostData: stockBody},
		{URL: "http://example.test/api/order", Method: "POST", ResourceType: "xhr",
			ContentType: "text/xml; charset=utf-8", PostData: orderBody},
		{URL: "http://example.test/api/soap", Method: "POST", ResourceType: "xhr",
			ContentType: "application/soap+xml", PostData: soapBody},
		{URL: "http://example.test/api/json", Method: "POST", ResourceType: "fetch",
			ContentType: "application/json", PostData: `{"id":1}`},
	}
	if err := n.emitNetwork(context.Background(), in, sink, network); err != nil {
		t.Fatalf("emitNetwork: %v", err)
	}

	bodies := map[string]string{}
	for _, ep := range sink.endpoints {
		bodies[ep.URL] = ep.RequestBody
	}
	for url, want := range map[string]string{
		"http://example.test/api/stock": stockBody,
		"http://example.test/api/order": orderBody,
		"http://example.test/api/soap":  soapBody,
		"http://example.test/api/json":  "",
	} {
		if got := bodies[url]; got != want {
			t.Fatalf("%s request body = %q, want %q", url, got, want)
		}
	}

	// Only the JSON event yields parameters; an XML body's elements are not
	// flattened into individual injection points.
	for _, p := range sink.params {
		if p.EndpointURL != "http://example.test/api/json" {
			t.Fatalf("XML request produced a parameter: %+v", p)
		}
	}
}

func TestIsXMLContentType(t *testing.T) {
	cases := map[string]bool{
		"application/xml":                   true,
		"text/xml":                          true,
		"text/xml; charset=utf-8":           true,
		"application/soap+xml":              true,
		"application/atom+xml":              true,
		"application/json":                  false,
		"application/x-www-form-urlencoded": false,
		"text/html":                         false,
		"":                                  false,
		"not a media type":                  false,
	}
	for raw, want := range cases {
		if got := isXMLContentType(raw); got != want {
			t.Fatalf("isXMLContentType(%q) = %v, want %v", raw, got, want)
		}
	}
}
