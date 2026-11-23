package discovery_test

// Tests for the OpenAPI/Swagger import source. The contract under test:
//   - both dialects are read (OpenAPI 3 `servers`/`components.schemas`,
//     Swagger 2.0 `host`/`basePath`/`definitions`);
//   - local refs resolve, path variables become concrete values, and query
//     parameters / JSON bodies are synthesized from the schema;
//   - only in-scope URLs are registered, an unparseable document is an error
//     rather than a silent no-op, and nothing is ever requested from a
//     declared endpoint.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// runOpenAPISpec runs the source over one Input and returns what it registered.
func runOpenAPISpec(t *testing.T, src discovery.Source, in discovery.Input) *recordingSink {
	t.Helper()
	sink := &recordingSink{}
	if err := src.Run(context.Background(), in, sink); err != nil {
		t.Fatalf("openapi run: %v", err)
	}
	return sink
}

// specEndpoints indexes the registered endpoints by "METHOD url".
func specEndpoints(sink *recordingSink) map[string]discovery.EndpointCandidate {
	out := map[string]discovery.EndpointCandidate{}
	for _, ep := range sink.eps {
		out[string(ep.Method)+" "+ep.URL] = ep
	}
	return out
}

// specParamsFor returns the parameters registered for one endpoint, by name.
func specParamsFor(sink *recordingSink, method domain.HTTPMethod, url string) map[string]discovery.ParamCandidate {
	out := map[string]discovery.ParamCandidate{}
	for _, p := range sink.params {
		if p.EndpointMethod == method && p.EndpointURL == url {
			out[p.Name] = p
		}
	}
	return out
}

// An OpenAPI 3 document: a relative `servers` URL resolved against the seed, a
// templated path variable taken from its declared example, query parameters
// synthesized from enum/default, and a JSON request body built from a
// $ref'd schema.
func TestOpenAPIV3ImportsPathsQueryAndJSONBody(t *testing.T) {
	const spec = `{
	  "openapi": "3.0.3",
	  "info": {"title": "t", "version": "1"},
	  "servers": [{"url": "/api/v1"}],
	  "paths": {
	    "/users/{userId}": {
	      "parameters": [
	        {"name": "userId", "in": "path", "required": true,
	         "schema": {"type": "integer", "example": 42}}
	      ],
	      "get": {
	        "parameters": [
	          {"name": "expand", "in": "query", "schema": {"type": "string", "enum": ["profile"]}},
	          {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}}
	        ]
	      },
	      "post": {
	        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewUser"}}}}
	      }
	    }
	  },
	  "components": {
	    "schemas": {
	      "NewUser": {
	        "type": "object",
	        "required": ["name"],
	        "properties": {
	          "name": {"type": "string", "example": "ada"},
	          "age": {"type": "integer"},
	          "admin": {"type": "boolean"},
	          "tags": {"type": "array", "items": {"type": "string"}}
	        }
	      }
	    }
	  }
	}`

	src := discovery.NewOpenAPISource(nil) // inline document: no engine needed
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: spec,
	})

	eps := specEndpoints(sink)
	get, ok := eps["GET http://app.example.test/api/v1/users/42?expand=profile&page=1"]
	if !ok {
		t.Fatalf("GET endpoint not registered as expected; got %v", sink.endpointURLs())
	}
	if strings.Contains(get.URL, "{") {
		t.Fatalf("templated path registered literally: %s", get.URL)
	}
	if _, ok := eps["POST http://app.example.test/api/v1/users/42"]; !ok {
		t.Fatalf("POST endpoint not registered; got %v", sink.endpointURLs())
	}

	post := eps["POST http://app.example.test/api/v1/users/42"]
	if post.ContentType != "application/json" {
		t.Fatalf("content type = %q, want application/json", post.ContentType)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(post.RequestBody), &body); err != nil {
		t.Fatalf("JSON body skeleton is not valid JSON (%q): %v", post.RequestBody, err)
	}
	if body["name"] != "ada" {
		t.Fatalf("body did not carry the schema example: %v", body)
	}
	if body["age"] != float64(0) || body["admin"] != false {
		t.Fatalf("body did not use type-derived placeholders: %v", body)
	}
	if tags, ok := body["tags"].([]any); !ok || len(tags) != 0 {
		t.Fatalf("array property skeleton = %v, want []", body["tags"])
	}

	params := specParamsFor(sink, domain.MethodPOST, post.URL)
	for _, want := range []string{"name", "age", "admin", "tags"} {
		p, ok := params[want]
		if !ok {
			t.Fatalf("JSON body property %q not registered as a parameter; got %v", want, params)
		}
		if p.Location != domain.LocationJSON {
			t.Fatalf("%q location = %s, want json", want, p.Location)
		}
		if p.Source != domain.SourceOpenAPI {
			t.Fatalf("%q source = %s, want openapi", want, p.Source)
		}
	}
	if params["name"].Example != `"ada"` {
		t.Fatalf("name example = %s, want the JSON string literal \"ada\"", params["name"].Example)
	}
}

// A Swagger 2.0 document: host/basePath/schemes decide the base URL,
// definitions resolve the body ref, and a type-only query parameter (no
// schema object) still yields a concrete value.
func TestSwaggerV2ImportsBasePathDefinitionsAndQueryParams(t *testing.T) {
	const spec = `{
	  "swagger": "2.0",
	  "info": {"title": "t", "version": "1"},
	  "host": "api.example.test",
	  "basePath": "/v2",
	  "schemes": ["http"],
	  "paths": {
	    "/orders": {
	      "post": {
	        "parameters": [
	          {"name": "body", "in": "body", "required": true,
	           "schema": {"$ref": "#/definitions/Order"}},
	          {"name": "dryRun", "in": "query", "type": "boolean", "default": false}
	        ]
	      },
	      "get": {
	        "parameters": [{"name": "limit", "in": "query", "type": "integer", "default": 10}]
	      }
	    }
	  },
	  "definitions": {
	    "Order": {
	      "type": "object",
	      "properties": {
	        "id": {"type": "integer"},
	        "note": {"type": "string", "example": "hi"}
	      }
	    }
	  }
	}`

	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://api.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"api.example.test"}},
		OpenAPISpecJSON: spec,
	})

	eps := specEndpoints(sink)
	get, ok := eps["GET http://api.example.test/v2/orders?limit=10"]
	if !ok {
		t.Fatalf("swagger GET not registered with basePath and query; got %v", sink.endpointURLs())
	}
	if get.Source != domain.SourceOpenAPI {
		t.Fatalf("source = %s, want %s", get.Source, domain.SourceOpenAPI)
	}
	post, ok := eps["POST http://api.example.test/v2/orders?dryRun=false"]
	if !ok {
		t.Fatalf("swagger POST not registered; got %v", sink.endpointURLs())
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(post.RequestBody), &body); err != nil {
		t.Fatalf("definitions ref did not produce a JSON body (%q): %v", post.RequestBody, err)
	}
	if body["note"] != "hi" {
		t.Fatalf("body did not resolve #/definitions/Order: %v", body)
	}
	params := specParamsFor(sink, domain.MethodPOST, post.URL)
	if len(params) != 2 {
		t.Fatalf("POST parameters = %v, want the two body properties", params)
	}
	if _, ok := params["note"]; !ok {
		t.Fatalf("body property 'note' missing from %v", params)
	}
}

// Scope is enforced before registration: a document describing a host outside
// the scan's scope contributes nothing, and in-scope paths in the same document
// still come through.
func TestOpenAPIDropsOutOfScopeEndpoints(t *testing.T) {
	const spec = `{
	  "openapi": "3.0.0",
	  "servers": [{"url": "https://api.example.test"}],
	  "paths": {
	    "/inside": {"get": {}},
	    "/also-inside": {"get": {}}
	  }
	}`

	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"https://api.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"other.test"}},
		OpenAPISpecJSON: spec,
	})
	if got := sink.endpointURLs(); len(got) != 0 {
		t.Fatalf("out-of-scope spec registered endpoints: %v", got)
	}

	sink = runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"https://api.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"api.example.test"}},
		OpenAPISpecJSON: spec,
	})
	if got := len(sink.endpointURLs()); got != 2 {
		t.Fatalf("in-scope spec registered %d endpoints, want 2: %v", got, sink.endpointURLs())
	}

	// A path-prefix exclusion must also be honoured.
	sink = runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"https://api.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"api.example.test"}, ExcludePathPrefixes: []string{"/inside"}},
		OpenAPISpecJSON: spec,
	})
	got := sink.endpointURLs()
	if len(got) != 1 || !strings.HasSuffix(got[0], "/also-inside") {
		t.Fatalf("path-prefix exclusion not enforced: %v", got)
	}
}

// A document that is not JSON at all is an error (the operator supplied
// something broken and must hear about it), never a silent empty scan.
func TestOpenAPIInvalidJSONIsAnError(t *testing.T) {
	src := discovery.NewOpenAPISource(nil)
	sink := &recordingSink{}
	err := src.Run(context.Background(), discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: `{"openapi": "3.0.0", "paths": {`,
	}, sink)
	if err == nil {
		t.Fatal("invalid JSON was accepted")
	}
	if !strings.Contains(err.Error(), "parse document") {
		t.Fatalf("error does not name the parse failure: %v", err)
	}
	if len(sink.eps) != 0 {
		t.Fatalf("invalid document registered %d endpoints", len(sink.eps))
	}

	// JSON that is valid but is not a spec is refused too.
	err = src.Run(context.Background(), discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: `{"hello": "world"}`,
	}, &recordingSink{})
	if err == nil {
		t.Fatal("a non-OpenAPI JSON document was accepted")
	}
}

// A spec URL is fetched exactly once, through the engine, and only the spec
// document is ever requested: declared endpoints are registered, not probed.
func TestOpenAPISpecURLFetchesOnlyTheDocument(t *testing.T) {
	var specHits, endpointHits atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		specHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"openapi":"3.0.0","servers":[{"url":%q}],"paths":{"/api/items":{"get":{}},"/api/orders":{"post":{}}}}`, srv.URL)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		endpointHits.Add(1)
	})
	// A path the spec declares, to prove discovery never sends it.
	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		endpointHits.Add(1)
	})

	info, err := discovery.Normalize(srv.URL)
	if err != nil {
		t.Fatalf("normalize test server url: %v", err)
	}
	eng := &countingEngine{inner: httpengine.NewDefault()}
	src := discovery.NewOpenAPISource(eng)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:       []string{srv.URL},
		Scope:          domain.Scope{IncludeHosts: []string{info.Host}},
		OpenAPISpecURL: srv.URL + "/openapi.json",
	})

	if got := specHits.Load(); got != 1 {
		t.Fatalf("spec fetched %d times, want exactly 1", got)
	}
	if got := endpointHits.Load(); got != 0 {
		t.Fatalf("%d requests were sent to declared endpoints; discovery must only register them", got)
	}
	if got := eng.n.Load(); got != 1 {
		t.Fatalf("engine saw %d requests, want only the spec GET", got)
	}
	if got := len(sink.endpointURLs()); got != 2 {
		t.Fatalf("registered %d endpoints, want 2: %v", got, sink.endpointURLs())
	}
	// An out-of-scope spec URL is refused before any request is made.
	before := specHits.Load()
	sink2 := &recordingSink{}
	err = src.Run(context.Background(), discovery.Input{
		SeedURLs:       []string{"http://elsewhere.test/"},
		Scope:          domain.Scope{IncludeHosts: []string{"elsewhere.test"}},
		OpenAPISpecURL: srv.URL + "/openapi.json",
	}, sink2)
	if err == nil || !strings.Contains(err.Error(), "outside scope") {
		t.Fatalf("out-of-scope spec URL: err = %v, want a scope refusal", err)
	}
	if after := specHits.Load(); after != before {
		t.Fatalf("an out-of-scope spec URL was fetched anyway (%d -> %d hits)", before, after)
	}
	if len(sink2.eps) != 0 {
		t.Fatal("out-of-scope spec registered endpoints")
	}
}

// The endpoint count is bounded, so a generated spec for a large product cannot
// flood the queue ahead of what the crawl itself found.
func TestOpenAPIEndpointCountIsBounded(t *testing.T) {
	paths := make(map[string]any, 260)
	for i := 0; i < 260; i++ {
		paths[fmt.Sprintf("/p%03d", i)] = map[string]any{"get": map[string]any{}}
	}
	doc, err := json.Marshal(map[string]any{
		"openapi": "3.0.0",
		"servers": []any{map[string]any{"url": "http://app.example.test"}},
		"paths":   paths,
	})
	if err != nil {
		t.Fatalf("build spec: %v", err)
	}
	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: string(doc),
	})
	if got := len(sink.endpointURLs()); got != 200 {
		t.Fatalf("registered %d endpoints, want the 200 cap", got)
	}
}

// A self-referential schema is legal; resolving it must terminate with a
// bounded skeleton instead of recursing until the stack gives out.
func TestOpenAPIRecursiveSchemaTerminates(t *testing.T) {
	const spec = `{
	  "openapi": "3.1.0",
	  "servers": [{"url": "http://app.example.test"}],
	  "paths": {
	    "/nodes": {
	      "post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}
	    }
	  },
	  "components": {
	    "schemas": {
	      "Node": {
	        "type": "object",
	        "properties": {
	          "name": {"type": "string"},
	          "child": {"$ref": "#/components/schemas/Node"}
	        }
	      }
	    }
	  }
	}`
	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: spec,
	})
	eps := specEndpoints(sink)
	ep, ok := eps["POST http://app.example.test/nodes"]
	if !ok {
		t.Fatalf("POST /nodes not registered: %v", sink.endpointURLs())
	}
	if len(ep.RequestBody) > 64<<10 {
		t.Fatalf("recursive schema produced a %d-byte body; recursion is not bounded", len(ep.RequestBody))
	}
	if !json.Valid([]byte(ep.RequestBody)) {
		t.Fatalf("bounded skeleton is not valid JSON: %q", ep.RequestBody)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(ep.RequestBody), &body); err != nil {
		t.Fatalf("unmarshal skeleton: %v", err)
	}
	if _, ok := body["name"]; !ok {
		t.Fatalf("skeleton lost the non-recursive property: %v", body)
	}
}

// An undeclared path variable cannot become a requestable URL, so the path is
// skipped rather than registered with a literal "{id}".
func TestOpenAPISkipsUndeclaredPathVariables(t *testing.T) {
	const spec = `{
	  "openapi": "3.0.0",
	  "servers": [{"url": "http://app.example.test"}],
	  "paths": {
	    "/users/{id}": {"get": {}},
	    "/health": {"get": {}}
	  }
	}`
	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: spec,
	})
	urls := sink.endpointURLs()
	if len(urls) != 1 || !strings.HasSuffix(urls[0], "/health") {
		t.Fatalf("undeclared path variable was not skipped: %v", urls)
	}
	for _, u := range urls {
		if strings.ContainsAny(u, "{}") {
			t.Fatalf("literal placeholder registered: %s", u)
		}
	}
}

// No spec supplied means no work at all: the source is registered on every
// scan, so it must be inert (and engine-free) when the operator gave none.
func TestOpenAPINoSpecIsANoOp(t *testing.T) {
	calls := atomic.Int64{}
	src := discovery.NewOpenAPISource(engineFunc(func(context.Context, *httpengine.Request) (*httpengine.Response, error) {
		calls.Add(1)
		return nil, fmt.Errorf("must not be called")
	}))
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs: []string{"http://app.example.test/"},
		Scope:    domain.Scope{IncludeHosts: []string{"app.example.test"}},
	})
	if calls.Load() != 0 || len(sink.eps) != 0 || len(sink.params) != 0 {
		t.Fatalf("source did work with no spec: %d calls, %d endpoints", calls.Load(), len(sink.eps))
	}
}

// OpenAPI 3.x YAML documents are normalized into the same model: relative
// servers, path/query parameters, numeric response keys, and local $refs
// under components.schemas all work identically to JSON.
func TestOpenAPIV3YAMLImportsPathsQueryAndJSONBody(t *testing.T) {
	const spec = `
openapi: "3.0.3"
info:
  title: t
  version: "1"
servers:
  - url: /api/v1
paths:
  /users/{userId}:
    parameters:
      - name: userId
        in: path
        required: true
        schema:
          type: integer
          example: 42
    get:
      parameters:
        - name: expand
          in: query
          schema:
            type: string
            enum:
              - profile
        - name: page
          in: query
          schema:
            type: integer
            default: 1
      responses:
        200:
          description: ok
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/NewUser"
      responses:
        201:
          description: created
components:
  schemas:
    NewUser:
      type: object
      required:
        - name
      properties:
        name:
          type: string
          example: ada
        age:
          type: integer
        admin:
          type: boolean
        tags:
          type: array
          items:
            type: string
`

	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: spec,
	})

	eps := specEndpoints(sink)
	if _, ok := eps["GET http://app.example.test/api/v1/users/42?expand=profile&page=1"]; !ok {
		t.Fatalf("YAML GET endpoint not registered as expected; got %v", sink.endpointURLs())
	}
	post, ok := eps["POST http://app.example.test/api/v1/users/42"]
	if !ok {
		t.Fatalf("YAML POST endpoint not registered; got %v", sink.endpointURLs())
	}
	if post.ContentType != "application/json" {
		t.Fatalf("content type = %q, want application/json", post.ContentType)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(post.RequestBody), &body); err != nil {
		t.Fatalf("JSON body skeleton from YAML is not valid JSON (%q): %v", post.RequestBody, err)
	}
	if body["name"] != "ada" || body["age"] != float64(0) || body["admin"] != false {
		t.Fatalf("body from YAML $ref unexpected: %v", body)
	}
	if tags, ok := body["tags"].([]any); !ok || len(tags) != 0 {
		t.Fatalf("array property skeleton = %v, want []", body["tags"])
	}
	params := specParamsFor(sink, domain.MethodPOST, post.URL)
	if len(params) != 4 {
		t.Fatalf("POST parameters = %v, want 4 body properties", params)
	}
	if params["name"].Example != `"ada"` {
		t.Fatalf("name example = %s, want \"ada\"", params["name"].Example)
	}
}

// Swagger 2.0 YAML documents resolve host/basePath/schemes and local
// #/definitions refs identically to JSON.
func TestSwaggerV2YAMLImportsBasePathDefinitionsAndQueryParams(t *testing.T) {
	const spec = `
swagger: "2.0"
info:
  title: t
  version: "1"
host: api.example.test
basePath: /v2
schemes:
  - http
paths:
  /orders:
    post:
      parameters:
        - name: body
          in: body
          required: true
          schema:
            $ref: "#/definitions/Order"
        - name: dryRun
          in: query
          type: boolean
          default: false
    get:
      parameters:
        - name: limit
          in: query
          type: integer
          default: 10
definitions:
  Order:
    type: object
    properties:
      id:
        type: integer
      note:
        type: string
        example: hi
`

	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://api.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"api.example.test"}},
		OpenAPISpecJSON: spec,
	})

	eps := specEndpoints(sink)
	if _, ok := eps["GET http://api.example.test/v2/orders?limit=10"]; !ok {
		t.Fatalf("swagger YAML GET not registered; got %v", sink.endpointURLs())
	}
	post, ok := eps["POST http://api.example.test/v2/orders?dryRun=false"]
	if !ok {
		t.Fatalf("swagger YAML POST not registered; got %v", sink.endpointURLs())
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(post.RequestBody), &body); err != nil {
		t.Fatalf("definitions ref from YAML did not produce JSON (%q): %v", post.RequestBody, err)
	}
	if body["note"] != "hi" {
		t.Fatalf("body did not resolve #/definitions/Order: %v", body)
	}
	params := specParamsFor(sink, domain.MethodPOST, post.URL)
	if len(params) != 2 {
		t.Fatalf("POST parameters = %v, want 2 body properties", params)
	}
}

// Malformed YAML and valid YAML that is not an OpenAPI/Swagger spec are both
// rejected with an error and register no endpoints.
func TestOpenAPIInvalidYAMLIsAnError(t *testing.T) {
	src := discovery.NewOpenAPISource(nil)
	sink := &recordingSink{}
	err := src.Run(context.Background(), discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: "openapi: \"3.0.0\"\npaths:\n  /bad: [unclosed",
	}, sink)
	if err == nil {
		t.Fatal("invalid YAML was accepted")
	}
	if !strings.Contains(err.Error(), "parse document") {
		t.Fatalf("error does not name the parse failure: %v", err)
	}
	if len(sink.eps) != 0 {
		t.Fatalf("invalid YAML registered %d endpoints", len(sink.eps))
	}

	err = src.Run(context.Background(), discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: "hello: world\n",
	}, &recordingSink{})
	if err == nil {
		t.Fatal("a non-OpenAPI YAML document was accepted")
	}
}

// A YAML document served over HTTP is fetched and parsed exactly like a JSON
// one: the fetch path is format-agnostic, and a declared endpoint is still
// only registered, never requested.
func TestOpenAPIYAMLFetchedFromURLIsImported(t *testing.T) {
	var specHits, endpointHits atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		specHits.Add(1)
		w.Header().Set("Content-Type", "application/yaml")
		fmt.Fprint(w, `
swagger: "2.0"
info:
  title: t
  version: "1"
basePath: /v2
schemes:
  - http
paths:
  /widgets:
    get:
      parameters:
        - name: limit
          in: query
          type: integer
          default: 5
`)
	})
	mux.HandleFunc("/v2/widgets", func(w http.ResponseWriter, r *http.Request) {
		endpointHits.Add(1)
	})

	info, err := discovery.Normalize(srv.URL)
	if err != nil {
		t.Fatalf("normalize test server url: %v", err)
	}
	eng := &countingEngine{inner: httpengine.NewDefault()}
	src := discovery.NewOpenAPISource(eng)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:       []string{srv.URL},
		Scope:          domain.Scope{IncludeHosts: []string{info.Host}},
		OpenAPISpecURL: srv.URL + "/openapi.yaml",
	})

	if got := specHits.Load(); got != 1 {
		t.Fatalf("YAML spec fetched %d times, want exactly 1", got)
	}
	if got := endpointHits.Load(); got != 0 {
		t.Fatalf("%d requests were sent to a declared endpoint; discovery must only register it", got)
	}
	want := srv.URL + "/v2/widgets?limit=5"
	if _, ok := specEndpoints(sink)[string(domain.MethodGET)+" "+want]; !ok {
		t.Fatalf("YAML spec from url did not register %s; got %v", want, sink.endpointURLs())
	}
}

// YAML-only document features are honoured: an anchor/merge key shares one
// parameter shape, and a quoted scalar stays a string instead of being
// re-interpreted as a number.
func TestOpenAPIYAMLAnchorsAndMergeKeysAreImported(t *testing.T) {
	const spec = `
openapi: "3.0.3"
info:
  title: t
  version: "1"
servers:
  - url: http://app.example.test
paths:
  /search:
    get:
      parameters:
        - &paging
          name: page
          in: query
          schema:
            type: integer
            default: 1
        - <<: *paging
          name: size
        - name: code
          in: query
          schema:
            type: string
            example: "0042"
      responses:
        200:
          description: ok
`

	src := discovery.NewOpenAPISource(nil)
	sink := runOpenAPISpec(t, src, discovery.Input{
		SeedURLs:        []string{"http://app.example.test/"},
		Scope:           domain.Scope{IncludeHosts: []string{"app.example.test"}},
		OpenAPISpecJSON: spec,
	})

	want := "GET http://app.example.test/search?code=0042&page=1&size=1"
	if _, ok := specEndpoints(sink)[want]; !ok {
		t.Fatalf("merged/multi-document YAML parameters not imported as %s; got %v", want, sink.endpointURLs())
	}
}

// engineFunc adapts a function to httpengine.Engine.
type engineFunc func(context.Context, *httpengine.Request) (*httpengine.Response, error)

func (f engineFunc) Do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	return f(ctx, req)
}
