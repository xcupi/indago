package discovery

// Specification-driven discovery: an operator hands Indago a machine-readable
// API description — the OpenAPI 3.x / Swagger 2.0 document a target publishes
// at /openapi.json, /openapi.yaml or /swagger.json, or one saved to disk — and
// every endpoint it declares becomes a discovery candidate. Both JSON and YAML
// documents are accepted; YAML is normalized into the same JSON-shaped model,
// so one parser serves both dialects.
//
// This is the one discovery input that yields a COMPLETE endpoint inventory
// rather than a sample of it, which matters because a JSON API has no pages a
// crawler can follow: without a spec, an endpoint that is never linked and
// never called by a rendered page is invisible.
//
// Contract, same as every other source:
//   - the document is either supplied directly (Input.OpenAPISpecJSON) or read
//     with exactly ONE read-only GET through the scan's own scope-enforcing
//     engine (Input.OpenAPISpecURL). Discovery never sends a request to a
//     declared endpoint on its own account: registering is not requesting, and
//     the executor's own opt-ins decide what may be sent later;
//   - every declared URL is normalized and must be in scope, fail closed;
//   - the work is bounded: a fixed endpoint ceiling per document, a body-size
//     ceiling on the fetched document, and a recursion depth ceiling on local
//     $ref resolution (a self-referential schema must not spin);
//   - a document's own declarations are data, never evidence: no verdict, no
//     mutation, no payload.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"gopkg.in/yaml.v3"
)

const (
	// MaxOpenAPISpecBytes bounds the spec document, whether supplied inline or
	// fetched. The API's own request body is capped at 1 MiB, so this leaves
	// room for the rest of the scan-create envelope; a larger document is
	// refused rather than silently truncated (half a spec is worse than none:
	// the operator would believe coverage the scan never had).
	MaxOpenAPISpecBytes = 512 << 10

	// maxOpenAPISpecEndpoints bounds how many endpoints one document may
	// register. A generated spec for a large product can declare thousands of
	// operations; the scan's request budget cannot test them, and the queue
	// would be flooded ahead of anything the crawl itself found.
	maxOpenAPISpecEndpoints = 200

	// maxOpenAPISchemaDepth bounds local $ref hops and nested object skeleton
	// building. A schema that references itself (a tree node, a thread) is
	// legal and common; the builder stops descending instead of recursing.
	maxOpenAPISchemaDepth = 8

	// maxOpenAPISchemaProperties bounds how many properties one object skeleton
	// contributes, so a registry-style schema cannot expand the body without
	// limit.
	maxOpenAPISchemaProperties = 32
)

// openAPISource registers the endpoints an OpenAPI/Swagger document declares.
// engine may be nil when the operator supplies the document inline; it is only
// used to read a spec the scan has to fetch.
type openAPISource struct {
	engine httpengine.Engine
}

// NewOpenAPISource registers the endpoints declared by an operator-supplied
// OpenAPI 3.x or Swagger 2.0 document, in JSON or YAML. With neither
// Input.OpenAPISpecJSON nor Input.OpenAPISpecURL set it does nothing at all —
// no request, no registration — so every scan that supplies no spec is
// unaffected.
func NewOpenAPISource(engine httpengine.Engine) Source { return &openAPISource{engine: engine} }

func (s *openAPISource) Name() domain.DiscoverySource { return domain.SourceOpenAPI }

func (s *openAPISource) Run(ctx context.Context, in Input, sink Sink) error {
	doc, refURL, err := s.load(ctx, in, sink)
	if err != nil {
		return err
	}
	if len(doc) == 0 {
		return nil // no spec supplied: this source is a no-op
	}
	candidates, err := buildOpenAPIEndpoints(doc, refURL, in.Scope)
	if err != nil {
		return err
	}
	for _, c := range candidates {
		if err := in.wait(ctx); err != nil {
			return err
		}
		id, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL:         c.URL,
			Method:      c.Method,
			Source:      domain.SourceOpenAPI,
			ContentType: c.ContentType,
			RequestBody: c.RequestBody,
		})
		if err != nil {
			return err
		}
		if id == "" {
			continue // refused by the sink (out of scope, guarded, malformed)
		}
		// Body-carrying parameters are the one thing AddEndpoint cannot infer
		// from the URL, so they are proposed explicitly. Query parameters have
		// already been registered from the synthetic query string above.
		for _, p := range c.FormParams {
			if err := sink.AddParameter(ctx, ParamCandidate{
				EndpointURL:    c.URL,
				EndpointMethod: c.Method,
				Name:           p.Name,
				Location:       domain.LocationForm,
				Example:        p.Example,
				Source:         domain.SourceOpenAPI,
			}); err != nil {
				return err
			}
		}
		for _, p := range c.JSONParams {
			if err := sink.AddParameter(ctx, ParamCandidate{
				EndpointURL:    c.URL,
				EndpointMethod: c.Method,
				Name:           p.Name,
				Location:       domain.LocationJSON,
				Example:        p.Example,
				Source:         domain.SourceOpenAPI,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// load returns the spec document and the URL it should be resolved against
// (nil when the document is inline and no URL was given). It is the only place
// this source touches the network, and only for a spec the operator pointed at.
func (s *openAPISource) load(ctx context.Context, in Input, sink Sink) ([]byte, *url.URL, error) {
	specURL := strings.TrimSpace(in.OpenAPISpecURL)
	inline := strings.TrimSpace(in.OpenAPISpecJSON)

	var refURL *url.URL
	if specURL != "" {
		info, err := Normalize(specURL)
		if err != nil {
			return nil, nil, fmt.Errorf("openapi: spec url %q: %w", specURL, err)
		}
		if d := in.Scope.Permits(info.Canonical); !d.Allowed {
			return nil, nil, fmt.Errorf("openapi: spec url %s is outside scope: %s", info.Canonical, d.Reason)
		}
		refURL, _ = url.Parse(info.Canonical)
	}

	if inline != "" {
		if len(inline) > MaxOpenAPISpecBytes {
			return nil, nil, fmt.Errorf("openapi: spec document is %d bytes, limit is %d", len(inline), MaxOpenAPISpecBytes)
		}
		if refURL == nil {
			// An inline document has no location of its own, so a relative
			// `servers` URL (or a Swagger document with no host) resolves
			// against the scan's own first seed: the spec describes THAT
			// deployment. A host it names is still scope-checked like any
			// other discovered URL.
			for _, seed := range in.SeedURLs {
				if info, err := Normalize(seed); err == nil {
					refURL, _ = url.Parse(info.Canonical)
					break
				}
			}
		}
		return []byte(inline), refURL, nil
	}
	if refURL == nil {
		return nil, nil, nil // nothing supplied
	}

	// ONE read-only GET, through the scan's scope-enforcing engine. A spec
	// that cannot be fetched is a warning, not a scan failure: discovery keeps
	// its other sources.
	if !allowFetch(sink, refURL.String(), domain.SourceOpenAPI, domain.MethodGET) {
		return nil, nil, fmt.Errorf("openapi: spec url %s refused by the discovery guard", refURL)
	}
	if s.engine == nil {
		return nil, nil, fmt.Errorf("openapi: spec url %s supplied but no HTTP engine is configured", refURL)
	}
	if err := in.wait(ctx); err != nil {
		return nil, nil, err
	}
	resp, err := s.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: refURL.String()})
	if err != nil {
		return nil, nil, fmt.Errorf("openapi: fetch %s: %w", refURL, err)
	}
	if resp == nil || resp.Status < 200 || resp.Status >= 300 || len(resp.Body) == 0 {
		return nil, nil, fmt.Errorf("openapi: fetch %s: status %d with %d bytes", refURL, statusOf(resp), bodyLen(resp))
	}
	// The engine already caps a response body; this is the spec-specific
	// bound, and a spec larger than it is refused rather than truncated.
	if len(resp.Body) > MaxOpenAPISpecBytes {
		return nil, nil, fmt.Errorf("openapi: spec document is %d bytes, limit is %d", len(resp.Body), MaxOpenAPISpecBytes)
	}
	return resp.Body, refURL, nil
}

func statusOf(resp *httpengine.Response) int {
	if resp == nil {
		return 0
	}
	return resp.Status
}

func bodyLen(resp *httpengine.Response) int {
	if resp == nil {
		return 0
	}
	return len(resp.Body)
}

// ---------------------------------------------------------------------------
// document model
// ---------------------------------------------------------------------------

// openAPIDocument is the union of the two dialects this source reads. Only the
// fields discovery needs are modelled; everything else in the document is
// ignored rather than rejected, so a newer vendor extension cannot make a valid
// spec unreadable.
type openAPIDocument struct {
	OpenAPI  string   `json:"openapi"` // "3.0.x" / "3.1.x"
	Swagger  string   `json:"swagger"` // "2.0"
	Host     string   `json:"host"`
	BasePath string   `json:"basePath"`
	Schemes  []string `json:"schemes"`
	Servers  []struct {
		URL       string `json:"url"`
		Variables map[string]struct {
			Default string   `json:"default"`
			Enum    []string `json:"enum"`
		} `json:"variables"`
	} `json:"servers"`
	Paths map[string]json.RawMessage `json:"paths"`
	// Components.Schemas (OpenAPI 3) and Definitions (Swagger 2) are the two
	// ref roots a local document can use.
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
	Definitions map[string]json.RawMessage `json:"definitions"`
}

// specPathItem is one `paths` entry. The method keys are kept raw so an
// unknown/extension key is simply not a method.
type specPathItem map[string]json.RawMessage

// specOperation is one operation object; only parameters and the JSON request
// body matter to discovery.
type specOperation struct {
	Parameters  []specParameter `json:"parameters"`
	RequestBody struct {
		Content map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
}

// specParameter covers both dialects: OpenAPI 3 always describes the shape in
// Schema, Swagger 2 puts Type/Format/Items directly on a non-body parameter and
// uses Schema only for In=="body".
type specParameter struct {
	Name     string            `json:"name"`
	In       string            `json:"in"`
	Required bool              `json:"required"`
	Schema   json.RawMessage   `json:"schema"`
	Example  json.RawMessage   `json:"example"`
	Default  json.RawMessage   `json:"default"`
	Enum     []json.RawMessage `json:"enum"`
	Type     string            `json:"type"`
	Format   string            `json:"format"`
}

// specSchema is the subset of JSON Schema the skeleton builder understands.
type specSchema struct {
	Ref                  string                     `json:"$ref"`
	Type                 string                     `json:"type"`
	Format               string                     `json:"format"`
	Example              json.RawMessage            `json:"example"`
	Default              json.RawMessage            `json:"default"`
	Enum                 []json.RawMessage          `json:"enum"`
	Properties           map[string]json.RawMessage `json:"properties"`
	Items                json.RawMessage            `json:"items"`
	AllOf                []json.RawMessage          `json:"allOf"`
	AdditionalProperties json.RawMessage            `json:"additionalProperties"`
}

// openAPIEndpoint is one endpoint the document declares, ready to register.
type openAPIEndpoint struct {
	URL         string
	Method      domain.HTTPMethod
	ContentType string
	RequestBody string
	// FormParams / JSONParams are the body-carried parameters the document
	// declares, with the example value its types imply. Query parameters are
	// already part of URL.
	FormParams []openAPIParam
	JSONParams []openAPIParam
}

type openAPIParam struct {
	Name    string
	Example string
}

// specMethods is the operation-key order discovery walks, so a path that
// declares both GET and POST registers deterministically.
var specMethods = []struct {
	key    string
	method domain.HTTPMethod
}{
	{"get", domain.MethodGET},
	{"post", domain.MethodPOST},
	{"put", domain.MethodPUT},
	{"patch", domain.MethodPATCH},
	{"delete", domain.MethodDELETE},
	{"head", domain.MethodHEAD},
	{"options", domain.MethodOPTIONS},
}

// buildOpenAPIEndpoints turns a spec document into registrable endpoints.
// Every returned URL is in scope, normalized, and resolved against the
// document's own declared base; the count is capped at maxOpenAPISpecEndpoints.
// refURL is the document's reference location — the URL it was read from, or the
// scan's first seed when the document was supplied inline — and is what a
// relative `servers` URL or a missing Swagger host resolves against.
func buildOpenAPIEndpoints(doc []byte, refURL *url.URL, scope domain.Scope) ([]openAPIEndpoint, error) {
	spec, err := parseOpenAPIDocument(doc)
	if err != nil {
		return nil, err
	}
	if err := specUsable(spec); err != nil {
		return nil, err
	}
	base := specBaseURL(&spec, refURL)
	if base == nil {
		return nil, fmt.Errorf("openapi: cannot resolve a base URL (no servers, host or reference URL)")
	}
	resolver := &specResolver{schemas: spec.Components.Schemas, definitions: spec.Definitions}

	paths := make([]string, 0, len(spec.Paths))
	for p := range spec.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths) // deterministic registration order

	var out []openAPIEndpoint
	for _, path := range paths {
		if len(out) >= maxOpenAPISpecEndpoints {
			break
		}
		if !strings.HasPrefix(path, "/") {
			continue // a spec key that is not a path template
		}
		var item specPathItem
		if err := json.Unmarshal(spec.Paths[path], &item); err != nil {
			continue
		}
		var pathParams []specParameter
		if raw, ok := item["parameters"]; ok {
			_ = json.Unmarshal(raw, &pathParams)
		}
		for _, m := range specMethods {
			if len(out) >= maxOpenAPISpecEndpoints {
				break
			}
			raw, ok := item[m.key]
			if !ok {
				continue
			}
			var op specOperation
			if err := json.Unmarshal(raw, &op); err != nil {
				continue
			}
			ep, ok := resolver.endpoint(base, path, m.method, pathParams, op)
			if !ok {
				continue
			}
			info, err := Normalize(ep.URL)
			if err != nil {
				continue // a path that cannot be a real URL is never registered
			}
			if d := scope.Permits(info.Canonical); !d.Allowed {
				continue // outside scope: fail closed, silently (the sink would too)
			}
			ep.URL = info.Canonical
			out = append(out, ep)
		}
	}
	return out, nil
}

// parseOpenAPIDocument decodes a JSON or YAML OpenAPI/Swagger document into
// openAPIDocument. YAML inputs are normalized into JSON-compatible values so
// downstream json.RawMessage fields and $ref resolution work identically.
func parseOpenAPIDocument(doc []byte) (openAPIDocument, error) {
	var spec openAPIDocument
	if err := json.Unmarshal(doc, &spec); err == nil {
		return spec, nil
	}

	var raw any
	if err := yaml.Unmarshal(doc, &raw); err != nil {
		return openAPIDocument{}, fmt.Errorf("openapi: parse document: %w", err)
	}
	normalized, err := json.Marshal(yamlToJSONCompatible(raw))
	if err != nil {
		return openAPIDocument{}, fmt.Errorf("openapi: parse document: %w", err)
	}
	if err := json.Unmarshal(normalized, &spec); err != nil {
		return openAPIDocument{}, fmt.Errorf("openapi: parse document: %w", err)
	}
	return spec, nil
}

// ValidateOpenAPISpec reports whether doc is a document this source can use:
// well-formed JSON or YAML that declares an OpenAPI 3.x / Swagger 2.0 version
// or at least one path. It is the create-time gate the scan controller applies
// to an operator-supplied inline spec, and it deliberately runs the SAME parse
// and the same usability test NewOpenAPISource runs, so the two cannot drift:
// a document accepted here is one discovery will read, and a document refused
// here is one discovery would have failed on mid-scan. It performs no I/O and
// no scope check, and registers nothing.
func ValidateOpenAPISpec(doc []byte) error {
	spec, err := parseOpenAPIDocument(doc)
	if err != nil {
		return err
	}
	return specUsable(spec)
}

// specUsable rejects a document that parsed but describes no API: neither
// dialect's version field and no paths at all. A YAML file of unrelated keys
// parses cleanly, and accepting it would look like a successful import while
// registering nothing.
func specUsable(spec openAPIDocument) error {
	if spec.OpenAPI == "" && spec.Swagger == "" && len(spec.Paths) == 0 {
		return fmt.Errorf("openapi: document declares neither an openapi/swagger version nor any paths")
	}
	return nil
}

// yamlToJSONCompatible recursively converts map[any]any (which yaml.v3
// produces for non-string keys such as numeric HTTP status codes) into
// map[string]any so encoding/json can marshal the document.
func yamlToJSONCompatible(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = yamlToJSONCompatible(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = yamlToJSONCompatible(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = yamlToJSONCompatible(val)
		}
		return out
	default:
		return v
	}
}

// specBaseURL resolves the document's declared base. OpenAPI 3 names it in
// `servers` (a URL that may be relative, and may carry {variables}); Swagger 2
// names it in scheme/host/basePath. A document that declares neither resolves
// against the URL it was read from.
func specBaseURL(spec *openAPIDocument, refURL *url.URL) *url.URL {
	if len(spec.Servers) > 0 {
		if srv := expandServerURL(spec.Servers[0].URL, spec.Servers[0].Variables); srv != "" {
			if u, err := url.Parse(srv); err == nil {
				switch {
				case u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "":
					return u
				case refURL != nil:
					return refURL.ResolveReference(u)
				}
			}
		}
	}
	if spec.Swagger != "" || spec.Host != "" || spec.BasePath != "" {
		scheme := ""
		if refURL != nil {
			scheme = refURL.Scheme
		}
		if scheme != "http" && scheme != "https" {
			scheme = "https"
		}
		for _, s := range spec.Schemes {
			if s == "http" || s == "https" {
				scheme = s
				break
			}
		}
		host := spec.Host
		if host == "" && refURL != nil {
			host = refURL.Host
		}
		if host != "" {
			return &url.URL{Scheme: scheme, Host: host, Path: strings.TrimRight(spec.BasePath, "/")}
		}
	}
	if refURL != nil {
		return &url.URL{Scheme: refURL.Scheme, Host: refURL.Host}
	}
	return nil
}

// expandServerURL substitutes a server URL's {variables} with their declared
// default (or first enum value). An unresolved placeholder leaves the URL
// unusable, which the caller treats as "no usable server".
func expandServerURL(raw string, vars map[string]struct {
	Default string   `json:"default"`
	Enum    []string `json:"enum"`
}) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for name, v := range vars {
		value := v.Default
		if value == "" && len(v.Enum) > 0 {
			value = v.Enum[0]
		}
		raw = strings.ReplaceAll(raw, "{"+name+"}", value)
	}
	if strings.ContainsAny(raw, "{}") {
		return ""
	}
	return raw
}

// ---------------------------------------------------------------------------
// schema helpers
// ---------------------------------------------------------------------------

// specResolver resolves local references within one document. Only local
// "#/components/schemas/<name>" (OpenAPI 3) and "#/definitions/<name>"
// (Swagger 2) point inside the document; a reference to another file or URL
// cannot be fetched (that would be a second, unbounded request graph), so it is
// left unresolved and the caller falls back to a type-derived placeholder.
type specResolver struct {
	schemas     map[string]json.RawMessage
	definitions map[string]json.RawMessage
}

// lookup returns the raw schema a local ref points at.
func (r *specResolver) lookup(ref string) (json.RawMessage, bool) {
	const componentsPrefix = "#/components/schemas/"
	const definitionsPrefix = "#/definitions/"
	var name string
	switch {
	case strings.HasPrefix(ref, componentsPrefix):
		name = strings.TrimPrefix(ref, componentsPrefix)
		if raw, ok := r.schemas[name]; ok {
			return raw, true
		}
	case strings.HasPrefix(ref, definitionsPrefix):
		name = strings.TrimPrefix(ref, definitionsPrefix)
		if raw, ok := r.definitions[name]; ok {
			return raw, true
		}
	}
	return nil, false
}

// schema decodes raw as a schema, following a local $ref chain up to
// maxOpenAPISchemaDepth hops. A chain that is cyclic or too deep resolves to the
// last schema it reached rather than recursing forever.
func (r *specResolver) schema(raw json.RawMessage, depth int) specSchema {
	var s specSchema
	if len(raw) == 0 {
		return s
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return specSchema{}
	}
	for hops := 0; s.Ref != "" && hops < maxOpenAPISchemaDepth && depth < maxOpenAPISchemaDepth; hops++ {
		target, ok := r.lookup(s.Ref)
		if !ok {
			return s
		}
		var next specSchema
		if err := json.Unmarshal(target, &next); err != nil {
			return s
		}
		s = next
		depth++
	}
	return s
}

// example returns a JSON literal for a schema: its own example, then its
// default, then its first enum member, then a value derived from its type and
// format. depth bounds the recursion for object properties.
func (r *specResolver) example(raw json.RawMessage, depth int) json.RawMessage {
	s := r.schema(raw, depth)
	return r.exampleForSchema(s, depth)
}

func (r *specResolver) exampleForSchema(s specSchema, depth int) json.RawMessage {
	if lit := firstJSONLiteral(s.Example); lit != nil {
		return lit
	}
	if lit := firstJSONLiteral(s.Default); lit != nil {
		return lit
	}
	if len(s.Enum) > 0 && firstJSONLiteral(s.Enum[0]) != nil {
		return firstJSONLiteral(s.Enum[0])
	}
	switch s.Type {
	case "object":
		return r.objectSkeleton(s, depth)
	case "":
		if len(s.Properties) > 0 || len(s.AllOf) > 0 {
			return r.objectSkeleton(s, depth)
		}
		if len(s.Items) > 0 {
			return json.RawMessage(`[]`)
		}
		return json.RawMessage(`"string"`)
	case "array":
		return json.RawMessage(`[]`)
	case "integer", "number":
		return json.RawMessage("0")
	case "boolean":
		return json.RawMessage("false")
	default: // "string" and anything unrecognized
		return json.RawMessage(strconvQuote(formatPlaceholder(s.Format)))
	}
}

// objectSkeleton builds a JSON object carrying one example value per declared
// property (allOf members merged). It stops at maxOpenAPISchemaDepth, so a
// self-referential schema yields the properties reached so far.
func (r *specResolver) objectSkeleton(s specSchema, depth int) json.RawMessage {
	if depth >= maxOpenAPISchemaDepth {
		return json.RawMessage(`{}`)
	}
	props := r.objectProperties(s, depth, map[string]bool{})
	if len(props) == 0 {
		return json.RawMessage(`{}`)
	}
	encoded, err := json.Marshal(props)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return encoded
}

// objectProperties flattens s and its allOf members into property → example.
// built tracks the allOf members already visited so a cyclic composition
// cannot repeat.
func (r *specResolver) objectProperties(s specSchema, depth int, built map[string]bool) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(s.Properties))
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(out) >= maxOpenAPISchemaProperties {
			return out
		}
		out[name] = r.example(s.Properties[name], depth+1)
	}
	for _, member := range s.AllOf {
		if len(out) >= maxOpenAPISchemaProperties {
			return out
		}
		key := string(member)
		if built[key] {
			continue
		}
		built[key] = true
		sub := r.schema(member, depth+1)
		for name, value := range r.objectProperties(sub, depth+1, built) {
			if len(out) >= maxOpenAPISchemaProperties {
				return out
			}
			if _, exists := out[name]; !exists {
				out[name] = value
			}
		}
	}
	return out
}

// firstJSONLiteral reports raw as a usable example value: nil when it is absent
// or the JSON null, which means "no example" in both dialects.
func firstJSONLiteral(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	return json.RawMessage(trimmed)
}

// formatPlaceholder is the benign value a format implies for a body/query
// skeleton. It is a placeholder an application accepts, never a probe.
func formatPlaceholder(format string) string {
	switch strings.ToLower(format) {
	case "date":
		return "2024-01-01"
	case "date-time":
		return "2024-01-01T00:00:00Z"
	case "uuid":
		return "00000000-0000-4000-8000-000000000000"
	case "email":
		return "user@example.com"
	case "uri", "url":
		return "https://example.com/"
	case "hostname":
		return "example.com"
	case "ipv4":
		return "192.0.2.1"
	case "ipv6":
		return "2001:db8::1"
	default:
		return "string"
	}
}

// strconvQuote quotes s as a JSON string literal.
func strconvQuote(s string) string {
	encoded, err := json.Marshal(s)
	if err != nil {
		return `"string"`
	}
	return string(encoded)
}

// rawValueString renders a JSON example as the plain string a parameter value
// needs: a JSON string loses its quotes, anything else keeps its JSON form
// (so a numeric or boolean query value is "2"/"false", exactly as the document
// expresses it).
func rawValueString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// ---------------------------------------------------------------------------
// endpoint building
// ---------------------------------------------------------------------------

// endpoint builds one registrable endpoint from a path template and an
// operation: the concrete URL (path variables substituted, query string
// synthesized from the declared query parameters) plus the JSON/form body the
// operation declares. ok is false when the template cannot be turned into a
// requestable URL.
func (r *specResolver) endpoint(base *url.URL, path string, method domain.HTTPMethod, pathParams []specParameter, op specOperation) (openAPIEndpoint, bool) {
	params := mergeSpecParams(pathParams, op.Parameters)

	concrete, ok := substitutePathParams(path, params, r)
	if !ok {
		return openAPIEndpoint{}, false
	}
	query := buildQueryString(params, r)

	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + concrete
	u.RawPath = ""
	u.Fragment = ""
	u.RawQuery = query
	u.ForceQuery = false

	ep := openAPIEndpoint{URL: u.String(), Method: method}

	// JSON request body: OpenAPI 3 declares it in requestBody.content, Swagger
	// 2 as a parameter with in=="body".
	bodySchema := pickJSONBodySchema(op)
	if len(bodySchema) == 0 {
		for _, p := range params {
			if strings.EqualFold(p.In, "body") && len(p.Schema) > 0 {
				bodySchema = p.Schema
				break
			}
		}
	}
	if len(bodySchema) > 0 {
		ep.ContentType = "application/json"
		ep.RequestBody = string(firstJSONLiteral(r.example(bodySchema, 0)))
		ep.JSONParams = r.bodyParams(bodySchema)
	}

	// Swagger 2 form parameters (and OpenAPI 3 requestBody.form media types are
	// deliberately not synthesized: a multipart body is not something a
	// benign-marker query can be replayed in).
	for _, p := range params {
		if !strings.EqualFold(p.In, "formData") {
			continue
		}
		ep.FormParams = append(ep.FormParams, openAPIParam{Name: p.Name, Example: r.paramValue(p, 0)})
	}
	if len(ep.FormParams) > 0 && ep.ContentType == "" {
		ep.ContentType = "application/x-www-form-urlencoded"
	}
	return ep, true
}

// bodyParams lists the top-level JSON properties of a request body, each with
// the example value the schema implies. These are what the reflection engine
// mutates one field at a time, so only the top level is proposed (a nested
// property is reachable by the skeleton itself, not by a single-field override).
func (r *specResolver) bodyParams(bodySchema json.RawMessage) []openAPIParam {
	s := r.schema(bodySchema, 0)
	if s.Type != "" && s.Type != "object" {
		return nil
	}
	props := r.objectProperties(s, 0, map[string]bool{})
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]openAPIParam, 0, len(names))
	for _, name := range names {
		out = append(out, openAPIParam{Name: name, Example: string(props[name])})
	}
	return out
}

// pickJSONBodySchema returns the schema of the operation's JSON request body,
// preferring application/json and otherwise the first */*+json media type the
// document declares (deterministically: sorted).
func pickJSONBodySchema(op specOperation) json.RawMessage {
	if len(op.RequestBody.Content) == 0 {
		return nil
	}
	if media, ok := op.RequestBody.Content["application/json"]; ok && len(media.Schema) > 0 {
		return media.Schema
	}
	keys := make([]string, 0, len(op.RequestBody.Content))
	for k := range op.RequestBody.Content {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Contains(strings.ToLower(k), "json") && len(op.RequestBody.Content[k].Schema) > 0 {
			return op.RequestBody.Content[k].Schema
		}
	}
	return nil
}

// mergeSpecParams merges path-level and operation-level parameters. An
// operation-level parameter with the same (in, name) replaces the path-level
// one, which is what both dialects specify.
func mergeSpecParams(pathLevel, opLevel []specParameter) []specParameter {
	out := make([]specParameter, 0, len(pathLevel)+len(opLevel))
	index := make(map[string]int, len(pathLevel)+len(opLevel))
	key := func(p specParameter) string { return strings.ToLower(p.In) + "\x00" + p.Name }
	for _, p := range pathLevel {
		if p.Name == "" {
			continue
		}
		if _, ok := index[key(p)]; ok {
			continue
		}
		index[key(p)] = len(out)
		out = append(out, p)
	}
	for _, p := range opLevel {
		if p.Name == "" {
			continue
		}
		if i, ok := index[key(p)]; ok {
			out[i] = p
			continue
		}
		index[key(p)] = len(out)
		out = append(out, p)
	}
	return out
}

// substitutePathParams replaces every {name} in path with a concrete value: the
// declared path parameter's example/default/enum, or a type-derived
// placeholder. ok is false when a placeholder has no declaration at all — the
// path then cannot be turned into a URL a server would route, and registering a
// literal "{id}" would hand every later stage a URL that is not a URL.
func substitutePathParams(path string, params []specParameter, r *specResolver) (string, bool) {
	out := path
	for _, p := range params {
		if !strings.EqualFold(p.In, "path") || p.Name == "" {
			continue
		}
		placeholder := "{" + p.Name + "}"
		if !strings.Contains(out, placeholder) {
			continue
		}
		out = strings.ReplaceAll(out, placeholder, sanitizePathSegment(r.paramValue(p, 0)))
	}
	if strings.ContainsAny(out, "{}") {
		return "", false
	}
	return out, true
}

// sanitizePathSegment keeps a substituted value inside one path segment: a
// value that carried a slash, a space or a query delimiter must not reshape the
// path it was substituted into.
func sanitizePathSegment(v string) string {
	if v == "" {
		return "1"
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '~':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// buildQueryString synthesizes a query string from the declared query
// parameters, one value each, in sorted name order so the URL is deterministic
// (and deduplication across runs is exact). Name -> value only: this is a
// placeholder the application accepts, never a probe.
func buildQueryString(params []specParameter, r *specResolver) string {
	values := url.Values{}
	names := make([]string, 0, len(params))
	byName := make(map[string]string, len(params))
	for _, p := range params {
		if !strings.EqualFold(p.In, "query") || p.Name == "" {
			continue
		}
		if _, seen := byName[p.Name]; seen {
			continue
		}
		byName[p.Name] = r.paramValue(p, 0)
		names = append(names, p.Name)
	}
	sort.Strings(names)
	for _, name := range names {
		values.Set(name, byName[name])
	}
	return values.Encode()
}

// paramValue renders one declared parameter's example value.
func (r *specResolver) paramValue(p specParameter, depth int) string {
	if lit := firstJSONLiteral(p.Example); lit != nil {
		return rawValueString(lit)
	}
	if lit := firstJSONLiteral(p.Default); lit != nil {
		return rawValueString(lit)
	}
	if len(p.Enum) > 0 {
		if lit := firstJSONLiteral(p.Enum[0]); lit != nil {
			return rawValueString(lit)
		}
	}
	if len(p.Schema) > 0 {
		return rawValueString(r.example(p.Schema, depth))
	}
	// Swagger 2 non-body parameter: the shape is on the parameter itself.
	if p.Type != "" {
		return rawValueString(r.exampleForSchema(specSchema{Type: p.Type, Format: p.Format}, depth))
	}
	return "string"
}
