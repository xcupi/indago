package discovery

// Document-driven discovery: the documents a site publishes about itself
// (security.txt, OpenID configuration, OpenAPI/Swagger) name endpoints that the
// crawler cannot see because no page links to them. The path wordlists already
// probe for these files; this source reads what is inside them.
//
// Contract, same as every other source:
//   - only GET, through the scan's scope-enforcing engine (rate limit, host
//     scope, fail-closed redirects);
//   - reading the documents themselves only happens at recon level standard
//     and above, so default scans are unchanged. The ONE exception is the
//     bounded GraphQL well-known probe below, which runs at every level: a
//     GraphQL API is a single POST URL no crawler can link to, so without it a
//     GraphQL target is invisible on a scan that does no wordlist recon;
//   - a URL found inside a document is untrusted input: it is normalized and
//     must be in scope and safe to fetch before it becomes an endpoint;
//   - no verdict, no mutation — discovery only.

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// selfDescribingPaths are the well-known documents worth reading. Swagger and
// OpenAPI paths are included because an exposed spec is the cheapest complete
// endpoint inventory a target can hand over. The list covers both naming
// conventions: the OpenAPI 3 default (/openapi.json, /v3/api-docs), the
// Swagger 2 default (/swagger.json, /swagger/v1/swagger.json) and the
// springdoc/NSwag style /api-docs.
var selfDescribingPaths = []string{
	"/.well-known/security.txt",
	"/security.txt",
	"/.well-known/openid-configuration",
	"/swagger.json",
	"/swagger/v1/swagger.json",
	"/api/swagger.json",
	"/openapi.json",
	"/api-docs",
	"/v3/api-docs",
}

// graphQLProbePaths are the conventional GraphQL entry points. A GraphQL API
// is invisible to a link crawler — the whole application is one POST URL — so
// discovery has to ask for the path and let the answer decide. Every probe is a
// read-only `{__typename}` query, the cheapest operation a GraphQL server can
// execute and one that no server implements as a mutation.
var graphQLProbePaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/query",
}

// graphQLLightPath is the single path the lightweight probe tries when the
// scan asked for no wordlist recon (the conservative default). /graphql is the
// overwhelming convention (Apollo, graphql-go, Hasura, Graphene, DVGA), and one
// request is cheap enough to make on every scan.
const graphQLLightPath = "/graphql"

// graphQLTypenameQuery is the whole probe document. __typename is a built-in
// meta field, so the query is valid against every schema.
const graphQLTypenameQuery = "{__typename}"

// maxGraphQLProbeBody bounds the body parsed for a probe. The answer to
// {__typename} is a few dozen bytes; anything larger is not this probe's
// response.
const maxGraphQLProbeBody = 256 << 10

type wellKnownSource struct {
	engine httpengine.Engine
	cfg    Config
}

// NewWellKnownSource reads self-describing documents for endpoints.
func NewWellKnownSource(engine httpengine.Engine, cfg Config) Source {
	return &wellKnownSource{engine: engine, cfg: cfg.withDefaults()}
}

func (s *wellKnownSource) Name() domain.DiscoverySource { return domain.SourceWellKnown }

func (s *wellKnownSource) Run(ctx context.Context, in Input, sink Sink) error {
	// Reading the documents is the standard+ half of this source. The GraphQL
	// probe below is the part that must run regardless: it is the only way a
	// scan without wordlist recon can see a GraphQL API at all.
	readDocuments := s.cfg.ReconLevel == ReconStandard || s.cfg.ReconLevel == ReconAggressive
	for _, origin := range uniqueOrigins(in.SeedURLs) {
		base, err := url.Parse(origin)
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		if readDocuments {
			if err := s.readSelfDescribingDocuments(ctx, in, sink, origin, base, seen); err != nil {
				return err
			}
		}
		if err := s.probeGraphQL(ctx, in, sink, origin, seen); err != nil {
			return err
		}
	}
	if !s.cfg.SkipGraphQLProbe && s.cfg.ReconLevel != ReconOff {
		if err := s.introspectGraphQLEndpoints(ctx, in, sink, map[string]bool{}); err != nil {
			return err
		}
	}
	return nil
}

// readSelfDescribingDocuments fetches the well-known documents for one origin
// and registers the endpoints they name. seen deduplicates this origin's
// registrations across the source's phases.
func (s *wellKnownSource) readSelfDescribingDocuments(ctx context.Context, in Input, sink Sink, origin string, base *url.URL, seen map[string]bool) error {
	for _, p := range selfDescribingPaths {
		if err := in.wait(ctx); err != nil {
			return err
		}
		resp, err := s.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: origin + p})
		if err != nil || resp == nil || resp.Status != 200 || len(resp.Body) == 0 {
			continue
		}
		var found []string
		switch {
		case strings.HasSuffix(p, "security.txt"):
			found = securityTxtURLs(resp.Body, base)
		case strings.Contains(p, "swagger") || strings.Contains(p, "openapi") || strings.Contains(p, "api-docs"):
			found = openAPIPaths(resp.Body, base)
		default:
			found = jsonDocURLs(resp.Body, base)
		}
		for _, raw := range found {
			info, err := Normalize(raw)
			if err != nil || seen[info.Canonical] {
				continue
			}
			if !sameHost(base, info) || !in.Scope.Permits(info.Canonical).Allowed {
				continue
			}
			if !allowFetch(sink, info.Canonical, domain.SourceWellKnown, domain.MethodGET) {
				continue
			}
			seen[info.Canonical] = true
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
				URL: info.Canonical, Method: domain.MethodGET, Source: domain.SourceWellKnown,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// probeGraphQL asks the conventional GraphQL entry points whether the site
// speaks GraphQL, and registers the endpoint the answer proves.
//
// This is the one part of this source that runs at EVERY recon level. A GraphQL
// API is a single POST URL that no link points at, so on a scan that does no
// wordlist recon (the conservative default) the GraphQL engine would otherwise
// never be handed an endpoint and would silently never run. The cost is kept
// deliberately small:
//
//   - below standard, exactly ONE GET of /graphql per seed origin;
//   - at standard and above, the full conventional path set (the same probes
//     this source always made);
//   - nothing at all when a GraphQL-looking endpoint is already known (a
//     crawled link, an observed XHR, an API spec) or when the operator skipped
//     the GraphQL engine (Config.SkipGraphQLProbe).
//
// The path is conventional; the protocol is what identifies it. Only a
// response that actually looks like GraphQL to `{__typename}` registers the
// endpoint, so a site that answers 200 on /graphql with an HTML page or a
// generic JSON API error adds nothing. The registered method is GET (that is
// the request that proved the path); a GraphQL engine sends its own read-only
// POST queries.
func (s *wellKnownSource) probeGraphQL(ctx context.Context, in Input, sink Sink, origin string, seen map[string]bool) error {
	if s.cfg.SkipGraphQLProbe {
		return nil
	}
	paths := []string{graphQLLightPath}
	if s.cfg.ReconLevel == ReconStandard || s.cfg.ReconLevel == ReconAggressive {
		paths = graphQLProbePaths
	}
	if knowsEndpoint(sink, looksLikeGraphQLEndpointURL) {
		return nil
	}
	for _, p := range paths {
		info, err := Normalize(origin + p)
		if err != nil || seen[info.Canonical] || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		// Same pre-request veto every other source honours: a session-
		// terminating path must not be requested just to classify it.
		if !allowFetch(sink, info.Canonical, domain.SourceWellKnown, domain.MethodGET) {
			continue
		}
		if err := in.wait(ctx); err != nil {
			return err
		}
		probe := info.Canonical + "?query=" + url.QueryEscape(graphQLTypenameQuery)
		resp, err := s.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: probe})
		if err != nil || resp == nil || !looksLikeGraphQLResponse(resp.Body) {
			continue
		}
		seen[info.Canonical] = true
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL: info.Canonical, Method: domain.MethodGET, Source: domain.SourceWellKnown,
		}); err != nil {
			return err
		}
	}
	return nil
}

// looksLikeGraphQLEndpointURL reports whether a URL's path is a GraphQL entry
// point by its name alone. It proves nothing (only a probe can); it exists so
// the light probe is not sent when the scan already registered the API — for
// example a SPA whose bundle posts to /graphql. The convention matches the
// GraphQL engine's own candidate filter, so "found by discovery" and "tested by
// the engine" cannot drift apart.
func looksLikeGraphQLEndpointURL(rawURL string) bool {
	info, err := Normalize(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(strings.TrimSuffix(info.Path, "/"))
	return strings.Contains(p, "graphql") || p == "/query" || p == "/api/query"
}

// looksLikeGraphQLResponse reports whether body is a GraphQL response to the
// `{__typename}` probe. Data carrying __typename is definitive. An error
// envelope counts only when a message names GraphQL itself (__typename,
// graphql, operation, syntax): a generic JSON API error such as
// {"errors":["field required"]} is not a GraphQL server.
func looksLikeGraphQLResponse(body []byte) bool {
	if len(body) == 0 || len(body) > maxGraphQLProbeBody {
		return false
	}
	var doc struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return false
	}
	if len(doc.Data) > 0 && string(doc.Data) != "null" {
		return strings.Contains(string(doc.Data), "__typename")
	}
	for _, e := range doc.Errors {
		msg := strings.ToLower(e.Message)
		for _, marker := range []string{"__typename", "graphql", "operation", "syntax"} {
			if strings.Contains(msg, marker) {
				return true
			}
		}
	}
	return false
}

// sameHost keeps document-derived URLs on the origin being scanned. An
// external policy URL is interesting to a human, not an endpoint of this scan.
func sameHost(base *url.URL, info URLInfo) bool {
	u, err := url.Parse(info.Canonical)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, base.Host)
}

var securityTxtLine = regexp.MustCompile(`(?mi)^\s*(contact|policy|canonical|encryption|hiring|acknowledgments|csaf)\s*:\s*(.+)$`)

// securityTxtURLs pulls the http(s) URLs out of the fields that carry them.
// The file is plain text with one "Field: value" per line; mailto: contacts are
// ignored because they are not endpoints.
func securityTxtURLs(body []byte, base *url.URL) []string {
	var out []string
	for _, m := range securityTxtLine.FindAllStringSubmatch(string(body), -1) {
		for _, raw := range regexp.MustCompile(`https?://[^\s,;]+`).FindAllString(m[2], -1) {
			out = append(out, strings.TrimRight(raw, ".)."))
		}
	}
	return out
}

// jsonDocURLs walks an OpenID-style JSON document and returns every absolute
// URL value. Relative values are resolved against the origin first.
func jsonDocURLs(body []byte, base *url.URL) []string {
	var doc any
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
				out = append(out, t)
			} else if strings.HasPrefix(t, "/") {
				out = append(out, base.Scheme+"://"+base.Host+t)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(doc)
	return out
}

// openAPIPaths turns a spec into endpoints: every path key, resolved against
// the spec's declared base. OpenAPI 3 documents describe it in `servers`;
// Swagger 2.0 documents use `host`/`basePath`/`schemes`, which is still the
// most common shape in the wild, so both are handled.
//
// Templated paths ("/users/{id}") are skipped: the braces are a parameter
// declaration, not a requestable URL, and registering them would queue a
// literal "/users/{id}" request that no router matches.
func openAPIPaths(body []byte, base *url.URL) []string {
	var spec struct {
		Swagger  string   `json:"swagger"`
		Host     string   `json:"host"`
		BasePath string   `json:"basePath"`
		Schemes  []string `json:"schemes"`
		Servers  []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]any `json:"paths"`
	}
	if json.Unmarshal(body, &spec) != nil || len(spec.Paths) == 0 {
		return nil
	}
	prefix := base.Scheme + "://" + base.Host
	switch {
	case len(spec.Servers) > 0 && spec.Servers[0].URL != "":
		server := spec.Servers[0].URL
		if strings.HasPrefix(server, "/") {
			prefix += server
		} else if strings.HasPrefix(server, "http") {
			prefix = server
		}
	case spec.Host != "" || spec.BasePath != "":
		scheme := base.Scheme
		if len(spec.Schemes) > 0 && spec.Schemes[0] != "" {
			scheme = spec.Schemes[0]
		}
		host := base.Host
		if spec.Host != "" {
			host = spec.Host
		}
		prefix = scheme + "://" + host + strings.TrimRight(spec.BasePath, "/")
	}
	out := make([]string, 0, len(spec.Paths))
	for p := range spec.Paths {
		if strings.ContainsAny(p, "{}") {
			continue
		}
		out = append(out, strings.TrimRight(prefix, "/")+"/"+strings.TrimLeft(p, "/"))
	}
	sort.Strings(out) // deterministic registration order across runs
	return out
}
