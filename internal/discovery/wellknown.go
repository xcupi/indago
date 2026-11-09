package discovery

// Document-driven discovery: the documents a site publishes about itself
// (security.txt, OpenID configuration, OpenAPI/Swagger) name endpoints that the
// crawler cannot see because no page links to them. The path wordlists already
// probe for these files; this source reads what is inside them.
//
// Contract, same as every other source:
//   - only GET, through the scan's scope-enforcing engine (rate limit, host
//     scope, fail-closed redirects);
//   - only at recon level standard and above, so default scans are unchanged;
//   - a URL found inside a document is untrusted input: it is normalized and
//     must be in scope and safe to fetch before it becomes an endpoint;
//   - no verdict, no mutation — discovery only.

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// selfDescribingPaths are the well-known documents worth reading. Swagger and
// OpenAPI paths are included because an exposed spec is the cheapest complete
// endpoint inventory a target can hand over.
var selfDescribingPaths = []string{
	"/.well-known/security.txt",
	"/security.txt",
	"/.well-known/openid-configuration",
	"/swagger.json",
	"/openapi.json",
	"/api/swagger.json",
	"/v3/api-docs",
}

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
	if s.cfg.ReconLevel != ReconStandard && s.cfg.ReconLevel != ReconAggressive {
		return nil
	}
	for _, origin := range uniqueOrigins(in.SeedURLs) {
		base, err := url.Parse(origin)
		if err != nil {
			continue
		}
		seen := map[string]bool{}
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
				if !allowFetch(sink, info.Canonical, domain.SourceWellKnown) {
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
	}
	return nil
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
// the first server URL when the spec declares one.
func openAPIPaths(body []byte, base *url.URL) []string {
	var spec struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]any `json:"paths"`
	}
	if json.Unmarshal(body, &spec) != nil || len(spec.Paths) == 0 {
		return nil
	}
	prefix := base.Scheme + "://" + base.Host
	if len(spec.Servers) > 0 && spec.Servers[0].URL != "" {
		server := spec.Servers[0].URL
		if strings.HasPrefix(server, "/") {
			prefix += server
		} else if strings.HasPrefix(server, "http") {
			prefix = server
		}
	}
	var out []string
	for p := range spec.Paths {
		out = append(out, strings.TrimRight(prefix, "/")+"/"+strings.TrimLeft(p, "/"))
	}
	return out
}
