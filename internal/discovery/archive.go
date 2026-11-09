package discovery

// Historical-URL discovery through the Wayback Machine CDX API.
//
// Why: a target's current pages do not link to the endpoints that were removed
// last year — the old admin panel, the API version before the rewrite, the
// backup path. The archive knows them, and those stale surfaces are routinely
// still deployed. This is the passive half of web reconnaissance and the only
// source here that talks to a third party.
//
// Contract:
//   - aggressive level only, because the query discloses the target host to
//     archive.org; that is a privacy decision the operator makes explicitly;
//   - the CDX request goes to the archive, not to the target, so it does not
//     pass through the scan's scoped engine; every URL it returns is filtered
//     to the scanned host and goes through Normalize + scope before use;
//   - bounded: one CDX query per origin, at most 200 URLs, collapsed by
//     urlkey, status 200 only;
//   - discovery only: no request is sent to the target here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
)

// DefaultArchiveCDX is the public Wayback Machine index endpoint.
const DefaultArchiveCDX = "https://web.archive.org/cdx/search/cdx"

// MaxArchiveURLs bounds one origin's contribution to the endpoint set. The
// archive can return tens of thousands of rows for a long-lived site; the
// oldest and newest 200 are enough to surface stale paths without turning a
// scan into an archive crawl.
const MaxArchiveURLs = 200

type archiveSource struct {
	cfg      Config
	endpoint string
	client   *http.Client
}

// NewArchiveSource queries the Wayback CDX index for historical URLs.
func NewArchiveSource(cfg Config) Source {
	endpoint := cfg.ArchiveEndpoint
	if endpoint == "" {
		endpoint = DefaultArchiveCDX
	}
	return &archiveSource{
		cfg:      cfg.withDefaults(),
		endpoint: endpoint,
		client:   &http.Client{Timeout: 20 * time.Second},
	}
}

func (s *archiveSource) Name() domain.DiscoverySource { return domain.SourceArchive }

func (s *archiveSource) Run(ctx context.Context, in Input, sink Sink) error {
	if s.cfg.ReconLevel != ReconAggressive {
		return nil
	}
	for _, origin := range uniqueOrigins(in.SeedURLs) {
		base, err := url.Parse(origin)
		if err != nil {
			continue
		}
		urls, err := s.query(ctx, base.Hostname())
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue // archive unreachable or rate-limited: not a scan failure
		}
		seen := map[string]bool{}
		for _, raw := range urls {
			info, err := Normalize(raw)
			if err != nil || seen[info.Canonical] {
				continue
			}
			u, err := url.Parse(info.Canonical)
			if err != nil || !strings.EqualFold(u.Host, base.Host) {
				continue
			}
			if !in.Scope.Permits(info.Canonical).Allowed {
				continue
			}
			seen[info.Canonical] = true
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
				URL: info.Canonical, Method: domain.MethodGET, Source: domain.SourceArchive,
			}); err != nil {
				return err
			}
			if len(seen) >= MaxArchiveURLs {
				break
			}
		}
	}
	return nil
}

// query asks the CDX index for captured URLs on host. The response is a JSON
// array of arrays; the first row is the field header.
func (s *archiveSource) query(ctx context.Context, host string) ([]string, error) {
	q := url.Values{
		"url":       {host},
		"matchType": {"host"},
		"fl":        {"original"},
		"collapse":  {"urlkey"},
		"filter":    {"statuscode:200"},
		"limit":     {"200"},
		"output":    {"json"},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", s.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "indago-recon/1.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errStatus(resp.StatusCode)
	}
	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	var out []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // header row
			continue
		}
		out = append(out, row[0])
	}
	return out, nil
}

type errStatus int

func (e errStatus) Error() string { return "archive: status " + http.StatusText(int(e)) }
