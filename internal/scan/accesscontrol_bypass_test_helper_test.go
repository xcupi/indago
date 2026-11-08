package scan_test

import (
	"net/url"

	"github.com/indago/indago/internal/accesscontrol"
	"github.com/indago/indago/internal/domain"
)

// accessBypassJobCount is the number of access-control bypass jobs the one-time
// pass adds for these endpoints: one per bounded privileged path per distinct
// origin (see internal/scan/accesscontrol_bypass.go).
func accessBypassJobCount(eps []*domain.Endpoint) int {
	seen := map[string]struct{}{}
	for _, ep := range eps {
		u, err := url.Parse(ep.URL)
		if err != nil || u.Host == "" {
			continue
		}
		seen[u.Scheme+"://"+u.Host] = struct{}{}
	}
	return len(seen) * len(accesscontrol.BypassPaths)
}

// disclosureJobCount is how many endpoints the passive disclosure pass queues:
// every GET endpoint without a query, capped at the pass's own bound.
func disclosureJobCount(eps []*domain.Endpoint) int {
	n := 0
	for _, ep := range eps {
		if ep.Method != domain.MethodGET {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || u.RawQuery != "" {
			continue
		}
		n++
	}
	if n > 40 {
		n = 40
	}
	return n
}
