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
