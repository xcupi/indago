package report

import (
	"strings"

	"github.com/indago/indago/internal/domain"
)

func browserArtifactsWithheld(f *domain.Finding, evidence map[domain.ID]*domain.Evidence) bool {
	switch f.VulnClass {
	case domain.VulnReflectedXSS, domain.VulnDOMXSS, domain.VulnStoredXSS:
	default:
		return false
	}
	withheld := false
	for _, id := range f.EvidenceIDs {
		ev := evidence[id]
		if ev == nil || ev.ScanID != f.ScanID {
			continue
		}
		if ev.Role() == domain.RoleBrowser {
			return false
		}
		if ev.Kind == domain.EvidenceOther && strings.Contains(ev.Note, " browser artifacts withheld (") {
			withheld = true
		}
	}
	return withheld
}
