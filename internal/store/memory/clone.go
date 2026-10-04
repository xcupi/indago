package memory

import (
	"time"

	"github.com/indago/indago/internal/domain"
)

// Deep-copy helpers. These prevent callers from mutating stored state through a
// returned pointer or a shared slice/map backing array.

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneIDs(in []domain.ID) []domain.ID {
	if in == nil {
		return nil
	}
	out := make([]domain.ID, len(in))
	copy(out, in)
	return out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func cloneTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	t := *in
	return &t
}

func cloneProject(p *domain.Project) *domain.Project {
	c := *p
	return &c
}

func cloneTarget(t *domain.Target) *domain.Target {
	c := *t
	return &c
}

func cloneScope(s *domain.Scope) *domain.Scope {
	c := *s
	c.IncludeHosts = cloneStrings(s.IncludeHosts)
	c.ExcludeHosts = cloneStrings(s.ExcludeHosts)
	c.IncludePathPrefixes = cloneStrings(s.IncludePathPrefixes)
	c.ExcludePathPrefixes = cloneStrings(s.ExcludePathPrefixes)
	return &c
}

func cloneScan(s *domain.Scan) *domain.Scan {
	c := *s
	c.StartedAt = cloneTimePtr(s.StartedAt)
	c.EndedAt = cloneTimePtr(s.EndedAt)
	c.SeedURLs = cloneStrings(s.SeedURLs)
	return &c
}

func cloneEndpoint(e *domain.Endpoint) *domain.Endpoint {
	c := *e
	return &c
}

func cloneParameter(p *domain.Parameter) *domain.Parameter {
	c := *p
	return &c
}

func cloneInjectionPoint(i *domain.InjectionPoint) *domain.InjectionPoint {
	c := *i
	return &c
}

func cloneJob(j *domain.TestJob) *domain.TestJob {
	c := *j
	c.Payload = cloneBytes(j.Payload)
	c.LeasedUntil = cloneTimePtr(j.LeasedUntil)
	return &c
}

func cloneTestCase(t *domain.TestCase) *domain.TestCase {
	c := *t
	c.EvidenceIDs = cloneIDs(t.EvidenceIDs)
	c.Detail = cloneBytes(t.Detail)
	c.StartedAt = cloneTimePtr(t.StartedAt)
	c.FinishedAt = cloneTimePtr(t.FinishedAt)
	return &c
}

func cloneFinding(f *domain.Finding) *domain.Finding {
	c := *f
	c.EvidenceIDs = cloneIDs(f.EvidenceIDs)
	c.Provenance.VerifiedAt = cloneTimePtr(f.Provenance.VerifiedAt)
	c.Detail = cloneBytes(f.Detail)
	return &c
}

func cloneEvidence(e *domain.Evidence) *domain.Evidence {
	c := *e
	return &c
}

func cloneSession(s *domain.Session) *domain.Session {
	c := *s
	c.ExpiresAt = cloneTimePtr(s.ExpiresAt)
	return &c
}

func cloneReport(r *domain.Report) *domain.Report {
	c := *r
	c.Summary.ByVerdict = cloneVerdictMap(r.Summary.ByVerdict)
	c.Summary.BySeverity = cloneSeverityMap(r.Summary.BySeverity)
	c.Summary.ByVulnClass = cloneVulnClassMap(r.Summary.ByVulnClass)
	return &c
}

func cloneAITask(t *domain.AITask) *domain.AITask {
	c := *t
	c.Request = cloneBytes(t.Request)
	c.Response = cloneBytes(t.Response)
	return &c
}

func cloneVerdictMap(in map[domain.Verdict]int) map[domain.Verdict]int {
	if in == nil {
		return nil
	}
	out := make(map[domain.Verdict]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneSeverityMap(in map[domain.Severity]int) map[domain.Severity]int {
	if in == nil {
		return nil
	}
	out := make(map[domain.Severity]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneVulnClassMap(in map[domain.VulnClass]int) map[domain.VulnClass]int {
	if in == nil {
		return nil
	}
	out := make(map[domain.VulnClass]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
