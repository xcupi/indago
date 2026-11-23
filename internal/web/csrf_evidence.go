package web

import (
	"bytes"
	"slices"
	"strconv"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

type csrfEvidenceReview struct {
	RequestsRead            int   `json:"requests_read"`
	RequestsWithCredentials int   `json:"requests_with_credentials"`
	ResponseStatuses        []int `json:"response_statuses"`
	BrowserArtifactsLinked  int   `json:"browser_artifacts_linked"`
	UnreadOrUnreviewed      int   `json:"unread_or_unreviewed"`
}

// reviewCSRFEvidence describes existing artifacts without treating headers,
// successful HTTP responses, or a linked browser artifact as proof of impact.
func (s *Server) reviewCSRFEvidence(f *domain.Finding, lookup *evidenceLookup) *csrfEvidenceReview {
	if f.VulnClass != domain.VulnCSRF {
		return nil
	}
	result := &csrfEvidenceReview{ResponseStatuses: []int{}}
	readAttempts := 0
	for _, item := range lookup.metadata(f) {
		if item.Role() == domain.RoleBrowser {
			result.BrowserArtifactsLinked++
			continue
		}
		if item.Role() != domain.RoleCandidate ||
			(item.Kind != domain.EvidenceRequest && item.Kind != domain.EvidenceResponse) {
			continue
		}
		if s.evidence == nil || readAttempts >= maxReportRequestBlobs {
			result.UnreadOrUnreviewed++
			continue
		}
		readAttempts++
		blob, ok := s.readEvidenceBlob(item)
		if !ok || !result.inspect(item.Kind, blob) {
			result.UnreadOrUnreviewed++
		}
	}
	slices.Sort(result.ResponseStatuses)
	return result
}

func (r *csrfEvidenceReview) inspect(kind domain.EvidenceKind, blob []byte) bool {
	if kind == domain.EvidenceRequest {
		request, err := report.ParseHTTPRequestEvidence(blob)
		if err != nil {
			return false
		}
		r.RequestsRead++
		if slices.ContainsFunc(request.Headers, func(h report.HTTPHeader) bool {
			return strings.TrimSpace(h.Value) != "" &&
				(strings.EqualFold(h.Name, "Cookie") || strings.EqualFold(h.Name, "Authorization"))
		}) {
			r.RequestsWithCredentials++
		}
		return true
	}
	line, _, _ := bytes.Cut(blob, []byte("\n"))
	fields := strings.Fields(string(line))
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return false
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 599 {
		return false
	}
	if !slices.Contains(r.ResponseStatuses, status) {
		r.ResponseStatuses = append(r.ResponseStatuses, status)
	}
	return true
}
