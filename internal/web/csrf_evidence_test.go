package web_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestCSRFEvidenceReviewUsesStoredArtifacts(t *testing.T) {
	a := newAPI(t, nil)
	ctx := context.Background()
	scan := &domain.Scan{ID: "archived-scan", State: domain.ScanCompleted}
	if err := a.st.Scans().Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	finding := &domain.Finding{
		ID: "archived-csrf", ScanID: scan.ID, VulnClass: domain.VulnCSRF,
		Verdict: domain.VerdictInconclusive, Severity: domain.SeverityInfo,
	}
	for _, item := range []struct {
		id   domain.ID
		kind domain.EvidenceKind
		note string
		text string
	}{
		{"baseline", domain.EvidenceRequest, domain.EvidenceNoteBaselinePrefix, "GET /status HTTP/1.1\r\nHost: fixture.invalid\r\nCookie: synthetic-baseline\r\n\r\n"},
		{"request", domain.EvidenceRequest, "", "GET /status HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"},
		{"authenticated-record", domain.EvidenceRequest, "", "GET /status HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: synthetic-secret\r\n\r\n"},
		{"response", domain.EvidenceResponse, "", "HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{"unreadable", domain.EvidenceResponse, "", ""},
		{"browser-log", domain.EvidenceBrowserLog, "", "synthetic diagnostic"},
	} {
		ev := &domain.Evidence{ID: item.id, ScanID: scan.ID, Kind: item.kind, Note: item.note}
		if item.text != "" {
			ref, err := a.ev.Put(scan.ID, item.kind, ".txt", []byte(item.text))
			if err != nil {
				t.Fatal(err)
			}
			ev.BlobPath, ev.Size, ev.SHA256 = ref.BlobPath, ref.Size, ref.SHA256
		}
		if err := a.st.Evidence().Create(ctx, ev); err != nil {
			t.Fatal(err)
		}
		finding.EvidenceIDs = append(finding.EvidenceIDs, ev.ID)
	}
	if err := a.st.Findings().Create(ctx, finding); err != nil {
		t.Fatal(err)
	}

	var out struct {
		Verdict domain.Verdict `json:"verdict"`
		Review  *struct {
			Requests           int   `json:"requests_read"`
			Credentials        int   `json:"requests_with_credentials"`
			Statuses           []int `json:"response_statuses"`
			BrowserArtifacts   int   `json:"browser_artifacts_linked"`
			UnreadOrUnreviewed int   `json:"unread_or_unreviewed"`
		} `json:"csrf_evidence_review"`
	}
	rec := a.do(http.MethodGet, "/api/scans/archived-scan/findings/archived-csrf", nil)
	a.mustJSON(rec, http.StatusOK, &out)
	r := out.Review
	if r == nil || r.Requests != 2 || r.Credentials != 1 || !slices.Equal(r.Statuses, []int{200}) ||
		r.BrowserArtifacts != 1 || r.UnreadOrUnreviewed != 1 || out.Verdict != domain.VerdictInconclusive {
		t.Fatalf("unexpected assessment: %#v, verdict %s", r, out.Verdict)
	}
	if strings.Contains(rec.Body.String(), "synthetic-secret") || strings.Contains(rec.Body.String(), "synthetic-baseline") {
		t.Fatal("assessment exposed a recorded header value")
	}
}
