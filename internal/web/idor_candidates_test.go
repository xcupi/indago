package web_test

// The harvested-candidate surface is read-only and must never invent data:
// before the IDOR engine ran it returns an empty list with a note, and after it
// ran it returns exactly the set persisted on the identity-baseline TestCase.

import (
	"context"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

func TestIDORCandidatesEndpointSurfacesPersistedHarvest(t *testing.T) {
	a, scanID := coverageAPI(t, web.Capabilities{})

	type candidate struct {
		Value  string `json:"value"`
		Shape  string `json:"shape"`
		Origin struct {
			Endpoint string `json:"endpoint"`
			Field    string `json:"field"`
			Via      string `json:"via"`
		} `json:"origin"`
	}
	type resp struct {
		ScanID     string      `json:"scan_id"`
		Candidates []candidate `json:"candidates"`
		Total      int         `json:"total"`
		Note       string      `json:"note"`
	}

	var before resp
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/idor/candidates", nil), 200, &before)
	if before.Total != 0 || len(before.Candidates) != 0 {
		t.Fatalf("an unrun IDOR pass must expose no candidates: %+v", before)
	}
	if before.Note == "" {
		t.Fatal("an empty harvest must say why it is empty")
	}

	now := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: scanID, VulnClass: domain.VulnIDOR,
		Status: domain.TestCaseCompleted, Note: "idor identity baseline",
		Detail: []byte(`{"engine":"idor","harvest_note":"1 identifier harvested",` +
			`"harvested_candidates":[{"value":"carlos","shape":"username",` +
			`"origin":{"endpoint":"https://app.test/admin/users","field":"shared.username","via":"json"}}]}`),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.TestCases().Create(context.Background(), tc); err != nil {
		t.Fatal(err)
	}

	var after resp
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/idor/candidates", nil), 200, &after)
	if after.Total != 1 || len(after.Candidates) != 1 {
		t.Fatalf("candidates = %+v, want the one persisted value", after)
	}
	c := after.Candidates[0]
	if c.Value != "carlos" || c.Shape != "username" {
		t.Fatalf("candidate = %+v, want carlos/username", c)
	}
	if c.Origin.Endpoint != "https://app.test/admin/users" || c.Origin.Field != "shared.username" || c.Origin.Via != "json" {
		t.Fatalf("provenance = %+v, want the persisted JSON field origin", c.Origin)
	}

	if rec := a.do("GET", "/api/scans/"+string(domain.NewID())+"/idor/candidates", nil); rec.Code != 404 {
		t.Fatalf("unknown scan status = %d, want 404", rec.Code)
	}
}
