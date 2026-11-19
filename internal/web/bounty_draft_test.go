package web_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

func seedConfirmedFindingForDraft(t *testing.T, st *memory.Store, notes string) (*domain.Scan, *domain.Finding, *domain.Finding) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	proj := &domain.Project{ID: domain.NewID(), Name: "ACME", Notes: notes, CreatedAt: now, UpdatedAt: now}
	if err := st.Projects().Create(ctx, proj); err != nil {
		t.Fatal(err)
	}
	tgt := &domain.Target{ID: domain.NewID(), ProjectID: proj.ID, Name: "acme", BaseURL: "https://app.acme.test/", CreatedAt: now, UpdatedAt: now}
	if err := st.Targets().Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: proj.ID, TargetID: tgt.ID, Name: "scan", State: domain.ScanCompleted, CreatedAt: now, UpdatedAt: now}
	if err := st.Scans().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: "https://app.acme.test/search", Method: "GET"}
	if err := st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	confirmed := &domain.Finding{
		ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID,
		Title: "Reflected XSS in q", Summary: "q reflects unsanitized",
		VulnClass: domain.VulnReflectedXSS, Severity: domain.SeverityHigh,
		Confidence: domain.ConfidenceHigh, Verdict: domain.VerdictConfirmed,
		Location: domain.LocationQuery, CreatedAt: now, UpdatedAt: now,
	}
	rejected := &domain.Finding{
		ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID,
		Title: "Rejected probe", VulnClass: domain.VulnReflectedXSS,
		Severity: domain.SeverityLow, Confidence: domain.ConfidenceLow,
		Verdict: domain.VerdictRejected, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Findings().Create(ctx, confirmed); err != nil {
		t.Fatal(err)
	}
	if err := st.Findings().Create(ctx, rejected); err != nil {
		t.Fatal(err)
	}
	return sc, confirmed, rejected
}

func TestYesWeHackDraftCreateAndUpdateNeverSubmits(t *testing.T) {
	var calls []string
	var lastDraft bounty.DraftReport
	ywh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/programs/acme/reports" {
			t.Fatalf("submit endpoint /reports must never be called")
		}
		if r.Header.Get("Authorization") != "Bearer a.b.c" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&lastDraft); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":77,"url":"https://yeswehack.com/programs/acme/drafts/77"}`))
			return
		}
		w.Write([]byte(`{"id":77,"url":"https://yeswehack.com/programs/acme/drafts/77"}`))
	}))
	defer ywh.Close()
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)

	st := memory.New()
	sc, confirmed, _ := seedConfirmedFindingForDraft(t, st, "Imported from YesWeHack (acme)")
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	tokens := bounty.NewStore(t.TempDir())
	if err := tokens.Set("a.b.c"); err != nil {
		t.Fatal(err)
	}
	srv.SetBountyStore(tokens)
	a := api{t: t, h: srv.Handler(), st: st}

	var createResp struct {
		ProgramSlug string `json:"program_slug"`
		FindingID   string `json:"finding_id"`
		DraftID     string `json:"draft_id"`
		Action      string `json:"action"`
		Submitted   bool   `json:"submitted"`
		URL         string `json:"url"`
	}
	a.mustJSON(a.do("POST", "/api/scans/"+string(sc.ID)+"/bounty/yeswehack/draft", map[string]any{}), http.StatusCreated, &createResp)
	if createResp.ProgramSlug != "acme" || createResp.FindingID != string(confirmed.ID) || createResp.DraftID != "77" || createResp.Action != "created" || createResp.Submitted {
		t.Fatalf("unexpected create response: %+v", createResp)
	}
	if !strings.Contains(lastDraft.DescriptionMarkdown, "## Description") || !strings.Contains(lastDraft.DescriptionMarkdown, "## PoC") {
		t.Fatalf("draft markdown missing YesWeHack sections: %q", lastDraft.DescriptionMarkdown)
	}

	var updateResp struct {
		DraftID   string `json:"draft_id"`
		Action    string `json:"action"`
		Submitted bool   `json:"submitted"`
	}
	a.mustJSON(a.do("POST", "/api/scans/"+string(sc.ID)+"/bounty/yeswehack/draft", map[string]any{
		"finding_id": string(confirmed.ID),
		"draft_id":   "77",
	}), http.StatusOK, &updateResp)
	if updateResp.DraftID != "77" || updateResp.Action != "updated" || updateResp.Submitted {
		t.Fatalf("unexpected update response: %+v", updateResp)
	}

	if len(calls) != 2 || calls[0] != "POST /programs/acme/reports/draft" || calls[1] != "PUT /programs/acme/reports/draft/77" {
		t.Fatalf("platform calls = %v", calls)
	}
}

func TestYesWeHackDraftValidation(t *testing.T) {
	ywh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ywh.Close()
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)

	st := memory.New()
	sc, _, rejected := seedConfirmedFindingForDraft(t, st, "")
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	tokens := bounty.NewStore(t.TempDir())
	srv.SetBountyStore(tokens)
	a := api{t: t, h: srv.Handler(), st: st}

	// Missing token -> 400.
	resp := a.do("POST", "/api/scans/"+string(sc.ID)+"/bounty/yeswehack/draft", map[string]any{"program_slug": "acme"})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("missing token status = %d, want 400", resp.Code)
	}

	if err := tokens.Set("tok"); err != nil {
		t.Fatal(err)
	}

	// Missing program_slug on non-imported project -> 400.
	resp = a.do("POST", "/api/scans/"+string(sc.ID)+"/bounty/yeswehack/draft", map[string]any{})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("missing slug status = %d, want 400", resp.Code)
	}

	// Non-confirmed finding -> 400.
	resp = a.do("POST", "/api/scans/"+string(sc.ID)+"/bounty/yeswehack/draft", map[string]any{
		"program_slug": "acme",
		"finding_id":   string(rejected.ID),
	})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("rejected finding status = %d, want 400", resp.Code)
	}

	// Platform 401 -> 401.
	resp = a.do("POST", "/api/scans/"+string(sc.ID)+"/bounty/yeswehack/draft", map[string]any{"program_slug": "acme"})
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want 401", resp.Code)
	}
}
