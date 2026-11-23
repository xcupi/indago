package web_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

func TestDashboardScanOverview(t *testing.T) {
	a := newAPI(t, nil)
	now := time.Unix(1700000000, 0).UTC()
	for i := 0; i < 12; i++ {
		scan := &domain.Scan{
			ID: domain.ID(fmt.Sprintf("scan-%02d", i)), State: domain.ScanCreated,
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		}
		if i < 4 {
			scan.State = domain.ScanAwaitingAuth
			scan.Stats.FindingsConfirmed = 2
			scan.Stats.FindingsRejected = 1
			scan.SessionID = "fixture-session"
		}
		if err := a.st.Scans().Create(context.Background(), scan); err != nil {
			t.Fatal(err)
		}
	}

	rec := a.do(http.MethodGet, "/api/dashboard/scans", nil)
	var overview store.ScanOverview
	a.mustJSON(rec, http.StatusOK, &overview)
	if overview.Total != 12 || overview.States[domain.ScanCreated] != 8 ||
		overview.States[domain.ScanAwaitingAuth] != 4 || overview.FindingsConfirmed != 8 || overview.FindingsRejected != 4 {
		t.Fatalf("unexpected scan overview: %+v", overview)
	}
	if len(overview.Recent) != 8 || overview.Recent[0].ID != "scan-11" || overview.Recent[7].ID != "scan-04" {
		t.Fatalf("unexpected recent scans: %+v", overview.Recent)
	}
	if strings.Contains(rec.Body.String(), `"config"`) || strings.Contains(rec.Body.String(), `"session_id"`) {
		t.Fatalf("dashboard payload contains full scan fields: %s", rec.Body.String())
	}
}
