package web_test

// createScanReq.allow_insecure_tls is the API surface of the lab/staging TLS
// opt-in. It must reach the persisted domain.ScanConfig, and omitting it must
// leave strict certificate verification (the default) untouched.

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestCreateScanAllowInsecureTLSPersists(t *testing.T) {
	a := newAPI(t, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	var on domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "allow_insecure_tls": true,
	}), 201, &on)
	if !on.Config.AllowInsecureTLS {
		t.Fatalf("create response config = %+v, want allow_insecure_tls", on.Config)
	}
	stored, err := a.st.Scans().Get(context.Background(), on.ID)
	if err != nil {
		t.Fatalf("read stored scan: %v", err)
	}
	if !stored.Config.AllowInsecureTLS {
		t.Fatalf("stored config = %+v, want allow_insecure_tls persisted", stored.Config)
	}

	// Omitted is the default: strict verification stays on.
	var off domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID,
	}), 201, &off)
	if off.Config.AllowInsecureTLS {
		t.Fatalf("omitted allow_insecure_tls produced %+v, want strict verification (false)", off.Config)
	}
}
