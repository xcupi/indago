package web_test

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/web"
)

// The SPA reads /api/capabilities to decide whether to advertise the built-in
// OAST collaborator and to default the private-lab switch. Reporting the
// listener as present when it is not (or omitting it when it is) would make the
// UI claim callback coverage the server cannot deliver.
func TestCapabilitiesReportOASTWiring(t *testing.T) {
	a, _ := coverageAPI(t, web.Capabilities{
		OASTEnabled:      true,
		OASTCallbackURL:  "https://cb.example.test",
		AllowPrivateOAST: true,
	})
	var got map[string]any
	a.mustJSON(a.do("GET", "/api/capabilities", nil), 200, &got)
	if got["oast_enabled"] != true || got["oast_callback_url"] != "https://cb.example.test" || got["allow_private_oast"] != true {
		t.Fatalf("capabilities do not report the OAST wiring: %v", got)
	}

	// The default server starts no listener; the UI must be able to say so.
	zero, _ := coverageAPI(t, web.Capabilities{})
	var off map[string]any
	zero.mustJSON(zero.do("GET", "/api/capabilities", nil), 200, &off)
	if off["oast_enabled"] != false || off["oast_callback_url"] != nil || off["allow_private_oast"] != false {
		t.Fatalf("a server without a collaborator must report OAST off: %v", off)
	}
}

// The scan-detail Capabilities dialog sends every engine switch in one PUT.
// A field the handler does not decode is accepted with 200 and silently
// discarded, so each switch is pinned to the stored scan config.
func TestUpdateScanCapabilitiesPersistsEveryEngineSwitch(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{})
	body := map[string]any{
		"skip_reflected_xss":       true,
		"skip_dom_xss":             true,
		"skip_access_control":      true,
		"skip_idor":                true,
		"skip_info_disclosure":     true,
		"skip_ssrf":                true,
		"skip_path_traversal":      true,
		"skip_security_headers":    true,
		"skip_method_tls":          true,
		"skip_host_header":         true,
		"skip_jwt":                 true,
		"skip_cors":                true,
		"skip_open_redirect":       true,
		"skip_graphql":             true,
		"enable_command_injection": true,
		"enable_ssti":              true,
		"enable_sqli":              true,
		"enable_nosqli":            true,
		"enable_xxe":               true,
	}
	a.mustJSON(a.do("PUT", "/api/scans/"+string(id)+"/capabilities", body), 200, nil)

	stored, err := a.st.Scans().Get(context.Background(), id)
	if err != nil {
		t.Fatalf("read stored scan: %v", err)
	}
	cfg := stored.Config
	for _, c := range []struct {
		name  string
		value bool
	}{
		{"skip_reflected_xss", cfg.SkipReflectedXSS},
		{"skip_dom_xss", cfg.SkipDOMXSS},
		{"skip_access_control", cfg.SkipAccessControl},
		{"skip_idor", cfg.SkipIDOR},
		{"skip_info_disclosure", cfg.SkipInfoDisclosure},
		{"skip_ssrf", cfg.SkipSSRF},
		{"skip_path_traversal", cfg.SkipPathTraversal},
		{"skip_security_headers", cfg.SkipSecurityHeaders},
		{"skip_method_tls", cfg.SkipMethodTLS},
		{"skip_host_header", cfg.SkipHostHeader},
		{"skip_jwt", cfg.SkipJWT},
		{"skip_cors", cfg.SkipCORS},
		{"skip_open_redirect", cfg.SkipOpenRedirect},
		{"skip_graphql", cfg.SkipGraphQL},
		{"enable_command_injection", cfg.EnableCommandInjection},
		{"enable_ssti", cfg.EnableSSTI},
		{"enable_sqli", cfg.EnableSQLi},
		{"enable_nosqli", cfg.EnableNoSQLi},
		{"enable_xxe", cfg.EnableXXE},
	} {
		if !c.value {
			t.Errorf("PUT /capabilities dropped %s", c.name)
		}
	}
}
