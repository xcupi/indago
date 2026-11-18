package scan_test

// Wiring tests for the operator-supplied OpenAPI/Swagger import: the document
// must survive the whole path (CreateScanParams → domain.ScanConfig →
// discovery.RunParams → the discovery source → the collector) and its declared
// endpoints must be persisted with their own provenance. Validation failures are
// refused at creation, not discovered halfway through a scan.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// openAPISpecFor declares two endpoints on the site — one the site itself never
// links to — so a passing test proves the endpoints came from the document.
func openAPISpecFor(base string) string {
	return fmt.Sprintf(`{
	  "openapi": "3.0.3",
	  "info": {"title": "fixture", "version": "1"},
	  "servers": [{"url": %q}],
	  "paths": {
	    "/api/unlinked-endpoint": {
	      "get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string", "example": "x"}}]}
	    },
	    "/api/submit": {
	      "post": {"requestBody": {"content": {"application/json": {
	        "schema": {"type": "object", "properties": {"note": {"type": "string", "example": "hi"}}}
	      }}}}
	    }
	  }
	}`, base)
}

// A spec supplied at creation reaches discovery and its endpoints are
// persisted with openapi provenance, including one no page links to.
func TestOpenAPISpecImportRegistersDeclaredEndpoints(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})

	spec := openAPISpecFor(s.URL)
	// The legacy pipeline config keeps the Wave-1 engines out of the way; their
	// own Skip* switches are CreateScanParams fields, so they are mirrored here
	// exactly like the shared createScan helper does.
	sc, err := ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID:         proj,
		TargetID:          tgt,
		Name:              "openapi",
		Profile:           domain.ProfileCustom,
		Config:            legacyPipelineCfg(0),
		SkipSSRF:          true,
		SkipPathTraversal: true,
		SkipCORS:          true,
		SkipOpenRedirect:  true,
		SkipGraphQL:       true,
		OpenAPISpecJSON:   spec,
	})
	if err != nil {
		t.Fatalf("create scan with an inline spec: %v", err)
	}
	if sc.Config.OpenAPISpecJSON != spec {
		t.Fatalf("the spec was not persisted on the scan config (got %d bytes)", len(sc.Config.OpenAPISpecJSON))
	}

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	got := waitStatus(t, ctrl, sc.ID, 10*time.Second, func(st *scan.Status) bool {
		return st.Discovery.State == domain.DiscoveryComplete
	})
	if got.Discovery.EndpointsBySource[domain.SourceOpenAPI] < 2 {
		t.Fatalf("no openapi-provenance endpoints persisted: %v", got.Discovery.EndpointsBySource)
	}

	// The declared POST endpoint exists as its own method+URL row, which is what
	// gives it a test job (the executor's own state-changing opt-in decides
	// whether anything is ever sent to it).
	eps, err := st.Endpoints().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	var unlinked, submit bool
	for _, ep := range eps {
		if ep.Source != domain.SourceOpenAPI {
			continue
		}
		switch {
		case ep.Method == domain.MethodGET && ep.URL == s.URL+"/api/unlinked-endpoint?q=x":
			unlinked = true
		case ep.Method == domain.MethodPOST && ep.URL == s.URL+"/api/submit":
			submit = true
			if ep.RequestBody == "" || ep.ContentType != "application/json" {
				t.Fatalf("POST endpoint lost its synthesized JSON body: %+v", ep)
			}
		}
	}
	if !unlinked {
		t.Fatalf("the unlinked GET endpoint was not registered (endpoints: %d)", len(eps))
	}
	if !submit {
		t.Fatal("the declared POST endpoint was not registered")
	}
	// Nothing was sent to the declared endpoints: the fixture site never saw
	// them, because registration is not a request.
	if n := s.hitCount("/api/unlinked-endpoint"); n != 0 {
		t.Fatalf("discovery requested a declared endpoint %d time(s)", n)
	}
}

// A document that is not valid JSON, and a spec URL outside scope, are refused
// at creation (fail closed) instead of silently importing nothing.
func TestOpenAPISpecImportValidation(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})

	base := scan.CreateScanParams{ProjectID: proj, TargetID: tgt, Name: "openapi", Profile: domain.ProfileBalanced}

	badJSON := base
	badJSON.OpenAPISpecJSON = `{"openapi":"3.0.0","paths":{`
	if _, err := ctrl.CreateScan(ctx, badJSON); !errors.Is(err, scan.ErrBadConfig) {
		t.Fatalf("invalid JSON: err = %v, want ErrBadConfig", err)
	}

	outOfScope := base
	outOfScope.OpenAPISpecURL = "https://not-this-target.test/openapi.json"
	if _, err := ctrl.CreateScan(ctx, outOfScope); !errors.Is(err, scan.ErrBadConfig) {
		t.Fatalf("out-of-scope spec url: err = %v, want ErrBadConfig", err)
	}

	inScope := base
	inScope.OpenAPISpecURL = s.URL + "/openapi.json"
	saved, err := ctrl.CreateScan(ctx, inScope)
	if err != nil {
		t.Fatalf("in-scope spec url refused: %v", err)
	}
	if saved.Config.OpenAPISpecURL != inScope.OpenAPISpecURL {
		t.Fatalf("spec url not persisted: %q", saved.Config.OpenAPISpecURL)
	}
}
