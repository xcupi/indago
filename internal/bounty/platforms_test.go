package bounty

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestStoreMultiProviderRoundTripAndValidation(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(dir)

	if err := st.SetFor("unknown", "tok"); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("SetFor(unknown) = %v, want ErrUnsupportedProvider", err)
	}
	if err := st.ClearFor("unknown"); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("ClearFor(unknown) = %v, want ErrUnsupportedProvider", err)
	}
	if st.TokenFor("unknown") != "" || st.ConfiguredFor("unknown") {
		t.Fatal("unknown provider must report empty/unconfigured")
	}

	providers := []string{ProviderYesWeHack, ProviderHackerOne, ProviderBugcrowd, ProviderIntigriti}
	for _, p := range providers {
		if st.ConfiguredFor(p) {
			t.Fatalf("%s should start unconfigured", p)
		}
		tok := "tok-" + p
		if err := st.SetFor(p, "  "+tok+"  "); err != nil {
			t.Fatalf("SetFor(%s): %v", p, err)
		}
		if got := st.TokenFor(p); got != tok {
			t.Fatalf("TokenFor(%s) = %q, want %q", p, got, tok)
		}
		if !st.ConfiguredFor(p) {
			t.Fatalf("ConfiguredFor(%s) = false", p)
		}
		info, err := os.Stat(filepath.Join(dir, p+".token"))
		if err != nil {
			t.Fatalf("stat %s.token: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s.token mode = %o, want 600", p, perm)
		}
	}

	// Legacy methods still map to yeswehack.
	if st.Token() != "tok-yeswehack" || !st.Configured() {
		t.Fatalf("legacy Token/Configured mismatch: %q %v", st.Token(), st.Configured())
	}
	if err := st.Clear(); err != nil {
		t.Fatal(err)
	}
	if st.ConfiguredFor(ProviderYesWeHack) {
		t.Fatal("yeswehack should be cleared")
	}
	if !st.ConfiguredFor(ProviderHackerOne) {
		t.Fatal("clearing yeswehack must not affect hackerone")
	}
	if err := st.ClearFor(ProviderHackerOne); err != nil {
		t.Fatal(err)
	}
	if st.ConfiguredFor(ProviderHackerOne) {
		t.Fatal("hackerone should be cleared")
	}
}

func TestHackerOneClient(t *testing.T) {
	var listCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Basic "+base64.StdEncoding.EncodeToString([]byte("bad:tok")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/hackers/programs":
			listCalls.Add(1)
			if r.URL.Query().Get("page[number]") == "" || r.URL.Query().Get("page[size]") == "" {
				t.Errorf("missing pagination query: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{
				"data":[{
					"id":"1",
					"type":"program",
					"attributes":{"handle":"acme","name":"ACME Corp","state":"public_mode","submission_state":"open","offers_bounties":true}
				}],
				"meta":{"total_count":12}
			}`))
		case "/hackers/programs/acme":
			w.Write([]byte(`{
				"data":{
					"id":"1",
					"type":"program",
					"attributes":{"handle":"acme","name":"ACME Corp","state":"public_mode","submission_state":"open","offers_bounties":true,"policy":"Be nice"},
					"relationships":{
						"structured_scopes":{
							"data":[
								{"id":"s1","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"https://app.acme.test","eligible_for_submission":true,"instruction":"Main app"}},
								{"id":"s2","type":"structured-scope","attributes":{"asset_type":"WILDCARD","asset_identifier":"*.acme.test","eligible_for_submission":true}},
								{"id":"s3","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"https://oos.acme.test","eligible_for_submission":false}},
								{"id":"s4","type":"structured-scope","attributes":{"asset_type":"APPLE_STORE_APP_ID","asset_identifier":"12345","eligible_for_submission":true}}
							]
						}
					}
				}
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewHackerOneClient(srv.URL, func() string { return "user:secret" })

	if err := c.Validate(context.Background(), "user:secret"); err != nil {
		t.Fatalf("Validate valid: %v", err)
	}
	if err := c.Validate(context.Background(), "bad:tok"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Validate bad = %v, want ErrUnauthorized", err)
	}

	q := Query{Page: 2, PerPage: 25}
	items, total, cached, err := c.ListPrograms(context.Background(), q, false)
	if err != nil || cached || total != 12 || len(items) != 1 {
		t.Fatalf("ListPrograms = items:%v total:%d cached:%v err:%v", items, total, cached, err)
	}
	if items[0].Slug != "acme" || !items[0].Bounty || items[0].Provider != ProviderHackerOne {
		t.Fatalf("unexpected program: %+v", items[0])
	}
	if _, _, cached, err = c.ListPrograms(context.Background(), q, false); err != nil || !cached {
		t.Fatalf("expected cache hit: cached=%v err=%v", cached, err)
	}
	if _, _, cached, err = c.ListPrograms(context.Background(), q, true); err != nil || cached {
		t.Fatalf("expected cache bypass on refresh: cached=%v err=%v", cached, err)
	}
	if listCalls.Load() != 3 { // 1 from Validate + 2 from ListPrograms
		t.Fatalf("listCalls = %d, want 3", listCalls.Load())
	}

	prog, err := c.GetProgram(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetProgram: %v", err)
	}
	if len(prog.Scopes) != 2 || prog.Scopes[0].Target != "https://app.acme.test" || prog.Scopes[0].Type != "url" || prog.Scopes[1].Type != "wildcard" {
		t.Fatalf("unexpected scopes: %+v", prog.Scopes)
	}
}

func TestBugcrowdClient(t *testing.T) {
	var listCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token bc-good" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/programs":
			listCalls.Add(1)
			w.Write([]byte(`{
				"programs":[{"code":"bc-acme","name":"BC ACME","program_type":"bug_bounty","status":"open","min_reward":100,"max_reward":5000,"public":true}],
				"meta":{"total_hits":7}
			}`))
		case "/programs/bc-acme":
			w.Write([]byte(`{
				"code":"bc-acme",
				"name":"BC ACME",
				"program_type":"bug_bounty",
				"status":"open",
				"max_reward":5000
			}`))
		case "/programs/bc-acme/target_groups":
			w.Write([]byte(`{
				"target_groups":[
					{
						"name":"In Scope",
						"in_scope":true,
						"targets":[
							{"uri":"https://web.bc.test","category":"website","in_scope":true},
							{"uri":"https://api.bc.test/v1","category":"api","in_scope":true},
							{"uri":"com.bc.mobile","category":"android","in_scope":true},
							{"uri":"https://excluded.bc.test","category":"website","in_scope":false}
						]
					},
					{
						"name":"Out of Scope",
						"in_scope":false,
						"targets":[{"uri":"https://oos.bc.test","category":"website"}]
					}
				]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewBugcrowdClient(srv.URL, func() string { return "bc-good" })
	if err := c.Validate(context.Background(), "bc-good"); err != nil {
		t.Fatalf("Validate valid: %v", err)
	}
	if err := c.Validate(context.Background(), "bc-bad"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Validate bad = %v, want ErrUnauthorized", err)
	}

	items, total, cached, err := c.ListPrograms(context.Background(), Query{Page: 1, PerPage: 10}, false)
	if err != nil || cached || total != 7 || len(items) != 1 {
		t.Fatalf("ListPrograms = items:%v total:%d cached:%v err:%v", items, total, cached, err)
	}
	if _, _, cached, _ = c.ListPrograms(context.Background(), Query{Page: 1, PerPage: 10}, false); !cached {
		t.Fatal("expected cache hit")
	}
	if _, _, cached, _ = c.ListPrograms(context.Background(), Query{Page: 1, PerPage: 10}, true); cached {
		t.Fatal("expected refresh bypass")
	}
	if listCalls.Load() != 3 {
		t.Fatalf("listCalls = %d, want 3", listCalls.Load())
	}

	prog, err := c.GetProgram(context.Background(), "bc-acme")
	if err != nil {
		t.Fatalf("GetProgram: %v", err)
	}
	if len(prog.Scopes) != 2 || prog.Scopes[0].Type != "url" || prog.Scopes[1].Type != "api" {
		t.Fatalf("unexpected scopes: %+v", prog.Scopes)
	}
}

func TestIntigritiClient(t *testing.T) {
	var listCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer int-good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/programs":
			listCalls.Add(1)
			w.Write([]byte(`{
				"records":[{
					"id":"prog-1",
					"handle":"int-acme",
					"name":"Intigriti ACME",
					"type":{"value":"Bug bounty"},
					"status":{"value":"Open"},
					"confidentialityLevel":{"value":"Public"},
					"minBounty":{"value":50},
					"maxBounty":{"value":2500}
				}],
				"maxCount":9
			}`))
		case "/programs/prog-1":
			w.Write([]byte(`{
				"id":"prog-1",
				"handle":"int-acme",
				"name":"Intigriti ACME",
				"type":{"value":"Bug bounty"},
				"status":{"value":"Open"},
				"domains":{
					"content":[
						{"endpoint":"https://app.int.test","type":{"value":"url"},"tier":{"value":"Tier 1"}},
						{"endpoint":"*.int.test","type":{"value":"wildcard"},"tier":{"value":"Tier 2"}},
						{"endpoint":"https://oos.int.test","type":{"value":"url"},"tier":{"value":"out_of_scope"}},
						{"endpoint":"1.2.3.4","type":{"value":"iprange"},"tier":{"value":"Tier 1"}}
					]
				}
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewIntigritiClient(srv.URL, func() string { return "int-good" })
	if err := c.Validate(context.Background(), "int-good"); err != nil {
		t.Fatalf("Validate valid: %v", err)
	}
	if err := c.Validate(context.Background(), "int-bad"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Validate bad = %v, want ErrUnauthorized", err)
	}

	items, total, cached, err := c.ListPrograms(context.Background(), Query{Page: 1, PerPage: 20}, false)
	if err != nil || cached || total != 9 || len(items) != 1 {
		t.Fatalf("ListPrograms = items:%v total:%d cached:%v err:%v", items, total, cached, err)
	}
	if items[0].RewardMax != 2500 || !items[0].Public {
		t.Fatalf("unexpected program: %+v", items[0])
	}
	if _, _, cached, _ = c.ListPrograms(context.Background(), Query{Page: 1, PerPage: 20}, false); !cached {
		t.Fatal("expected cache hit")
	}
	if _, _, cached, _ = c.ListPrograms(context.Background(), Query{Page: 1, PerPage: 20}, true); cached {
		t.Fatal("expected refresh bypass")
	}
	if listCalls.Load() != 3 {
		t.Fatalf("listCalls = %d, want 3", listCalls.Load())
	}

	prog, err := c.GetProgram(context.Background(), "prog-1")
	if err != nil {
		t.Fatalf("GetProgram: %v", err)
	}
	if len(prog.Scopes) != 2 || prog.Scopes[0].Target != "https://app.int.test" || prog.Scopes[1].Target != "*.int.test" {
		t.Fatalf("unexpected scopes: %+v", prog.Scopes)
	}
}

func TestNewPlatformClientFactory(t *testing.T) {
	for _, p := range []string{ProviderHackerOne, ProviderBugcrowd, ProviderIntigriti} {
		pc, err := NewPlatformClient(p, "", nil)
		if err != nil {
			t.Fatalf("NewPlatformClient(%s): %v", p, err)
		}
		if pc.Provider() != p {
			t.Fatalf("Provider() = %q, want %q", pc.Provider(), p)
		}
	}
	if _, err := NewPlatformClient("unknown", "", nil); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("NewPlatformClient(unknown) = %v, want ErrUnsupportedProvider", err)
	}
}
