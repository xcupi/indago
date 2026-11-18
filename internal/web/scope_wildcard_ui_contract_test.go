package web_test

// Contract test for the scope editor's wildcard field.
//
// The project page is a bundled SPA (web/ -> internal/web/assets/next), so the
// field is asserted against the emitted scripts rather than a hand-written
// file, following assets_contract_test.go. A wildcard asset is a review-scope
// fact, not cosmetics: the UI has to show the list separately from exact hosts,
// say that it covers subdomains and not the apex, and send it on save (the API
// preserves an absent field, so a form that dropped it could never clear a
// list an import created).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeUIExposesWildcardHostsSeparately(t *testing.T) {
	var js strings.Builder
	err := filepath.Walk("assets", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".js") {
			return err
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		js.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if js.Len() == 0 {
		t.Fatal("no JavaScript assets found; run the UI build (make ui)")
	}
	bundle := js.String()

	for _, want := range []struct{ needle, why string }{
		{"Wildcard hosts (subdomains only)", "the scope editor must name the wildcard list as its own field"},
		{"subdomain_only_hosts:", "the scope form must SEND the API field (an object key, not just a read); an absent field is preserved and could never be cleared"},
		{"NOT the host itself", "the field must say a wildcard does not authorize its apex"},
		{"subdomains only, apex not in scope", "the new-scan scope summary must show a wildcard host's meaning"},
		{"this list already means", "the field must refuse the *.example.com spelling instead of reinterpreting it"},
	} {
		if !strings.Contains(bundle, want.needle) {
			t.Errorf("bundled UI is missing %q (%s); rebuild with make ui", want.needle, want.why)
		}
	}
}
