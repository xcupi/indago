package web_test

// Contract test for the report format pickers.
//
// SARIF is a real export the server already renders (internal/report), but an
// operator can only ask for it if both dashboard surfaces offer it: the legacy
// dashboard (assets/scans.js, served at "/") and the bundled SPA
// (web/ -> assets/next, served at "/next/"). The option must carry the value
// the API expects ("sarif") and name the extension it is saved as, so a
// generated report never arrives as an unlabelled machine blob.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReportFormatPickersOfferSARIF(t *testing.T) {
	const label = "SARIF 2.1.0 (.sarif)"

	legacy, err := os.ReadFile(filepath.Join("assets", "scans.js"))
	if err != nil {
		t.Fatalf("read legacy dashboard: %v", err)
	}
	if !strings.Contains(string(legacy), `["sarif", "`+label+`"]`) {
		t.Fatalf(`legacy report picker does not offer {"sarif", %q}`, label)
	}

	var spa strings.Builder
	err = filepath.Walk(filepath.Join("assets", "next"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".js") {
			return err
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		spa.Write(b)
		return nil
	})
	if err != nil {
		t.Fatalf("read bundled SPA: %v", err)
	}
	if spa.Len() == 0 {
		t.Fatal("no bundled SPA scripts found; run the UI build (make ui)")
	}
	bundle := spa.String()
	if !strings.Contains(bundle, label) {
		t.Fatalf("bundled SPA report picker does not name %q", label)
	}
	if !regexp.MustCompile(`value:\s*"sarif"`).MatchString(bundle) {
		t.Fatalf(`bundled SPA report picker does not send format "sarif"; rebuild with make ui`)
	}
}
