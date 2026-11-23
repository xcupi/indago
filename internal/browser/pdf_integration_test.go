package browser_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
)

func TestPrintPDFWithIsolatedChromium(t *testing.T) {
	if testing.Short() {
		t.Skip("real-browser test")
	}
	exe := findChromium()
	if exe == "" {
		t.Skip("Chromium not installed")
	}
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	doc := fmt.Sprintf(`<!doctype html><h1>PDF renderer integration</h1><img src="%s">`, target.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	pdf, err := browser.PrintPDF(ctx, exe, os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1", []byte(doc))
	if errors.Is(err, browser.ErrPDFDriverUnavailable) {
		t.Skip("Playwright driver not installed")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatal("Chromium returned an invalid PDF")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("offline PDF document made %d HTTP requests", n)
	}
}
