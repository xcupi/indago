package web

// PDF export: the HTML report is rendered to a print-ready page by the report
// package, then converted by a headless Chromium. The converter lives here (not
// in internal/report) because it is I/O and process execution; the report
// package stays pure so its output is deterministic and testable.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PDFRenderer converts one self-contained HTML document into PDF bytes.
type PDFRenderer interface {
	Render(ctx context.Context, htmlDoc []byte) ([]byte, error)
}

// ChromiumPDFRenderer shells out to Chrome/Chromium's --print-to-pdf. It is
// deliberately not the Playwright browser session: report export must work
// without -browser, and a crash of the print process must never touch the
// scanning browser.
type ChromiumPDFRenderer struct {
	// Path is the Chrome/Chromium executable.
	Path string
	// DisableSandbox passes --no-sandbox; required when the server itself runs
	// as root or in a container without user namespaces.
	DisableSandbox bool
	// Timeout bounds the whole conversion (default 45s).
	Timeout time.Duration
}

// NewChromiumPDFRenderer returns a renderer for the given executable.
func NewChromiumPDFRenderer(path string, disableSandbox bool) *ChromiumPDFRenderer {
	return &ChromiumPDFRenderer{Path: path, DisableSandbox: disableSandbox}
}

// Render writes the document to a private temp dir, prints it to PDF and reads
// the result back. Every failure is returned with the browser's own stderr so
// the operator can tell "chromium missing" from "print crashed".
func (c *ChromiumPDFRenderer) Render(ctx context.Context, htmlDoc []byte) ([]byte, error) {
	if c == nil || strings.TrimSpace(c.Path) == "" {
		return nil, errors.New("pdf renderer: no chromium executable configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "indago-pdf-")
	if err != nil {
		return nil, fmt.Errorf("pdf renderer: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "report.html")
	out := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(in, htmlDoc, 0o600); err != nil {
		return nil, fmt.Errorf("pdf renderer: write html: %w", err)
	}

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--user-data-dir=" + filepath.Join(dir, "profile"),
		"--no-pdf-header-footer",
		"--print-to-pdf-no-header",
		"--virtual-time-budget=3000",
		"--print-to-pdf=" + out,
		"file://" + in,
	}
	if c.DisableSandbox {
		args = append([]string{"--no-sandbox"}, args...)
	}
	cmd := exec.CommandContext(ctx, c.Path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 600 {
			msg = msg[:600]
		}
		return nil, fmt.Errorf("pdf renderer: chromium: %w: %s", err, msg)
	}
	pdf, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("pdf renderer: read output: %w", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF")) {
		return nil, errors.New("pdf renderer: chromium produced no PDF")
	}
	return pdf, nil
}

// ChromiumForPDF resolves the print executable: the -chromium flag first, then
// INDAGO_CHROMIUM_PATH, then the usual PATH names. Empty means PDF export is
// unavailable (the API answers 503 with that reason rather than failing later).
func ChromiumForPDF(flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("INDAGO_CHROMIUM_PATH")); v != "" {
		return v
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
