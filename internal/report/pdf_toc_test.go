package report

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractPDFSectionPages_ChromiumDestsAndNestedPages(t *testing.T) {
	// Mimics Chromium/Skia PDF output:
	// - compressed stream object before /Pages
	// - nested /Pages -> /Kids tree (3 pages total: obj 2, obj 5, obj 7)
	// - /Catalog -> /Dests indirect dictionary mapping /s1, /s2, /s3
	pdf := `%PDF-1.4
1 0 obj
<< /Length 12 /Filter /FlateDecode >>
stream
binaryobjdata
endstream
endobj
2 0 obj
<< /Type /Page /Parent 3 0 R >>
endobj
5 0 obj
<< /Type /Page /Parent 4 0 R >>
endobj
7 0 obj
<< /Type /Page /Parent 4 0 R >>
endobj
4 0 obj
<< /Type /Pages /Count 2 /Kids [5 0 R 7 0 R] >>
endobj
3 0 obj
<< /Type /Pages /Count 3 /Kids [2 0 R 4 0 R] >>
endobj
8 0 obj
<< /s1 [2 0 R /XYZ 6 800 0]
/s2 [5 0 R /XYZ 6 750 0]
/s3 [7 0 R /XYZ 6 820 0] >>
endobj
9 0 obj
<< /Type /Catalog /Pages 3 0 R /Dests 8 0 R >>
endobj
trailer
<< /Size 10 /Root 9 0 R >>
%%EOF`

	got := ExtractPDFSectionPages([]byte(pdf))
	want := map[string]int{"s1": 1, "s2": 2, "s3": 3}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("page[%q] = %d, want %d", k, got[k], w)
		}
	}
}

func TestExtractPDFSectionPages_NameTreeAndXRefRoot(t *testing.T) {
	// PDF 1.5+ style: /Root in /XRef object (no trailer), /Names -> /Dests name tree.
	pdf := `%PDF-1.5
1 0 obj
<< /Type /Page >>
endobj
2 0 obj
<< /Type /Page >>
endobj
3 0 obj
<< /Type /Pages /Count 2 /Kids [1 0 R 2 0 R] >>
endobj
4 0 obj
<< /Names [(s1) [1 0 R /Fit] (s2) 5 0 R] >>
endobj
5 0 obj
<< /D [2 0 R /XYZ 0 700 0] >>
endobj
6 0 obj
<< /Dests 4 0 R >>
endobj
7 0 obj
<< /Type /Catalog /Pages 3 0 R /Names 6 0 R >>
endobj
8 0 obj
<< /Type /XRef /Root 7 0 R /Length 4 >>
stream
xref
endstream
endobj
%%EOF`

	got := ExtractPDFSectionPages([]byte(pdf))
	if got["s1"] != 1 || got["s2"] != 2 {
		t.Fatalf("got %v, want s1=1 s2=2", got)
	}
}

func TestExtractPDFSectionPages_InvalidOrEmpty(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("not a pdf"),
		[]byte("%PDF-1.7\nstub pdf body\n"),
	} {
		if got := ExtractPDFSectionPages(in); got != nil {
			t.Fatalf("expected nil for %q, got %v", in, got)
		}
	}
}

func TestDeliverableHTMLRendersTOCPageNumbersOnlyWhenProvided(t *testing.T) {
	data := templateFixture()
	data.Template = TemplatePentest

	var pass1 bytes.Buffer
	if err := (HTMLGenerator{}).Generate(&pass1, data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pass1.String(), `<span class="tp">`) {
		t.Fatal("pass 1 / standalone HTML must not render empty TOC page numbers")
	}

	data.TOCPageNumbers = map[string]int{
		"s1": 2,
		"s2": 3,
		"s8": 6,
	}
	var pass2 bytes.Buffer
	if err := (HTMLGenerator{}).Generate(&pass2, data); err != nil {
		t.Fatal(err)
	}
	out := pass2.String()
	for _, want := range []string{
		`<a href="#s1">Statement of Confidentiality</a><span class="tp">2</span>`,
		`<a href="#s2">Engagement &amp; Scope</a><span class="tp">3</span>`,
		`<a href="#s8">Appendix A`,
		`<span class="tp">6</span>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("pass 2 HTML missing %q", want)
		}
	}
}

func TestTwoPassPDFTOCWithChromium(t *testing.T) {
	chrome := findTestChromium()
	if chrome == "" {
		t.Skip("no chromium executable available in environment")
	}

	data := templateFixture()
	data.Template = TemplatePentest

	var pass1HTML bytes.Buffer
	if err := (HTMLGenerator{}).Generate(&pass1HTML, data); err != nil {
		t.Fatal(err)
	}

	pass1PDF := renderTestPDF(t, chrome, pass1HTML.Bytes())
	pages := ExtractPDFSectionPages(pass1PDF)
	if len(pages) == 0 {
		t.Fatalf("expected ExtractPDFSectionPages to extract section pages from Chromium PDF")
	}
	// Cover page has break-after: page, so section 1 starts on page 2+.
	if pages["s1"] < 2 {
		t.Fatalf("expected s1 on page >= 2 (after cover), got %v", pages)
	}
	// Appendix A has class="major" (break-before: page), so it must be after s1.
	if pages["s8"] <= pages["s1"] {
		t.Fatalf("expected Appendix A (s8) on a later page than s1, got %v", pages)
	}

	data.TOCPageNumbers = pages
	var pass2HTML bytes.Buffer
	if err := (HTMLGenerator{}).Generate(&pass2HTML, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pass2HTML.String(), `<span class="tp">`) {
		t.Fatal("pass 2 HTML missing rendered TOC page numbers")
	}
	pass2PDF := renderTestPDF(t, chrome, pass2HTML.Bytes())
	if !bytes.HasPrefix(pass2PDF, []byte("%PDF")) {
		t.Fatal("pass 2 did not produce a valid PDF")
	}
}

func findTestChromium() string {
	if p := strings.TrimSpace(os.Getenv("INDAGO_CHROMIUM_PATH")); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func renderTestPDF(t *testing.T, chrome string, htmlDoc []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "report.html")
	out := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(in, htmlDoc, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome,
		"--no-sandbox",
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--user-data-dir="+filepath.Join(dir, "profile"),
		"--no-pdf-header-footer",
		"--print-to-pdf-no-header",
		"--virtual-time-budget=3000",
		"--print-to-pdf="+out,
		"file://"+in,
	)
	if outLog, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("chromium failed: %v\n%s", err, outLog)
	}
	pdf, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return pdf
}
