package report

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestBountyTemplatesValidity(t *testing.T) {
	for _, tmpl := range []Template{TemplateHackerOne, TemplateBugcrowd, TemplateIntigriti} {
		if !tmpl.IsValid() {
			t.Fatalf("%q.IsValid() = false, want true", tmpl)
		}
	}
}

func bountyTemplateFixture(tmpl Template) Data {
	data := templateFixture()
	data.Template = tmpl
	data.Endpoints = map[domain.ID]string{
		"e1": "https://shop.example.test/?search=x",
	}
	data.Findings[0].Detail = []byte(`{
		"method": "GET",
		"parameter_name": "search",
		"candidates": [{"value": "<svg onload=indago123>"}],
		"attempts": [{
			"candidate_value": "<svg onload=indago123>",
			"verdict": "confirmed",
			"notes": "the browser threw ReferenceError for the marker",
			"evidence_ids": ["ev-req"]
		}]
	}`)
	data.Evidence = []*domain.Evidence{
		{
			ID:        "ev-req",
			FindingID: data.Findings[0].ID,
			Kind:      domain.EvidenceRequest,
			MediaType: "message/http",
			Size:      78,
		},
	}
	data.RequestEvidence = map[domain.ID][]byte{
		"ev-req": []byte("GET /?search=%3Csvg%20onload%3Dindago123%3E HTTP/1.1\r\nHost: shop.example.test\r\n\r\n"),
	}
	return data
}

func TestHackerOneTemplateRendersPlatformSections(t *testing.T) {
	data := bountyTemplateFixture(TemplateHackerOne)

	var b strings.Builder
	if err := (MarkdownGenerator{}).Generate(&b, data); err != nil {
		t.Fatalf("Generate(hackerone): %v", err)
	}
	out := b.String()

	for _, want := range []string{
		"# HackerOne submission — Acme Program",
		"# 1. Reflected XSS in \"search\"",
		"**Weakness:** CWE-79:",
		"**Asset:** https://shop.example.test/?search=x",
		"**Severity:** High — CVSS:3.1/",
		"**Vulnerable parameter:** `search`",
		"**Payload:** `<svg onload=indago123>`",
		"## Summary",
		"## Steps To Reproduce",
		"## Proof of Concept",
		"```bash\ncurl ",
		"```http\nGET ",
		"## Impact",
		"## Remediation",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("hackerone markdown missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Admin probe rejected") {
		t.Fatal("rejected diagnostic finding was rendered into HackerOne submission")
	}
}

func TestBugcrowdTemplateRendersPlatformSections(t *testing.T) {
	data := bountyTemplateFixture(TemplateBugcrowd)

	var b strings.Builder
	if err := (MarkdownGenerator{}).Generate(&b, data); err != nil {
		t.Fatalf("Generate(bugcrowd): %v", err)
	}
	out := b.String()

	for _, want := range []string{
		"# Bugcrowd submission — Acme Program",
		"# 1. Reflected XSS in \"search\"",
		"**VRT / Weakness:** Cross-Site Scripting (XSS) (CWE-79:",
		"**Target / Asset:** https://shop.example.test/?search=x",
		"**Severity / CVSS:** High — CVSS:3.1/",
		"**Vulnerable parameter:** `search`",
		"**Payload:** `<svg onload=indago123>`",
		"## Summary",
		"## Steps to Reproduce",
		"## Proof of Concept (PoC)",
		"```bash\ncurl ",
		"```http\nGET ",
		"## Impact",
		"## Remediation",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bugcrowd markdown missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Admin probe rejected") {
		t.Fatal("rejected diagnostic finding was rendered into Bugcrowd submission")
	}
}

func TestIntigritiTemplateRendersPlatformSections(t *testing.T) {
	data := bountyTemplateFixture(TemplateIntigriti)

	var b strings.Builder
	if err := (MarkdownGenerator{}).Generate(&b, data); err != nil {
		t.Fatalf("Generate(intigriti): %v", err)
	}
	out := b.String()

	for _, want := range []string{
		"# Intigriti submission — Acme Program",
		"# 1. Reflected XSS in \"search\"",
		"**Vulnerability Type:** CWE-79:",
		"**Endpoint:** https://shop.example.test/?search=x",
		"**Severity:** High — CVSS:3.1/",
		"**Vulnerable parameter:** `search`",
		"**Payload:** `<svg onload=indago123>`",
		"## Summary",
		"## Steps to Reproduce",
		"## Proof of Concept",
		"```bash\ncurl ",
		"```http\nGET ",
		"## Impact",
		"## Remediation",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("intigriti markdown missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Admin probe rejected") {
		t.Fatal("rejected diagnostic finding was rendered into Intigriti submission")
	}
}

func TestBountyTemplatesDeduplicateAndHandleNoConfirmed(t *testing.T) {
	for _, tmpl := range []Template{TemplateHackerOne, TemplateBugcrowd, TemplateIntigriti} {
		t.Run(string(tmpl)+"/dedup", func(t *testing.T) {
			data := bountyTemplateFixture(tmpl)
			dup := *data.Findings[0]
			dup.ID = "f-dup"
			data.Findings = append(data.Findings, &dup)

			var b1, b2 strings.Builder
			if err := (MarkdownGenerator{}).Generate(&b1, data); err != nil {
				t.Fatal(err)
			}
			if err := (MarkdownGenerator{}).Generate(&b2, data); err != nil {
				t.Fatal(err)
			}
			if b1.String() != b2.String() {
				t.Fatal("output is not deterministic")
			}
			if !strings.Contains(b1.String(), "1 duplicate finding(s) for the same endpoint/parameter/payload were omitted.") {
				t.Fatalf("expected duplicate omission note in:\n%s", b1.String())
			}
		})

		t.Run(string(tmpl)+"/no_confirmed", func(t *testing.T) {
			data := bountyTemplateFixture(tmpl)
			var unconfirmed []*domain.Finding
			for _, f := range data.Findings {
				if f.Verdict != domain.VerdictConfirmed {
					unconfirmed = append(unconfirmed, f)
				}
			}
			data.Findings = unconfirmed

			var b strings.Builder
			if err := (MarkdownGenerator{}).Generate(&b, data); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), "No confirmed findings were recorded in the selected set — nothing to submit.") {
				t.Fatalf("expected empty-confirmed message in:\n%s", b.String())
			}
		})
	}
}
