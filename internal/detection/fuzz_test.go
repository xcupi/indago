package detection_test

// This file guards the hand-written HTML/JS/CSS/URL context tokenizers
// (internal/detection/context_*.go) against malformed input: they parse
// bytes straight from a scanned target's HTTP response, which is untrusted
// and — since the whole point of this tool is testing applications that may
// themselves be buggy or hostile — must never panic or hang the scanner no
// matter how broken the markup is. Unlike golang.org/x/net/html (not used
// here per the project's minimal-dependency policy), these tokenizers are
// project-local, so they get their own fuzz target rather than relying on an
// upstream library's own hardening.

import (
	"testing"

	"github.com/indago/indago/internal/detection"
)

// FuzzClassifyAt feeds arbitrary bytes and offsets straight at the
// classifier. The only requirement is "does not panic" — any ContextAnalysis
// value is an acceptable answer for garbage input.
func FuzzClassifyAt(f *testing.F) {
	seeds := []struct {
		body        string
		offset      int
		contentType string
	}{
		{`<html><body>HERE</body></html>`, 18, "text/html"},
		{`<div class="HERE">`, 12, "text/html"},
		{`<script>var x = "HERE";</script>`, 17, "text/html"},
		{`<!-- HERE -->`, 5, "text/html"},
		{`<a href="HERE">`, 9, "text/html"},
		{`<style>.c { color: HERE; }</style>`, 19, "text/html"},
		{`<`, 0, "text/html"},
		{`<!`, 1, "text/html"},
		{`<script`, 7, "text/html"},
		{`<script><!--`, 10, "text/html"},
		{`</`, 1, ""},
		{``, 0, ""},
		{"\x00\x01\x02binary\xff\xfe", 3, ""},
		{`<svg onload=HERE>`, 12, "image/svg+xml"},
		{`{"key": "HERE"}`, 9, "application/json"},
		{`a { background: url(HERE) }`, 21, "text/css"},
		{`<a href="javascript:HERE">`, 20, "text/html"},
		{`<`, -1, "text/html"},
		{`abc`, 100, "text/html"},
		{`<!DOCTYPE html><html class=HERE`, 28, "text/html"},
	}
	for _, s := range seeds {
		f.Add(s.body, s.offset, s.contentType)
	}

	f.Fuzz(func(t *testing.T, body string, offset int, contentType string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ClassifyAt panicked on body=%q offset=%d contentType=%q: %v", body, offset, contentType, r)
			}
		}()
		_ = detection.ClassifyAt([]byte(body), offset, detection.ContextOptions{ContentType: contentType})
	})
}
