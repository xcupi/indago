package detection

import (
	"strings"
	"testing"
)

func TestDetectDOMClobberingSurfacesAndPayloads(t *testing.T) {
	domPurifyHTML := `<script src="/resources/js/domPurify-2.0.15.js"></script>
<script>let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'};</script>`
	surfaces := DetectDOMClobberingSurfaces(domPurifyHTML, nil)
	if len(surfaces) == 0 {
		t.Fatal("expected DOMPurify/defaultAvatar clobbering surface")
	}
	foundAvatar := false
	for _, s := range surfaces {
		if s.GlobalName == "defaultAvatar" && s.PropertyName == "avatar" {
			foundAvatar = true
			specs := DOMClobberingPayloadsFor(s, "clb1234")
			if len(specs) == 0 || !strings.Contains(specs[0].Payload, "id=defaultAvatar") || !strings.Contains(specs[0].Payload, "onerror=clb1234") {
				t.Fatalf("unexpected payload specs: %+v", specs)
			}
		}
	}
	if !foundAvatar {
		t.Fatalf("missing defaultAvatar.avatar surface in %+v", surfaces)
	}

	janitorHTML := `<script src="/resources/js/htmlJanitor.js"></script>`
	janitorSurfaces := DetectDOMClobberingSurfaces(janitorHTML, nil)
	if len(janitorSurfaces) != 1 || janitorSurfaces[0].Kind != DOMClobberSanitizerAttr {
		t.Fatalf("unexpected HTMLJanitor surfaces: %+v", janitorSurfaces)
	}
	jSpecs := DOMClobberingPayloadsFor(janitorSurfaces[0], "clb5678")
	if len(jSpecs) != 1 || jSpecs[0].Fragment != "#xclb5678" || !strings.Contains(jSpecs[0].Payload, "id=attributes") {
		t.Fatalf("unexpected HTMLJanitor payload specs: %+v", jSpecs)
	}

	// Generic unguarded window.<Global>.<Property> fallback in an external script.
	genericScript := DOMXSSExternalScript{URL: "https://app.example/app.js", Body: `const cfg = (window.appConfig && window.appConfig.scriptUrl) || '/app.js';`}
	genSurfaces := DetectDOMClobberingSurfaces(`<html></html>`, []DOMXSSExternalScript{genericScript})
	if len(genSurfaces) != 1 || genSurfaces[0].GlobalName != "appConfig" || genSurfaces[0].PropertyName != "scriptUrl" {
		t.Fatalf("unexpected generic surfaces: %+v", genSurfaces)
	}
	gSpecs := DOMClobberingPayloadsFor(genSurfaces[0], "clb9999")
	if len(gSpecs) != 2 {
		t.Fatalf("expected 2 payload specs for scriptUrl property, got %+v", gSpecs)
	}

	// Builtin globals like window.location must not be flagged as clobberable.
	builtinScript := DOMXSSExternalScript{URL: "https://app.example/nav.js", Body: `const loc = (window.location || {}).href;`}
	if got := DetectDOMClobberingSurfaces(`<html></html>`, []DOMXSSExternalScript{builtinScript}); len(got) != 0 {
		t.Fatalf("builtin global flagged as clobberable: %+v", got)
	}
}

func TestExtractDOMClobberingForms(t *testing.T) {
	html := `<html><body>
<form action="/login" method="POST"><input name="username"><input type="password" name="password"></form>
<form action="/post/comment" method="POST">
  <input type="hidden" name="csrf" value="tok123">
  <input type="hidden" name="postId" value="42">
  <textarea name="comment"></textarea>
  <input type="text" name="name">
  <input type="email" name="email">
  <input type="url" name="website">
</form>
</body></html>`
	forms := ExtractDOMClobberingForms(html, "https://app.example/post?postId=42")
	if len(forms) != 1 {
		t.Fatalf("expected 1 comment form, got %+v", forms)
	}
	f := forms[0]
	if f.Action != "https://app.example/post/comment" || f.TextField != "comment" {
		t.Fatalf("unexpected form: %+v", f)
	}
	if f.HiddenFields["csrf"] != "tok123" || f.HiddenFields["postId"] != "42" {
		t.Fatalf("unexpected hidden fields: %+v", f.HiddenFields)
	}
}
