package detection

import (
	"strings"
	"testing"
)

func TestDOMNavigationAndElementSrcSinks(t *testing.T) {
	cases := []struct {
		name string
		html string
		want DOMXSSSink
	}{
		{
			name: "location href assignment from the query",
			html: `<script>var n = new URLSearchParams(location.search).get("next"); location.href = n;</script>`,
			want: DOMSinkLocationAssign,
		},
		{
			name: "location assign call from the query",
			html: `<script>var n = new URLSearchParams(location.search).get("next"); location.assign(n);</script>`,
			want: DOMSinkLocationAssign,
		},
		{
			name: "element src from the query",
			html: `<script>var u = new URLSearchParams(location.search).get("next"); var f = document.createElement("iframe"); f.src = u;</script>`,
			want: DOMSinkElementSrc,
		},
		{
			name: "cookie write from the query",
			html: `<script>var n = new URLSearchParams(location.search).get("next"); document.cookie = "last=" + n;</script>`,
			want: DOMSinkCookie,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := DOMXSSStaticReachability(tc.html, DOMSourceQuery, "next")
			found := false
			for _, site := range res.Sites {
				if site.Sink == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("sink %s not found in %+v", tc.want, res.Sites)
			}
		})
	}
}

func TestCookieSinkPlansNoXSSCandidate(t *testing.T) {
	if cands := DOMXSSPayloadsFor(DOMSourcePostMessage, DOMSinkCookie, "indM123"); len(cands) != 0 {
		t.Fatalf("cookie write planned %d payloads, want none", len(cands))
	}
}

func TestNavigationSinkPlansJavascriptURL(t *testing.T) {
	cands := DOMXSSPayloadsFor(DOMSourcePostMessage, DOMSinkLocationAssign, "indM123")
	if len(cands) < 1 || cands[0].Value != "javascript:indM123" {
		t.Fatalf("candidates = %+v", cands)
	}
	// A JSON message handler needs an object shape; it is planned after the
	// raw javascript: URL shapes, never instead of them.
	last := cands[len(cands)-1].Value
	if !strings.Contains(last, `"url":"javascript:indM123"`) {
		t.Fatalf("last candidate = %q", last)
	}
}
