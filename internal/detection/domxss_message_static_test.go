package detection

import "testing"

func TestPostMessageHandlerNavigationIsStaticallyReachable(t *testing.T) {
	html := `<script>
window.addEventListener('message', function(e) {
  var url = e.data;
  if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
    location.href = url;
  }
}, false);
</script>`
	res := DOMXSSStaticReachability(html, DOMSourcePostMessage, "")
	found := false
	for _, s := range res.Sites {
		if s.Sink == DOMSinkLocationAssign {
			found = true
		}
	}
	if !found {
		t.Fatalf("sites = %+v unresolved = %+v", res.Sites, res.Unresolved)
	}
}
