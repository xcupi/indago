package verification

import "testing"

func TestMatchExecutionSignal(t *testing.T) {
	const token = "indb2c4d8e6a1f2a3b4"

	t.Run("page error names the token", func(t *testing.T) {
		sig, text, ok := matchExecutionSignal(token, []string{"ReferenceError: " + token + " is not defined"}, nil)
		if !ok || sig != SignalPageError || text == "" {
			t.Fatalf("sig=%s text=%q ok=%v", sig, text, ok)
		}
	})

	t.Run("console error names the token", func(t *testing.T) {
		sig, _, ok := matchExecutionSignal(token, nil, []string{"Uncaught ReferenceError: " + token + " is not defined"})
		if !ok || sig != SignalConsoleError {
			t.Fatalf("sig=%s ok=%v", sig, ok)
		}
	})

	t.Run("page error takes priority over console error", func(t *testing.T) {
		sig, _, ok := matchExecutionSignal(token, []string{token + " via page error"}, []string{token + " via console"})
		if !ok || sig != SignalPageError {
			t.Fatalf("sig=%s ok=%v, want page_error to win", sig, ok)
		}
	})

	t.Run("no channel mentions the token: no signal", func(t *testing.T) {
		sig, text, ok := matchExecutionSignal(token, []string{"unrelated error"}, []string{"also unrelated"})
		if ok || sig != SignalNone || text != "" {
			t.Fatalf("sig=%s text=%q ok=%v, want no match", sig, text, ok)
		}
	})

	t.Run("empty observations: no signal, no panic", func(t *testing.T) {
		sig, _, ok := matchExecutionSignal(token, nil, nil)
		if ok || sig != SignalNone {
			t.Fatalf("sig=%s ok=%v", sig, ok)
		}
	})

	t.Run("empty token never matches", func(t *testing.T) {
		sig, _, ok := matchExecutionSignal("", []string{"anything"}, nil)
		if ok || sig != SignalNone {
			t.Fatal("an empty token must never be reported as matched")
		}
	})

	t.Run("a message merely containing an unrelated substring does not match", func(t *testing.T) {
		// Sanity: the token is specific enough (sha256-derived) that this is really
		// about substring semantics, not false positives from short tokens.
		sig, _, ok := matchExecutionSignal(token, []string{token[:len(token)-1]}, nil) // one char short
		if ok || sig != SignalNone {
			t.Fatal("a truncated token must not match")
		}
	})
}

func TestDOMExcerpt(t *testing.T) {
	const token = "MARKER123"

	t.Run("token present: bounded window around it", func(t *testing.T) {
		html := "<html><body><p>before " + token + " after</p></body></html>"
		got := domExcerpt(html, token, 6)
		if got == "" {
			t.Fatal("expected a non-empty excerpt")
		}
		if !contains(got, token) {
			t.Fatalf("excerpt %q does not contain the token", got)
		}
		if len(got) >= len(html) {
			t.Fatalf("excerpt should be bounded, got len=%d of html len=%d", len(got), len(html))
		}
	})

	t.Run("token absent: empty excerpt", func(t *testing.T) {
		if got := domExcerpt("<html>nothing here</html>", token, 10); got != "" {
			t.Fatalf("expected empty excerpt, got %q", got)
		}
	})

	t.Run("token near the start/end: window clamps, never panics", func(t *testing.T) {
		html := token + " at the very start"
		got := domExcerpt(html, token, 100)
		if !contains(got, token) {
			t.Fatalf("excerpt %q missing token", got)
		}
		html2 := "ends with " + token
		got2 := domExcerpt(html2, token, 100)
		if !contains(got2, token) {
			t.Fatalf("excerpt %q missing token", got2)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return len(sub) == 0
}
