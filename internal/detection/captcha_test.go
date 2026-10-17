package detection

import "testing"

func TestDetectCaptcha(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"recaptcha widget", `<div class="g-recaptcha" data-sitekey="x"></div>`, true},
		{"recaptcha script", `<script src="https://www.google.com/recaptcha/api.js"></script>`, true},
		{"hcaptcha", `<div class="h-captcha" data-sitekey="x"></div>`, true},
		{"cloudflare challenge", `<form id="challenge-form"><input type="hidden" name="jschl_vc" value="1"></form>`, true},
		{"cloudflare managed challenge", `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>`, true},
		{"plain page", `<html><body>hello safe</body></html>`, false},
		{"mentions the word captcha in prose but no marker", `<p>please don't send me a captcha</p>`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := DetectCaptcha([]byte(c.body))
			if ok != c.want {
				t.Fatalf("DetectCaptcha(%q) ok=%v, want %v", c.body, ok, c.want)
			}
		})
	}
}

func TestCaptchaSuspected(t *testing.T) {
	recaptcha := `<div class="g-recaptcha"></div>`
	plain := `<html><body>hello</body></html>`

	if _, ok := CaptchaSuspected([]byte(plain), []byte(recaptcha)); !ok {
		t.Fatal("expected suspected=true: captcha appears only in mutated response")
	}
	if _, ok := CaptchaSuspected([]byte(recaptcha), []byte(recaptcha)); ok {
		t.Fatal("expected suspected=false: captcha already present in baseline (e.g. a contact form) is not a new signal")
	}
	if _, ok := CaptchaSuspected([]byte(plain), []byte(plain)); ok {
		t.Fatal("expected suspected=false: no captcha anywhere")
	}
}
