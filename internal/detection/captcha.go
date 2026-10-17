package detection

import "bytes"

// captchaMaxScan bounds how much of a response body DetectCaptcha looks at —
// a CAPTCHA/bot-challenge marker always lives in the page's head/early body
// (script tags, widget divs), so scanning the full body of a large page for
// every mutated request would be pure overhead for no extra detection power.
const captchaMaxScan = 64 << 10

// captchaMarkers are well-known, low-false-positive substrings for the three
// most common CAPTCHA/bot-challenge providers an authorized scan is likely to
// run into. Matching is substring-only, case-insensitive, lowercase body —
// deliberately NOT a full HTML/JS parse: this is advisory detection only,
// never evasion (AGENTS.md §2.2), so a cheap, auditable string match is the
// right amount of engineering for it.
var captchaMarkers = []struct {
	label  string
	needle string
}{
	{"reCAPTCHA", "g-recaptcha"},
	{"reCAPTCHA", "recaptcha/api.js"},
	{"reCAPTCHA", "grecaptcha"},
	{"hCaptcha", "h-captcha"},
	{"hCaptcha", "hcaptcha.com"},
	{"Cloudflare challenge", "cf-chl-widget"},
	{"Cloudflare challenge", "challenges.cloudflare.com"},
	{"Cloudflare challenge", "cf_chl_opt"},
	{"Cloudflare challenge", "jschl_vc"}, // classic Cloudflare "I'm Under Attack" 5-second challenge
	{"Generic CAPTCHA", "captcha-container"},
}

// DetectCaptcha reports the first known CAPTCHA/bot-challenge provider whose
// marker appears in body, or ("", false) when none does. Pure and bounded —
// makes no request, no verdict; see CaptchaSuspected for the actual
// before/after comparison a caller should use.
func DetectCaptcha(body []byte) (label string, ok bool) {
	if len(body) > captchaMaxScan {
		body = body[:captchaMaxScan]
	}
	lower := bytes.ToLower(body)
	for _, m := range captchaMarkers {
		if bytes.Contains(lower, []byte(m.needle)) {
			return m.label, true
		}
	}
	return "", false
}

// CaptchaSuspected reports whether a CAPTCHA/bot-challenge NEWLY appears in
// the mutated response that was NOT already present in the baseline — a page
// that legitimately embeds a reCAPTCHA widget on every load (e.g. a contact
// form) must never be flagged just for existing; only a challenge that
// starts appearing specifically once Indago's own probe/candidate value is
// sent is a signal worth surfacing.
func CaptchaSuspected(baselineBody, mutatedBody []byte) (label string, ok bool) {
	mutLabel, mutOK := DetectCaptcha(mutatedBody)
	if !mutOK {
		return "", false
	}
	if _, baseOK := DetectCaptcha(baselineBody); baseOK {
		return "", false
	}
	return mutLabel, true
}
