package llm

import (
	"regexp"
	"strings"
)

// Redacted is the placeholder substituted for a secret.
const Redacted = "[redacted]"

// maxErrorBody bounds the upstream text kept in an error message. It is small
// on purpose: an error string is for the operator, not a copy of the response.
const maxErrorBody = 300

var (
	// A bearer credential, as an upstream body might echo it back.
	bearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{4,}`)
	// The conventional OpenAI/DeepSeek key shape. This also catches a key
	// that differs from the configured one (for example a key pasted into a
	// gateway error message).
	skPattern = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{4,}`)
	// key=value / "api_key": "value" shapes.
	keyAssignPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|token)["']?\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{4,}`)
)

// Redact removes secret from s and scrubs the credential shapes an upstream
// provider error commonly echoes. The configured secret is replaced verbatim
// first, so a key with an unusual format is still caught.
func Redact(s, secret string) string {
	if s == "" {
		return s
	}
	if secret != "" {
		s = strings.ReplaceAll(s, secret, Redacted)
	}
	s = bearerPattern.ReplaceAllString(s, "Bearer "+Redacted)
	s = skPattern.ReplaceAllString(s, Redacted)
	s = keyAssignPattern.ReplaceAllString(s, "${1}="+Redacted)
	return s
}

// RedactAndTrim scrubs s, collapses it to one line, and bounds its length.
//
// Redaction runs BEFORE truncation on purpose: truncating first could cut a
// key in half and leave a recognisable prefix behind that the exact-match
// replacement no longer recognises.
func RedactAndTrim(s, secret string) string {
	s = Redact(s, secret)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxErrorBody {
		s = strings.ToValidUTF8(s[:maxErrorBody], "") + "..."
	}
	return s
}
