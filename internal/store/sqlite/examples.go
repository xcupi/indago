package sqlite

import (
	"encoding/json"
	"strings"
)

// encodeStrings stores a string slice as a JSON array. A failure to encode is
// impossible for []string, so an empty document is the safe fallback.
func encodeStrings(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// decodeStrings reads a JSON array column, tolerating legacy/empty values: any
// value that is not a JSON array decodes to nil rather than failing the read.
func decodeStrings(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
