package store

import "strings"

// AppendDistinctExamples returns dst with every value from more appended in
// order, skipping blanks and values already present (case-sensitive: an
// identifier's exact bytes matter), stopping at max. It never mutates dst's
// backing array, so callers can compare the result to decide whether a write is
// needed.
func AppendDistinctExamples(dst, more []string, max int) []string {
	if max <= 0 {
		return dst
	}
	out := make([]string, 0, len(dst)+len(more))
	seen := make(map[string]struct{}, len(dst)+len(more))
	add := func(v string) bool {
		v = strings.TrimSpace(v)
		if v == "" {
			return false
		}
		if _, ok := seen[v]; ok {
			return false
		}
		seen[v] = struct{}{}
		out = append(out, v)
		return true
	}
	for _, v := range dst {
		if len(out) >= max {
			return out
		}
		add(v)
	}
	for _, v := range more {
		if len(out) >= max {
			break
		}
		add(v)
	}
	return out
}
