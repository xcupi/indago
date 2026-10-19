package discovery

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
)

const (
	maxObservedJSONBodyBytes = 64 << 10
	maxObservedJSONFields    = 64
)

// JSONBodyParam is one top-level field and its serialized JSON value captured
// from a browser-observed JSON request. RawValue preserves the JSON type so
// replay can retain numbers, booleans, nulls, and nested values for every
// non-focused field.
type JSONBodyParam struct {
	Name     string
	RawValue string
}

// ExtractJSONBodyParams extracts all bounded top-level fields from a JSON
// object. Arrays/scalars, malformed/trailing data, duplicate or empty names,
// bodies above 64 KiB, and objects above 64 fields are skipped whole so a later
// replay does not silently omit a piece of the original request body.
func ExtractJSONBodyParams(body string) []JSONBodyParam {
	if len(body) == 0 || len(body) > maxObservedJSONBodyBytes {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(body))
	first, err := dec.Token()
	delim, ok := first.(json.Delim)
	if err != nil || !ok || delim != '{' {
		return nil
	}

	values := make(map[string]string)
	for dec.More() {
		token, err := dec.Token()
		key, ok := token.(string)
		if err != nil || !ok || key == "" {
			return nil
		}
		if _, duplicate := values[key]; duplicate || len(values) >= maxObservedJSONFields {
			return nil
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return nil
		}
		values[key] = compact.String()
	}
	last, err := dec.Token()
	if err != nil {
		return nil
	}
	closing, ok := last.(json.Delim)
	if !ok || closing != '}' || len(values) == 0 {
		return nil
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	params := make([]JSONBodyParam, 0, len(keys))
	for _, key := range keys {
		params = append(params, JSONBodyParam{Name: key, RawValue: values[key]})
	}
	return params
}
