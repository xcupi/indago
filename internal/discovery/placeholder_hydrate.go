package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

const (
	maxPlaceholderJSONFetches  = 16
	maxHydratedPerPlaceholder  = 2
	maxPlaceholderJSONDepth    = 6
	maxPlaceholderArrayItems   = 50
	maxPlaceholderIDValueBytes = 64
)

type placeholderKind uint8

const (
	placeholderPath placeholderKind = iota + 1
	placeholderQuery
)

type placeholderTarget struct {
	rawURL       string
	kind         placeholderKind
	segIndex     int    // path segment index when kind == placeholderPath
	paramName    string // query param name when kind == placeholderQuery
	prefix       string // path prefix before placeholder segment (or full path for query)
	resourceHint string // preceding path segment or query param name
}

type jsonIDCandidate struct {
	sourceURL string
	key       string
	parentKey string
	value     string
}

func isPlaceholderToken(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "null", "undefined", "nan":
		return true
	default:
		return false
	}
}

func recordObservedGETs(dst map[string]struct{}, network []browser.NetworkEvent, in Input) {
	if dst == nil {
		return
	}
	for _, ev := range network {
		if !strings.EqualFold(strings.TrimSpace(ev.Method), "GET") && strings.TrimSpace(ev.Method) != "" {
			continue
		}
		if !in.Scope.Permits(ev.URL).Allowed {
			continue
		}
		info, err := Normalize(ev.URL)
		if err != nil || IsStaticAssetPath(info.Path) {
			continue
		}
		dst[info.Canonical] = struct{}{}
	}
}

func findPlaceholderTargets(urls []string) []placeholderTarget {
	var out []placeholderTarget
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		segs := strings.Split(u.Path, "/")
		foundPath := false
		for i, seg := range segs {
			if !isPlaceholderToken(seg) {
				continue
			}
			hint := ""
			for j := i - 1; j >= 0; j-- {
				if segs[j] != "" {
					hint = strings.ToLower(segs[j])
					break
				}
			}
			prefix := strings.Join(segs[:i], "/") + "/"
			out = append(out, placeholderTarget{
				rawURL:       raw,
				kind:         placeholderPath,
				segIndex:     i,
				prefix:       prefix,
				resourceHint: hint,
			})
			foundPath = true
			break
		}
		if foundPath {
			continue
		}
		q := u.Query()
		for k, vals := range q {
			for _, v := range vals {
				if isPlaceholderToken(v) {
					out = append(out, placeholderTarget{
						rawURL:       raw,
						kind:         placeholderQuery,
						paramName:    k,
						prefix:       u.Path,
						resourceHint: strings.ToLower(k),
					})
					break
				}
			}
		}
	}
	return out
}

func placeholderSourceScore(rawURL string, targets []placeholderTarget) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	p := strings.ToLower(u.Path)
	score := 1
	for _, t := range targets {
		if t.prefix != "" && strings.HasPrefix(p, strings.ToLower(t.prefix)) {
			score += 10
			break
		}
	}
	for _, hint := range []string{"/api/", "/all", "/recent", "/list", "/dashboard", "/user"} {
		if strings.Contains(p, hint) {
			score += 2
		}
	}
	return score
}

func isJSONResponse(resp *httpengine.Response) bool {
	if resp == nil || len(resp.Body) == 0 {
		return false
	}
	ct := strings.ToLower(resp.Headers.Get("Content-Type"))
	if strings.Contains(ct, "json") {
		return true
	}
	trimmed := strings.TrimSpace(string(resp.Body))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func isIDKey(k string) bool {
	kl := strings.ToLower(strings.TrimSpace(k))
	if kl == "id" || kl == "uuid" || kl == "code" {
		return true
	}
	if strings.HasSuffix(kl, "_id") || strings.HasSuffix(kl, "_uuid") {
		return true
	}
	if strings.HasSuffix(k, "Id") || strings.HasSuffix(k, "ID") || strings.HasSuffix(k, "Uuid") || strings.HasSuffix(k, "UUID") {
		return true
	}
	return false
}

func formatScalarID(v any) (string, bool) {
	switch x := v.(type) {
	case float64:
		if x <= 0 || x != float64(int64(x)) {
			return "", false
		}
		return strconv.FormatInt(int64(x), 10), true
	case string:
		s := strings.TrimSpace(x)
		if s == "" || len(s) > maxPlaceholderIDValueBytes {
			return "", false
		}
		if isPlaceholderToken(s) || strings.EqualFold(s, "true") || strings.EqualFold(s, "false") {
			return "", false
		}
		if strings.ContainsAny(s, " \t\r\n/?#&") {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}

func extractJSONIDs(sourceURL string, body []byte) []jsonIDCandidate {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var out []jsonIDCandidate
	var walk func(node any, parentKey string, depth int)
	walk = func(node any, parentKey string, depth int) {
		if depth > maxPlaceholderJSONDepth {
			return
		}
		switch v := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				val := v[k]
				if isIDKey(k) {
					if s, ok := formatScalarID(val); ok {
						out = append(out, jsonIDCandidate{
							sourceURL: sourceURL,
							key:       k,
							parentKey: parentKey,
							value:     s,
						})
					}
				}
				walk(val, k, depth+1)
			}
		case []any:
			limit := len(v)
			if limit > maxPlaceholderArrayItems {
				limit = maxPlaceholderArrayItems
			}
			for i := 0; i < limit; i++ {
				walk(v[i], parentKey, depth+1)
			}
		}
	}
	walk(root, "", 0)
	return out
}

func singularizeResource(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasSuffix(s, "ies") && len(s) > 3 {
		return s[:len(s)-3] + "y"
	}
	if strings.HasSuffix(s, "s") && len(s) > 1 {
		return s[:len(s)-1]
	}
	return s
}

func scoreIDMatch(target placeholderTarget, cand jsonIDCandidate) int {
	score := 1
	su, err := url.Parse(cand.sourceURL)
	if err == nil {
		sp := strings.ToLower(su.Path)
		tp := strings.ToLower(target.prefix)
		if tp != "" && strings.HasPrefix(sp, tp) {
			score += 10
		} else {
			tSegs := strings.Split(strings.Trim(tp, "/"), "/")
			sSegs := strings.Split(strings.Trim(sp, "/"), "/")
			if len(tSegs) >= 2 && len(sSegs) >= 2 && tSegs[0] == sSegs[0] && tSegs[1] == sSegs[1] {
				score += 4
			}
		}
	}
	hint := singularizeResource(target.resourceHint)
	keyLower := strings.ToLower(cand.key)
	parentLower := singularizeResource(cand.parentKey)
	if hint != "" {
		if keyLower == strings.ToLower(target.resourceHint) ||
			keyLower == hint+"_id" || keyLower == hint+"id" ||
			parentLower == hint {
			score += 6
		}
	}
	if keyLower == "id" {
		score += 2
	}
	return score
}

func buildHydratedURL(target placeholderTarget, idVal string) (string, bool) {
	u, err := url.Parse(target.rawURL)
	if err != nil {
		return "", false
	}
	switch target.kind {
	case placeholderPath:
		segs := strings.Split(u.Path, "/")
		if target.segIndex < 0 || target.segIndex >= len(segs) {
			return "", false
		}
		segs[target.segIndex] = url.PathEscape(idVal)
		u.Path = strings.Join(segs, "/")
	case placeholderQuery:
		q := u.Query()
		q.Set(target.paramName, idVal)
		u.RawQuery = q.Encode()
	default:
		return "", false
	}
	info, err := Normalize(u.String())
	if err != nil {
		return "", false
	}
	return info.Canonical, true
}

func (n *networkSource) hydratePlaceholderEndpoints(ctx context.Context, in Input, sink Sink, observedGETs map[string]struct{}) error {
	if n.engine == nil || len(observedGETs) == 0 {
		return nil
	}
	allURLs := make([]string, 0, len(observedGETs))
	for u := range observedGETs {
		allURLs = append(allURLs, u)
	}
	sort.Strings(allURLs)

	targets := findPlaceholderTargets(allURLs)
	if len(targets) == 0 {
		return nil
	}
	placeholderSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		placeholderSet[t.rawURL] = struct{}{}
	}

	var sources []string
	for _, u := range allURLs {
		if _, isPH := placeholderSet[u]; isPH {
			continue
		}
		if !in.Scope.Permits(u).Allowed || !allowFetch(sink, u, domain.SourceBrowserNetwork, domain.MethodGET) {
			continue
		}
		sources = append(sources, u)
	}
	sort.SliceStable(sources, func(i, j int) bool {
		return placeholderSourceScore(sources[i], targets) > placeholderSourceScore(sources[j], targets)
	})
	if len(sources) > maxPlaceholderJSONFetches {
		sources = sources[:maxPlaceholderJSONFetches]
	}

	var ids []jsonIDCandidate
	for _, srcURL := range sources {
		if err := in.wait(ctx); err != nil {
			return err
		}
		resp, err := n.engine.Do(ctx, httpengine.GET(srcURL))
		if err != nil || resp == nil || resp.Status >= 400 || !isJSONResponse(resp) {
			continue
		}
		ids = append(ids, extractJSONIDs(srcURL, resp.Body)...)
	}
	if len(ids) == 0 {
		return nil
	}

	for _, target := range targets {
		type rankedCand struct {
			url   string
			score int
		}
		seenURL := make(map[string]struct{})
		var ranked []rankedCand
		for _, id := range ids {
			candURL, ok := buildHydratedURL(target, id.value)
			if !ok {
				continue
			}
			if _, dup := seenURL[candURL]; dup {
				continue
			}
			if !in.Scope.Permits(candURL).Allowed || !allowFetch(sink, candURL, domain.SourceBrowserNetwork, domain.MethodGET) {
				continue
			}
			seenURL[candURL] = struct{}{}
			ranked = append(ranked, rankedCand{url: candURL, score: scoreIDMatch(target, id)})
		}
		sort.SliceStable(ranked, func(i, j int) bool {
			return ranked[i].score > ranked[j].score
		})
		if len(ranked) > maxHydratedPerPlaceholder {
			ranked = ranked[:maxHydratedPerPlaceholder]
		}
		for _, cand := range ranked {
			if err := in.wait(ctx); err != nil {
				return err
			}
			resp, err := n.engine.Do(ctx, httpengine.GET(cand.url))
			if err != nil || resp == nil || resp.Status >= 400 {
				continue
			}
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
				URL:    cand.url,
				Method: domain.MethodGET,
				Source: domain.SourceBrowserNetwork,
			}); err != nil {
				if errors.Is(err, ErrLimitReached) {
					return nil
				}
				return err
			}
		}
	}
	return nil
}
