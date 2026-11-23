package web

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/fingerprint"
)

const (
	// maxTechEvidenceBlobs caps how many response/DOM evidence blobs a single
	// GET /api/scans/{id}/tech request will open, keeping latency and I/O bounded.
	maxTechEvidenceBlobs = 500

	// maxTechBlobReadBytes bounds the per-blob read: up to 64 KiB for HTTP
	// status/headers plus 128 KiB for body (matching fingerprint.bodyScanLimit).
	maxTechBlobReadBytes = 192 << 10

	// maxTechBodyBytes bounds how many body bytes are retained per observation.
	maxTechBodyBytes = 128 << 10

	// maxTechExamples bounds how many sample URLs are attached per technology.
	maxTechExamples = 3
)

type scanTechInventory struct {
	ScanID            domain.ID      `json:"scan_id"`
	EndpointsAnalyzed int            `json:"endpoints_analyzed"`
	Technologies      []techItem     `json:"technologies"`
	Languages         []string       `json:"languages"`
	Frameworks        []string       `json:"frameworks"`
	Templates         []string       `json:"templates"`
	Servers           []string       `json:"servers"`
	PoweredBy         []string       `json:"powered_by,omitempty"`
	WAFVendors        []string       `json:"waf_vendors,omitempty"`
	ContentKinds      map[string]int `json:"content_kinds,omitempty"`
}

type techItem struct {
	Name       string                 `json:"name"`
	Category   string                 `json:"category"`
	Confidence fingerprint.Confidence `json:"confidence,omitempty"`
	Count      int                    `json:"count"`
	Sources    []string               `json:"sources,omitempty"`
	Examples   []string               `json:"examples,omitempty"`
}

// handleScanTech returns the aggregated passive technology-stack inventory
// derived from captured HTTP response/DOM evidence and discovered endpoints.
func (s *Server) handleScanTech(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), scanID); err != nil {
		s.writeLookupError(w, err)
		return
	}

	inv, err := s.collectTechInventory(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "collect tech inventory", err)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

func (s *Server) collectTechInventory(ctx context.Context, scanID domain.ID) (*scanTechInventory, error) {
	evRows, err := s.store.Evidence().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	testCases, err := s.store.TestCases().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	endpoints, err := s.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}

	urlByEvidence := buildEvidenceURLMap(testCases)
	agg := newTechAggregator()

	blobsRead := 0
	if s.evidence != nil {
		for _, ev := range evRows {
			if blobsRead >= maxTechEvidenceBlobs {
				break
			}
			if ev == nil || (ev.Kind != domain.EvidenceResponse && ev.Kind != domain.EvidenceDOM) {
				continue
			}
			fallbackURL := urlByEvidence[ev.ID]
			if fallbackURL == "" {
				fallbackURL = extractURLFromNote(ev.Note)
			}
			obs, ok := s.readObservationFromEvidence(ev, fallbackURL)
			if !ok {
				continue
			}
			blobsRead++
			key := obs.URL
			if key == "" {
				key = "evidence:" + string(ev.ID)
			}
			agg.add(key, fingerprint.Analyze(obs))
		}
	}

	for _, ep := range endpoints {
		if ep == nil || ep.URL == "" {
			continue
		}
		if agg.hasKey(ep.URL) {
			continue
		}
		var h http.Header
		if ep.ContentType != "" {
			h = http.Header{"Content-Type": []string{ep.ContentType}}
		}
		agg.add(ep.URL, fingerprint.Analyze(fingerprint.Observation{
			URL:    ep.URL,
			Header: h,
		}))
	}

	return agg.build(scanID), nil
}

func buildEvidenceURLMap(testCases []*domain.TestCase) map[domain.ID]string {
	out := make(map[domain.ID]string, len(testCases))
	for _, tc := range testCases {
		if tc == nil || tc.URL == "" {
			continue
		}
		for _, evID := range tc.EvidenceIDs {
			if _, exists := out[evID]; !exists {
				out[evID] = tc.URL
			}
		}
	}
	return out
}

func extractURLFromNote(note string) string {
	for _, field := range strings.Fields(note) {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			return field
		}
	}
	return ""
}

func (s *Server) readObservationFromEvidence(ev *domain.Evidence, fallbackURL string) (fingerprint.Observation, bool) {
	rc, err := s.evidence.Open(ev.BlobPath)
	if err != nil {
		return fingerprint.Observation{}, false
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxTechBlobReadBytes))
	_ = rc.Close()
	if err != nil || len(raw) == 0 {
		return fingerprint.Observation{}, false
	}
	return parseHTTPEvidenceBlob(raw, ev.MediaType, fallbackURL), true
}

func parseHTTPEvidenceBlob(raw []byte, mediaType, rawURL string) fingerprint.Observation {
	obs := fingerprint.Observation{URL: rawURL}
	if mediaType == "message/http" || bytes.HasPrefix(raw, []byte("HTTP/")) {
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
		if err == nil {
			defer resp.Body.Close()
			obs.Status = resp.StatusCode
			obs.Header = resp.Header
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTechBodyBytes))
			obs.Body = body
			return obs
		}
	}
	if len(raw) > maxTechBodyBytes {
		raw = raw[:maxTechBodyBytes]
	}
	if mediaType != "" && mediaType != "message/http" {
		obs.Header = http.Header{"Content-Type": []string{mediaType}}
	}
	obs.Body = raw
	return obs
}

type techEntry struct {
	name       string
	category   string
	confidence fingerprint.Confidence
	count      int
	sources    map[string]bool
	examples   []string
	seenEx     map[string]bool
}

type techAggregator struct {
	analyzedKeys map[string]bool
	langs        map[string]bool
	fws          map[string]bool
	tpls         map[string]bool
	servers      map[string]bool
	poweredBy    map[string]bool
	wafs         map[string]bool
	contentKinds map[string]int
	items        map[string]*techEntry
}

func newTechAggregator() *techAggregator {
	return &techAggregator{
		analyzedKeys: make(map[string]bool),
		langs:        make(map[string]bool),
		fws:          make(map[string]bool),
		tpls:         make(map[string]bool),
		servers:      make(map[string]bool),
		poweredBy:    make(map[string]bool),
		wafs:         make(map[string]bool),
		contentKinds: make(map[string]int),
		items:        make(map[string]*techEntry),
	}
}

func (a *techAggregator) hasKey(key string) bool {
	return a.analyzedKeys[key]
}

func (a *techAggregator) add(key string, p fingerprint.Profile) {
	a.analyzedKeys[key] = true
	if p.ContentKind != "" {
		a.contentKinds[string(p.ContentKind)]++
	}

	safeURL := redactTechURL(p.URL)

	sigSources := make(map[string]map[string]bool)
	sigConf := make(map[string]fingerprint.Confidence)
	for _, sig := range p.Signals {
		k := sig.Class + ":" + sig.Tech
		if sigSources[k] == nil {
			sigSources[k] = make(map[string]bool)
		}
		if sig.Source != "" {
			sigSources[k][sig.Source] = true
		}
		if confidenceRank(sig.Confidence) > confidenceRank(sigConf[k]) {
			sigConf[k] = sig.Confidence
		}
	}

	for _, lang := range p.Languages {
		name := string(lang)
		a.langs[name] = true
		k := fingerprint.ClassLanguage + ":" + name
		a.record(fingerprint.ClassLanguage, name, sigConf[k], sigSources[k], safeURL)
	}
	for _, fw := range p.Frameworks {
		name := string(fw)
		a.fws[name] = true
		k := fingerprint.ClassFramework + ":" + name
		a.record(fingerprint.ClassFramework, name, sigConf[k], sigSources[k], safeURL)
	}
	for _, tpl := range p.TemplateHints {
		if tpl == "" || tpl == fingerprint.TplNone {
			continue
		}
		a.tpls[tpl] = true
		k := fingerprint.ClassTemplate + ":" + tpl
		a.record(fingerprint.ClassTemplate, tpl, sigConf[k], sigSources[k], safeURL)
	}
	if srv := strings.TrimSpace(maskSecrets(p.Server)); srv != "" {
		a.servers[srv] = true
		a.record("server", srv, fingerprint.ConfidenceHigh, map[string]bool{fingerprint.SourceHeader: true}, safeURL)
	}
	if pb := strings.TrimSpace(maskSecrets(p.PoweredBy)); pb != "" {
		a.poweredBy[pb] = true
		a.record("powered_by", pb, fingerprint.ConfidenceHigh, map[string]bool{fingerprint.SourceHeader: true}, safeURL)
	}
	if p.WAFVendor != "" {
		a.wafs[p.WAFVendor] = true
		a.record(fingerprint.ClassWAF, p.WAFVendor, p.WAFConfidence, sigSources[fingerprint.ClassWAF+":"+p.WAFVendor], safeURL)
	}
}

func (a *techAggregator) record(category, name string, conf fingerprint.Confidence, sources map[string]bool, exampleURL string) {
	key := category + "\x00" + name
	entry, ok := a.items[key]
	if !ok {
		entry = &techEntry{
			name:     name,
			category: category,
			sources:  make(map[string]bool),
			seenEx:   make(map[string]bool),
		}
		a.items[key] = entry
	}
	entry.count++
	if confidenceRank(conf) > confidenceRank(entry.confidence) {
		entry.confidence = conf
	}
	for src := range sources {
		entry.sources[src] = true
	}
	if exampleURL != "" && len(entry.examples) < maxTechExamples && !entry.seenEx[exampleURL] {
		entry.seenEx[exampleURL] = true
		entry.examples = append(entry.examples, exampleURL)
	}
}

func (a *techAggregator) build(scanID domain.ID) *scanTechInventory {
	items := make([]techItem, 0, len(a.items))
	for _, e := range a.items {
		items = append(items, techItem{
			Name:       e.name,
			Category:   e.category,
			Confidence: e.confidence,
			Count:      e.count,
			Sources:    sortedKeys(e.sources),
			Examples:   e.examples,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Category != items[j].Category {
			return items[i].Category < items[j].Category
		}
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Name < items[j].Name
	})

	inv := &scanTechInventory{
		ScanID:            scanID,
		EndpointsAnalyzed: len(a.analyzedKeys),
		Technologies:      items,
		Languages:         sortedKeys(a.langs),
		Frameworks:        sortedKeys(a.fws),
		Templates:         sortedKeys(a.tpls),
		Servers:           sortedKeys(a.servers),
	}
	if len(a.poweredBy) > 0 {
		inv.PoweredBy = sortedKeys(a.poweredBy)
	}
	if len(a.wafs) > 0 {
		inv.WAFVendors = sortedKeys(a.wafs)
	}
	if len(a.contentKinds) > 0 {
		inv.ContentKinds = a.contentKinds
	}
	return inv
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func confidenceRank(c fingerprint.Confidence) int {
	switch c {
	case fingerprint.ConfidenceHigh:
		return 3
	case fingerprint.ConfidenceMedium:
		return 2
	case fingerprint.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func redactTechURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return maskSecrets(rawURL)
	}
	u.User = nil
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "token") || strings.Contains(lk, "secret") ||
				strings.Contains(lk, "key") || strings.Contains(lk, "pass") ||
				strings.Contains(lk, "auth") || strings.Contains(lk, "session") {
				q.Set(k, "[REDACTED]")
			}
		}
		u.RawQuery = q.Encode()
	}
	return maskSecrets(u.String())
}
