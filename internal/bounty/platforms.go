package bounty

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultHackerOneBaseURL = "https://api.hackerone.com/v1"
	defaultBugcrowdBaseURL  = "https://api.bugcrowd.com"
	defaultIntigritiBaseURL = "https://api.intigriti.com/external/researcher/v1"
)

// ScopeAsset is a normalized in-scope web/API target returned by platform clients.
type ScopeAsset struct {
	Target      string `json:"target"`
	Type        string `json:"type"`
	Eligible    bool   `json:"eligible"`
	Description string `json:"description,omitempty"`
}

// PlatformClient is the common interface implemented by bug-bounty platform clients.
type PlatformClient interface {
	Provider() string
	Validate(ctx context.Context, token string) error
	ListPrograms(ctx context.Context, q Query, refresh bool) ([]Program, int, bool, error)
	GetProgram(ctx context.Context, slug string) (Program, error)
}

// NewPlatformClient constructs a PlatformClient for the named provider.
func NewPlatformClient(provider, baseURL string, tokenFn func() string) (PlatformClient, error) {
	p, err := normalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	switch p {
	case ProviderHackerOne:
		return NewHackerOneClient(baseURL, tokenFn), nil
	case ProviderBugcrowd:
		return NewBugcrowdClient(baseURL, tokenFn), nil
	case ProviderIntigriti:
		return NewIntigritiClient(baseURL, tokenFn), nil
	default:
		return nil, fmt.Errorf("%w: %q (use NewClient for yeswehack)", ErrUnsupportedProvider, provider)
	}
}

type platformBase struct {
	provider string
	BaseURL  string
	HTTP     *http.Client
	Token    func() string
	authFn   func(token string) string

	mu    sync.Mutex
	cache map[string]cacheEntry
	ttl   time.Duration
}

func newPlatformBase(provider, baseURL, defaultURL string, tokenFn func() string, authFn func(string) string) platformBase {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultURL
	}
	if tokenFn == nil {
		tokenFn = func() string { return "" }
	}
	return platformBase{
		provider: provider,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		HTTP:     &http.Client{Timeout: 25 * time.Second},
		Token:    tokenFn,
		authFn:   authFn,
		cache:    map[string]cacheEntry{},
		ttl:      10 * time.Minute,
	}
}

func (b *platformBase) Provider() string { return b.provider }

func normalizeQuery(q Query) Query {
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.PerPage <= 0 {
		q.PerPage = 50
	}
	return q
}

func (b *platformBase) cached(key string, refresh bool) ([]Program, int, bool) {
	if refresh {
		return nil, 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.cache[key]
	if ok && time.Since(e.fetchedAt) < b.ttl {
		return e.programs, e.total, true
	}
	return nil, 0, false
}

func (b *platformBase) storeCache(key string, items []Program, total int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cache[key] = cacheEntry{programs: items, total: total, fetchedAt: time.Now()}
}

func (b *platformBase) get(ctx context.Context, path string, dst any) error {
	return b.doJSON(ctx, http.MethodGet, path, "", dst)
}

func (b *platformBase) getWithToken(ctx context.Context, path, token string, dst any) error {
	return b.doJSON(ctx, http.MethodGet, path, token, dst)
}

func (b *platformBase) doJSON(ctx context.Context, method, path, tokenOverride string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, b.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "indago-bounty/1.0")

	tok := strings.TrimSpace(tokenOverride)
	if tok == "" && b.Token != nil {
		tok = strings.TrimSpace(b.Token())
	}
	if tok != "" && b.authFn != nil {
		if hdr := b.authFn(tok); hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
	}

	resp, err := b.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w (status %d)", ErrUnauthorized, resp.StatusCode)
	case http.StatusNotFound:
		return fmt.Errorf("%w (%s)", ErrNotFound, path)
	default:
		return fmt.Errorf("bounty: %s %s returned %d", b.provider, path, resp.StatusCode)
	}
	if dst == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("bounty: decode %s %s: %w", b.provider, path, err)
	}
	return nil
}

// --- HackerOne ---

// HackerOneClient talks to the HackerOne v1 Hacker API.
type HackerOneClient struct {
	platformBase
}

// NewHackerOneClient returns a client for HackerOne (default https://api.hackerone.com/v1).
// Tokens containing ":" are sent as HTTP Basic auth (username:api_token);
// otherwise they are sent as Bearer tokens.
func NewHackerOneClient(baseURL string, tokenFn func() string) *HackerOneClient {
	return &HackerOneClient{
		platformBase: newPlatformBase(ProviderHackerOne, baseURL, defaultHackerOneBaseURL, tokenFn, func(tok string) string {
			if strings.Contains(tok, ":") {
				return "Basic " + base64.StdEncoding.EncodeToString([]byte(tok))
			}
			return "Bearer " + tok
		}),
	}
}

// Validate checks a HackerOne credential against /hackers/programs without storing it.
func (c *HackerOneClient) Validate(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrNoToken
	}
	var out map[string]any
	return c.getWithToken(ctx, "/hackers/programs?page[number]=1&page[size]=1", token, &out)
}

type h1ProgramResource struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Handle          string `json:"handle"`
		Name            string `json:"name"`
		State           string `json:"state"`
		SubmissionState string `json:"submission_state"`
		OffersBounties  bool   `json:"offers_bounties"`
		Policy          string `json:"policy"`
		URL             string `json:"url"`
	} `json:"attributes"`
	Relationships struct {
		StructuredScopes struct {
			Data []h1ScopeResource `json:"data"`
		} `json:"structured_scopes"`
	} `json:"relationships"`
}

type h1ScopeResource struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Attributes h1ScopeAttributes `json:"attributes"`
}

type h1ScopeAttributes struct {
	AssetType             string `json:"asset_type"`
	AssetIdentifier       string `json:"asset_identifier"`
	EligibleForSubmission bool   `json:"eligible_for_submission"`
	EligibleForBounty     bool   `json:"eligible_for_bounty"`
	Instruction           string `json:"instruction"`
}

func (r h1ProgramResource) toProgram(included map[string]h1ScopeAttributes) Program {
	var scopes []ScopeAsset
	for _, sc := range r.Relationships.StructuredScopes.Data {
		attrs := sc.Attributes
		if attrs.AssetIdentifier == "" && sc.ID != "" {
			if inc, ok := included[sc.ID]; ok {
				attrs = inc
			}
		}
		if !attrs.EligibleForSubmission {
			continue
		}
		normType, ok := normalizeH1AssetType(attrs.AssetType)
		if !ok || strings.TrimSpace(attrs.AssetIdentifier) == "" {
			continue
		}
		scopes = append(scopes, ScopeAsset{
			Target:      strings.TrimSpace(attrs.AssetIdentifier),
			Type:        normType,
			Eligible:    true,
			Description: strings.TrimSpace(attrs.Instruction),
		})
	}
	ptype := "vdp"
	if r.Attributes.OffersBounties {
		ptype = "bug-bounty"
	}
	status := r.Attributes.SubmissionState
	if status == "" {
		status = r.Attributes.State
	}
	return Program{
		Slug:        r.Attributes.Handle,
		Title:       r.Attributes.Name,
		Type:        ptype,
		Status:      status,
		Bounty:      r.Attributes.OffersBounties,
		Public:      r.Attributes.State == "public_mode",
		VDP:         !r.Attributes.OffersBounties,
		ScopesCount: len(scopes),
		Provider:    ProviderHackerOne,
		URL:         r.Attributes.URL,
		Rules:       r.Attributes.Policy,
		Scopes:      scopes,
	}
}

func normalizeH1AssetType(t string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "URL":
		return "url", true
	case "WILDCARD":
		return "wildcard", true
	default:
		return "", false
	}
}

// ListPrograms lists HackerOne programs with 10-minute caching and pagination.
func (c *HackerOneClient) ListPrograms(ctx context.Context, q Query, refresh bool) ([]Program, int, bool, error) {
	q = normalizeQuery(q)
	key := cacheKey(q)
	if items, total, ok := c.cached(key, refresh); ok {
		return items, total, true, nil
	}

	params := url.Values{}
	params.Set("page[number]", strconv.Itoa(q.Page))
	params.Set("page[size]", strconv.Itoa(q.PerPage))
	if q.Search != "" {
		params.Set("filter[search]", q.Search)
	}

	var out struct {
		Data     []h1ProgramResource `json:"data"`
		Included []h1ScopeResource   `json:"included"`
		Meta     struct {
			TotalCount int `json:"total_count"`
		} `json:"meta"`
	}
	if err := c.get(ctx, "/hackers/programs?"+params.Encode(), &out); err != nil {
		return nil, 0, false, err
	}

	included := make(map[string]h1ScopeAttributes, len(out.Included))
	for _, inc := range out.Included {
		if inc.ID != "" {
			included[inc.ID] = inc.Attributes
		}
	}

	items := make([]Program, 0, len(out.Data))
	for _, d := range out.Data {
		items = append(items, d.toProgram(included))
	}
	total := out.Meta.TotalCount
	if total == 0 {
		total = len(items)
	}
	c.storeCache(key, items, total)
	return items, total, false, nil
}

// GetProgram fetches a single HackerOne program and its structured scopes.
func (c *HackerOneClient) GetProgram(ctx context.Context, slug string) (Program, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return Program{}, errors.New("bounty: program handle is required")
	}
	var out struct {
		Data     h1ProgramResource `json:"data"`
		Included []h1ScopeResource `json:"included"`
	}
	if err := c.get(ctx, "/hackers/programs/"+url.PathEscape(slug), &out); err != nil {
		return Program{}, err
	}
	included := make(map[string]h1ScopeAttributes, len(out.Included))
	for _, inc := range out.Included {
		if inc.ID != "" {
			included[inc.ID] = inc.Attributes
		}
	}
	return out.Data.toProgram(included), nil
}

// --- Bugcrowd ---

// BugcrowdClient talks to the Bugcrowd REST API.
type BugcrowdClient struct {
	platformBase
}

// NewBugcrowdClient returns a client for Bugcrowd (default https://api.bugcrowd.com).
// JWT tokens are sent as Bearer; standard API tokens are sent as "Token <token>".
func NewBugcrowdClient(baseURL string, tokenFn func() string) *BugcrowdClient {
	return &BugcrowdClient{
		platformBase: newPlatformBase(ProviderBugcrowd, baseURL, defaultBugcrowdBaseURL, tokenFn, func(tok string) string {
			if strings.HasPrefix(tok, "Token ") || strings.HasPrefix(tok, "Bearer ") {
				return tok
			}
			if strings.Count(tok, ".") == 2 {
				return "Bearer " + tok
			}
			return "Token " + tok
		}),
	}
}

// Validate checks a Bugcrowd credential against /programs without storing it.
func (c *BugcrowdClient) Validate(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrNoToken
	}
	var out map[string]any
	return c.getWithToken(ctx, "/programs?page=1&per_page=1", token, &out)
}

type bcTarget struct {
	Name        string `json:"name"`
	URI         string `json:"uri"`
	Target      string `json:"target"`
	Category    string `json:"category"`
	Type        string `json:"type"`
	InScope     *bool  `json:"in_scope"`
	Description string `json:"description"`
}

type bcTargetGroup struct {
	Name    string     `json:"name"`
	InScope *bool      `json:"in_scope"`
	Targets []bcTarget `json:"targets"`
}

type bcProgram struct {
	Code         string          `json:"code"`
	Slug         string          `json:"slug"`
	Name         string          `json:"name"`
	ProgramType  string          `json:"program_type"`
	Status       string          `json:"status"`
	MinReward    int             `json:"min_reward"`
	MaxReward    int             `json:"max_reward"`
	Public       bool            `json:"public"`
	URL          string          `json:"url"`
	Description  string          `json:"description"`
	TargetGroups []bcTargetGroup `json:"target_groups"`
	Targets      []bcTarget      `json:"targets"`
}

func (p bcProgram) toProgram() Program {
	slug := p.Code
	if slug == "" {
		slug = p.Slug
	}
	isBounty := p.MaxReward > 0 || strings.Contains(strings.ToLower(p.ProgramType), "bounty")
	ptype := "vdp"
	if isBounty {
		ptype = "bug-bounty"
	}
	scopes := extractBugcrowdScopes(p.TargetGroups, p.Targets)
	return Program{
		Slug:        slug,
		Title:       p.Name,
		Type:        ptype,
		Status:      p.Status,
		Bounty:      isBounty,
		Public:      p.Public,
		VDP:         !isBounty,
		ScopesCount: len(scopes),
		RewardMin:   p.MinReward,
		RewardMax:   p.MaxReward,
		Provider:    ProviderBugcrowd,
		URL:         p.URL,
		Rules:       p.Description,
		Scopes:      scopes,
	}
}

func extractBugcrowdScopes(groups []bcTargetGroup, direct []bcTarget) []ScopeAsset {
	var scopes []ScopeAsset
	appendTarget := func(t bcTarget, groupInScope bool) {
		if !groupInScope {
			return
		}
		if t.InScope != nil && !*t.InScope {
			return
		}
		cat := strings.ToLower(strings.TrimSpace(t.Category))
		if cat == "" {
			cat = strings.ToLower(strings.TrimSpace(t.Type))
		}
		normType, ok := normalizeBugcrowdCategory(cat)
		if !ok {
			return
		}
		target := strings.TrimSpace(t.URI)
		if target == "" {
			target = strings.TrimSpace(t.Target)
		}
		if target == "" {
			target = strings.TrimSpace(t.Name)
		}
		if target == "" {
			return
		}
		scopes = append(scopes, ScopeAsset{
			Target:      target,
			Type:        normType,
			Eligible:    true,
			Description: strings.TrimSpace(t.Description),
		})
	}
	for _, g := range groups {
		inScope := g.InScope == nil || *g.InScope
		for _, t := range g.Targets {
			appendTarget(t, inScope)
		}
	}
	for _, t := range direct {
		appendTarget(t, true)
	}
	return scopes
}

func normalizeBugcrowdCategory(cat string) (string, bool) {
	switch cat {
	case "", "website", "web", "web_application", "url":
		return "url", true
	case "api":
		return "api", true
	case "wildcard", "domain":
		return "wildcard", true
	default:
		return "", false
	}
}

// ListPrograms lists Bugcrowd programs with 10-minute caching and pagination.
func (c *BugcrowdClient) ListPrograms(ctx context.Context, q Query, refresh bool) ([]Program, int, bool, error) {
	q = normalizeQuery(q)
	key := cacheKey(q)
	if items, total, ok := c.cached(key, refresh); ok {
		return items, total, true, nil
	}

	params := url.Values{}
	params.Set("page", strconv.Itoa(q.Page))
	params.Set("per_page", strconv.Itoa(q.PerPage))
	if q.Search != "" {
		params.Set("q", q.Search)
	}

	var out struct {
		Programs []bcProgram `json:"programs"`
		Meta     struct {
			TotalHits  int `json:"total_hits"`
			TotalCount int `json:"total_count"`
			Total      int `json:"total"`
		} `json:"meta"`
	}
	if err := c.get(ctx, "/programs?"+params.Encode(), &out); err != nil {
		return nil, 0, false, err
	}

	items := make([]Program, 0, len(out.Programs))
	for _, p := range out.Programs {
		items = append(items, p.toProgram())
	}
	total := out.Meta.TotalHits
	if total == 0 {
		total = out.Meta.TotalCount
	}
	if total == 0 {
		total = out.Meta.Total
	}
	if total == 0 {
		total = len(items)
	}
	c.storeCache(key, items, total)
	return items, total, false, nil
}

// GetProgram fetches a Bugcrowd program and its web/API targets.
func (c *BugcrowdClient) GetProgram(ctx context.Context, slug string) (Program, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return Program{}, errors.New("bounty: program code is required")
	}
	var out bcProgram
	if err := c.get(ctx, "/programs/"+url.PathEscape(slug), &out); err != nil {
		return Program{}, err
	}
	if len(out.TargetGroups) == 0 && len(out.Targets) == 0 {
		var tgOut struct {
			TargetGroups []bcTargetGroup `json:"target_groups"`
		}
		if err := c.get(ctx, "/programs/"+url.PathEscape(slug)+"/target_groups", &tgOut); err == nil {
			out.TargetGroups = tgOut.TargetGroups
		}
	}
	return out.toProgram(), nil
}

// --- Intigriti ---

// IntigritiClient talks to the Intigriti External Researcher API v1.
type IntigritiClient struct {
	platformBase
}

// NewIntigritiClient returns a client for Intigriti
// (default https://api.intigriti.com/external/researcher/v1).
func NewIntigritiClient(baseURL string, tokenFn func() string) *IntigritiClient {
	return &IntigritiClient{
		platformBase: newPlatformBase(ProviderIntigriti, baseURL, defaultIntigritiBaseURL, tokenFn, func(tok string) string {
			return "Bearer " + tok
		}),
	}
}

// Validate checks an Intigriti Bearer token against /programs without storing it.
func (c *IntigritiClient) Validate(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrNoToken
	}
	var out map[string]any
	return c.getWithToken(ctx, "/programs?page=1&per_page=1", token, &out)
}

// flexString decodes either a JSON string ("Open") or an Intigriti enum object ({"value":"Open"}).
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var obj struct {
		Value string `json:"value"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	if obj.Value != "" {
		*f = flexString(obj.Value)
	} else {
		*f = flexString(obj.Name)
	}
	return nil
}

type flexInt int

func (f *flexInt) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '{' {
		var obj struct {
			Value float64 `json:"value"`
		}
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		*f = flexInt(int(obj.Value))
		return nil
	}
	var v float64
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*f = flexInt(int(v))
	return nil
}

type intigritiDomain struct {
	Endpoint    string     `json:"endpoint"`
	Value       string     `json:"value"`
	Type        flexString `json:"type"`
	Tier        flexString `json:"tier"`
	Description string     `json:"description"`
}

type intigritiDomains struct {
	Content []intigritiDomain
}

func (d *intigritiDomains) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '[' {
		return json.Unmarshal(data, &d.Content)
	}
	var wrapped struct {
		Content []intigritiDomain `json:"content"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	d.Content = wrapped.Content
	return nil
}

type intigritiProgram struct {
	ID                   string           `json:"id"`
	Handle               string           `json:"handle"`
	Name                 string           `json:"name"`
	Type                 flexString       `json:"type"`
	Status               flexString       `json:"status"`
	ConfidentialityLevel flexString       `json:"confidentialityLevel"`
	MinBounty            flexInt          `json:"minBounty"`
	MaxBounty            flexInt          `json:"maxBounty"`
	URL                  string           `json:"webLinks"`
	Rules                string           `json:"rulesOfEngagement"`
	Domains              intigritiDomains `json:"domains"`
}

func (p intigritiProgram) toProgram() Program {
	slug := p.ID
	if slug == "" {
		slug = p.Handle
	}
	var scopes []ScopeAsset
	for _, d := range p.Domains.Content {
		tier := strings.ToLower(strings.TrimSpace(string(d.Tier)))
		if tier == "out_of_scope" || tier == "out of scope" || tier == "outofscope" {
			continue
		}
		normType, ok := normalizeIntigritiDomainType(string(d.Type))
		if !ok {
			continue
		}
		target := strings.TrimSpace(d.Endpoint)
		if target == "" {
			target = strings.TrimSpace(d.Value)
		}
		if target == "" {
			continue
		}
		scopes = append(scopes, ScopeAsset{
			Target:      target,
			Type:        normType,
			Eligible:    true,
			Description: strings.TrimSpace(d.Description),
		})
	}
	typeStr := strings.ToLower(string(p.Type))
	isBounty := int(p.MaxBounty) > 0 || strings.Contains(typeStr, "bounty")
	ptype := "vdp"
	if isBounty {
		ptype = "bug-bounty"
	}
	return Program{
		Slug:        slug,
		Title:       p.Name,
		Type:        ptype,
		Status:      string(p.Status),
		Bounty:      isBounty,
		Public:      strings.EqualFold(string(p.ConfidentialityLevel), "Public"),
		VDP:         !isBounty,
		ScopesCount: len(scopes),
		RewardMin:   int(p.MinBounty),
		RewardMax:   int(p.MaxBounty),
		Provider:    ProviderIntigriti,
		Rules:       p.Rules,
		Scopes:      scopes,
	}
}

func normalizeIntigritiDomainType(t string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "url":
		return "url", true
	case "wildcard":
		return "wildcard", true
	default:
		return "", false
	}
}

// ListPrograms lists Intigriti programs with 10-minute caching and pagination.
func (c *IntigritiClient) ListPrograms(ctx context.Context, q Query, refresh bool) ([]Program, int, bool, error) {
	q = normalizeQuery(q)
	key := cacheKey(q)
	if items, total, ok := c.cached(key, refresh); ok {
		return items, total, true, nil
	}

	params := url.Values{}
	params.Set("page", strconv.Itoa(q.Page))
	params.Set("per_page", strconv.Itoa(q.PerPage))
	if q.Search != "" {
		params.Set("search", q.Search)
	}

	var out struct {
		Records  []intigritiProgram `json:"records"`
		MaxCount int                `json:"maxCount"`
		Total    int                `json:"total"`
	}
	if err := c.get(ctx, "/programs?"+params.Encode(), &out); err != nil {
		return nil, 0, false, err
	}

	items := make([]Program, 0, len(out.Records))
	for _, r := range out.Records {
		items = append(items, r.toProgram())
	}
	total := out.MaxCount
	if total == 0 {
		total = out.Total
	}
	if total == 0 {
		total = len(items)
	}
	c.storeCache(key, items, total)
	return items, total, false, nil
}

// GetProgram fetches an Intigriti program and its in-scope URL/wildcard domains.
func (c *IntigritiClient) GetProgram(ctx context.Context, slug string) (Program, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return Program{}, errors.New("bounty: program id is required")
	}
	var out intigritiProgram
	if err := c.get(ctx, "/programs/"+url.PathEscape(slug), &out); err != nil {
		return Program{}, err
	}
	return out.toProgram(), nil
}
