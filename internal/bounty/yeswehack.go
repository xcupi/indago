// Package bounty integrates external bug-bounty platforms.
//
// YesWeHack's public API is the first provider. Two facts shape the design:
//
//   - Authentication is a Personal Access Token sent as X-AUTH-TOKEN. There is
//     no password flow, and this package never handles a password.
//   - The program list is public; scopes, report templates and drafts are not.
//     So "browse programs" works anonymously, while "import a program's scope"
//     requires a token and fails with a clear message instead of guessing.
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

// ErrNoToken means the operation needs a Personal Access Token.
var ErrNoToken = errors.New("bounty: this provider needs a personal access token")

// ErrUnauthorized is a provider 401/403.
var ErrUnauthorized = errors.New("bounty: provider rejected the token")

// ErrNotFound is a provider 404.
var ErrNotFound = errors.New("bounty: resource not found")

// Program is one program row from the list endpoint.
type Program struct {
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Type        string `json:"type"` // bug-bounty | vdp | pentest
	Status      string `json:"status"`
	Bounty      bool   `json:"bounty"`
	Public      bool   `json:"public"`
	VDP         bool   `json:"vdp"`
	ScopesCount int    `json:"scopes_count"`
	RewardMin   int    `json:"bounty_reward_min"`
	RewardMax   int    `json:"bounty_reward_max"`
	Reports     int    `json:"reports_count"`
}

// ProgramDetail carries the rules, which is where the platform states its
// testing requirements (required header, forbidden actions, out-of-scope
// behaviour).
type ProgramDetail struct {
	Program
	Rules     string `json:"rules"`
	RulesHTML string `json:"rules_html"`
}

// Scope is one in-scope asset.
type Scope struct {
	Scope         string `json:"scope"`
	ScopeType     string `json:"scope_type"`
	ScopeTypeName string `json:"scope_type_name"`
	AssetValue    string `json:"asset_value"`
	ReportCount   int    `json:"report_count"`
}

// ReportTemplate is a per-program submission template.
type ReportTemplate struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Template string `json:"template"`
	Type     string `json:"type"`
}

// DraftReport is the payload for creating or updating a YesWeHack draft
// report. Indago only ever writes to the draft endpoint; it never submits.
type DraftReport struct {
	Title               string `json:"title"`
	BugType             string `json:"bug_type,omitempty"`
	Scope               string `json:"scope,omitempty"`
	EndPoint            string `json:"end_point,omitempty"`
	VulnerablePart      string `json:"vulnerable_part,omitempty"`
	PartName            string `json:"part_name,omitempty"`
	Payload             string `json:"payload,omitempty"`
	DescriptionMarkdown string `json:"description_markdown,omitempty"`
	TechnicalEnv        string `json:"technical_environment,omitempty"`
}

// DraftResult is the platform response when reading, creating, or updating a
// YesWeHack draft report.
type DraftResult struct {
	ID       json.RawMessage `json:"id,omitempty"`
	DraftKey string          `json:"draft_id,omitempty"`
	Title    string          `json:"title,omitempty"`
	Slug     string          `json:"slug,omitempty"`
	URL      string          `json:"url,omitempty"`
}

// DraftID returns the draft identifier as a string regardless of whether the
// API returned a numeric id, string id, or draft_id field.
func (d DraftResult) DraftID() string {
	if s := strings.TrimSpace(d.DraftKey); s != "" {
		return s
	}
	raw := strings.TrimSpace(string(d.ID))
	if raw == "" || raw == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(d.ID, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return raw
}

// Query selects programs. Empty ScopeTypes defaults to web-application and
// empty Types defaults to bug-bounty: the two filters the operator asked for.
type Query struct {
	Search     string
	ScopeTypes []string
	Types      []string
	Page       int
	PerPage    int
}

// Client talks to the YesWeHack API. Token is read on every call so a token
// saved in Settings takes effect without restarting the server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Token   func() string

	// WebBase hosts the public program pages, used when no token is available
	// (hunter accounts cannot create personal access tokens).
	WebBase string

	mu          sync.Mutex
	cache       map[string]cacheEntry
	publicCache map[string]publicScopesCache
	ttl         time.Duration
}

type cacheEntry struct {
	programs  []Program
	total     int
	fetchedAt time.Time
}

// NewClient returns a client for the given API base (api.yeswehack.com).
func NewClient(base string, token func() string) *Client {
	if base == "" {
		base = "https://api.yeswehack.com"
	}
	if token == nil {
		token = func() string { return "" }
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), WebBase: DefaultWebBase,
		HTTP: &http.Client{Timeout: 25 * time.Second}, Token: token,
		cache: map[string]cacheEntry{}, publicCache: map[string]publicScopesCache{}, ttl: 10 * time.Minute}
}

// ListPrograms returns the program list. refresh=false serves a cached result
// for up to 10 minutes: the UI has an explicit "Load" button, and a page that
// re-renders must not hammer the platform.
func (c *Client) ListPrograms(ctx context.Context, q Query, refresh bool) ([]Program, int, bool, error) {
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.PerPage <= 0 {
		q.PerPage = 50
	}
	if len(q.Types) == 0 {
		q.Types = []string{"bug-bounty"}
	}
	if len(q.ScopeTypes) == 0 {
		q.ScopeTypes = []string{"web-application"}
	}
	key := cacheKey(q)
	if !refresh {
		c.mu.Lock()
		e, ok := c.cache[key]
		c.mu.Unlock()
		if ok && time.Since(e.fetchedAt) < c.ttl {
			return e.programs, e.total, true, nil
		}
	}

	params := url.Values{}
	params.Set("page", strconv.Itoa(q.Page))
	params.Set("resultsPerPage", strconv.Itoa(q.PerPage))
	if q.Search != "" {
		params.Set("filter[search]", q.Search)
	}
	for _, t := range q.Types {
		params.Add("filter[type][]", t)
	}
	for _, s := range q.ScopeTypes {
		params.Add("filter[scopeType][]", s)
	}

	var out struct {
		Items      []Program `json:"items"`
		Pagination struct {
			NbResults int `json:"nb_results"`
		} `json:"pagination"`
	}
	if err := c.get(ctx, "/programs?"+params.Encode(), &out); err != nil {
		return nil, 0, false, err
	}
	c.mu.Lock()
	c.cache[key] = cacheEntry{programs: out.Items, total: out.Pagination.NbResults, fetchedAt: time.Now()}
	c.mu.Unlock()
	return out.Items, out.Pagination.NbResults, false, nil
}

// Detail returns one program, including its rules text.
func (c *Client) Detail(ctx context.Context, slug string) (*ProgramDetail, error) {
	var out ProgramDetail
	if err := c.get(ctx, "/programs/"+url.PathEscape(slug), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Scopes returns the program's in-scope assets. Requires a token.
func (c *Client) Scopes(ctx context.Context, slug string) ([]Scope, error) {
	if c.Token() == "" {
		return nil, ErrNoToken
	}
	var out struct {
		Items []Scope `json:"items"`
	}
	if err := c.get(ctx, "/programs/"+url.PathEscape(slug)+"/scopes", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// ReportTemplates returns the program's submission templates. Requires a token.
func (c *Client) ReportTemplates(ctx context.Context, slug string) ([]ReportTemplate, error) {
	if c.Token() == "" {
		return nil, ErrNoToken
	}
	var out struct {
		Items []ReportTemplate `json:"items"`
	}
	if err := c.get(ctx, "/programs/"+url.PathEscape(slug)+"/report-templates", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// GetDraft fetches the current draft report for a program, if one exists.
// Requires a token.
func (c *Client) GetDraft(ctx context.Context, slug string) (*DraftResult, error) {
	if c.Token() == "" {
		return nil, ErrNoToken
	}
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return nil, errors.New("bounty: program slug is required")
	}
	var out DraftResult
	if err := c.get(ctx, "/programs/"+url.PathEscape(slug)+"/reports/draft", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateDraft creates a draft report on YesWeHack without submitting it.
// Requires a token. Indago never calls the report submission endpoint.
func (c *Client) CreateDraft(ctx context.Context, slug string, draft DraftReport) (*DraftResult, error) {
	if c.Token() == "" {
		return nil, ErrNoToken
	}
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return nil, errors.New("bounty: program slug is required")
	}
	if strings.TrimSpace(draft.Title) == "" {
		return nil, errors.New("bounty: draft title is required")
	}
	var out DraftResult
	if err := c.doJSON(ctx, http.MethodPost, "/programs/"+url.PathEscape(slug)+"/reports/draft", draft, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateDraft updates an existing draft report on YesWeHack without submitting
// it. Requires a token.
func (c *Client) UpdateDraft(ctx context.Context, slug, draftID string, draft DraftReport) (*DraftResult, error) {
	if c.Token() == "" {
		return nil, ErrNoToken
	}
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return nil, errors.New("bounty: program slug is required")
	}
	if strings.TrimSpace(draft.Title) == "" {
		return nil, errors.New("bounty: draft title is required")
	}
	path := "/programs/" + url.PathEscape(slug) + "/reports/draft"
	if id := strings.TrimSpace(draftID); id != "" {
		path += "/" + url.PathEscape(id)
	}
	var out DraftResult
	if err := c.doJSON(ctx, http.MethodPut, path, draft, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) get(ctx context.Context, path string, dst any) error {
	return c.doJSON(ctx, http.MethodGet, path, nil, dst)
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody, dst any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		encoded, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("bounty: encode %s: %w", path, err)
		}
		bodyReader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "indago-bounty/1.0")
	if tok := c.Token(); tok != "" {
		// Two credential shapes reach this API: a personal access token
		// (X-AUTH-TOKEN, manager roles only) and the web session JWT a hunter
		// gets after logging in (Authorization: Bearer). A JWT has dots; a PAT
		// does not.
		if strings.Count(tok, ".") == 2 {
			req.Header.Set("Authorization", "Bearer "+tok)
		} else {
			req.Header.Set("X-AUTH-TOKEN", tok)
		}
	}
	resp, err := c.HTTP.Do(req)
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
		return fmt.Errorf("bounty: %s returned %d", path, resp.StatusCode)
	}
	if dst == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("bounty: decode %s: %w", path, err)
	}
	return nil
}

func cacheKey(q Query) string {
	return strings.Join([]string{q.Search, strings.Join(q.Types, ","), strings.Join(q.ScopeTypes, ","), strconv.Itoa(q.Page), strconv.Itoa(q.PerPage)}, "|")
}

// Validate checks a credential without storing it: /programs/count is readable
// by both a session JWT and a personal access token, and answers 401 for a bad
// one.
func (c *Client) Validate(ctx context.Context, token string) error {
	probe := NewClient(c.BaseURL, func() string { return strings.TrimSpace(token) })
	var out map[string]any
	if err := probe.get(ctx, "/programs/count", &out); err != nil {
		return err
	}
	return nil
}

// CredentialKind reports "session" for a JWT and "pat" for a personal token.
func CredentialKind(token string) string {
	if strings.Count(strings.TrimSpace(token), ".") == 2 {
		return "session"
	}
	return "pat"
}

// CredentialInfo describes a credential without revealing it: kind and, for a
// JWT, the expiry the token itself carries.
func CredentialInfo(token string) (kind string, expires time.Time) {
	token = strings.TrimSpace(token)
	kind = CredentialKind(token)
	if kind != "session" {
		return kind, time.Time{}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return kind, time.Time{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return kind, time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp == 0 {
		return kind, time.Time{}
	}
	return kind, time.Unix(claims.Exp, 0)
}
