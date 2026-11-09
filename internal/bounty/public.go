package bounty

// Public scope extraction.
//
// YesWeHack only lets Business Unit / Program Manager roles create personal
// access tokens, so a hunter account cannot authenticate to the API at all.
// The program page, however, is public and ships its scope table in the
// server-rendered transfer state:
//
//	"scopes":[{"scope":"https://www.example.com","scope_type":"web-application",
//	           "scope_type_name":"Web application","asset_value":"MEDIUM",...}]
//
// Note the trap: in the API schema `asset_value` is the asset, but in this
// state blob it is the *severity* ("MEDIUM"), while `scope` is the asset. The
// importer therefore treats a value as a host only when it parses as one, and
// never falls back to a severity word.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultWebBase is the public site that renders program pages.
const DefaultWebBase = "https://yeswehack.com"

type publicScopesCache struct {
	scopes    []Scope
	fetchedAt time.Time
}

// PublicScopes reads the program's scope table from its public page. It is the
// unauthenticated path used for hunter accounts.
func (c *Client) PublicScopes(ctx context.Context, slug string) ([]Scope, error) {
	if c.WebBase == "" {
		c.WebBase = DefaultWebBase
	}
	key := "public:" + slug
	c.mu.Lock()
	if e, ok := c.publicCache[key]; ok && time.Since(e.fetchedAt) < c.ttl {
		c.mu.Unlock()
		return e.scopes, nil
	}
	c.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(c.WebBase, "/")+"/programs/"+slug, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bounty: program page returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	scopes, err := extractPublicScopes(body)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.publicCache == nil {
		c.publicCache = map[string]publicScopesCache{}
	}
	c.publicCache[key] = publicScopesCache{scopes: scopes, fetchedAt: time.Now()}
	c.mu.Unlock()
	return scopes, nil
}

// extractPublicScopes finds the first "scopes":[...] array in the page and
// decodes it. The blob is JSON embedded in a JS assignment, so the array is
// copied out by bracket matching rather than by a regex.
func extractPublicScopes(page []byte) ([]Scope, error) {
	marker := []byte(`"scopes":[`)
	i := strings.Index(string(page), string(marker))
	if i < 0 {
		return nil, errors.New("bounty: no scopes table on the program page")
	}
	start := i + len(`"scopes":`)
	depth := 0
	inStr := false
	esc := false
	end := -1
	for j := start; j < len(page); j++ {
		c := page[j]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				end = j + 1
			}
		}
		if end > 0 {
			break
		}
	}
	if end < 0 {
		return nil, errors.New("bounty: unterminated scopes array")
	}
	var scopes []Scope
	if err := json.Unmarshal(page[start:end], &scopes); err != nil {
		return nil, fmt.Errorf("bounty: decode scopes: %w", err)
	}
	return scopes, nil
}
