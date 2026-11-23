package scan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/indago/indago/internal/auth"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
)

var ErrSnapshotFetch = errors.New("could not read the approved target URL")

// ReadSnapshot retrieves the exact, operator-approved URL once. The only
// outbound action here is a bodyless GET. In-scope redirects remain evidence
// of a redirect and require a separate approval before reading their URL.
func (c *Controller) ReadSnapshot(ctx context.Context, projectID domain.ID, rawURL string, approved bool, profileID domain.ID) (*httpengine.Response, error) {
	if !c.ReadOnlyTargets() {
		return nil, ErrTargetReadOnly
	}
	if !approved {
		return nil, fmt.Errorf("%w: confirm that the exact URL and account are read-only", ErrBadConfig)
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" ||
		u.User != nil || u.Fragment != "" || strings.Contains(rawURL, "#") {
		return nil, fmt.Errorf("%w: use an exact HTTP or HTTPS URL without credentials or a fragment", ErrBadConfig)
	}
	scope, err := c.loadScope(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if d := scope.Permits(u.String()); !d.Allowed {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
	}

	req := httpengine.GET(u.String())
	req.NoRedirects = true
	req.NoJar = true
	req.NoCookies = profileID.Empty()
	eng := newScopedEngine(c.opts.HTTP, scope)
	if !profileID.Empty() {
		profile, err := c.store.AuthProfiles().Get(ctx, profileID)
		if err != nil {
			return nil, err
		}
		if profile.ProjectID != projectID {
			return nil, store.ErrNotFound
		}
		state := profile.StatePath
		if !filepath.IsAbs(state) || auth.ValidateStateFile(state) != nil {
			return nil, fmt.Errorf("%w: the saved session is unavailable; import a read-only session", ErrAuth)
		}
		eng = eng.WithSessionCookies(sessionCookies(state)).WithSessionAuthHeaders(sessionAuthHeaders(state))
		if len(eng.cookiesForURL(req.URL, req.URL, nil, true)) == 0 && eng.sessionBearerFor(req.URL) == "" {
			return nil, fmt.Errorf("%w: the saved session contains no usable credentials for this URL", ErrAuth)
		}
	}
	resp, err := eng.Do(ctx, req)
	if err != nil {
		return nil, ErrSnapshotFetch
	}
	return resp, nil
}
