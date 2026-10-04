package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

// scanner abstracts *sql.Row and *sql.Rows for shared row-scan helpers.
type scanner interface {
	Scan(dest ...any) error
}

func jsonEncode(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func jsonDecode(s string, v any) error {
	if s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), v)
}

// nonNilStrings returns a non-nil slice so it encodes as [] rather than null.
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// discoveryOrPending defaults an unset discovery state to pending.
func discoveryOrPending(d domain.DiscoveryState) domain.DiscoveryState {
	if d == "" {
		return domain.DiscoveryPending
	}
	return d
}

// mapGetErr translates sql.ErrNoRows into store.ErrNotFound.
func mapGetErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// Accessors.

func (d *DB) Projects() store.ProjectRepo               { return &projectRepo{d.db} }
func (d *DB) Targets() store.TargetRepo                 { return &targetRepo{d.db} }
func (d *DB) Scopes() store.ScopeRepo                   { return &scopeRepo{d.db} }
func (d *DB) Scans() store.ScanRepo                     { return &scanRepo{d.db} }
func (d *DB) Endpoints() store.EndpointRepo             { return &endpointRepo{d.db} }
func (d *DB) Parameters() store.ParameterRepo           { return &parameterRepo{d.db} }
func (d *DB) InjectionPoints() store.InjectionPointRepo { return &injectionPointRepo{d.db} }
func (d *DB) Jobs() store.JobRepo                       { return &jobRepo{d.db} }
func (d *DB) TestCases() store.TestCaseRepo             { return &testCaseRepo{d.db} }
func (d *DB) Findings() store.FindingRepo               { return &findingRepo{d.db} }
func (d *DB) Evidence() store.EvidenceRepo              { return &evidenceRepo{d.db} }
func (d *DB) Sessions() store.SessionRepo               { return &sessionRepo{d.db} }
func (d *DB) Reports() store.ReportRepo                 { return &reportRepo{d.db} }
func (d *DB) AITasks() store.AITaskRepo                 { return &aiTaskRepo{d.db} }

// --- Project ---

type projectRepo struct{ db *sql.DB }

func (r *projectRepo) Create(ctx context.Context, p *domain.Project) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO projects (id, name, notes, created_at, updated_at) VALUES (?,?,?,?,?)`,
		p.ID, p.Name, p.Notes, ts(p.CreatedAt), ts(p.UpdatedAt))
	return err
}

func scanProject(sc scanner) (*domain.Project, error) {
	var p domain.Project
	var created, updated string
	if err := sc.Scan(&p.ID, &p.Name, &p.Notes, &created, &updated); err != nil {
		return nil, err
	}
	p.CreatedAt, _ = parseTS(created)
	p.UpdatedAt, _ = parseTS(updated)
	return &p, nil
}

func (r *projectRepo) Get(ctx context.Context, id domain.ID) (*domain.Project, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, name, notes, created_at, updated_at FROM projects WHERE id=?`, id)
	p, err := scanProject(row)
	return p, mapGetErr(err)
}

func (r *projectRepo) List(ctx context.Context) ([]*domain.Project, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, notes, created_at, updated_at FROM projects ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *projectRepo) Update(ctx context.Context, p *domain.Project) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE projects SET name=?, notes=?, updated_at=? WHERE id=?`,
		p.Name, p.Notes, ts(p.UpdatedAt), p.ID)
	return affected(res, err)
}

func (r *projectRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM projects WHERE id=?`, id)
	return affected(res, err)
}

// --- Target ---

type targetRepo struct{ db *sql.DB }

func (r *targetRepo) Create(ctx context.Context, t *domain.Target) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO targets (id, project_id, name, base_url, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		t.ID, t.ProjectID, t.Name, t.BaseURL, ts(t.CreatedAt), ts(t.UpdatedAt))
	return err
}

func scanTarget(sc scanner) (*domain.Target, error) {
	var t domain.Target
	var created, updated string
	if err := sc.Scan(&t.ID, &t.ProjectID, &t.Name, &t.BaseURL, &created, &updated); err != nil {
		return nil, err
	}
	t.CreatedAt, _ = parseTS(created)
	t.UpdatedAt, _ = parseTS(updated)
	return &t, nil
}

func (r *targetRepo) Get(ctx context.Context, id domain.ID) (*domain.Target, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, project_id, name, base_url, created_at, updated_at FROM targets WHERE id=?`, id)
	t, err := scanTarget(row)
	return t, mapGetErr(err)
}

func (r *targetRepo) ListByProject(ctx context.Context, projectID domain.ID) ([]*domain.Target, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, project_id, name, base_url, created_at, updated_at FROM targets WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *targetRepo) Update(ctx context.Context, t *domain.Target) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE targets SET project_id=?, name=?, base_url=?, updated_at=? WHERE id=?`,
		t.ProjectID, t.Name, t.BaseURL, ts(t.UpdatedAt), t.ID)
	return affected(res, err)
}

func (r *targetRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM targets WHERE id=?`, id)
	return affected(res, err)
}

// --- Scope ---

type scopeRepo struct{ db *sql.DB }

func (r *scopeRepo) Create(ctx context.Context, s *domain.Scope) error {
	inc, _ := jsonEncode(s.IncludeHosts)
	exc, _ := jsonEncode(s.ExcludeHosts)
	incP, _ := jsonEncode(s.IncludePathPrefixes)
	excP, _ := jsonEncode(s.ExcludePathPrefixes)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO scopes (id, project_id, include_hosts, exclude_hosts, include_path_prefixes, exclude_path_prefixes, allow_subdomains, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		s.ID, s.ProjectID, inc, exc, incP, excP, boolToInt(s.AllowSubdomains), ts(s.CreatedAt), ts(s.UpdatedAt))
	return err
}

func scanScope(sc scanner) (*domain.Scope, error) {
	var s domain.Scope
	var inc, exc, incP, excP, created, updated string
	var allow int
	if err := sc.Scan(&s.ID, &s.ProjectID, &inc, &exc, &incP, &excP, &allow, &created, &updated); err != nil {
		return nil, err
	}
	_ = jsonDecode(inc, &s.IncludeHosts)
	_ = jsonDecode(exc, &s.ExcludeHosts)
	_ = jsonDecode(incP, &s.IncludePathPrefixes)
	_ = jsonDecode(excP, &s.ExcludePathPrefixes)
	s.AllowSubdomains = allow != 0
	s.CreatedAt, _ = parseTS(created)
	s.UpdatedAt, _ = parseTS(updated)
	return &s, nil
}

const scopeCols = `id, project_id, include_hosts, exclude_hosts, include_path_prefixes, exclude_path_prefixes, allow_subdomains, created_at, updated_at`

func (r *scopeRepo) Get(ctx context.Context, id domain.ID) (*domain.Scope, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+scopeCols+` FROM scopes WHERE id=?`, id)
	s, err := scanScope(row)
	return s, mapGetErr(err)
}

func (r *scopeRepo) GetByProject(ctx context.Context, projectID domain.ID) (*domain.Scope, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+scopeCols+` FROM scopes WHERE project_id=? ORDER BY created_at LIMIT 1`, projectID)
	s, err := scanScope(row)
	return s, mapGetErr(err)
}

func (r *scopeRepo) Update(ctx context.Context, s *domain.Scope) error {
	inc, _ := jsonEncode(s.IncludeHosts)
	exc, _ := jsonEncode(s.ExcludeHosts)
	incP, _ := jsonEncode(s.IncludePathPrefixes)
	excP, _ := jsonEncode(s.ExcludePathPrefixes)
	res, err := r.db.ExecContext(ctx,
		`UPDATE scopes SET project_id=?, include_hosts=?, exclude_hosts=?, include_path_prefixes=?, exclude_path_prefixes=?, allow_subdomains=?, updated_at=? WHERE id=?`,
		s.ProjectID, inc, exc, incP, excP, boolToInt(s.AllowSubdomains), ts(s.UpdatedAt), s.ID)
	return affected(res, err)
}

func (r *scopeRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM scopes WHERE id=?`, id)
	return affected(res, err)
}

// --- Scan ---

type scanRepo struct{ db *sql.DB }

const scanCols = `id, project_id, target_id, name, state, profile, config, stop_policy, session_id, stats, error, created_at, started_at, updated_at, ended_at, seed_urls, discovery_state`

func (r *scanRepo) Create(ctx context.Context, s *domain.Scan) error {
	cfg, _ := jsonEncode(s.Config)
	stop, _ := jsonEncode(s.Stop)
	stats, _ := jsonEncode(s.Stats)
	seeds, _ := jsonEncode(nonNilStrings(s.SeedURLs))
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO scans (`+scanCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.ID, s.ProjectID, s.TargetID, s.Name, s.State, s.Profile, cfg, stop, s.SessionID, stats, s.Error,
		ts(s.CreatedAt), tsPtr(s.StartedAt), ts(s.UpdatedAt), tsPtr(s.EndedAt), seeds, discoveryOrPending(s.Discovery))
	return err
}

func scanScan(sc scanner) (*domain.Scan, error) {
	var s domain.Scan
	var cfg, stop, stats, created, updated, seeds string
	var started, ended sql.NullString
	if err := sc.Scan(&s.ID, &s.ProjectID, &s.TargetID, &s.Name, &s.State, &s.Profile,
		&cfg, &stop, &s.SessionID, &stats, &s.Error, &created, &started, &updated, &ended,
		&seeds, &s.Discovery); err != nil {
		return nil, err
	}
	_ = jsonDecode(seeds, &s.SeedURLs)
	_ = jsonDecode(cfg, &s.Config)
	_ = jsonDecode(stop, &s.Stop)
	_ = jsonDecode(stats, &s.Stats)
	s.CreatedAt, _ = parseTS(created)
	s.UpdatedAt, _ = parseTS(updated)
	s.StartedAt, _ = parseTSPtr(started)
	s.EndedAt, _ = parseTSPtr(ended)
	return &s, nil
}

func (r *scanRepo) Get(ctx context.Context, id domain.ID) (*domain.Scan, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scans WHERE id=?`, id)
	s, err := scanScan(row)
	return s, mapGetErr(err)
}

func (r *scanRepo) listWhere(ctx context.Context, where string, args ...any) ([]*domain.Scan, error) {
	q := `SELECT ` + scanCols + ` FROM scans`
	if where != "" {
		q += ` WHERE ` + where
	}
	q += ` ORDER BY created_at`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Scan
	for rows.Next() {
		s, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *scanRepo) ListByProject(ctx context.Context, projectID domain.ID) ([]*domain.Scan, error) {
	return r.listWhere(ctx, `project_id=?`, projectID)
}

func (r *scanRepo) List(ctx context.Context) ([]*domain.Scan, error) {
	return r.listWhere(ctx, "")
}

func (r *scanRepo) Update(ctx context.Context, s *domain.Scan) error {
	cfg, _ := jsonEncode(s.Config)
	stop, _ := jsonEncode(s.Stop)
	stats, _ := jsonEncode(s.Stats)
	seeds, _ := jsonEncode(nonNilStrings(s.SeedURLs))
	res, err := r.db.ExecContext(ctx,
		`UPDATE scans SET project_id=?, target_id=?, name=?, state=?, profile=?, config=?, stop_policy=?, session_id=?, stats=?, error=?, started_at=?, updated_at=?, ended_at=?, seed_urls=?, discovery_state=? WHERE id=?`,
		s.ProjectID, s.TargetID, s.Name, s.State, s.Profile, cfg, stop, s.SessionID, stats, s.Error,
		tsPtr(s.StartedAt), ts(s.UpdatedAt), tsPtr(s.EndedAt), seeds, discoveryOrPending(s.Discovery), s.ID)
	return affected(res, err)
}

func (r *scanRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM scans WHERE id=?`, id)
	return affected(res, err)
}

// --- Endpoint ---

type endpointRepo struct{ db *sql.DB }

const endpointCols = `id, scan_id, url, method, source, content_type, fingerprint, created_at`

func (r *endpointRepo) Create(ctx context.Context, e *domain.Endpoint) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO endpoints (`+endpointCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		e.ID, e.ScanID, e.URL, e.Method, e.Source, e.ContentType, e.Fingerprint, ts(e.CreatedAt))
	return err
}

func scanEndpoint(sc scanner) (*domain.Endpoint, error) {
	var e domain.Endpoint
	var created string
	if err := sc.Scan(&e.ID, &e.ScanID, &e.URL, &e.Method, &e.Source, &e.ContentType, &e.Fingerprint, &created); err != nil {
		return nil, err
	}
	e.CreatedAt, _ = parseTS(created)
	return &e, nil
}

func (r *endpointRepo) Get(ctx context.Context, id domain.ID) (*domain.Endpoint, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+endpointCols+` FROM endpoints WHERE id=?`, id)
	e, err := scanEndpoint(row)
	return e, mapGetErr(err)
}

func (r *endpointRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Endpoint, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+endpointCols+` FROM endpoints WHERE scan_id=? ORDER BY created_at`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Endpoint
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *endpointRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM endpoints WHERE id=?`, id)
	return affected(res, err)
}

// --- Parameter ---

type parameterRepo struct{ db *sql.DB }

const parameterCols = `id, scan_id, endpoint_id, name, location, example, source, created_at`

func (r *parameterRepo) Create(ctx context.Context, p *domain.Parameter) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO parameters (`+parameterCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		p.ID, p.ScanID, p.EndpointID, p.Name, p.Location, p.Example, p.Source, ts(p.CreatedAt))
	return err
}

func scanParameter(sc scanner) (*domain.Parameter, error) {
	var p domain.Parameter
	var created string
	if err := sc.Scan(&p.ID, &p.ScanID, &p.EndpointID, &p.Name, &p.Location, &p.Example, &p.Source, &created); err != nil {
		return nil, err
	}
	p.CreatedAt, _ = parseTS(created)
	return &p, nil
}

func (r *parameterRepo) Get(ctx context.Context, id domain.ID) (*domain.Parameter, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+parameterCols+` FROM parameters WHERE id=?`, id)
	p, err := scanParameter(row)
	return p, mapGetErr(err)
}

func (r *parameterRepo) queryList(ctx context.Context, where string, arg domain.ID) ([]*domain.Parameter, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+parameterCols+` FROM parameters WHERE `+where+` ORDER BY created_at`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Parameter
	for rows.Next() {
		p, err := scanParameter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *parameterRepo) ListByEndpoint(ctx context.Context, endpointID domain.ID) ([]*domain.Parameter, error) {
	return r.queryList(ctx, `endpoint_id=?`, endpointID)
}

func (r *parameterRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Parameter, error) {
	return r.queryList(ctx, `scan_id=?`, scanID)
}

func (r *parameterRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM parameters WHERE id=?`, id)
	return affected(res, err)
}

// --- InjectionPoint ---

type injectionPointRepo struct{ db *sql.DB }

const injCols = `id, scan_id, endpoint_id, parameter_id, location, created_at`

func (r *injectionPointRepo) Create(ctx context.Context, ip *domain.InjectionPoint) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO injection_points (`+injCols+`) VALUES (?,?,?,?,?,?)`,
		ip.ID, ip.ScanID, ip.EndpointID, ip.ParameterID, ip.Location, ts(ip.CreatedAt))
	return err
}

func scanInjectionPoint(sc scanner) (*domain.InjectionPoint, error) {
	var ip domain.InjectionPoint
	var created string
	if err := sc.Scan(&ip.ID, &ip.ScanID, &ip.EndpointID, &ip.ParameterID, &ip.Location, &created); err != nil {
		return nil, err
	}
	ip.CreatedAt, _ = parseTS(created)
	return &ip, nil
}

func (r *injectionPointRepo) Get(ctx context.Context, id domain.ID) (*domain.InjectionPoint, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+injCols+` FROM injection_points WHERE id=?`, id)
	ip, err := scanInjectionPoint(row)
	return ip, mapGetErr(err)
}

func (r *injectionPointRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.InjectionPoint, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+injCols+` FROM injection_points WHERE scan_id=? ORDER BY created_at`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.InjectionPoint
	for rows.Next() {
		ip, err := scanInjectionPoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

func (r *injectionPointRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM injection_points WHERE id=?`, id)
	return affected(res, err)
}

// --- Job ---

type jobRepo struct{ db *sql.DB }

const jobCols = `id, scan_id, type, state, priority, target, payload, attempts, max_attempts, lease_id, leased_until, last_error, available_at, created_at, updated_at`

func (r *jobRepo) Create(ctx context.Context, j *domain.TestJob) error {
	tgt, _ := jsonEncode(j.Target)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO jobs (`+jobCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		j.ID, j.ScanID, j.Type, j.State, j.Priority, tgt, j.Payload, j.Attempts, j.MaxAttempts,
		j.LeaseID, tsPtr(j.LeasedUntil), j.LastError, ts(j.AvailableAt), ts(j.CreatedAt), ts(j.UpdatedAt))
	return err
}

func scanJob(sc scanner) (*domain.TestJob, error) {
	var j domain.TestJob
	var tgt, available, created, updated string
	var leased sql.NullString
	if err := sc.Scan(&j.ID, &j.ScanID, &j.Type, &j.State, &j.Priority, &tgt, &j.Payload,
		&j.Attempts, &j.MaxAttempts, &j.LeaseID, &leased, &j.LastError, &available, &created, &updated); err != nil {
		return nil, err
	}
	_ = jsonDecode(tgt, &j.Target)
	j.LeasedUntil, _ = parseTSPtr(leased)
	j.AvailableAt, _ = parseTS(available)
	j.CreatedAt, _ = parseTS(created)
	j.UpdatedAt, _ = parseTS(updated)
	return &j, nil
}

func (r *jobRepo) Get(ctx context.Context, id domain.ID) (*domain.TestJob, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=?`, id)
	j, err := scanJob(row)
	return j, mapGetErr(err)
}

func (r *jobRepo) listWhere(ctx context.Context, where string, args ...any) ([]*domain.TestJob, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE `+where+` ORDER BY priority DESC, created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.TestJob
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (r *jobRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.TestJob, error) {
	return r.listWhere(ctx, `scan_id=?`, scanID)
}

func (r *jobRepo) ListByState(ctx context.Context, scanID domain.ID, state domain.JobState) ([]*domain.TestJob, error) {
	return r.listWhere(ctx, `scan_id=? AND state=?`, scanID, state)
}

func (r *jobRepo) Update(ctx context.Context, j *domain.TestJob) error {
	tgt, _ := jsonEncode(j.Target)
	res, err := r.db.ExecContext(ctx,
		`UPDATE jobs SET scan_id=?, type=?, state=?, priority=?, target=?, payload=?, attempts=?, max_attempts=?, lease_id=?, leased_until=?, last_error=?, available_at=?, updated_at=? WHERE id=?`,
		j.ScanID, j.Type, j.State, j.Priority, tgt, j.Payload, j.Attempts, j.MaxAttempts,
		j.LeaseID, tsPtr(j.LeasedUntil), j.LastError, ts(j.AvailableAt), ts(j.UpdatedAt), j.ID)
	return affected(res, err)
}

func (r *jobRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, id)
	return affected(res, err)
}

// --- TestCase ---

type testCaseRepo struct{ db *sql.DB }

const testCaseCols = `id, scan_id, job_id, injection_point_id, vuln_class, status, note, created_at, updated_at,
	attempt, outcome, method, url, http_status, duration_ms, error, evidence_ids, started_at, finished_at, detail`

func (r *testCaseRepo) Create(ctx context.Context, tc *domain.TestCase) error {
	ev, _ := jsonEncode(nonNilIDs(tc.EvidenceIDs))
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO test_cases (`+testCaseCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		tc.ID, tc.ScanID, tc.JobID, tc.InjectionPointID, tc.VulnClass, tc.Status, tc.Note, ts(tc.CreatedAt), ts(tc.UpdatedAt),
		tc.Attempt, tc.Outcome, tc.Method, tc.URL, tc.HTTPStatus, tc.DurationMS, tc.Error, ev, tsPtr(tc.StartedAt), tsPtr(tc.FinishedAt), string(tc.Detail))
	return err
}

func scanTestCase(sc scanner) (*domain.TestCase, error) {
	var tc domain.TestCase
	var created, updated, ev, detail string
	var started, finished sql.NullString
	if err := sc.Scan(&tc.ID, &tc.ScanID, &tc.JobID, &tc.InjectionPointID, &tc.VulnClass, &tc.Status, &tc.Note, &created, &updated,
		&tc.Attempt, &tc.Outcome, &tc.Method, &tc.URL, &tc.HTTPStatus, &tc.DurationMS, &tc.Error, &ev, &started, &finished, &detail); err != nil {
		return nil, err
	}
	_ = jsonDecode(ev, &tc.EvidenceIDs)
	if detail != "" {
		tc.Detail = []byte(detail)
	}
	tc.StartedAt, _ = parseTSPtr(started)
	tc.FinishedAt, _ = parseTSPtr(finished)
	tc.CreatedAt, _ = parseTS(created)
	tc.UpdatedAt, _ = parseTS(updated)
	return &tc, nil
}

func (r *testCaseRepo) Get(ctx context.Context, id domain.ID) (*domain.TestCase, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+testCaseCols+` FROM test_cases WHERE id=?`, id)
	tc, err := scanTestCase(row)
	return tc, mapGetErr(err)
}

func (r *testCaseRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.TestCase, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+testCaseCols+` FROM test_cases WHERE scan_id=? ORDER BY created_at`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.TestCase
	for rows.Next() {
		tc, err := scanTestCase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tc)
	}
	return out, rows.Err()
}

func (r *testCaseRepo) Update(ctx context.Context, tc *domain.TestCase) error {
	ev, _ := jsonEncode(nonNilIDs(tc.EvidenceIDs))
	res, err := r.db.ExecContext(ctx,
		`UPDATE test_cases SET status=?, note=?, updated_at=?, vuln_class=?, outcome=?, method=?, url=?, http_status=?, duration_ms=?, error=?, evidence_ids=?, started_at=?, finished_at=?, detail=? WHERE id=?`,
		tc.Status, tc.Note, ts(tc.UpdatedAt), tc.VulnClass, tc.Outcome, tc.Method, tc.URL, tc.HTTPStatus, tc.DurationMS, tc.Error, ev,
		tsPtr(tc.StartedAt), tsPtr(tc.FinishedAt), string(tc.Detail), tc.ID)
	return affected(res, err)
}

// nonNilIDs returns a non-nil slice so it encodes as [] rather than null.
func nonNilIDs(in []domain.ID) []domain.ID {
	if in == nil {
		return []domain.ID{}
	}
	return in
}

// --- Finding ---

type findingRepo struct{ db *sql.DB }

const findingCols = `id, scan_id, project_id, vuln_class, verdict, severity, confidence, title, summary, endpoint_id, injection_point_id, location, evidence_ids, provenance, created_at, updated_at`

func (r *findingRepo) Create(ctx context.Context, f *domain.Finding) error {
	evIDs, _ := jsonEncode(f.EvidenceIDs)
	prov, _ := jsonEncode(f.Provenance)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO findings (`+findingCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, f.ScanID, f.ProjectID, f.VulnClass, f.Verdict, f.Severity, f.Confidence, f.Title, f.Summary,
		f.EndpointID, f.InjectionPointID, f.Location, evIDs, prov, ts(f.CreatedAt), ts(f.UpdatedAt))
	return err
}

func scanFinding(sc scanner) (*domain.Finding, error) {
	var f domain.Finding
	var evIDs, prov, created, updated string
	if err := sc.Scan(&f.ID, &f.ScanID, &f.ProjectID, &f.VulnClass, &f.Verdict, &f.Severity, &f.Confidence,
		&f.Title, &f.Summary, &f.EndpointID, &f.InjectionPointID, &f.Location, &evIDs, &prov, &created, &updated); err != nil {
		return nil, err
	}
	_ = jsonDecode(evIDs, &f.EvidenceIDs)
	_ = jsonDecode(prov, &f.Provenance)
	f.CreatedAt, _ = parseTS(created)
	f.UpdatedAt, _ = parseTS(updated)
	return &f, nil
}

func (r *findingRepo) Get(ctx context.Context, id domain.ID) (*domain.Finding, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings WHERE id=?`, id)
	f, err := scanFinding(row)
	return f, mapGetErr(err)
}

func (r *findingRepo) listWhere(ctx context.Context, where string, arg domain.ID) ([]*domain.Finding, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+findingCols+` FROM findings WHERE `+where+` ORDER BY created_at`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *findingRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Finding, error) {
	return r.listWhere(ctx, `scan_id=?`, scanID)
}

func (r *findingRepo) ListByProject(ctx context.Context, projectID domain.ID) ([]*domain.Finding, error) {
	return r.listWhere(ctx, `project_id=?`, projectID)
}

func (r *findingRepo) Update(ctx context.Context, f *domain.Finding) error {
	evIDs, _ := jsonEncode(f.EvidenceIDs)
	prov, _ := jsonEncode(f.Provenance)
	res, err := r.db.ExecContext(ctx,
		`UPDATE findings SET vuln_class=?, verdict=?, severity=?, confidence=?, title=?, summary=?, endpoint_id=?, injection_point_id=?, location=?, evidence_ids=?, provenance=?, updated_at=? WHERE id=?`,
		f.VulnClass, f.Verdict, f.Severity, f.Confidence, f.Title, f.Summary, f.EndpointID, f.InjectionPointID, f.Location, evIDs, prov, ts(f.UpdatedAt), f.ID)
	return affected(res, err)
}

func (r *findingRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM findings WHERE id=?`, id)
	return affected(res, err)
}

// --- Evidence ---

type evidenceRepo struct{ db *sql.DB }

const evidenceCols = `id, scan_id, finding_id, kind, media_type, blob_path, size, sha256, note, created_at`

func (r *evidenceRepo) Create(ctx context.Context, e *domain.Evidence) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO evidence (`+evidenceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.ScanID, e.FindingID, e.Kind, e.MediaType, e.BlobPath, e.Size, e.SHA256, e.Note, ts(e.CreatedAt))
	return err
}

func scanEvidence(sc scanner) (*domain.Evidence, error) {
	var e domain.Evidence
	var created string
	if err := sc.Scan(&e.ID, &e.ScanID, &e.FindingID, &e.Kind, &e.MediaType, &e.BlobPath, &e.Size, &e.SHA256, &e.Note, &created); err != nil {
		return nil, err
	}
	e.CreatedAt, _ = parseTS(created)
	return &e, nil
}

func (r *evidenceRepo) Get(ctx context.Context, id domain.ID) (*domain.Evidence, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+evidenceCols+` FROM evidence WHERE id=?`, id)
	e, err := scanEvidence(row)
	return e, mapGetErr(err)
}

func (r *evidenceRepo) queryList(ctx context.Context, where string, arg domain.ID) ([]*domain.Evidence, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+evidenceCols+` FROM evidence WHERE `+where+` ORDER BY created_at`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Evidence
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *evidenceRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Evidence, error) {
	return r.queryList(ctx, `scan_id=?`, scanID)
}

func (r *evidenceRepo) ListByFinding(ctx context.Context, findingID domain.ID) ([]*domain.Evidence, error) {
	return r.queryList(ctx, `finding_id=?`, findingID)
}

func (r *evidenceRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM evidence WHERE id=?`, id)
	return affected(res, err)
}

// --- Session ---

type sessionRepo struct{ db *sql.DB }

const sessionCols = `id, scan_id, mode, state, state_path, expires_at, last_error, created_at, updated_at`

func (r *sessionRepo) Create(ctx context.Context, s *domain.Session) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (`+sessionCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
		s.ID, s.ScanID, s.Mode, s.State, s.StatePath, tsPtr(s.ExpiresAt), s.LastError, ts(s.CreatedAt), ts(s.UpdatedAt))
	return err
}

func scanSession(sc scanner) (*domain.Session, error) {
	var s domain.Session
	var created, updated string
	var expires sql.NullString
	if err := sc.Scan(&s.ID, &s.ScanID, &s.Mode, &s.State, &s.StatePath, &expires, &s.LastError, &created, &updated); err != nil {
		return nil, err
	}
	s.ExpiresAt, _ = parseTSPtr(expires)
	s.CreatedAt, _ = parseTS(created)
	s.UpdatedAt, _ = parseTS(updated)
	return &s, nil
}

func (r *sessionRepo) Get(ctx context.Context, id domain.ID) (*domain.Session, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id=?`, id)
	s, err := scanSession(row)
	return s, mapGetErr(err)
}

func (r *sessionRepo) GetByScan(ctx context.Context, scanID domain.ID) (*domain.Session, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE scan_id=? ORDER BY created_at DESC LIMIT 1`, scanID)
	s, err := scanSession(row)
	return s, mapGetErr(err)
}

func (r *sessionRepo) Update(ctx context.Context, s *domain.Session) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET mode=?, state=?, state_path=?, expires_at=?, last_error=?, updated_at=? WHERE id=?`,
		s.Mode, s.State, s.StatePath, tsPtr(s.ExpiresAt), s.LastError, ts(s.UpdatedAt), s.ID)
	return affected(res, err)
}

func (r *sessionRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, id)
	return affected(res, err)
}

// --- Report ---

type reportRepo struct{ db *sql.DB }

const reportCols = `id, scan_id, project_id, format, path, summary, created_at`

func (r *reportRepo) Create(ctx context.Context, rep *domain.Report) error {
	sum, _ := jsonEncode(rep.Summary)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO reports (`+reportCols+`) VALUES (?,?,?,?,?,?,?)`,
		rep.ID, rep.ScanID, rep.ProjectID, rep.Format, rep.Path, sum, ts(rep.CreatedAt))
	return err
}

func scanReport(sc scanner) (*domain.Report, error) {
	var rep domain.Report
	var sum, created string
	if err := sc.Scan(&rep.ID, &rep.ScanID, &rep.ProjectID, &rep.Format, &rep.Path, &sum, &created); err != nil {
		return nil, err
	}
	_ = jsonDecode(sum, &rep.Summary)
	rep.CreatedAt, _ = parseTS(created)
	return &rep, nil
}

func (r *reportRepo) Get(ctx context.Context, id domain.ID) (*domain.Report, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+reportCols+` FROM reports WHERE id=?`, id)
	rep, err := scanReport(row)
	return rep, mapGetErr(err)
}

func (r *reportRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Report, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+reportCols+` FROM reports WHERE scan_id=? ORDER BY created_at`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Report
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, rows.Err()
}

func (r *reportRepo) Delete(ctx context.Context, id domain.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM reports WHERE id=?`, id)
	return affected(res, err)
}

// --- AITask ---

type aiTaskRepo struct{ db *sql.DB }

const aiTaskCols = `id, scan_id, kind, state, provider, model, advisory, request, response, error, created_at, updated_at`

func (r *aiTaskRepo) Create(ctx context.Context, t *domain.AITask) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO ai_tasks (`+aiTaskCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.ScanID, t.Kind, t.State, t.Provider, t.Model, boolToInt(t.Advisory), t.Request, t.Response, t.Error, ts(t.CreatedAt), ts(t.UpdatedAt))
	return err
}

func scanAITask(sc scanner) (*domain.AITask, error) {
	var t domain.AITask
	var advisory int
	var created, updated string
	if err := sc.Scan(&t.ID, &t.ScanID, &t.Kind, &t.State, &t.Provider, &t.Model, &advisory, &t.Request, &t.Response, &t.Error, &created, &updated); err != nil {
		return nil, err
	}
	t.Advisory = advisory != 0
	t.CreatedAt, _ = parseTS(created)
	t.UpdatedAt, _ = parseTS(updated)
	return &t, nil
}

func (r *aiTaskRepo) Get(ctx context.Context, id domain.ID) (*domain.AITask, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+aiTaskCols+` FROM ai_tasks WHERE id=?`, id)
	t, err := scanAITask(row)
	return t, mapGetErr(err)
}

func (r *aiTaskRepo) ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.AITask, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+aiTaskCols+` FROM ai_tasks WHERE scan_id=? ORDER BY created_at`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.AITask
	for rows.Next() {
		t, err := scanAITask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *aiTaskRepo) Update(ctx context.Context, t *domain.AITask) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE ai_tasks SET kind=?, state=?, provider=?, model=?, advisory=?, request=?, response=?, error=?, updated_at=? WHERE id=?`,
		t.Kind, t.State, t.Provider, t.Model, boolToInt(t.Advisory), t.Request, t.Response, t.Error, ts(t.UpdatedAt), t.ID)
	return affected(res, err)
}

// affected maps an Exec result to ErrNotFound when no rows changed.
func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
