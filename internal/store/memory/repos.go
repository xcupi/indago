package memory

import (
	"context"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

// Accessors wiring each repo to its table.

func (s *Store) Projects() store.ProjectRepo               { return projectRepo{s.projects} }
func (s *Store) Targets() store.TargetRepo                 { return targetRepo{s.targets} }
func (s *Store) Scopes() store.ScopeRepo                   { return scopeRepo{s.scopes} }
func (s *Store) Scans() store.ScanRepo                     { return scanRepo{s.scans} }
func (s *Store) Endpoints() store.EndpointRepo             { return endpointRepo{s.endpoints} }
func (s *Store) Parameters() store.ParameterRepo           { return parameterRepo{s.parameters} }
func (s *Store) InjectionPoints() store.InjectionPointRepo { return injectionPointRepo{s.injpoints} }
func (s *Store) Jobs() store.JobRepo                       { return jobRepo{s.jobs} }
func (s *Store) TestCases() store.TestCaseRepo             { return testCaseRepo{s.testcases} }
func (s *Store) Findings() store.FindingRepo               { return findingRepo{s.findings} }
func (s *Store) Evidence() store.EvidenceRepo              { return evidenceRepo{s.evidence} }
func (s *Store) Sessions() store.SessionRepo               { return sessionRepo{s.sessions} }
func (s *Store) Reports() store.ReportRepo                 { return reportRepo{s.reports} }
func (s *Store) AITasks() store.AITaskRepo                 { return aiTaskRepo{s.aitasks} }

// --- Project ---

type projectRepo struct{ t *table[domain.Project] }

func (r projectRepo) Create(_ context.Context, p *domain.Project) error { return r.t.create(p) }
func (r projectRepo) Get(_ context.Context, id domain.ID) (*domain.Project, error) {
	return r.t.get(id)
}
func (r projectRepo) List(_ context.Context) ([]*domain.Project, error) { return r.t.list(nil), nil }
func (r projectRepo) Update(_ context.Context, p *domain.Project) error { return r.t.update(p) }
func (r projectRepo) Delete(_ context.Context, id domain.ID) error      { return r.t.remove(id) }

// --- Target ---

type targetRepo struct{ t *table[domain.Target] }

func (r targetRepo) Create(_ context.Context, t *domain.Target) error { return r.t.create(t) }
func (r targetRepo) Get(_ context.Context, id domain.ID) (*domain.Target, error) {
	return r.t.get(id)
}
func (r targetRepo) ListByProject(_ context.Context, pid domain.ID) ([]*domain.Target, error) {
	return r.t.list(func(t *domain.Target) bool { return t.ProjectID == pid }), nil
}
func (r targetRepo) Update(_ context.Context, t *domain.Target) error { return r.t.update(t) }
func (r targetRepo) Delete(_ context.Context, id domain.ID) error     { return r.t.remove(id) }

// --- Scope ---

type scopeRepo struct{ t *table[domain.Scope] }

func (r scopeRepo) Create(_ context.Context, s *domain.Scope) error { return r.t.create(s) }
func (r scopeRepo) Get(_ context.Context, id domain.ID) (*domain.Scope, error) {
	return r.t.get(id)
}
func (r scopeRepo) GetByProject(_ context.Context, pid domain.ID) (*domain.Scope, error) {
	return r.t.first(func(s *domain.Scope) bool { return s.ProjectID == pid })
}
func (r scopeRepo) Update(_ context.Context, s *domain.Scope) error { return r.t.update(s) }
func (r scopeRepo) Delete(_ context.Context, id domain.ID) error    { return r.t.remove(id) }

// --- Scan ---

type scanRepo struct{ t *table[domain.Scan] }

func (r scanRepo) Create(_ context.Context, s *domain.Scan) error { return r.t.create(s) }
func (r scanRepo) Get(_ context.Context, id domain.ID) (*domain.Scan, error) {
	return r.t.get(id)
}
func (r scanRepo) ListByProject(_ context.Context, pid domain.ID) ([]*domain.Scan, error) {
	return r.t.list(func(s *domain.Scan) bool { return s.ProjectID == pid }), nil
}
func (r scanRepo) List(_ context.Context) ([]*domain.Scan, error) { return r.t.list(nil), nil }
func (r scanRepo) Update(_ context.Context, s *domain.Scan) error { return r.t.update(s) }
func (r scanRepo) Delete(_ context.Context, id domain.ID) error   { return r.t.remove(id) }

// --- Endpoint ---

type endpointRepo struct{ t *table[domain.Endpoint] }

func (r endpointRepo) Create(_ context.Context, e *domain.Endpoint) error { return r.t.create(e) }
func (r endpointRepo) Get(_ context.Context, id domain.ID) (*domain.Endpoint, error) {
	return r.t.get(id)
}
func (r endpointRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.Endpoint, error) {
	return r.t.list(func(e *domain.Endpoint) bool { return e.ScanID == sid }), nil
}
func (r endpointRepo) Delete(_ context.Context, id domain.ID) error { return r.t.remove(id) }

// --- Parameter ---

type parameterRepo struct{ t *table[domain.Parameter] }

func (r parameterRepo) Create(_ context.Context, p *domain.Parameter) error { return r.t.create(p) }
func (r parameterRepo) Get(_ context.Context, id domain.ID) (*domain.Parameter, error) {
	return r.t.get(id)
}
func (r parameterRepo) ListByEndpoint(_ context.Context, eid domain.ID) ([]*domain.Parameter, error) {
	return r.t.list(func(p *domain.Parameter) bool { return p.EndpointID == eid }), nil
}
func (r parameterRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.Parameter, error) {
	return r.t.list(func(p *domain.Parameter) bool { return p.ScanID == sid }), nil
}
func (r parameterRepo) Delete(_ context.Context, id domain.ID) error { return r.t.remove(id) }

// --- InjectionPoint ---

type injectionPointRepo struct{ t *table[domain.InjectionPoint] }

func (r injectionPointRepo) Create(_ context.Context, ip *domain.InjectionPoint) error {
	return r.t.create(ip)
}
func (r injectionPointRepo) Get(_ context.Context, id domain.ID) (*domain.InjectionPoint, error) {
	return r.t.get(id)
}
func (r injectionPointRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.InjectionPoint, error) {
	return r.t.list(func(ip *domain.InjectionPoint) bool { return ip.ScanID == sid }), nil
}
func (r injectionPointRepo) Delete(_ context.Context, id domain.ID) error { return r.t.remove(id) }

// --- Job ---

type jobRepo struct{ t *table[domain.TestJob] }

func (r jobRepo) Create(_ context.Context, j *domain.TestJob) error { return r.t.create(j) }
func (r jobRepo) Get(_ context.Context, id domain.ID) (*domain.TestJob, error) {
	return r.t.get(id)
}
func (r jobRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.TestJob, error) {
	return r.t.list(func(j *domain.TestJob) bool { return j.ScanID == sid }), nil
}
func (r jobRepo) ListByState(_ context.Context, sid domain.ID, st domain.JobState) ([]*domain.TestJob, error) {
	return r.t.list(func(j *domain.TestJob) bool { return j.ScanID == sid && j.State == st }), nil
}
func (r jobRepo) Update(_ context.Context, j *domain.TestJob) error { return r.t.update(j) }
func (r jobRepo) Delete(_ context.Context, id domain.ID) error      { return r.t.remove(id) }

// --- TestCase ---

type testCaseRepo struct{ t *table[domain.TestCase] }

func (r testCaseRepo) Create(_ context.Context, tc *domain.TestCase) error { return r.t.create(tc) }
func (r testCaseRepo) Get(_ context.Context, id domain.ID) (*domain.TestCase, error) {
	return r.t.get(id)
}
func (r testCaseRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.TestCase, error) {
	return r.t.list(func(tc *domain.TestCase) bool { return tc.ScanID == sid }), nil
}
func (r testCaseRepo) Update(_ context.Context, tc *domain.TestCase) error { return r.t.update(tc) }

// --- Finding ---

type findingRepo struct{ t *table[domain.Finding] }

func (r findingRepo) Create(_ context.Context, f *domain.Finding) error { return r.t.create(f) }
func (r findingRepo) Get(_ context.Context, id domain.ID) (*domain.Finding, error) {
	return r.t.get(id)
}
func (r findingRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.Finding, error) {
	return r.t.list(func(f *domain.Finding) bool { return f.ScanID == sid }), nil
}
func (r findingRepo) ListByProject(_ context.Context, pid domain.ID) ([]*domain.Finding, error) {
	return r.t.list(func(f *domain.Finding) bool { return f.ProjectID == pid }), nil
}
func (r findingRepo) Update(_ context.Context, f *domain.Finding) error { return r.t.update(f) }
func (r findingRepo) Delete(_ context.Context, id domain.ID) error      { return r.t.remove(id) }

// --- Evidence ---

type evidenceRepo struct{ t *table[domain.Evidence] }

func (r evidenceRepo) Create(_ context.Context, e *domain.Evidence) error { return r.t.create(e) }
func (r evidenceRepo) Get(_ context.Context, id domain.ID) (*domain.Evidence, error) {
	return r.t.get(id)
}
func (r evidenceRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.Evidence, error) {
	return r.t.list(func(e *domain.Evidence) bool { return e.ScanID == sid }), nil
}
func (r evidenceRepo) ListByFinding(_ context.Context, fid domain.ID) ([]*domain.Evidence, error) {
	return r.t.list(func(e *domain.Evidence) bool { return e.FindingID == fid }), nil
}
func (r evidenceRepo) Delete(_ context.Context, id domain.ID) error { return r.t.remove(id) }

// --- Session ---

type sessionRepo struct{ t *table[domain.Session] }

func (r sessionRepo) Create(_ context.Context, s *domain.Session) error { return r.t.create(s) }
func (r sessionRepo) Get(_ context.Context, id domain.ID) (*domain.Session, error) {
	return r.t.get(id)
}
func (r sessionRepo) GetByScan(_ context.Context, sid domain.ID) (*domain.Session, error) {
	return r.t.first(func(s *domain.Session) bool { return s.ScanID == sid })
}
func (r sessionRepo) Update(_ context.Context, s *domain.Session) error { return r.t.update(s) }
func (r sessionRepo) Delete(_ context.Context, id domain.ID) error      { return r.t.remove(id) }

// --- Report ---

type reportRepo struct{ t *table[domain.Report] }

func (r reportRepo) Create(_ context.Context, rep *domain.Report) error { return r.t.create(rep) }
func (r reportRepo) Get(_ context.Context, id domain.ID) (*domain.Report, error) {
	return r.t.get(id)
}
func (r reportRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.Report, error) {
	return r.t.list(func(rep *domain.Report) bool { return rep.ScanID == sid }), nil
}
func (r reportRepo) Delete(_ context.Context, id domain.ID) error { return r.t.remove(id) }

// --- AITask ---

type aiTaskRepo struct{ t *table[domain.AITask] }

func (r aiTaskRepo) Create(_ context.Context, t *domain.AITask) error { return r.t.create(t) }
func (r aiTaskRepo) Get(_ context.Context, id domain.ID) (*domain.AITask, error) {
	return r.t.get(id)
}
func (r aiTaskRepo) ListByScan(_ context.Context, sid domain.ID) ([]*domain.AITask, error) {
	return r.t.list(func(t *domain.AITask) bool { return t.ScanID == sid }), nil
}
func (r aiTaskRepo) Update(_ context.Context, t *domain.AITask) error { return r.t.update(t) }
