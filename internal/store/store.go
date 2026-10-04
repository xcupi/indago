// Package store defines Indago's persistence boundary: a set of repository
// interfaces over the domain model plus a Store aggregate that groups them.
//
// Two implementations satisfy these interfaces:
//
//   - store/memory — an in-memory store for tests and fast local development.
//   - store/sqlite — the durable, local-first SQLite store (pure-Go driver).
//
// Keeping persistence behind interfaces lets the rest of the system depend on
// behavior, not on SQLite, and makes the data layer independently testable.
package store

import (
	"context"
	"errors"

	"github.com/indago/indago/internal/domain"
)

// ErrNotFound is returned when a requested entity does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned on a unique-constraint or optimistic-concurrency
// violation.
var ErrConflict = errors.New("store: conflict")

// Store is the aggregate persistence interface. It exposes one repository per
// domain aggregate plus lifecycle methods.
type Store interface {
	Projects() ProjectRepo
	Targets() TargetRepo
	Scopes() ScopeRepo
	Scans() ScanRepo
	Endpoints() EndpointRepo
	Parameters() ParameterRepo
	InjectionPoints() InjectionPointRepo
	Jobs() JobRepo
	TestCases() TestCaseRepo
	Findings() FindingRepo
	Evidence() EvidenceRepo
	Sessions() SessionRepo
	Reports() ReportRepo
	AITasks() AITaskRepo

	// Migrate applies any pending schema migrations (no-op once current).
	Migrate(ctx context.Context) error
	// Ping verifies the backing store is reachable.
	Ping(ctx context.Context) error
	// Close releases resources held by the store.
	Close() error
}

// ProjectRepo persists projects.
type ProjectRepo interface {
	Create(ctx context.Context, p *domain.Project) error
	Get(ctx context.Context, id domain.ID) (*domain.Project, error)
	List(ctx context.Context) ([]*domain.Project, error)
	Update(ctx context.Context, p *domain.Project) error
	Delete(ctx context.Context, id domain.ID) error
}

// TargetRepo persists targets.
type TargetRepo interface {
	Create(ctx context.Context, t *domain.Target) error
	Get(ctx context.Context, id domain.ID) (*domain.Target, error)
	ListByProject(ctx context.Context, projectID domain.ID) ([]*domain.Target, error)
	Update(ctx context.Context, t *domain.Target) error
	Delete(ctx context.Context, id domain.ID) error
}

// ScopeRepo persists scope definitions.
type ScopeRepo interface {
	Create(ctx context.Context, s *domain.Scope) error
	Get(ctx context.Context, id domain.ID) (*domain.Scope, error)
	GetByProject(ctx context.Context, projectID domain.ID) (*domain.Scope, error)
	Update(ctx context.Context, s *domain.Scope) error
	Delete(ctx context.Context, id domain.ID) error
}

// ScanRepo persists scans.
type ScanRepo interface {
	Create(ctx context.Context, s *domain.Scan) error
	Get(ctx context.Context, id domain.ID) (*domain.Scan, error)
	ListByProject(ctx context.Context, projectID domain.ID) ([]*domain.Scan, error)
	List(ctx context.Context) ([]*domain.Scan, error)
	Update(ctx context.Context, s *domain.Scan) error
	Delete(ctx context.Context, id domain.ID) error
}

// EndpointRepo persists discovered endpoints.
type EndpointRepo interface {
	Create(ctx context.Context, e *domain.Endpoint) error
	Get(ctx context.Context, id domain.ID) (*domain.Endpoint, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Endpoint, error)
	Delete(ctx context.Context, id domain.ID) error
}

// ParameterRepo persists discovered parameters.
type ParameterRepo interface {
	Create(ctx context.Context, p *domain.Parameter) error
	Get(ctx context.Context, id domain.ID) (*domain.Parameter, error)
	ListByEndpoint(ctx context.Context, endpointID domain.ID) ([]*domain.Parameter, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Parameter, error)
	Delete(ctx context.Context, id domain.ID) error
}

// InjectionPointRepo persists injection points.
type InjectionPointRepo interface {
	Create(ctx context.Context, ip *domain.InjectionPoint) error
	Get(ctx context.Context, id domain.ID) (*domain.InjectionPoint, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.InjectionPoint, error)
	Delete(ctx context.Context, id domain.ID) error
}

// JobRepo persists test jobs. Queue leasing semantics live in package queue;
// this repo is plain persistence plus a few list filters.
type JobRepo interface {
	Create(ctx context.Context, j *domain.TestJob) error
	Get(ctx context.Context, id domain.ID) (*domain.TestJob, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.TestJob, error)
	ListByState(ctx context.Context, scanID domain.ID, state domain.JobState) ([]*domain.TestJob, error)
	Update(ctx context.Context, j *domain.TestJob) error
	Delete(ctx context.Context, id domain.ID) error
}

// TestCaseRepo persists test cases.
type TestCaseRepo interface {
	Create(ctx context.Context, tc *domain.TestCase) error
	Get(ctx context.Context, id domain.ID) (*domain.TestCase, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.TestCase, error)
	Update(ctx context.Context, tc *domain.TestCase) error
}

// FindingRepo persists findings.
type FindingRepo interface {
	Create(ctx context.Context, f *domain.Finding) error
	Get(ctx context.Context, id domain.ID) (*domain.Finding, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Finding, error)
	ListByProject(ctx context.Context, projectID domain.ID) ([]*domain.Finding, error)
	Update(ctx context.Context, f *domain.Finding) error
	Delete(ctx context.Context, id domain.ID) error
}

// EvidenceRepo persists evidence metadata (blobs live on the filesystem).
type EvidenceRepo interface {
	Create(ctx context.Context, e *domain.Evidence) error
	Get(ctx context.Context, id domain.ID) (*domain.Evidence, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Evidence, error)
	ListByFinding(ctx context.Context, findingID domain.ID) ([]*domain.Evidence, error)
	Delete(ctx context.Context, id domain.ID) error
}

// SessionRepo persists auth sessions.
type SessionRepo interface {
	Create(ctx context.Context, s *domain.Session) error
	Get(ctx context.Context, id domain.ID) (*domain.Session, error)
	GetByScan(ctx context.Context, scanID domain.ID) (*domain.Session, error)
	Update(ctx context.Context, s *domain.Session) error
	Delete(ctx context.Context, id domain.ID) error
}

// ReportRepo persists report index entries.
type ReportRepo interface {
	Create(ctx context.Context, r *domain.Report) error
	Get(ctx context.Context, id domain.ID) (*domain.Report, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.Report, error)
	Delete(ctx context.Context, id domain.ID) error
}

// AITaskRepo persists AI tasks (advisory records).
type AITaskRepo interface {
	Create(ctx context.Context, t *domain.AITask) error
	Get(ctx context.Context, id domain.ID) (*domain.AITask, error)
	ListByScan(ctx context.Context, scanID domain.ID) ([]*domain.AITask, error)
	Update(ctx context.Context, t *domain.AITask) error
}
