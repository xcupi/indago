// Package memory provides an in-memory implementation of store.Store. It is
// used by tests and for fast local development. All data is lost on exit.
//
// Entities are deep-copied on the way in and out so callers cannot mutate
// stored state by holding a returned pointer.
package memory

import (
	"context"
	"sync"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

// table is a generic, concurrency-safe map keyed by domain.ID.
type table[T any] struct {
	mu    sync.RWMutex
	items map[domain.ID]*T
	idOf  func(*T) domain.ID
	cp    func(*T) *T
}

func newTable[T any](idOf func(*T) domain.ID, cp func(*T) *T) *table[T] {
	return &table[T]{items: make(map[domain.ID]*T), idOf: idOf, cp: cp}
}

func (t *table[T]) create(v *T) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	id := t.idOf(v)
	if id.Empty() {
		return store.ErrConflict
	}
	if _, ok := t.items[id]; ok {
		return store.ErrConflict
	}
	t.items[id] = t.cp(v)
	return nil
}

func (t *table[T]) get(id domain.ID) (*T, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v, ok := t.items[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return t.cp(v), nil
}

func (t *table[T]) update(v *T) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	id := t.idOf(v)
	if _, ok := t.items[id]; !ok {
		return store.ErrNotFound
	}
	t.items[id] = t.cp(v)
	return nil
}

func (t *table[T]) remove(id domain.ID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.items[id]; !ok {
		return store.ErrNotFound
	}
	delete(t.items, id)
	return nil
}

// list returns deep copies of all items matching filter (nil filter = all).
func (t *table[T]) list(filter func(*T) bool) []*T {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*T, 0, len(t.items))
	for _, v := range t.items {
		if filter == nil || filter(v) {
			out = append(out, t.cp(v))
		}
	}
	return out
}

// first returns the first item matching filter, or ErrNotFound.
func (t *table[T]) first(filter func(*T) bool) (*T, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, v := range t.items {
		if filter(v) {
			return t.cp(v), nil
		}
	}
	return nil, store.ErrNotFound
}

// Store is the in-memory store.Store implementation.
type Store struct {
	projects   *table[domain.Project]
	targets    *table[domain.Target]
	scopes     *table[domain.Scope]
	scans      *table[domain.Scan]
	endpoints  *table[domain.Endpoint]
	parameters *table[domain.Parameter]
	injpoints  *table[domain.InjectionPoint]
	jobs       *table[domain.TestJob]
	testcases  *table[domain.TestCase]
	findings   *table[domain.Finding]
	evidence   *table[domain.Evidence]
	sessions   *table[domain.Session]
	reports    *table[domain.Report]
	aitasks    *table[domain.AITask]
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		projects:   newTable(func(p *domain.Project) domain.ID { return p.ID }, cloneProject),
		targets:    newTable(func(t *domain.Target) domain.ID { return t.ID }, cloneTarget),
		scopes:     newTable(func(s *domain.Scope) domain.ID { return s.ID }, cloneScope),
		scans:      newTable(func(s *domain.Scan) domain.ID { return s.ID }, cloneScan),
		endpoints:  newTable(func(e *domain.Endpoint) domain.ID { return e.ID }, cloneEndpoint),
		parameters: newTable(func(p *domain.Parameter) domain.ID { return p.ID }, cloneParameter),
		injpoints:  newTable(func(i *domain.InjectionPoint) domain.ID { return i.ID }, cloneInjectionPoint),
		jobs:       newTable(func(j *domain.TestJob) domain.ID { return j.ID }, cloneJob),
		testcases:  newTable(func(t *domain.TestCase) domain.ID { return t.ID }, cloneTestCase),
		findings:   newTable(func(f *domain.Finding) domain.ID { return f.ID }, cloneFinding),
		evidence:   newTable(func(e *domain.Evidence) domain.ID { return e.ID }, cloneEvidence),
		sessions:   newTable(func(s *domain.Session) domain.ID { return s.ID }, cloneSession),
		reports:    newTable(func(r *domain.Report) domain.ID { return r.ID }, cloneReport),
		aitasks:    newTable(func(t *domain.AITask) domain.ID { return t.ID }, cloneAITask),
	}
}

// Ensure Store satisfies the interface.
var _ store.Store = (*Store)(nil)

func (s *Store) Migrate(context.Context) error { return nil }
func (s *Store) Ping(context.Context) error    { return nil }
func (s *Store) Close() error                  { return nil }
