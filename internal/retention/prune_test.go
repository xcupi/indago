package retention_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/retention"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
)

const (
	oldAge    = 1000 * time.Hour // well past the cutoff
	cutoffAge = 720 * time.Hour
)

var ctx = context.Background()

// fx is a disposable data layout: base/data/{evidence,sessions,reports}. base
// itself is outside every root, so canary files placed there prove that
// nothing outside a root was touched.
type fx struct {
	t        *testing.T
	st       store.Store
	ev       *evidence.FSStore
	base     string
	sessions string
	reports  string
	now      time.Time
	project  domain.ID
}

func newFx(t *testing.T) *fx {
	t.Helper()
	base := t.TempDir()
	data := filepath.Join(base, "data")
	ev, err := evidence.NewFS(filepath.Join(data, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{
		t: t, st: memory.New(), ev: ev, base: base,
		sessions: filepath.Join(data, "sessions"),
		reports:  filepath.Join(data, "reports"),
		now:      time.Now().UTC(),
		project:  domain.NewID(),
	}
	for _, d := range []string{f.sessions, f.reports} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// scan creates a scan in state whose timestamps are age old. Terminal scans
// get an EndedAt; both UpdatedAt and EndedAt sit at now-age.
func (f *fx) scan(state domain.ScanState, age time.Duration) *domain.Scan {
	f.t.Helper()
	ts := f.now.Add(-age)
	sc := &domain.Scan{
		ID: domain.NewID(), ProjectID: f.project, State: state,
		CreatedAt: ts, UpdatedAt: ts,
	}
	if state.IsTerminal() {
		e := ts
		sc.EndedAt = &e
	}
	f.create(sc)
	return sc
}

func (f *fx) create(sc *domain.Scan) {
	f.t.Helper()
	if err := f.st.Scans().Create(ctx, sc); err != nil {
		f.t.Fatal(err)
	}
}

// blob writes a real blob for sc and records its evidence row. findingID, if
// non-empty, is set on the row (the evidence->finding link).
func (f *fx) blob(sc *domain.Scan, body string, findingID domain.ID) *domain.Evidence {
	f.t.Helper()
	ref, err := f.ev.Put(sc.ID, domain.EvidenceResponse, ".html", []byte(body))
	if err != nil {
		f.t.Fatal(err)
	}
	e := &domain.Evidence{
		ID: domain.NewID(), ScanID: sc.ID, FindingID: findingID,
		Kind: domain.EvidenceResponse, BlobPath: ref.BlobPath,
		Size: ref.Size, SHA256: ref.SHA256, CreatedAt: f.now,
	}
	if err := f.st.Evidence().Create(ctx, e); err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f *fx) blobAbs(e *domain.Evidence) string { return f.ev.AbsPath(e.BlobPath) }

func (f *fx) rowExists(id domain.ID) bool {
	f.t.Helper()
	_, err := f.st.Evidence().Get(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		f.t.Fatal(err)
	}
	return err == nil
}

func (f *fx) prune(opt retention.Options) (*retention.Summary, error) {
	f.t.Helper()
	opt.Store = f.st
	opt.Evidence = f.ev
	opt.SessionsDir = f.sessions
	opt.ReportsDir = f.reports
	if opt.Cutoff.IsZero() {
		opt.Cutoff = f.now.Add(-cutoffAge)
	}
	return retention.Prune(ctx, opt)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func mustPrune(t *testing.T, f *fx, opt retention.Options) *retention.Summary {
	t.Helper()
	sum, err := f.prune(opt)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	return sum
}

// (a) dry run deletes nothing.
func TestPruneDryRunDeletesNothing(t *testing.T) {
	f := newFx(t)
	sc := f.scan(domain.ScanCompleted, oldAge)
	e := f.blob(sc, "<html>dry</html>", "")

	sum := mustPrune(t, f, retention.Options{Apply: false})

	if !exists(f.blobAbs(e)) {
		t.Fatal("dry run removed the blob file")
	}
	if !f.rowExists(e.ID) {
		t.Fatal("dry run removed the evidence row")
	}
	if got := sum.Count(retention.StatusWouldRemove); got != 1 {
		t.Fatalf("dry run would-remove count = %d, want 1", got)
	}
	if got := sum.Count(retention.StatusRemoved); got != 0 {
		t.Fatalf("dry run reports %d removed", got)
	}
}

// (b) apply removes blob and row for an old terminal scan.
func TestPruneApplyRemovesBlobAndRowOfOldTerminalScan(t *testing.T) {
	f := newFx(t)
	sc := f.scan(domain.ScanCompleted, oldAge)
	e := f.blob(sc, "<html>apply</html>", "")

	sum := mustPrune(t, f, retention.Options{Apply: true})

	if exists(f.blobAbs(e)) {
		t.Fatal("apply left the blob file in place")
	}
	if f.rowExists(e.ID) {
		t.Fatal("apply left the evidence row in place")
	}
	if got := sum.Count(retention.StatusRemoved); got != 1 {
		t.Fatalf("removed count = %d, want 1", got)
	}
	if sum.Failures != 0 {
		t.Fatalf("failures = %d, want 0", sum.Failures)
	}
}

// (c) evidence of non-terminal scans is untouched, however old.
func TestPruneNeverTouchesNonTerminalScans(t *testing.T) {
	f := newFx(t)
	states := []domain.ScanState{
		domain.ScanCreated, domain.ScanRunning, domain.ScanPaused,
		domain.ScanAwaitingAuth, domain.ScanCanceling,
	}
	type kept struct {
		e  *domain.Evidence
		sc *domain.Scan
	}
	var keep []kept
	for _, st := range states {
		sc := f.scan(st, oldAge)
		keep = append(keep, kept{f.blob(sc, "<html>"+string(st)+"</html>", ""), sc})
	}

	sum := mustPrune(t, f, retention.Options{Apply: true})

	for _, k := range keep {
		if !exists(f.blobAbs(k.e)) || !f.rowExists(k.e.ID) {
			t.Fatalf("evidence of %s scan was touched", k.sc.State)
		}
	}
	if sum.KeptActive != len(states) {
		t.Fatalf("KeptActive = %d, want %d", sum.KeptActive, len(states))
	}
	if got := sum.Count(retention.StatusRemoved); got != 0 {
		t.Fatalf("removed %d items of non-terminal scans", got)
	}
}

// (d) a terminal scan with no usable timestamp is skipped and reported.
func TestPruneSkipsScanWithoutUsableTimestamp(t *testing.T) {
	f := newFx(t)
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: f.project, State: domain.ScanCompleted}
	f.create(sc) // zero UpdatedAt, nil EndedAt
	e := f.blob(sc, "<html>no ts</html>", "")

	sum := mustPrune(t, f, retention.Options{Apply: true})

	if !exists(f.blobAbs(e)) || !f.rowExists(e.ID) {
		t.Fatal("scan without a usable timestamp was pruned")
	}
	if len(sum.SkippedNoTimestamp) != 1 || sum.SkippedNoTimestamp[0] != sc.ID {
		t.Fatalf("SkippedNoTimestamp = %v, want [%s]", sum.SkippedNoTimestamp, sc.ID)
	}
}

// A terminal scan newer than the cutoff is kept.
func TestPruneKeepsRecentTerminalScan(t *testing.T) {
	f := newFx(t)
	sc := f.scan(domain.ScanCompleted, time.Hour)
	e := f.blob(sc, "<html>recent</html>", "")

	sum := mustPrune(t, f, retention.Options{Apply: true})

	if !exists(f.blobAbs(e)) || !f.rowExists(e.ID) {
		t.Fatal("recent terminal scan was pruned")
	}
	if sum.KeptRecent != 1 {
		t.Fatalf("KeptRecent = %d, want 1", sum.KeptRecent)
	}
}

// (e) a blob already missing: the row is removed and counted as already gone.
func TestPruneMissingBlobCountsAsAlreadyGone(t *testing.T) {
	f := newFx(t)
	sc := f.scan(domain.ScanCompleted, oldAge)
	e := f.blob(sc, "<html>missing</html>", "")
	if err := os.Remove(f.blobAbs(e)); err != nil {
		t.Fatal(err)
	}

	sum := mustPrune(t, f, retention.Options{Apply: true})

	if f.rowExists(e.ID) {
		t.Fatal("row for a missing blob was not removed")
	}
	if got := sum.Count(retention.StatusAlreadyGone); got != 1 {
		t.Fatalf("already-gone count = %d, want 1", got)
	}
	if sum.Failures != 0 {
		t.Fatalf("failures = %d, want 0 (missing blob is not a failure)", sum.Failures)
	}
}

// (f) rows whose path escapes the root are refused: nothing outside the root
// is deleted, the rows are kept, and the run reports failures.
func TestPruneRefusesPathTraversalRows(t *testing.T) {
	f := newFx(t)
	sc := f.scan(domain.ScanCompleted, oldAge)
	canary := filepath.Join(f.base, "canary.txt")
	if err := os.WriteFile(canary, []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}

	var rows []*domain.Evidence
	for _, bad := range []string{"../canary.txt", canary, "x/../../canary.txt"} {
		e := &domain.Evidence{
			ID: domain.NewID(), ScanID: sc.ID, Kind: domain.EvidenceResponse,
			BlobPath: bad, CreatedAt: f.now,
		}
		if err := f.st.Evidence().Create(ctx, e); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, e)
	}

	sum := mustPrune(t, f, retention.Options{Apply: true})

	if got, err := os.ReadFile(canary); err != nil || string(got) != "canary" {
		t.Fatalf("canary outside the evidence root was touched: %q, %v", got, err)
	}
	for _, e := range rows {
		if !f.rowExists(e.ID) {
			t.Fatalf("refused row %q was deleted", e.BlobPath)
		}
	}
	if got := sum.Count(retention.StatusRefused); got != len(rows) {
		t.Fatalf("refused count = %d, want %d", got, len(rows))
	}
	// A containment refusal is a warning, not a failure: the run is still clean
	// (exit 0) and the operator is told which rows were left alone.
	if sum.Warnings != len(rows) {
		t.Fatalf("warnings = %d, want %d", sum.Warnings, len(rows))
	}
	if sum.Failures != 0 {
		t.Fatalf("failures = %d, want 0 (refusals are warnings)", sum.Failures)
	}
}

// (g) findings are not deleted; their dangling evidence links are dropped and
// the affected count is reported. Dry run reports the same count, changes nothing.
func TestPruneReportsFindingEvidenceLinksLost(t *testing.T) {
	f := newFx(t)
	sc := f.scan(domain.ScanCompleted, oldAge)

	fID := domain.NewID()
	e1 := f.blob(sc, "<html>one</html>", fID)
	e2 := f.blob(sc, "<html>two</html>", "")
	finding := &domain.Finding{
		ID: fID, ScanID: sc.ID, ProjectID: f.project,
		EvidenceIDs: []domain.ID{e1.ID, e2.ID},
	}
	if err := f.st.Findings().Create(ctx, finding); err != nil {
		t.Fatal(err)
	}
	other := &domain.Finding{ID: domain.NewID(), ScanID: sc.ID, ProjectID: f.project}
	if err := f.st.Findings().Create(ctx, other); err != nil {
		t.Fatal(err)
	}

	dry := mustPrune(t, f, retention.Options{Apply: false})
	if dry.FindingsAffected != 1 {
		t.Fatalf("dry run FindingsAffected = %d, want 1", dry.FindingsAffected)
	}
	got, _ := f.st.Findings().Get(ctx, fID)
	if len(got.EvidenceIDs) != 2 {
		t.Fatalf("dry run changed finding links: %v", got.EvidenceIDs)
	}

	sum := mustPrune(t, f, retention.Options{Apply: true})
	if sum.FindingsAffected != 1 {
		t.Fatalf("FindingsAffected = %d, want 1", sum.FindingsAffected)
	}
	got, err := f.st.Findings().Get(ctx, fID)
	if err != nil {
		t.Fatalf("finding was deleted: %v", err)
	}
	if len(got.EvidenceIDs) != 0 {
		t.Fatalf("dangling evidence links kept: %v", got.EvidenceIDs)
	}
	if _, err := f.st.Findings().Get(ctx, other.ID); err != nil {
		t.Fatalf("unrelated finding deleted: %v", err)
	}
}

// (i) session files: removed only for eligible scans, only inside SessionsDir,
// and never while a non-eligible scan still references the same file.
func TestPruneSessionsRemovesOnlyUnsharedEligibleFiles(t *testing.T) {
	f := newFx(t)
	mkSession := func(sc *domain.Scan, path string) {
		t.Helper()
		s := &domain.Session{
			ID: domain.NewID(), ScanID: sc.ID, Mode: domain.AuthExisting,
			State: domain.SessionActive, StatePath: path, CreatedAt: f.now, UpdatedAt: f.now,
		}
		if err := f.st.Sessions().Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	writeFile := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ownFile := filepath.Join(f.sessions, "login-own.json")
	sharedFile := filepath.Join(f.sessions, "login-shared.json")
	outsideFile := filepath.Join(f.base, "elsewhere.json")
	for _, p := range []string{ownFile, sharedFile, outsideFile} {
		writeFile(p)
	}

	// One session per scan, as the controller creates them.
	old1 := f.scan(domain.ScanCompleted, oldAge)
	old2 := f.scan(domain.ScanCompleted, oldAge)
	old3 := f.scan(domain.ScanCompleted, oldAge)
	running := f.scan(domain.ScanRunning, oldAge)
	mkSession(old1, ownFile)
	mkSession(old2, sharedFile)
	mkSession(old3, outsideFile)
	mkSession(running, sharedFile)

	sum := mustPrune(t, f, retention.Options{Apply: true, IncludeSessions: true})

	if exists(ownFile) {
		t.Fatal("eligible scan's own session file was kept")
	}
	if !exists(sharedFile) {
		t.Fatal("session file still referenced by a running scan was removed")
	}
	if !exists(outsideFile) {
		t.Fatal("session file outside SessionsDir was removed")
	}
	if got := sum.Count(retention.StatusRemoved); got != 1 {
		t.Fatalf("removed count = %d, want 1", got)
	}
	if got := sum.Count(retention.StatusKept); got != 2 {
		t.Fatalf("kept count = %d, want 2", got)
	}
}

// (i, default) session files are untouched unless IncludeSessions is set, and
// a dry run with it set still deletes nothing.
func TestPruneSessionsOffByDefaultAndDryRunKeepsFiles(t *testing.T) {
	f := newFx(t)
	own := filepath.Join(f.sessions, "login-own.json")
	if err := os.WriteFile(own, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := f.scan(domain.ScanCompleted, oldAge)
	if err := f.st.Sessions().Create(ctx, &domain.Session{
		ID: domain.NewID(), ScanID: sc.ID, Mode: domain.AuthExisting,
		State: domain.SessionActive, StatePath: own, CreatedAt: f.now, UpdatedAt: f.now,
	}); err != nil {
		t.Fatal(err)
	}

	mustPrune(t, f, retention.Options{Apply: true})
	if !exists(own) {
		t.Fatal("session file removed without -include-sessions")
	}
	sum := mustPrune(t, f, retention.Options{Apply: false, IncludeSessions: true})
	if !exists(own) {
		t.Fatal("dry run removed a session file")
	}
	if sum.Count(retention.StatusWouldRemove) != 1 {
		t.Fatalf("dry run would-remove = %d, want 1", sum.Count(retention.StatusWouldRemove))
	}
}

// Reports: files and index rows of eligible scans, only with IncludeReports.
func TestPruneReportsRemovesFileAndIndexRowOnlyWhenRequested(t *testing.T) {
	f := newFx(t)
	sc := f.scan(domain.ScanCompleted, oldAge)
	rel := filepath.ToSlash(filepath.Join(string(sc.ID), "report-1.md"))
	abs := filepath.Join(f.reports, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("# report"), 0o640); err != nil {
		t.Fatal(err)
	}
	rep := &domain.Report{ID: domain.NewID(), ScanID: sc.ID, ProjectID: f.project, Format: "markdown", Path: rel, CreatedAt: f.now}
	if err := f.st.Reports().Create(ctx, rep); err != nil {
		t.Fatal(err)
	}

	mustPrune(t, f, retention.Options{Apply: true})
	if !exists(abs) {
		t.Fatal("report removed without -include-reports")
	}

	mustPrune(t, f, retention.Options{Apply: true, IncludeReports: true})
	if exists(abs) {
		t.Fatal("report file kept with -include-reports")
	}
	if _, err := f.st.Reports().Get(ctx, rep.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("report index row kept: %v", err)
	}
}

// -scan restricts the pass to one scan; an unknown scan is an error.
func TestPruneScanFilter(t *testing.T) {
	f := newFx(t)
	a := f.scan(domain.ScanCompleted, oldAge)
	b := f.scan(domain.ScanFailed, oldAge)
	ea := f.blob(a, "<html>a</html>", "")
	eb := f.blob(b, "<html>b</html>", "")

	mustPrune(t, f, retention.Options{Apply: true, ScanID: a.ID})
	if f.rowExists(ea.ID) {
		t.Fatal("selected scan was not pruned")
	}
	if !f.rowExists(eb.ID) || !exists(f.blobAbs(eb)) {
		t.Fatal("unselected scan was pruned")
	}

	_, err := f.prune(retention.Options{Apply: true, ScanID: domain.NewID()})
	if !errors.Is(err, retention.ErrScanNotFound) {
		t.Fatalf("unknown scan error = %v, want ErrScanNotFound", err)
	}
}

// (h) -older-than: missing, too short, and malformed values are rejected.
func TestParseOlderThanRequiresExplicitMinimum(t *testing.T) {
	for _, bad := range []string{"", "0s", "59m", "-2h", "bogus", "30d"} {
		if _, err := retention.ParseOlderThan(bad); err == nil {
			t.Errorf("ParseOlderThan(%q) accepted, want error", bad)
		}
	}
	for good, want := range map[string]time.Duration{"1h": time.Hour, "720h": 720 * time.Hour} {
		got, err := retention.ParseOlderThan(good)
		if err != nil || got != want {
			t.Errorf("ParseOlderThan(%q) = %v, %v; want %v", good, got, err, want)
		}
	}
}

// A zero cutoff is refused: there is no implicit "delete everything".
func TestPruneRequiresCutoff(t *testing.T) {
	f := newFx(t)
	_, err := retention.Prune(ctx, retention.Options{Store: f.st, Evidence: f.ev, Apply: true})
	if err == nil {
		t.Fatal("zero cutoff accepted")
	}
}

// Audit: one structured line per deleted scan, with no blob content or paths.
func TestPruneAuditLogsOneLinePerDeletedScan(t *testing.T) {
	f := newFx(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	a := f.scan(domain.ScanCompleted, oldAge)
	b := f.scan(domain.ScanCanceled, oldAge)
	f.scan(domain.ScanRunning, oldAge) // not deleted: no line
	ea := f.blob(a, "SECRET-BODY-A", "")
	f.blob(b, "SECRET-BODY-B", "")

	mustPrune(t, f, retention.Options{Apply: true, Log: log})

	out := buf.String()
	if n := strings.Count(out, "evidence pruned"); n != 2 {
		t.Fatalf("audit lines = %d, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, "scan_id="+string(a.ID)) || !strings.Contains(out, "scan_id="+string(b.ID)) {
		t.Fatalf("audit lines missing scan IDs:\n%s", out)
	}
	if strings.Contains(out, "SECRET-BODY") || strings.Contains(out, ea.BlobPath) {
		t.Fatalf("audit output leaks content or blob path:\n%s", out)
	}
}
