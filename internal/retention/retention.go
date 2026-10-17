// Package retention prunes stored evidence (and, opt-in, saved session material
// and generated reports) for scans that have ended long ago.
//
// Evidence blobs can carry the target's session cookies verbatim (see
// docs/deployment.md §6), so an operator needs a way to bound how long they
// live. Prune is conservative by design:
//
//   - dry run is the default: Options.Apply must be set to delete anything;
//   - only scans in a terminal state (completed, failed, canceled) are
//     considered, and only when their last activity is before Cutoff;
//   - a scan with no usable timestamp is skipped (fail closed);
//   - every path is validated to stay inside its root before any removal, and
//     a blob's metadata row is deleted only after its file is confirmed gone;
//   - findings are never deleted; only their dangling evidence links are dropped.
package retention

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store"
)

// MinOlderThan is the smallest accepted -older-than. Shorter cutoffs would
// race with scans that are still being inspected or re-run.
const MinOlderThan = time.Hour

// ErrScanNotFound is returned when Options.ScanID names no known scan.
var ErrScanNotFound = errors.New("retention: scan not found")

// ParseOlderThan parses and validates an -older-than value. An empty value is
// an error (there is deliberately no default), as is anything below
// MinOlderThan. Go durations only (h, m, s): write 720h for 30 days.
func ParseOlderThan(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, errors.New("-older-than is required (e.g. 720h); there is no default")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("-older-than %q: %v (Go duration syntax, e.g. 720h)", s, err)
	}
	if d < MinOlderThan {
		return 0, fmt.Errorf("-older-than %s is below the %s minimum", s, MinOlderThan)
	}
	return d, nil
}

// Options configures one prune pass.
type Options struct {
	Store    store.Store
	Evidence evidence.Store

	// SessionsDir and ReportsDir are the roots that session files and report
	// files must stay inside. Empty disables that category.
	SessionsDir string
	ReportsDir  string

	// Cutoff: a terminal scan is eligible when its last activity is before Cutoff.
	Cutoff time.Time
	// ScanID, when set, restricts the pass to one scan.
	ScanID domain.ID

	IncludeSessions bool // also remove saved session files of eligible scans
	IncludeReports  bool // also remove generated report files of eligible scans

	// Apply performs the deletions. Without it nothing is changed.
	Apply bool

	// Log receives one structured audit line per scan that had something
	// deleted (Apply only). nil discards.
	Log *slog.Logger
}

// Status is the outcome of one item (an evidence row, a session file, a report).
type Status string

const (
	StatusWouldRemove Status = "would-remove" // dry run: would be deleted
	StatusRemoved     Status = "removed"      // deleted (Apply)
	StatusAlreadyGone Status = "already-gone" // file was already missing; row/index entry cleared
	StatusRefused     Status = "refused"      // path failed the containment check; left alone
	StatusFailed      Status = "failed"       // I/O or store error; left alone, counted as a failure
	StatusKept        Status = "kept"         // intentionally not deleted (see Note)
)

// Item is one evidence row, session file, or report considered for removal.
// Path is relative to its root; no absolute paths are recorded.
type Item struct {
	Path   string
	Bytes  int64
	Status Status
	Note   string
}

// ScanResult describes one eligible scan.
type ScanResult struct {
	ScanID    domain.ID
	State     domain.ScanState
	Timestamp time.Time // the timestamp that made the scan eligible

	Evidence []Item
	Sessions []Item
	Reports  []Item

	FindingsAffected int // findings that lost at least one evidence link
}

// Summary is the result of Prune.
type Summary struct {
	Apply  bool
	Cutoff time.Time

	Scans []ScanResult // eligible scans

	KeptRecent         int         // terminal scans newer than the cutoff
	KeptActive         int         // scans not in a terminal state (never touched)
	SkippedNoTimestamp []domain.ID // terminal scans with no usable timestamp

	FindingsAffected int // distinct findings that lost at least one evidence link
	Failures         int // refused + failed items (non-zero means the run is not clean)
}

// Count returns how many items across all categories have the given status.
func (s *Summary) Count(st Status) int {
	n := 0
	for _, sc := range s.Scans {
		for _, group := range [][]Item{sc.Evidence, sc.Sessions, sc.Reports} {
			for _, it := range group {
				if it.Status == st {
					n++
				}
			}
		}
	}
	return n
}

// Prune runs one retention pass. It returns an error only for an invalid
// configuration or a failed store read; per-item problems are recorded in the
// Summary and counted in Failures. On a store read error mid-run the Summary
// so far is returned with the error: every completed deletion is final and
// safe, and a re-run picks up the rest.
func Prune(ctx context.Context, opt Options) (*Summary, error) {
	if opt.Store == nil || opt.Evidence == nil {
		return nil, errors.New("retention: store and evidence store are required")
	}
	if opt.Cutoff.IsZero() {
		return nil, errors.New("retention: cutoff is required")
	}
	log := opt.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var err error
	if opt.SessionsDir != "" {
		if opt.SessionsDir, err = filepath.Abs(opt.SessionsDir); err != nil {
			return nil, fmt.Errorf("retention: sessions dir: %w", err)
		}
	}
	if opt.ReportsDir != "" {
		if opt.ReportsDir, err = filepath.Abs(opt.ReportsDir); err != nil {
			return nil, fmt.Errorf("retention: reports dir: %w", err)
		}
	}

	scans, err := opt.Store.Scans().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("retention: list scans: %w", err)
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].ID < scans[j].ID })
	filtered := !opt.ScanID.Empty()
	if filtered {
		found := false
		for _, sc := range scans {
			found = found || sc.ID == opt.ScanID
		}
		if !found {
			return nil, ErrScanNotFound
		}
	}

	sum := &Summary{Apply: opt.Apply, Cutoff: opt.Cutoff}
	type eligible struct {
		sc *domain.Scan
		ts time.Time
	}
	var elig []eligible
	eligibleSet := map[domain.ID]bool{}
	for _, sc := range scans {
		if filtered && sc.ID != opt.ScanID {
			continue
		}
		if !sc.State.IsTerminal() {
			sum.KeptActive++
			continue
		}
		ts, ok := lastActivity(sc)
		if !ok {
			sum.SkippedNoTimestamp = append(sum.SkippedNoTimestamp, sc.ID)
			continue
		}
		if !ts.Before(opt.Cutoff) {
			sum.KeptRecent++
			continue
		}
		elig = append(elig, eligible{sc, ts})
		eligibleSet[sc.ID] = true
	}

	// Session files may be referenced by scans other than the eligible ones
	// (an operator can point several scans at one saved login). Such a file is
	// never removed. Built only when sessions are in play.
	var sessionRefs map[string]bool
	if opt.IncludeSessions && len(elig) > 0 {
		sessionRefs = map[string]bool{}
		for _, sc := range scans {
			if eligibleSet[sc.ID] {
				continue
			}
			sess, err := opt.Store.Sessions().GetByScan(ctx, sc.ID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return sum, fmt.Errorf("retention: session of scan: %w", err)
			}
			if sess.StatePath != "" {
				sessionRefs[filepath.Clean(sess.StatePath)] = true
			}
		}
	}

	affected := map[domain.ID]bool{}
	for _, el := range elig {
		res, err := pruneScan(ctx, opt, el.sc, el.ts, sessionRefs, affected)
		sum.Scans = append(sum.Scans, res)
		if err != nil {
			return sum, err
		}
		if opt.Apply {
			logScan(log, opt.Cutoff, res)
		}
	}

	sum.FindingsAffected = len(affected)
	for _, sc := range sum.Scans {
		for _, group := range [][]Item{sc.Evidence, sc.Sessions, sc.Reports} {
			for _, it := range group {
				if it.Status == StatusRefused || it.Status == StatusFailed {
					sum.Failures++
				}
			}
		}
	}
	return sum, nil
}

// pruneScan handles one eligible scan: its evidence rows (blob, then row),
// the finding links that point at those rows, then its session and report
// files when requested. affected collects distinct finding IDs across scans.
func pruneScan(ctx context.Context, opt Options, sc *domain.Scan, ts time.Time,
	sessionRefs map[string]bool, affected map[domain.ID]bool) (ScanResult, error) {

	res := ScanResult{ScanID: sc.ID, State: sc.State, Timestamp: ts}

	rows, err := opt.Store.Evidence().ListByScan(ctx, sc.ID)
	if err != nil {
		return res, fmt.Errorf("retention: list evidence of scan %s: %w", sc.ID, err)
	}
	gone := map[domain.ID]bool{}        // evidence rows deleted (or would be, dry run)
	goneFinding := map[domain.ID]bool{} // findings whose evidence row is gone
	for _, row := range rows {
		it, ok := evidenceItem(ctx, opt, row)
		res.Evidence = append(res.Evidence, it)
		if ok {
			gone[row.ID] = true
			if !row.FindingID.Empty() {
				goneFinding[row.FindingID] = true
			}
		}
	}

	if len(gone) > 0 {
		findings, err := opt.Store.Findings().ListByProject(ctx, sc.ProjectID)
		if err != nil {
			return res, fmt.Errorf("retention: list findings of project: %w", err)
		}
		for _, f := range findings {
			hit := goneFinding[f.ID]
			keep := make([]domain.ID, 0, len(f.EvidenceIDs))
			for _, id := range f.EvidenceIDs {
				if gone[id] {
					hit = true
				} else {
					keep = append(keep, id)
				}
			}
			if !hit {
				continue
			}
			res.FindingsAffected++
			affected[f.ID] = true
			if opt.Apply && len(keep) != len(f.EvidenceIDs) {
				f.EvidenceIDs = keep
				f.UpdatedAt = time.Now().UTC()
				if err := opt.Store.Findings().Update(ctx, f); err != nil {
					return res, fmt.Errorf("retention: update finding links: %w", err)
				}
			}
		}
	}

	if opt.IncludeSessions && opt.SessionsDir != "" {
		res.Sessions = sessionItems(ctx, opt, sc, sessionRefs)
	}
	if opt.IncludeReports && opt.ReportsDir != "" {
		res.Reports = reportItems(ctx, opt, sc)
	}
	return res, nil
}

// evidenceItem removes (Apply) or plans (dry run) one evidence row. It reports
// whether the row is gone, or would be gone, so its finding links can be cut.
func evidenceItem(ctx context.Context, opt Options, row *domain.Evidence) (Item, bool) {
	it := Item{Path: displayRel(row.BlobPath)}
	fi, serr := opt.Evidence.Stat(row.BlobPath)
	blobGone := false
	switch {
	case serr == nil:
		it.Bytes = fi.Size()
	case errors.Is(serr, fs.ErrNotExist):
		blobGone = true
	default:
		return failure(it, serr), false
	}

	if !opt.Apply {
		if blobGone {
			it.Status = StatusAlreadyGone
		} else {
			it.Status = StatusWouldRemove
		}
		return it, true
	}

	if !blobGone {
		if err := opt.Evidence.Remove(row.BlobPath); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return failure(it, err), false
			}
			blobGone = true
		}
	}
	// The blob is confirmed gone (or was never there): only now drop the row.
	if err := opt.Store.Evidence().Delete(ctx, row.ID); err != nil {
		it.Status = StatusFailed
		it.Note = "metadata row not deleted: " + brief(err)
		return it, false
	}
	if blobGone {
		it.Status = StatusAlreadyGone
		it.Bytes = 0
	} else {
		it.Status = StatusRemoved
	}
	return it, true
}

// sessionItems handles the saved session file recorded for a scan. The
// session row is the only scan-to-file mapping the code writes, so that is
// the mapping used. The file must be absolute and inside SessionsDir; files
// outside it (a login the operator kept elsewhere) are kept, and so is any
// file another non-eligible scan still references.
func sessionItems(ctx context.Context, opt Options, sc *domain.Scan, sessionRefs map[string]bool) []Item {
	sess, err := opt.Store.Sessions().GetByScan(ctx, sc.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return []Item{{Status: StatusFailed, Note: "session lookup: " + brief(err)}}
	}
	if sess.StatePath == "" {
		return nil
	}
	abs := filepath.Clean(sess.StatePath)
	if !filepath.IsAbs(abs) || !within(opt.SessionsDir, abs) {
		return []Item{{Path: "(outside sessions dir)", Status: StatusKept, Note: "not inside the sessions directory"}}
	}
	it := Item{Path: displayRel(relOf(opt.SessionsDir, abs))}
	if sessionRefs[abs] {
		it.Status = StatusKept
		it.Note = "still referenced by a scan that is not eligible"
		return []Item{it}
	}
	return []Item{fileItem(it, opt.SessionsDir, abs, opt.Apply)}
}

// reportItems removes the generated report files and index rows of a scan.
// Report paths are relative to ReportsDir; anything else is refused.
func reportItems(ctx context.Context, opt Options, sc *domain.Scan) []Item {
	reps, err := opt.Store.Reports().ListByScan(ctx, sc.ID)
	if err != nil {
		return []Item{{Status: StatusFailed, Note: "report index: " + brief(err)}}
	}
	var out []Item
	for _, r := range reps {
		it := Item{Path: displayRel(r.Path)}
		if filepath.IsAbs(r.Path) {
			out = append(out, failure(it, fmt.Errorf("%w: absolute report path", evidence.ErrRefused)))
			continue
		}
		abs := filepath.Join(opt.ReportsDir, filepath.FromSlash(r.Path))
		it = fileItem(it, opt.ReportsDir, abs, opt.Apply)
		if opt.Apply && (it.Status == StatusRemoved || it.Status == StatusAlreadyGone) {
			if err := opt.Store.Reports().Delete(ctx, r.ID); err != nil {
				it.Status = StatusFailed
				it.Note = "index row not deleted: " + brief(err)
			}
		}
		out = append(out, it)
	}
	return out
}

// fileItem decides (dry run) or performs (Apply) removal of one file at abs,
// which must lie inside root as a regular file. It does not touch any row.
func fileItem(it Item, root, abs string, apply bool) Item {
	fi, err := containedFile(root, abs)
	if errors.Is(err, fs.ErrNotExist) {
		it.Status = StatusAlreadyGone
		return it
	}
	if err != nil {
		return failure(it, err)
	}
	it.Bytes = fi.Size()
	if !apply {
		it.Status = StatusWouldRemove
		return it
	}
	if err := os.Remove(abs); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			it.Status, it.Bytes = StatusAlreadyGone, 0
			return it
		}
		return failure(it, err)
	}
	it.Status = StatusRemoved
	return it
}

// containedFile returns the file info for abs if it is a regular file (not a
// symlink) inside root, with no symlinked directory on the way that resolves
// outside root. Refusals wrap evidence.ErrRefused; a missing file wraps
// fs.ErrNotExist.
func containedFile(root, abs string) (fs.FileInfo, error) {
	if !filepath.IsAbs(abs) || !within(root, abs) {
		return nil, fmt.Errorf("%w: outside its directory", evidence.ErrRefused)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", evidence.ErrRefused)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	realDir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	if !within(realRoot, realDir) {
		return nil, fmt.Errorf("%w: resolves outside its directory", evidence.ErrRefused)
	}
	return fi, nil
}

// within reports whether p (cleaned) is root itself or lies beneath it.
// Callers that need "strictly beneath" must check p != root separately.
func within(root, p string) bool {
	root, p = filepath.Clean(root), filepath.Clean(p)
	return p == root || strings.HasPrefix(p, root+string(os.PathSeparator))
}

// lastActivity is the later of EndedAt and UpdatedAt, the conservative choice:
// a scan touched recently is never pruned on the strength of an older end time.
func lastActivity(sc *domain.Scan) (time.Time, bool) {
	var ts time.Time
	if sc.EndedAt != nil && !sc.EndedAt.IsZero() {
		ts = *sc.EndedAt
	}
	if sc.UpdatedAt.After(ts) {
		ts = sc.UpdatedAt
	}
	return ts, !ts.IsZero()
}

// failure classifies err as refused (containment) or failed (anything else)
// without echoing absolute paths: the Note carries only the brief reason.
func failure(it Item, err error) Item {
	if errors.Is(err, evidence.ErrRefused) {
		it.Status = StatusRefused
		it.Note = "refused: outside its directory or not a regular file"
		return it
	}
	it.Status = StatusFailed
	it.Note = brief(err)
	return it
}

// brief strips the path from an *fs.PathError so messages never echo absolute
// paths; the operator sees "permission denied", not "/home/.../blob".
func brief(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// displayRel makes a stored path safe to print: relative and free of "..".
// Anything else is shown as a placeholder (the raw value is a corrupt row).
func displayRel(p string) string {
	if p == "" || filepath.IsAbs(p) || strings.Contains(filepath.ToSlash(p), "..") {
		return "(non-relative path)"
	}
	return filepath.ToSlash(p)
}

// relOf returns p relative to root for display, or "" if p is not under root.
func relOf(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return ""
	}
	return rel
}

// logScan writes the audit line for a scan that had deletions. Only IDs,
// counts and the cutoff are logged: never blob content or paths.
func logScan(log *slog.Logger, cutoff time.Time, r ScanResult) {
	count := func(items []Item, st Status) int {
		n := 0
		for _, it := range items {
			if it.Status == st {
				n++
			}
		}
		return n
	}
	removed := count(r.Evidence, StatusRemoved) + count(r.Evidence, StatusAlreadyGone) +
		count(r.Sessions, StatusRemoved) + count(r.Reports, StatusRemoved) + count(r.Reports, StatusAlreadyGone)
	if removed == 0 {
		return
	}
	log.Info("evidence pruned",
		"scan_id", r.ScanID,
		"state", r.State,
		"cutoff", cutoff.UTC().Format(time.RFC3339),
		"evidence_removed", count(r.Evidence, StatusRemoved),
		"evidence_already_gone", count(r.Evidence, StatusAlreadyGone),
		"sessions_removed", count(r.Sessions, StatusRemoved),
		"reports_removed", count(r.Reports, StatusRemoved),
		"findings_affected", r.FindingsAffected,
		"failed", count(r.Evidence, StatusFailed)+count(r.Evidence, StatusRefused),
	)
}
