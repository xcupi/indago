package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/indago/indago/internal/config"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/retention"
	"github.com/indago/indago/internal/store/sqlite"
)

// cmdEvidence dispatches `indago evidence <subcommand>`. Only `prune` exists.
func cmdEvidence(args []string) error {
	return runEvidencePrune(args, os.Stdout, os.Stderr)
}

const evidencePruneUsage = `usage: indago evidence prune -older-than DURATION [-data DIR] [-scan ID]
                              [-include-sessions] [-include-reports] [-apply]

Deletes captured evidence of scans that ended before the cutoff. DRY RUN by
default: nothing is deleted unless -apply is given. Findings are kept; only
their dangling evidence links are dropped. See docs/deployment.md (Retention).`

// runEvidencePrune implements `indago evidence prune`. It opens the SQLite
// database directly (WAL + busy timeout, so it can run while the server is up)
// and needs no server, no network, and no lock.
func runEvidencePrune(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 || args[0] != "prune" {
		return errors.New(evidencePruneUsage)
	}
	fs := flag.NewFlagSet("evidence prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", config.DefaultDataDir, "data directory")
	olderThan := fs.String("older-than", "", "delete evidence of scans that ended before now-DURATION (required; min 1h; e.g. 720h)")
	scanFlag := fs.String("scan", "", "restrict to one scan ID")
	includeSessions := fs.Bool("include-sessions", false, "also remove saved session files of eligible scans (inside the sessions dir only)")
	includeReports := fs.Bool("include-reports", false, "also remove generated report files of eligible scans")
	apply := fs.Bool("apply", false, "actually delete (default: dry run)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q\n\n%s", fs.Arg(0), evidencePruneUsage)
	}
	age, err := retention.ParseOlderThan(*olderThan)
	if err != nil {
		return err
	}

	cfg := config.Default()
	cfg.DataDir = *dataDir
	if _, err := os.Stat(cfg.DBPath()); err != nil {
		return fmt.Errorf("no database in -data %s (run `indago db init` first): %w", *dataDir, err)
	}
	ctx := context.Background()
	db, err := sqlite.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	ev, err := evidence.NewFS(cfg.EvidenceDir())
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))
	cutoff := time.Now().UTC().Add(-age)
	sum, err := retention.Prune(ctx, retention.Options{
		Store:           db,
		Evidence:        ev,
		SessionsDir:     cfg.SessionsDir(),
		ReportsDir:      cfg.ReportsDir(),
		Cutoff:          cutoff,
		ScanID:          domain.ID(*scanFlag),
		IncludeSessions: *includeSessions,
		IncludeReports:  *includeReports,
		Apply:           *apply,
		Log:             log,
	})
	if errors.Is(err, retention.ErrScanNotFound) {
		return fmt.Errorf("scan %s not found", *scanFlag)
	}
	if sum != nil {
		printPruneReport(stdout, sum, *includeSessions, *includeReports)
	}
	if err != nil {
		return err
	}
	if sum.Failures > 0 {
		return fmt.Errorf("%d item(s) refused or failed (listed above); the rest was processed", sum.Failures)
	}
	return nil
}

// printPruneReport writes the human-readable report. It prints scan IDs,
// relative blob paths, counts and byte sizes, and never blob content.
func printPruneReport(w io.Writer, sum *retention.Summary, includeSessions, includeReports bool) {
	if sum.Apply {
		fmt.Fprintln(w, "mode: APPLY (deleting)")
	} else {
		fmt.Fprintln(w, "mode: DRY RUN (nothing deleted; re-run with -apply to delete)")
	}
	fmt.Fprintf(w, "cutoff: %s (terminal scans whose last activity is before this)\n",
		sum.Cutoff.UTC().Format(time.RFC3339))

	var evBytes int64
	var evRows int
	if len(sum.Scans) == 0 {
		fmt.Fprintln(w, "no eligible scans")
	}
	for _, sc := range sum.Scans {
		fmt.Fprintf(w, "scan %s state=%s last_activity=%s\n",
			sc.ScanID, sc.State, sc.Timestamp.UTC().Format(time.RFC3339))
		for _, it := range sc.Evidence {
			evRows++
			if it.Status == retention.StatusWouldRemove || it.Status == retention.StatusRemoved {
				evBytes += it.Bytes
			}
			printItem(w, "  evidence", it)
		}
		for _, it := range sc.Sessions {
			printItem(w, "  session", it)
		}
		for _, it := range sc.Reports {
			printItem(w, "  report", it)
		}
		if sc.FindingsAffected > 0 {
			fmt.Fprintf(w, "  findings losing evidence links: %d (findings kept)\n", sc.FindingsAffected)
		}
	}

	fmt.Fprintf(w, "summary: eligible scans=%d evidence rows=%d bytes=%d\n", len(sum.Scans), evRows, evBytes)
	fmt.Fprintf(w, "  evidence: would-remove=%d removed=%d already-gone=%d refused=%d failed=%d\n",
		countEvidence(sum, retention.StatusWouldRemove), countEvidence(sum, retention.StatusRemoved),
		countEvidence(sum, retention.StatusAlreadyGone), countEvidence(sum, retention.StatusRefused),
		countEvidence(sum, retention.StatusFailed))
	fmt.Fprintf(w, "  findings losing evidence links: %d (findings are never deleted)\n", sum.FindingsAffected)
	fmt.Fprintf(w, "kept: terminal scans newer than cutoff=%d; non-terminal scans (never touched)=%d\n",
		sum.KeptRecent, sum.KeptActive)
	if len(sum.SkippedNoTimestamp) > 0 {
		ids := make([]string, len(sum.SkippedNoTimestamp))
		for i, id := range sum.SkippedNoTimestamp {
			ids[i] = string(id)
		}
		fmt.Fprintf(w, "skipped (terminal, no usable timestamp; fail closed): %s\n", strings.Join(ids, " "))
	}
	if includeSessions {
		fmt.Fprintln(w, "sessions: included; mapped via each scan's session record; files outside the sessions dir or shared with a non-eligible scan are kept")
	} else {
		fmt.Fprintln(w, "sessions: not included (add -include-sessions to remove saved session files of eligible scans)")
	}
	if includeReports {
		fmt.Fprintln(w, "reports: included (report files and their index rows of eligible scans)")
	} else {
		fmt.Fprintln(w, "reports: not included (add -include-reports to remove generated reports of eligible scans)")
	}
}

func printItem(w io.Writer, label string, it retention.Item) {
	line := fmt.Sprintf("%s: %s %s", label, it.Status, it.Path)
	if it.Bytes > 0 {
		line += fmt.Sprintf(" (%d bytes)", it.Bytes)
	}
	if it.Note != "" {
		line += " - " + it.Note
	}
	fmt.Fprintln(w, line)
}

func countEvidence(sum *retention.Summary, st retention.Status) int {
	n := 0
	for _, sc := range sum.Scans {
		for _, it := range sc.Evidence {
			if it.Status == st {
				n++
			}
		}
	}
	return n
}
