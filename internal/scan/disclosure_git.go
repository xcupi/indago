package scan

// Version-control history disclosure (the exposed-.git case).
//
// One job per origin, GET-only and tightly bounded: HEAD, config, logs/HEAD, the
// newest commit object, its tree, and up to a handful of blobs. The finding is
// confirmed by the repository's own bytes — a real HEAD, a real config, a log
// the caller can walk, and a loose commit object that decompresses — not by a
// 200 on a path. When a blob carries a credential literal, the finding names the
// KEY and the file; the value is never echoed into evidence.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/indago/indago/internal/disclosure"
	"github.com/indago/indago/internal/domain"
)

const (
	disclosureModeGitProbe = "git_probe"
	// maxGitProbes bounds the pass to a few origins per scan.
	maxGitProbes = 3
	// maxGitBlobs bounds how many blobs one repository may contribute.
	maxGitBlobs = 6
)

// runGitProbe walks one origin's served .git metadata and records the verdict.
func (e *disclosureExecutor) runGitProbe(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) error {
	origin := disclosureOrigin(job.Target.URL)
	if origin == "" {
		tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess
		tc.Note = "git probe: no usable origin"
		_ = e.store.TestCases().Update(ctx, tc)
		return nil
	}
	headURL := origin + disclosure.GitHeadPath
	tc.Method, tc.URL = "GET", headURL

	headResp, err := e.fetch(ctx, headURL)
	if err != nil {
		tc.Status, tc.Outcome = domain.TestCaseFailed, domain.OutcomeError
		tc.Error = truncate(err.Error(), 1024)
		_ = e.store.TestCases().Update(ctx, tc)
		return nil
	}
	ref, sha, headOK := disclosure.GitHeadRef(headResp.Body)
	if headResp.Status != 200 || !headOK {
		tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess
		tc.Note = fmt.Sprintf("git probe: %s answered %d without a repository HEAD", disclosure.GitHeadPath, headResp.Status)
		_ = e.store.TestCases().Update(ctx, tc)
		return nil
	}

	cfgResp, cfgErr := e.fetch(ctx, origin+disclosure.GitConfigPath)
	if cfgErr != nil || cfgResp.Status != 200 || !disclosure.GitConfigIsRepository(cfgResp.Body) {
		tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess
		tc.Note = "git probe: HEAD looked like git metadata but .git/config was not a repository file"
		_ = e.store.TestCases().Update(ctx, tc)
		return nil
	}

	logsResp, _ := e.fetch(ctx, origin+disclosure.GitLogPath)
	commits := disclosure.GitLogSHAs(logsResp.Body, disclosure.MaxGitLogCommits)
	if sha != "" {
		commits = append([]string{sha}, commits...)
	}
	commits = dedupeStrings(commits)
	if len(commits) == 0 {
		tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess
		tc.Note = "git probe: the repository metadata is served but no commit id could be resolved"
		_ = e.store.TestCases().Update(ctx, tc)
		return nil
	}

	commitURL := disclosure.GitObjectURL(origin, commits[0])
	commitResp, commitErr := e.fetch(ctx, commitURL)
	kind, commitPayload, inflated := "", []byte(nil), false
	if commitErr == nil && commitResp.Status == 200 {
		kind, commitPayload, inflated = disclosure.InflateLooseObject(commitResp.Body)
	}
	if !inflated || kind != "commit" {
		tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess
		tc.Note = fmt.Sprintf("git probe: HEAD/config/logs are served, but the newest object %s did not decompress as a commit", shortSHA(commits[0]))
		_ = e.store.TestCases().Update(ctx, tc)
		return nil
	}

	// Walk the log's commits (newest first) and read interesting blobs from each
	// tree. A credential is usually in an OLDER commit — the newest one is what
	// removed it — so stopping at HEAD would miss the disclosure entirely.
	var (
		blobNames  []string
		secretKeys []string
		secretFile []string
		secretAt   []string
		commitSubj string
	)
	seenBlobs := map[string]struct{}{}
	blobs := 0
	for i, sha := range commits {
		if blobs >= maxGitBlobs {
			break
		}
		var payload []byte
		if i == 0 {
			payload = commitPayload // already fetched above
		} else {
			resp, err := e.fetch(ctx, disclosure.GitObjectURL(origin, sha))
			if err != nil || resp.Status != 200 {
				continue
			}
			k, p, ok := disclosure.InflateLooseObject(resp.Body)
			if !ok || k != "commit" {
				continue
			}
			payload = p
		}
		if i == 0 {
			commitSubj = disclosure.GitCommitSubject(payload)
		}
		subject := disclosure.GitCommitSubject(payload)
		treeSHA, ok := disclosure.GitCommitTree(payload)
		if !ok {
			continue
		}
		treeResp, treeErr := e.fetch(ctx, disclosure.GitObjectURL(origin, treeSHA))
		if treeErr != nil || treeResp.Status != 200 {
			continue
		}
		tKind, tPayload, tOK := disclosure.InflateLooseObject(treeResp.Body)
		if !tOK || tKind != "tree" {
			continue
		}
		for _, entry := range disclosure.ParseGitTree(tPayload) {
			if blobs >= maxGitBlobs {
				break
			}
			if !strings.HasPrefix(entry.Mode, "100") || !disclosure.GitBlobNameInteresting(entry.Name) {
				continue
			}
			if _, dup := seenBlobs[entry.SHA]; dup {
				continue
			}
			seenBlobs[entry.SHA] = struct{}{}
			blobResp, blobErr := e.fetch(ctx, disclosure.GitObjectURL(origin, entry.SHA))
			if blobErr != nil || blobResp.Status != 200 {
				continue
			}
			bKind, bPayload, bOK := disclosure.InflateLooseObject(blobResp.Body)
			if !bOK || bKind != "blob" {
				continue
			}
			blobs++
			blobNames = append(blobNames, entry.Name)
			if key, found := disclosure.GitSecretHint(bPayload); found {
				secretKeys = append(secretKeys, key)
				secretFile = append(secretFile, entry.Name)
				secretAt = append(secretAt, fmt.Sprintf("%s (%s)", shortSHA(sha), subject))
			}
		}
	}

	reason := fmt.Sprintf("version control metadata is served: HEAD names %s, .git/config is a repository file, and commit %s decompresses as a real commit object",
		gitHeadLabel(ref, commits[0]), shortSHA(commits[0]))
	detail := ""
	if len(secretKeys) > 0 {
		reason += fmt.Sprintf("; the served history carries a credential literal (%s) in %s at %s",
			strings.Join(dedupeStrings(secretKeys), ", "), strings.Join(dedupeStrings(secretFile), ", "), strings.Join(dedupeStrings(secretAt), " | "))
		detail = "credential in history: " + strings.Join(dedupeStrings(secretFile), ", ")
	} else if len(blobNames) > 0 {
		reason += "; blobs from the same trees were readable (" + strings.Join(dedupeStrings(blobNames), ", ") + ")"
	}
	if commitSubj != "" {
		reason += fmt.Sprintf("; newest commit subject %q", truncate(commitSubj, 120))
	}

	// Evidence: the HEAD response plus the decompressed-commit response.
	var ids []domain.ID
	if evIDs, evErr := e.persist(ctx, tc, headResp, string(disclosure.KindGitHistory)); evErr == nil {
		ids = append(ids, evIDs...)
	} else {
		tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
	}
	if commitErr == nil {
		if evIDs, evErr := e.persist(ctx, tc, commitResp, string(disclosure.KindGitHistory)+"-commit"); evErr == nil {
			ids = append(ids, evIDs...)
		}
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
	tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess
	tc.Note = strings.TrimSpace(tc.Note + " disclosure: " + string(disclosure.KindGitHistory) + " at " + origin + " (" + truncate(reason, 300) + ")")
	e.correlate(ctx, &domain.TestJob{ScanID: tc.ScanID, Target: domain.JobTarget{URL: origin + disclosure.GitHeadPath}}, tc,
		disclosure.Verdict{Kind: disclosure.KindGitHistory, Reason: reason, Detail: detail})
	_ = e.store.TestCases().Update(ctx, tc)
	return nil
}

func gitHeadLabel(ref, sha string) string {
	if ref != "" {
		return ref
	}
	return shortSHA(sha)
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// disclosureOrigin reduces a URL to scheme://host, refusing anything without a
// host.
func disclosureOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// dedupeStrings keeps first-seen order.
func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// enqueueGitProbes queues one git probe per discovered origin, bounded.
func (c *Controller) enqueueGitProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("git probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	seen := map[string]struct{}{}
	n := 0
	for _, ep := range endpoints {
		if n >= maxGitProbes {
			break
		}
		origin := disclosureOrigin(ep.URL)
		if origin == "" {
			continue
		}
		if _, dup := seen[origin]; dup {
			continue
		}
		seen[origin] = struct{}{}
		payload, _ := json.Marshal(map[string]string{"mode": disclosureModeGitProbe})
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobDisclosure, State: domain.JobQueued,
			Priority: disclosurePriorityHit, Target: domain.JobTarget{URL: origin + disclosure.GitHeadPath},
			Payload: payload, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("git probes: enqueued", "scan", scanID, "jobs", n)
	}
}
