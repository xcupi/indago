import { useEffect, useMemo, useState } from "react";
import { PageTitle } from "@/components/Layout";
import { selectedProject, setSelectedProject } from "@/components/Layout";
import { Badge, SeverityBadge, VerdictBadge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Empty, Loading } from "@/components/ui/misc";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/lib/api";
import { navigate, useQuery } from "@/lib/router";
import type { Finding, Project, Report, Scan } from "@/lib/types";
import { formatTime, shortId } from "@/lib/utils";

/** Project/scan filter shared by both collection pages. The project comes from
 * the hash (?project=…) so a link from a project page lands pre-filtered. */
function useCollectionFilter(scans: Scan[]) {
  const query = useQuery();
  const [project, setProjectState] = useState(() => query.get("project") || selectedProject());
  const [scan, setScan] = useState(query.get("scan") ?? "");
  const projects = useApi<Project[]>("/api/projects");

  // A link from a project page (?project=) becomes the global selection too, so
  // the sidebar and the Scans page follow the same context.
  useEffect(() => {
    const fromLink = query.get("project");
    if (fromLink) setSelectedProject(fromLink);
  }, []);

  // The sidebar's project picker is the shared context: when it changes, this
  // page follows instead of holding a stale filter.
  useEffect(() => {
    const sync = () => setProjectState(selectedProject());
    window.addEventListener("indago:refresh", sync);
    return () => window.removeEventListener("indago:refresh", sync);
  }, []);

  function chooseProject(id: string) {
    setProjectState(id);
    setSelectedProject(id);
    setScan("");
  }

  const projectScans = useMemo(
    () => scans.filter((s) => !project || s.project_id === project),
    [scans, project],
  );
  const scanIDs = useMemo(() => new Set(projectScans.map((s) => s.id)), [projectScans]);

  return {
    project,
    setProject: chooseProject,
    scan,
    setScan,
    projects: projects.data ?? [],
    projectScans,
    scanIDs,
  };
}

function FilterBar({
  project,
  setProject,
  scan,
  setScan,
  projects,
  scans,
}: {
  project: string;
  setProject: (v: string) => void;
  scan: string;
  setScan: (v: string) => void;
  projects: Project[];
  scans: Scan[];
}) {
  return (
    <Card className="mb-4">
      <CardContent className="flex flex-wrap items-center gap-3 p-3">
        <label className="flex min-w-0 max-w-full items-center gap-2 text-[11px] uppercase tracking-wide text-muted-foreground">
          Project
          <select
            className="h-8 max-w-full rounded-md border border-border bg-background px-2 text-xs normal-case"
            value={project}
            onChange={(e) => {
              setProject(e.target.value);
              setScan("");
            }}
          >
            <option value="">All projects</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-w-0 max-w-full items-center gap-2 text-[11px] uppercase tracking-wide text-muted-foreground">
          Scan
          <select
            className="h-8 w-full max-w-full rounded-md border border-border bg-background px-2 text-xs normal-case"
            value={scan}
            onChange={(e) => setScan(e.target.value)}
          >
            <option value="">All scans</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {shortId(s.id)} — {s.name || s.seed_urls?.[0] || "scan"}
              </option>
            ))}
          </select>
        </label>
        {project ? (
          <a
            href={`#/projects/${project}`}
            className="text-[11px] text-emerald-700 hover:underline dark:text-emerald-400"
          >
            open project →
          </a>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function FindingsPage() {
  const scans = useApi<Scan[]>("/api/scans");
  const findings = useApi<Finding[]>("/api/findings");
  const filter = useCollectionFilter(scans.data ?? []);
  const scanById = useMemo(() => new Map((scans.data ?? []).map((s) => [s.id, s])), [scans.data]);

  const rows = useMemo(() => {
    return (findings.data ?? []).filter((f) => {
      if (filter.scan) return f.scan_id === filter.scan;
      return filter.scanIDs.has(f.scan_id);
    });
  }, [findings.data, filter.scan, filter.scanIDs]);

  const confirmed = rows.filter((f) => f.verdict === "confirmed").length;

  return (
    <div>
      <PageTitle
        title="Findings"
        subtitle={`Every finding across scans and projects — ${rows.length} shown, ${confirmed} confirmed.`}
      />
      {scans.loading && !scans.data ? (
        <Loading />
      ) : (
        <>
          <FilterBar
            project={filter.project}
            setProject={filter.setProject}
            scan={filter.scan}
            setScan={filter.setScan}
            projects={filter.projects}
            scans={filter.projectScans}
          />
          {findings.loading && !findings.data ? (
            <Loading />
          ) : rows.length === 0 ? (
            <Empty>No findings in this selection.</Empty>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Finding</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Verdict</TableHead>
                      <TableHead>Scan</TableHead>
                      <TableHead>Project</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((f) => {
                      const sc = scanById.get(f.scan_id);
                      const projectName = filter.projects.find((p) => p.id === sc?.project_id)?.name ?? "—";
                      return (
                        <TableRow
                          key={f.id}
                          className="cursor-pointer"
                          onClick={() => navigate(`/scans/${f.scan_id}?tab=findings`)}
                        >
                          <TableCell className="max-w-[26rem]">
                            <div className="truncate text-xs text-foreground">{f.title}</div>
                            <div className="text-[10px] text-muted-foreground">{f.vuln_class}</div>
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={f.severity} />
                          </TableCell>
                          <TableCell>
                            <VerdictBadge verdict={f.verdict} />
                          </TableCell>
                          <TableCell className="font-mono text-[11px] text-muted-foreground">
                            {shortId(f.scan_id)}
                          </TableCell>
                          <TableCell className="text-[11px] text-muted-foreground">{projectName}</TableCell>
                          <TableCell className="text-[11px] text-muted-foreground">{formatTime(f.created_at)}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

export function ReportsPage() {
  const scans = useApi<Scan[]>("/api/scans");
  const reports = useApi<Report[]>("/api/reports");
  const filter = useCollectionFilter(scans.data ?? []);
  const scanById = useMemo(() => new Map((scans.data ?? []).map((s) => [s.id, s])), [scans.data]);

  const rows = useMemo(() => {
    return (reports.data ?? []).filter((r) => {
      if (filter.scan) return r.scan_id === filter.scan;
      return filter.scanIDs.has(r.scan_id);
    });
  }, [reports.data, filter.scan, filter.scanIDs]);

  return (
    <div>
      <PageTitle
        title="Reports"
        subtitle={`Every generated report — ${rows.length} shown. The scan's evidence stays the source of truth.`}
      />
      {scans.loading && !scans.data ? (
        <Loading />
      ) : (
        <>
          <FilterBar
            project={filter.project}
            setProject={filter.setProject}
            scan={filter.scan}
            setScan={filter.setScan}
            projects={filter.projects}
            scans={filter.projectScans}
          />
          {reports.loading && !reports.data ? (
            <Loading />
          ) : rows.length === 0 ? (
            <Empty>No reports in this selection. Generate one from a scan's Reports tab.</Empty>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Format</TableHead>
                      <TableHead>Template</TableHead>
                      <TableHead>Findings</TableHead>
                      <TableHead>Scan</TableHead>
                      <TableHead>Project</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((r) => {
                      const sc = scanById.get(r.scan_id);
                      const projectName = filter.projects.find((p) => p.id === sc?.project_id)?.name ?? "—";
                      const total = Number((r.summary as { total_findings?: number } | undefined)?.total_findings ?? 0);
                      return (
                        <TableRow key={r.id}>
                          <TableCell>
                            <Badge tone="success">{r.format}</Badge>
                          </TableCell>
                          <TableCell className="text-[11px] text-muted-foreground">{r.template || "—"}</TableCell>
                          <TableCell className="tabular-nums text-xs">{total}</TableCell>
                          <TableCell>
                            <a
                              href={`#/scans/${r.scan_id}?tab=reports`}
                              className="font-mono text-[11px] text-emerald-700 hover:underline dark:text-emerald-400"
                            >
                              {shortId(r.scan_id)}
                            </a>
                          </TableCell>
                          <TableCell className="text-[11px] text-muted-foreground">{projectName}</TableCell>
                          <TableCell className="text-[11px] text-muted-foreground">{formatTime(r.created_at)}</TableCell>
                          <TableCell className="text-right">
                            <a
                              href={`/api/reports/${r.id}/content`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[11px] text-emerald-700 hover:underline dark:text-emerald-400"
                            >
                              open
                            </a>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
