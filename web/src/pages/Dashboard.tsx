import { useMemo } from "react";
import { ArrowUpRight, ScanLine, ShieldAlert, ShieldCheck, Target } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge, StateBadge, VerdictBadge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Loading, Stat } from "@/components/ui/misc";
import { useApi } from "@/lib/api";
import type { Finding, Project, Scan, Target as TargetType } from "@/lib/types";
import { navigate } from "@/lib/router";
import { formatTime, pct, shortId } from "@/lib/utils";

export default function Dashboard() {
  const projects = useApi<Project[]>("/api/projects");
  const scans = useApi<Scan[]>("/api/scans", [], 5000);
  const targets = useApi<TargetType[] | null>(null);

  const list = scans.data ?? [];
  const states = useMemo(() => {
    const by = new Map<string, number>();
    for (const s of list) by.set(s.state, (by.get(s.state) ?? 0) + 1);
    return by;
  }, [list]);

  const confirmed = list.reduce((n, s) => n + (s.stats?.findings_confirmed ?? 0), 0);
  const rejected = list.reduce((n, s) => n + (s.stats?.findings_rejected ?? 0), 0);

  // Recent findings come from the most recent scans; the API is per scan, so
  // fetch a bounded slice of the newest ones.
  const recent = [...list]
    .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))
    .slice(0, 3);
  const findingsByScan = useApi<Finding[]>(
    recent[0] ? `/api/scans/${recent[0].id}/findings` : null,
  );

  return (
    <div>
      <PageTitle
        title="Dashboard"
        subtitle="Coverage, throughput and the newest confirmed findings across this control plane."
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Projects" value={projects.data?.length ?? "—"} hint="scoped targets" />
        <Stat label="Scans" value={list.length} hint={`${states.get("running") ?? 0} running`} />
        <Stat label="Confirmed findings" value={confirmed} tone="danger" hint="all scans" />
        <Stat
          label="Rejected / verified-clean"
          value={rejected}
          tone="success"
          hint={`${pct(rejected, confirmed + rejected)}% of tested points`}
        />
      </div>

      <div className="mt-4 grid min-w-0 gap-4 lg:grid-cols-3">
        <Card className="min-w-0 lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <ScanLine className="size-4 text-emerald-700 dark:text-emerald-400" /> Recent scans
            </CardTitle>
            <a href="#/scans" className="text-[11px] text-emerald-700 dark:text-emerald-400 hover:underline">
              all scans <ArrowUpRight className="inline size-3" />
            </a>
          </CardHeader>
          <CardContent className="p-0">
            {scans.loading && !scans.data ? (
              <Loading />
            ) : list.length === 0 ? (
              <div className="p-4">
                <Empty>No scans yet. Create a project, add a target, then start a scan.</Empty>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Scan</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Confirmed</TableHead>
                    <TableHead>Endpoints</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {[...list]
                    .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))
                    .slice(0, 8)
                    .map((s) => (
                      <TableRow
                        key={s.id}
                        className="cursor-pointer"
                        onClick={() => navigate(`/scans/${s.id}`)}
                      >
                        <TableCell>
                          <div className="mono text-[11px] text-muted-foreground">{shortId(s.id)}</div>
                          <div className="max-w-[22rem] truncate text-xs text-foreground">
                            {s.name || s.seed_urls?.[0] || "—"}
                          </div>
                        </TableCell>
                        <TableCell>
                          <StateBadge state={s.state} />
                        </TableCell>
                        <TableCell className="tabular-nums">{s.stats?.findings_confirmed ?? 0}</TableCell>
                        <TableCell className="tabular-nums">{s.stats?.endpoints_discovered ?? 0}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatTime(s.created_at)}</TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="size-4 text-amber-700 dark:text-amber-400" /> Newest findings
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {findingsByScan.loading ? (
              <Loading />
            ) : (findingsByScan.data ?? []).length === 0 ? (
              <p className="text-xs text-muted-foreground">No findings on the newest scan.</p>
            ) : (
              (findingsByScan.data ?? []).slice(0, 8).map((f) => (
                <button
                  key={f.id}
                  onClick={() => navigate(`/scans/${f.scan_id}?tab=findings`)}
                  className="w-full rounded-md border border-border bg-muted p-2 text-left hover:border-border"
                >
                  <div className="flex items-center gap-2">
                    <VerdictBadge verdict={f.verdict} />
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <div className="mt-1 line-clamp-2 text-xs text-foreground">{f.title}</div>
                </button>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="size-4 text-sky-700 dark:text-sky-400" /> Projects
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {(projects.data ?? []).length === 0 ? (
              <p className="text-xs text-muted-foreground">No projects yet.</p>
            ) : (
              (projects.data ?? []).slice(0, 6).map((p) => (
                <button
                  key={p.id}
                  onClick={() => navigate(`/projects/${p.id}`)}
                  className="flex w-full items-center justify-between rounded-md border border-border bg-muted px-2.5 py-2 text-left hover:border-border"
                >
                  <span className="truncate text-xs text-foreground">{p.name}</span>
                  <span className="mono text-[10px] text-muted-foreground">{shortId(p.id)}</span>
                </button>
              ))
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-emerald-700 dark:text-emerald-400" /> Scan states
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {["queued", "running", "paused", "completed", "failed", "canceled"].map((s) => (
              <div
                key={s}
                className="flex items-center gap-2 rounded-md border border-border bg-muted px-2.5 py-1.5"
              >
                <StateBadge state={s} />
                <span className="tabular-nums text-xs text-foreground">{states.get(s) ?? 0}</span>
              </div>
            ))}
            {targets.data === null ? null : null}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
