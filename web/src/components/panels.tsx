import { useMemo, useState } from "react";
import { ExternalLink, FileText, Plus } from "lucide-react";
import { Badge, SeverityBadge, VerdictBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, Switch } from "@/components/ui/controls";
import { Input } from "@/components/ui/input";
import { Code, Empty, Loading } from "@/components/ui/misc";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, refreshAll, useApi } from "@/lib/api";
import type { Coverage, EndpointRow, Evidence, Finding, Report, TestRow } from "@/lib/types";
import { formatTime, shortId } from "@/lib/utils";

function decodeDetail(detail?: string): unknown {
  if (!detail) return undefined;
  try {
    const text = atob(detail);
    return JSON.parse(text);
  } catch {
    return detail;
  }
}

/* Findings ---------------------------------------------------------------- */

export function FindingsPanel({ scanId }: { scanId: string }) {
  const [verdict, setVerdict] = useState("");
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const findings = useApi<Finding[]>(
    `/api/scans/${scanId}/findings${verdict ? `?verdict=${verdict}` : ""}`,
    [verdict],
    5000,
  );

  const rows = (findings.data ?? []).filter((f) => !severity || f.severity === severity);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1.5">
        {[
          ["", "All"],
          ["confirmed", "Confirmed"],
          ["rejected", "Rejected"],
          ["inconclusive", "Inconclusive"],
        ].map(([value, label]) => (
          <button
            key={value}
            onClick={() => setVerdict(value)}
            className={`rounded-md border px-2.5 py-1 text-[11px] ${
              verdict === value
                ? "border-emerald-200 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-400"
                : "border-border text-muted-foreground hover:bg-muted"
            }`}
          >
            {label}
          </button>
        ))}
        <span className="mx-1 h-4 w-px bg-muted" />
        {["", "critical", "high", "medium", "low"].map((value) => (
          <button
            key={value}
            onClick={() => setSeverity(value)}
            className={`rounded-md border px-2.5 py-1 text-[11px] ${
              severity === value
                ? "border-border bg-muted text-foreground"
                : "border-border text-muted-foreground hover:bg-muted"
            }`}
          >
            {value || "Any severity"}
          </button>
        ))}
      </div>

      {findings.loading && !findings.data ? (
        <Loading />
      ) : rows.length === 0 ? (
        <Empty>No findings match this filter.</Empty>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Class</TableHead>
                  <TableHead>Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((f) => (
                  <TableRow key={f.id} className="cursor-pointer" onClick={() => setSelected(f)}>
                    <TableCell>
                      <VerdictBadge verdict={f.verdict} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={f.severity} />
                    </TableCell>
                    <TableCell className="max-w-[34rem]">
                      <div className="truncate text-xs text-foreground">{f.title}</div>
                      <div className="truncate text-[11px] text-muted-foreground">{f.summary}</div>
                    </TableCell>
                    <TableCell>
                      <Badge tone="violet">{f.vuln_class}</Badge>
                    </TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{formatTime(f.updated_at ?? f.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Dialog open={Boolean(selected)} onOpenChange={(v) => !v && setSelected(null)}>
        {selected ? (
          <DialogContent
            title={selected.title}
            description={`${selected.vuln_class} · ${selected.verdict} · ${selected.severity} · confidence ${selected.confidence}`}
            className="max-w-3xl"
          >
            <div className="max-h-[65vh] space-y-3 overflow-y-auto pr-1">
              <p className="text-xs leading-relaxed text-foreground">{selected.summary}</p>
              <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                <span className="mono">id {shortId(selected.id)}</span>
                <span className="mono">engine {selected.provenance?.engine ?? "—"}</span>
                <span className="mono">source {selected.provenance?.discovery_source ?? "—"}</span>
              </div>
              {selected.evidence_ids?.length ? (
                <div className="flex flex-wrap gap-2">
                  {selected.evidence_ids.map((id) => (
                    <a
                      key={id}
                      href={`/api/evidence/${id}/content`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] text-emerald-700 dark:text-emerald-400 hover:bg-muted"
                    >
                      evidence {shortId(id)} <ExternalLink className="size-3" />
                    </a>
                  ))}
                </div>
              ) : null}
              {selected.detail ? (
                <Code>{JSON.stringify(decodeDetail(selected.detail), null, 2)}</Code>
              ) : null}
            </div>
          </DialogContent>
        ) : null}
      </Dialog>
    </div>
  );
}

/* Evidence ---------------------------------------------------------------- */

export function EvidencePanel({ scanId }: { scanId: string }) {
  const evidence = useApi<Evidence[]>(`/api/scans/${scanId}/evidence`);
  if (evidence.loading && !evidence.data) return <Loading />;
  if (!(evidence.data ?? []).length) return <Empty>No evidence recorded yet.</Empty>;
  return (
    <Card>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Kind</TableHead>
              <TableHead>Note</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Created</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {(evidence.data ?? []).map((e) => (
              <TableRow key={e.id}>
                <TableCell>
                  <Badge tone="info">{e.kind}</Badge>
                </TableCell>
                <TableCell className="max-w-[28rem] truncate text-xs text-muted-foreground">{e.note ?? "—"}</TableCell>
                <TableCell className="mono text-[11px] text-muted-foreground">{e.media_type ?? "—"}</TableCell>
                <TableCell className="tabular-nums text-xs text-muted-foreground">
                  {(e.size / 1024).toFixed(1)} KB
                </TableCell>
                <TableCell className="text-[11px] text-muted-foreground">{formatTime(e.created_at)}</TableCell>
                <TableCell className="text-right">
                  <a
                    href={`/api/evidence/${e.id}/content`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] text-emerald-700 dark:text-emerald-400 hover:underline"
                  >
                    open <ExternalLink className="size-3" />
                  </a>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

/* Reports ----------------------------------------------------------------- */

export function ReportsPanel({ scanId }: { scanId: string }) {
  const reports = useApi<Report[]>(`/api/scans/${scanId}/reports`);
  const [format, setFormat] = useState("html");
  const [mode, setMode] = useState("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function create() {
    setBusy(true);
    setError("");
    try {
      await api(`/api/scans/${scanId}/reports`, {
        method: "POST",
        body: { format, mode: mode === "all" ? "all" : "confirmed" },
      });
      refreshAll();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <Card>
        <CardContent className="flex flex-wrap items-end gap-2 p-3">
          <div className="flex flex-col gap-1">
            <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Format</span>
            <select
              className="h-8 rounded-md border border-border bg-background px-2 text-xs"
              value={format}
              onChange={(e) => setFormat(e.target.value)}
            >
              {["html", "markdown", "json"].map((f) => (
                <option key={f}>{f}</option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Findings</span>
            <select
              className="h-8 rounded-md border border-border bg-background px-2 text-xs"
              value={mode}
              onChange={(e) => setMode(e.target.value)}
            >
              <option value="all">all</option>
              <option value="confirmed">confirmed only</option>
            </select>
          </div>
          <Button size="sm" onClick={create} disabled={busy}>
            <Plus className="size-4" /> {busy ? "Generating…" : "Generate report"}
          </Button>
          <a
            href={`/api/scans/${scanId}/reports/preview?format=${format}&mode=${mode}`}
            target="_blank"
            rel="noreferrer"
            className="text-[11px] text-emerald-700 dark:text-emerald-400 hover:underline"
          >
            preview
          </a>
          {error ? <span className="text-[11px] text-red-700 dark:text-red-400">{error}</span> : null}
        </CardContent>
      </Card>

      {reports.loading && !reports.data ? (
        <Loading />
      ) : (reports.data ?? []).length === 0 ? (
        <Empty>No reports generated for this scan yet.</Empty>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Format</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(reports.data ?? []).map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <Badge tone="success">
                        <FileText className="size-3" /> {r.format}
                      </Badge>
                    </TableCell>
                    <TableCell className="mono text-[11px] text-muted-foreground">{shortId(r.id)}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{formatTime(r.created_at)}</TableCell>
                    <TableCell className="text-right">
                      <a
                        href={`/api/reports/${r.id}/content`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-emerald-700 dark:text-emerald-400 hover:underline"
                      >
                        open
                      </a>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* Coverage ---------------------------------------------------------------- */

export function CoveragePanel({ scanId }: { scanId: string }) {
  const coverage = useApi<Coverage>(`/api/scans/${scanId}/coverage`, [], 5000);
  const data = coverage.data ?? {};
  const entries = Object.entries(data).filter(([k]) => k !== "scan_id");

  return (
    <div className="space-y-3">
      <Card>
        <CardContent className="p-3">
          <p className="text-[11px] leading-relaxed text-muted-foreground">
            Coverage is what the engine actually exercised, not what it could run. A point skipped for
            CAPTCHA, incomplete evidence, no replayable verifier, an already-recorded bypass attempt, or
            429/503 backpressure is listed with that reason — it is never counted as clean.
          </p>
        </CardContent>
      </Card>
      {coverage.loading && !coverage.data ? (
        <Loading />
      ) : entries.length === 0 ? (
        <Empty>No coverage data yet.</Empty>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {entries.map(([key, value]) => (
            <div key={key} className="rounded-lg border border-border bg-muted p-3">
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{key.replaceAll("_", " ")}</div>
              <div className="mt-1 text-sm text-foreground">
                {typeof value === "object" ? (
                  <Code className="max-h-40">{JSON.stringify(value, null, 2)}</Code>
                ) : (
                  String(value)
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* Endpoints --------------------------------------------------------------- */

export function EndpointsPanel({ scanId }: { scanId: string }) {
  const endpoints = useApi<EndpointRow[]>(`/api/scans/${scanId}/endpoints`, [], 5000);
  if (endpoints.loading && !endpoints.data) return <Loading />;
  if (!(endpoints.data ?? []).length) return <Empty>No endpoints discovered yet.</Empty>;
  return (
    <Card>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Method</TableHead>
              <TableHead>URL</TableHead>
              <TableHead>Parameters</TableHead>
              <TableHead>Type</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(endpoints.data ?? []).map((e) => (
              <TableRow key={e.id}>
                <TableCell>
                  <Badge tone="info">{e.method}</Badge>
                </TableCell>
                <TableCell className="mono max-w-[36rem] truncate text-[11px] text-foreground">{e.url}</TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {(e.parameters ?? []).map((p) => p.name).join(", ") || "—"}
                </TableCell>
                <TableCell className="mono text-[11px] text-muted-foreground">{e.content_type ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

/* Explorer ---------------------------------------------------------------- */

interface ExplorerItem {
  id: string;
  method: string;
  url: string;
  source?: string;
  content_type?: string;
  status: string;
  gap: boolean;
  dom_scheduled?: boolean;
  parameters?: Array<{ name?: string; location?: string; gap?: boolean }>;
  dom?: Array<{ source?: string; sink?: string }>;
}

interface ExplorerResponse {
  total: number;
  limit: number;
  offset: number;
  summary?: Record<string, unknown>;
  items: ExplorerItem[];
}

export function ExplorerPanel({ scanId }: { scanId: string }) {
  const [q, setQ] = useState("");
  const [gaps, setGaps] = useState(false);
  const query = new URLSearchParams();
  if (q.trim()) query.set("q", q.trim());
  if (gaps) query.set("gaps", "1");
  query.set("limit", "200");
  const explorer = useApi<ExplorerResponse>(`/api/scans/${scanId}/explorer?${query.toString()}`, [q, gaps], 5000);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by URL…"
          className="h-8 max-w-xs text-xs"
        />
        <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <Switch checked={gaps} onCheckedChange={setGaps} /> Only endpoints with gaps
        </label>
        <span className="text-[11px] text-muted-foreground">{explorer.data?.total ?? 0} endpoints</span>
      </div>
      {explorer.loading && !explorer.data ? (
        <Loading />
      ) : !(explorer.data?.items ?? []).length ? (
        <Empty>No endpoints match this filter.</Empty>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Method</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Gap</TableHead>
                  <TableHead>Parameters</TableHead>
                  <TableHead>DOM</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(explorer.data?.items ?? []).map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>
                      <Badge tone="info">{e.method}</Badge>
                    </TableCell>
                    <TableCell className="mono max-w-[30rem] truncate text-[11px] text-foreground">{e.url}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{e.status}</TableCell>
                    <TableCell>{e.gap ? <Badge tone="warn">gap</Badge> : <span className="text-[11px] text-muted-foreground">—</span>}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">
                      {(e.parameters ?? []).map((p) => p.name).filter(Boolean).join(", ") || "—"}
                    </TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">
                      {(e.dom ?? []).map((d) => d.sink).filter(Boolean).join(", ") || (e.dom_scheduled ? "scheduled" : "—")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* IDOR candidates ---------------------------------------------------------- */

interface IDORCandidate {
  value: string;
  shape: string;
  origin?: { source?: string; url?: string } | string;
  observed_count?: number;
}

interface IDORResponse {
  scan_id: string;
  candidates: IDORCandidate[];
  total: number;
  note?: string;
}

export function IDORPanel({ scanId }: { scanId: string }) {
  const candidates = useApi<IDORResponse>(`/api/scans/${scanId}/idor/candidates`);
  if (candidates.loading && !candidates.data) return <Loading />;
  const list = candidates.data?.candidates ?? [];
  return (
    <div className="space-y-3">
      {candidates.data?.note ? <p className="text-[11px] text-muted-foreground">{candidates.data.note}</p> : null}
      {list.length === 0 ? (
        <Empty>No harvested object identifiers for this scan.</Empty>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Value</TableHead>
                  <TableHead>Shape</TableHead>
                  <TableHead>Origin</TableHead>
                  <TableHead>Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((c, i) => (
                  <TableRow key={`${c.value}-${i}`}>
                    <TableCell className="mono text-[11px] text-foreground">{c.value}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{c.shape}</TableCell>
                    <TableCell className="max-w-[26rem] truncate text-[11px] text-muted-foreground">
                      {typeof c.origin === "string" ? c.origin : c.origin?.url ?? c.origin?.source ?? "—"}
                    </TableCell>
                    <TableCell className="tabular-nums text-xs text-muted-foreground">{c.observed_count ?? 1}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* Tests ------------------------------------------------------------------- */

export function TestsPanel({ scanId }: { scanId: string }) {
  const tests = useApi<TestRow[]>(`/api/scans/${scanId}/tests`, [], 5000);
  const rows = tests.data ?? [];
  const [filter, setFilter] = useState("");
  const visible = useMemo(() => rows.filter((t) => !filter || t.vuln_class === filter), [rows, filter]);
  const classes = useMemo(() => Array.from(new Set(rows.map((t) => t.vuln_class))).sort(), [rows]);

  if (tests.loading && !tests.data) return <Loading />;
  if (!rows.length) return <Empty>No test cases recorded yet.</Empty>;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5">
        <button
          onClick={() => setFilter("")}
          className={`rounded-md border px-2.5 py-1 text-[11px] ${
            filter === "" ? "border-emerald-200 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-400" : "border-border text-muted-foreground"
          }`}
        >
          all ({rows.length})
        </button>
        {classes.map((c) => (
          <button
            key={c}
            onClick={() => setFilter(c)}
            className={`rounded-md border px-2.5 py-1 text-[11px] ${
              filter === c ? "border-emerald-200 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-400" : "border-border text-muted-foreground"
            }`}
          >
            {c} ({rows.filter((t) => t.vuln_class === c).length})
          </button>
        ))}
      </div>
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Class</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Note</TableHead>
                <TableHead>Finished</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.slice(0, 300).map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    <Badge tone="violet">{t.vuln_class}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-foreground">{t.outcome ?? t.status}</TableCell>
                  <TableCell className="mono max-w-[26rem] truncate text-[11px] text-muted-foreground">
                    {t.method ? `${t.method} ` : ""}
                    {t.url ?? "—"}
                  </TableCell>
                  <TableCell className="max-w-[24rem] truncate text-[11px] text-muted-foreground">{t.note ?? "—"}</TableCell>
                  <TableCell className="text-[11px] text-muted-foreground">{formatTime(t.finished_at ?? t.started_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
