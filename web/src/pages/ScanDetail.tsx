import { useEffect, useState } from "react";
import { Pause, Play, RotateCcw, Square, SlidersHorizontal } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Badge, StateBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, Switch, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/controls";
import { Field, Input } from "@/components/ui/input";
import { Alert, Code, Loading, Stat } from "@/components/ui/misc";
import { AIAssistPanel, CoveragePanel, EndpointsPanel, EvidencePanel, ExplorerPanel, FindingsPanel, IDORPanel, ReportsPanel, TestsPanel } from "@/components/panels";
import { api, refreshAll, useApi } from "@/lib/api";
import type { Scan, ScanTechInventory } from "@/lib/types";
import { formatTime, pct, shortId } from "@/lib/utils";

interface QueueStats {
  queued: number;
  leased: number;
  running: number;
  succeeded: number;
  failed: number;
  canceled: number;
  dead: number;
}

function currentTab(): string {
  const hash = window.location.hash;
  const i = hash.indexOf("?");
  if (i < 0) return "overview";
  return new URLSearchParams(hash.slice(i + 1)).get("tab") ?? "overview";
}

export default function ScanDetail({ id }: { id: string }) {
  const targetPolicy = useApi<{ target_read_only: boolean }>("/api/capabilities");
  const scan = useApi<Scan>(`/api/scans/${id}`, [], 3000);
  // The queue is the source of truth for job progress. Reading it separately
  // keeps the denominator stable when cancel moves queued jobs to canceled:
  // 1200/1400 must not become 1200/1200.
  const jobStats = useApi<QueueStats>(`/api/scans/${id}/stats`, [], 3000);
  const tech = useApi<ScanTechInventory>(
    `/api/scans/${id}/tech`,
    [id, scan.data?.state],
    scan.data?.state === "running" ? 5000 : 0,
  );
  const [tab, setTab] = useState(currentTab());

  // Keep the active tab in the hash so a deep link, a reload and Back/Forward
  // all land on the same view — and so the browser's own navigation drives it.
  useEffect(() => {
    const onHash = () => setTab(currentTab());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  function changeTab(next: string) {
    setTab(next);
    const base = window.location.hash.split("?")[0] || `#/scans/${id}`;
    window.location.hash = `${base}?tab=${next}`;
  }
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [tuneOpen, setTuneOpen] = useState(false);
  const [tune, setTune] = useState({ discovery: 2, http: 4, browser: 1, rate: 2 });
  const [capOpen, setCapOpen] = useState(false);
  const [caps, setCaps] = useState({
    reflected: true,
    dom: true,
    access: true,
    idor: true,
    disclosure: true,
    ssrf: true,
    cors: true,
    openRedirect: true,
    graphql: true,
    csrf: true,
    prototypePollution: true,
    cachePoisoning: true,
    fileUpload: true,
    command: false,
    ssti: false,
    sqli: false,
    nosqli: false,
    xxe: false,
    storedXSS: false,
  });

  useEffect(() => {
    if (scan.data?.config) {
      setTune({
        discovery: scan.data.config.discovery_concurrency ?? 2,
        http: scan.data.config.http_concurrency ?? 4,
        browser: scan.data.config.browser_concurrency ?? 1,
        rate: scan.data.config.requests_per_second ?? 2,
      });
    }
  }, [scan.data?.id]);

  useEffect(() => {
    const c = scan.data?.config;
    if (!c) return;
    setCaps({
      reflected: !c.skip_reflected_xss,
      dom: !c.skip_dom_xss,
      access: !c.skip_access_control,
      idor: !c.skip_idor,
      disclosure: !c.skip_info_disclosure,
      ssrf: !c.skip_ssrf,
      cors: !c.skip_cors,
      openRedirect: !c.skip_open_redirect,
      graphql: !c.skip_graphql,
      csrf: !c.skip_csrf,
      prototypePollution: !c.skip_prototype_pollution,
      cachePoisoning: !c.skip_cache_poisoning,
      fileUpload: !c.skip_file_upload,
      command: Boolean(c.enable_command_injection),
      ssti: Boolean(c.enable_ssti),
      sqli: Boolean(c.enable_sqli),
      nosqli: Boolean(c.enable_nosqli),
      xxe: Boolean(c.enable_xxe),
      storedXSS: Boolean(c.enable_stored_xss),
    });
  }, [scan.data?.id, scan.data?.updated_at]);

  async function act(action: string) {
    setBusy(action);
    setError("");
    try {
      await api(`/api/scans/${id}/${action}`, { method: "POST" });
      refreshAll();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  async function saveTune() {
    setBusy("tune");
    setError("");
    try {
      await api(`/api/scans/${id}/config`, {
        method: "POST",
        body: {
          discovery_concurrency: tune.discovery,
          http_concurrency: tune.http,
          browser_concurrency: tune.browser,
          requests_per_second: tune.rate,
        },
      });
      setTuneOpen(false);
      refreshAll();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  async function saveCapabilities() {
    setBusy("caps");
    setError("");
    try {
      await api(`/api/scans/${id}/capabilities`, {
        method: "PUT",
        body: {
          skip_reflected_xss: !caps.reflected,
          skip_dom_xss: !caps.dom,
          skip_access_control: !caps.access,
          skip_idor: !caps.idor,
          skip_info_disclosure: !caps.disclosure,
          skip_ssrf: !caps.ssrf,
          skip_cors: !caps.cors,
          skip_open_redirect: !caps.openRedirect,
          skip_graphql: !caps.graphql,
          skip_csrf: !caps.csrf,
          skip_prototype_pollution: !caps.prototypePollution,
          skip_cache_poisoning: !caps.cachePoisoning,
          skip_file_upload: !caps.fileUpload,
          enable_command_injection: caps.command,
          enable_ssti: caps.ssti,
          enable_sqli: caps.sqli,
          enable_nosqli: caps.nosqli,
          enable_xxe: caps.xxe,
          enable_stored_xss: caps.storedXSS,
        },
      });
      setCapOpen(false);
      refreshAll();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  const s = scan.data;
  if (!s && scan.loading) return <Loading label="Loading scan…" />;
  if (!s) return <Alert>{scan.error ?? "Scan not found."}</Alert>;

  const stats = s.stats;
  const jobsTotal = jobStats.data
    ? jobStats.data.queued + jobStats.data.leased + jobStats.data.running +
      jobStats.data.succeeded + jobStats.data.failed + jobStats.data.canceled + jobStats.data.dead
    : stats?.jobs_total ?? (stats?.jobs_completed ?? 0) + (stats?.jobs_queued ?? 0);
  const jobsDone = jobStats.data?.succeeded ?? stats?.jobs_completed ?? 0;
  const jobsCanceled = jobStats.data?.canceled ?? stats?.jobs_canceled ?? 0;
  const jobsFailed = jobStats.data?.failed ?? stats?.jobs_failed ?? 0;
  const activeScanAllowed = targetPolicy.data?.target_read_only === false;
  const canStart = activeScanAllowed && ["created", "queued", "draft"].includes(s.state);
  const canPause = s.state === "running";
  const canResume = activeScanAllowed && ["paused", "awaiting_auth"].includes(s.state);
  const canCancel = ["running", "paused", "queued"].includes(s.state);

  return (
    <div>
      <PageTitle
        title={s.name || s.seed_urls?.[0] || `Scan ${shortId(s.id)}`}
        subtitle={`${shortId(s.id)} · ${s.profile} · created ${formatTime(s.created_at)}`}
        actions={
          <>
            {canStart ? (
              <Button size="sm" disabled={busy === "start"} onClick={() => act("start")}>
                <Play className="size-4" /> Start
              </Button>
            ) : null}
            {canPause ? (
              <Button size="sm" variant="secondary" disabled={busy === "pause"} onClick={() => act("pause")}>
                <Pause className="size-4" /> Pause
              </Button>
            ) : null}
            {canResume ? (
              <Button size="sm" variant="secondary" disabled={busy === "resume"} onClick={() => act("resume")}>
                <RotateCcw className="size-4" /> Resume
              </Button>
            ) : null}
            {canCancel ? (
              <Button size="sm" variant="destructive" disabled={busy === "cancel"} onClick={() => act("cancel")}>
                <Square className="size-4" /> Cancel
              </Button>
            ) : null}
            {activeScanAllowed ? <Button size="sm" variant="outline" onClick={() => setTuneOpen(true)}>
              <SlidersHorizontal className="size-4" /> Tune
            </Button> : null}
            {activeScanAllowed && s.state === "created" ? (
              <Button size="sm" variant="outline" onClick={() => setCapOpen(true)}>
                Capabilities
              </Button>
            ) : null}
          </>
        }
      />

      {targetPolicy.data?.target_read_only ? (
        <p className="mb-3 text-xs text-muted-foreground">
          Stored scan. Use <a className="underline" href={`#/projects/${s.project_id}`}>Read-only snapshot in this project</a> for a new target read.
        </p>
      ) : null}
      {error ? <Alert className="mb-3">{error}</Alert> : null}
      {s.error ? <Alert className="mb-3">{s.error}</Alert> : null}

      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-6">
        <Stat label="State" value={<StateBadge state={s.state} />} />
        <Stat label="Endpoints" value={stats?.endpoints_discovered ?? 0} />
        <Stat label="Parameters" value={stats?.parameters_discovered ?? 0} />
        <Stat label="Confirmed" value={stats?.findings_confirmed ?? 0} tone="danger" />
        <Stat label="Rejected" value={stats?.findings_rejected ?? 0} tone="success" />
        <Stat
          label="Jobs"
          value={`${jobsDone}/${jobsTotal}`}
          hint={`${pct(jobsDone, jobsTotal)}% done${jobsCanceled ? ` · ${jobsCanceled} canceled` : ""}${jobsFailed ? ` · ${jobsFailed} failed` : ""}`}
        />
      </div>

      <Tabs value={tab} onValueChange={changeTab}>
        <TabsList className="flex-wrap">
          {[
            ["overview", "Overview"],
            ["findings", "Findings"],
            ["coverage", "Coverage"],
            ["explorer", "Explorer"],
            ["endpoints", "Endpoints"],
            ["tests", "Tests"],
            ["evidence", "Evidence"],
            ["reports", "Reports"],
            ["idor", "IDOR"],
            ["ai", "AI advisory"],
          ].map(([value, label]) => (
            <TabsTrigger key={value} value={value}>
              {label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="overview">
          <div className="grid gap-4 lg:grid-cols-2">
            <TechStackCard tech={tech.data} />

            <Card>
              <CardHeader>
                <CardTitle>Configuration</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs text-foreground">
                <Row label="Profile" value={<Badge tone="violet">{s.profile}</Badge>} />
                <Row label="Discovery" value={s.discovery ?? "—"} />
                <Row
                  label="Seeds"
                  value={<span className="mono text-[11px]">{(s.seed_urls ?? []).join(", ") || "target base URL"}</span>}
                />
                <Row
                  label="Limits"
                  value={`depth ${s.config.max_depth ?? "—"} · pages ${s.config.max_pages ?? "—"} · endpoints ${s.config.max_endpoints ?? "—"}`}
                />
                <Row
                  label="Concurrency"
                  value={`disc ${s.config.discovery_concurrency ?? "—"} · http ${s.config.http_concurrency ?? "—"} · browser ${s.config.browser_concurrency ?? "—"} · rate ${s.config.requests_per_second ?? "—"}/s`}
                />
                <Row label="Stop policy" value={`${s.stop?.mode ?? "continue_all"}${s.stop?.confirmed_limit ? ` (${s.stop.confirmed_limit})` : ""}`} />
                <Row label="Session" value={s.session_id ? shortId(s.session_id) : "anonymous"} />
                <Row label="Started" value={formatTime(s.started_at)} />
                <Row label="Ended" value={formatTime(s.ended_at)} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Raw status</CardTitle>
              </CardHeader>
              <CardContent>
                <Code>{JSON.stringify(s, null, 2)}</Code>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="findings">
          <FindingsPanel scanId={id} />
        </TabsContent>
        <TabsContent value="coverage">
          <CoveragePanel scanId={id} />
        </TabsContent>
        <TabsContent value="explorer">
          <ExplorerPanel scanId={id} />
        </TabsContent>
        <TabsContent value="endpoints">
          <EndpointsPanel scanId={id} />
        </TabsContent>
        <TabsContent value="tests">
          <TestsPanel scanId={id} />
        </TabsContent>
        <TabsContent value="evidence">
          <EvidencePanel scanId={id} />
        </TabsContent>
        <TabsContent value="reports">
          <ReportsPanel scanId={id} />
        </TabsContent>
        <TabsContent value="idor">
          <IDORPanel scanId={id} />
        </TabsContent>
        <TabsContent value="ai">
          <AIAssistPanel scanId={id} />
        </TabsContent>
      </Tabs>

      <Dialog open={tuneOpen} onOpenChange={setTuneOpen}>
        <DialogContent
          title="Runtime controls"
          description="Concurrency and rate only; crawl extent is fixed at creation."
        >
          <div className="grid grid-cols-2 gap-3">
            <Field label="Discovery concurrency">
              <Input
                type="number"
                value={tune.discovery}
                onChange={(e) => setTune({ ...tune, discovery: Number(e.target.value) })}
              />
            </Field>
            <Field label="HTTP concurrency">
              <Input
                type="number"
                value={tune.http}
                onChange={(e) => setTune({ ...tune, http: Number(e.target.value) })}
              />
            </Field>
            <Field label="Browser concurrency">
              <Input
                type="number"
                value={tune.browser}
                onChange={(e) => setTune({ ...tune, browser: Number(e.target.value) })}
              />
            </Field>
            <Field label="Requests / second">
              <Input
                type="number"
                step="0.5"
                value={tune.rate}
                onChange={(e) => setTune({ ...tune, rate: Number(e.target.value) })}
              />
            </Field>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setTuneOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={saveTune} disabled={busy === "tune"}>
              {busy === "tune" ? "Saving…" : "Apply"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={capOpen} onOpenChange={setCapOpen}>
        <DialogContent
          title="Attack capabilities"
          description="Changes are allowed until the scan starts. Imported scans start as drafts, so their defaults can be adjusted here before the first start."
        >
          <div className="space-y-3">
            {[
              ["reflected", "Reflected XSS", "Per-parameter reflection and candidate jobs."],
              ["dom", "DOM XSS + client redirect", "Browser taint analysis and client-side open-redirect probe."],
              ["access", "Access control", "Role/flag/field and admin-path checks."],
              ["idor", "IDOR", "Object-family and identifier checks."],
              ["disclosure", "Information disclosure", "Sensitive files, SCM/git exposure and error probes."],
              ["ssrf", "SSRF", "URL-like parameters probed with an OAST canary; confirmed only by a marker-bearing callback."],
              ["cors", "CORS", "Origin-reflection checks on cross-origin responses."],
              ["openRedirect", "Open redirect", "Redirect targets that leave the site's own origin."],
              ["graphql", "GraphQL", "Introspection and field-level authorization probes on GraphQL endpoints."],
              ["csrf", "CSRF", "Cross-site request forgery token and SameSite/origin protection checks on state-changing endpoints."],
              ["prototypePollution", "Prototype pollution", "Client-side and server-side __proto__/constructor payload probes."],
              ["cachePoisoning", "Cache poisoning", "Unkeyed header and query parameter reflection checks on cacheable responses."],
              ["fileUpload", "File upload", "Bounded multipart extension and MIME validation checks on upload endpoints (requires -allow-state-changing)."],
              ["command", "OS command injection", "Opt-in marker probes; confirms two independent executions."],
              ["ssti", "Server-side template injection", "Opt-in arithmetic template probes; confirms two independent evaluations."],
              ["sqli", "SQL injection", "Opt-in quote-breaking and boolean pairs; confirmed by the database's own error signature."],
              ["nosqli", "NoSQL injection", "Opt-in checks on GET query parameters. JSON request bodies on write methods require server permission and a scan that includes write-like endpoints."],
              ["xxe", "XML external entity", "Opt-in XML-body probes; confirms in-band entity expansion, and uses your callback when one is set."],
              ["storedXSS", "Stored XSS", "Opt-in state-changing canary probes verified across subsequent crawled pages."],
            ].map(([key, label, hint]) => (
              <label key={key} className="flex items-start justify-between gap-4 rounded-md border border-border p-3">
                <span>
                  <span className="block text-xs font-medium text-foreground">{label}</span>
                  <span className="block text-[11px] text-muted-foreground">{hint}</span>
                </span>
                <Switch
                  checked={Boolean(caps[key as keyof typeof caps])}
                  onCheckedChange={(v) => setCaps({ ...caps, [key]: v })}
                />
              </label>
            ))}
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setCapOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={saveCapabilities} disabled={busy === "caps"}>
              {busy === "caps" ? "Saving…" : "Save capabilities"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function TechStackCard({ tech }: { tech?: ScanTechInventory }) {
  if (!tech || tech.endpoints_analyzed <= 0) return null;

  const allGroups: Array<{
    label: string;
    items: string[];
    tone: "info" | "violet" | "neutral" | "success" | "warn";
  }> = [
    { label: "Languages", items: tech.languages ?? [], tone: "info" },
    { label: "Frameworks", items: tech.frameworks ?? [], tone: "violet" },
    { label: "Templates", items: tech.templates ?? [], tone: "neutral" },
    { label: "Servers", items: tech.servers ?? [], tone: "success" },
    { label: "WAF", items: tech.waf_vendors ?? [], tone: "warn" },
  ];
  const groups = allGroups.filter((g) => g.items.length > 0);

  return (
    <Card className="lg:col-span-2">
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle>Tech stack</CardTitle>
        <span className="text-[11px] text-muted-foreground">
          {tech.endpoints_analyzed} {tech.endpoints_analyzed === 1 ? "endpoint" : "endpoints"} analyzed
        </span>
      </CardHeader>
      <CardContent>
        {groups.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No specific technologies fingerprinted yet.
          </p>
        ) : (
          <div className="space-y-2 text-xs text-foreground">
            {groups.map((g) => (
              <Row
                key={g.label}
                label={g.label}
                value={
                  <span className="flex flex-wrap justify-end gap-1.5">
                    {g.items.map((name) => (
                      <Badge key={name} tone={g.tone}>
                        {name}
                      </Badge>
                    ))}
                  </span>
                }
              />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border pb-1.5 last:border-0">
      <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className="max-w-[70%] text-right">{value}</span>
    </div>
  );
}
