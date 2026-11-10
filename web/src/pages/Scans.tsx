import { useEffect, useMemo, useState } from "react";
import { Play, Plus } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTrigger, Tooltip } from "@/components/ui/controls";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/input";
import { Switch } from "@/components/ui/controls";
import { StateBadge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, Empty, Loading, Stat } from "@/components/ui/misc";
import { api, refreshAll, useApi } from "@/lib/api";
import type { AuthProfile, Project, Scan, Scope, Target } from "@/lib/types";
import { navigate } from "@/lib/router";
import { formatTime, shortId } from "@/lib/utils";
import { selectedProject } from "@/components/Layout";

const PROFILES = ["conservative", "balanced", "fast"];

function InfoTip({ text }: { text: string }) {
  return (
    <Tooltip label={text}>
      <button
        type="button"
        aria-label="More information"
        className="inline-flex size-4 items-center justify-center rounded-full border border-border text-[9px] font-semibold text-muted-foreground hover:bg-muted"
      >
        i
      </button>
    </Tooltip>
  );
}

export default function Scans() {
  const [projectId, setProjectId] = useState(selectedProject());
  // The sidebar's project picker is shared context: follow it while this page
  // is open, instead of only reading it once at mount.
  useEffect(() => {
    const sync = () => setProjectId(selectedProject());
    window.addEventListener("indago:refresh", sync);
    return () => window.removeEventListener("indago:refresh", sync);
  }, []);
  const projects = useApi<Project[]>("/api/projects");
  const scans = useApi<Scan[]>("/api/scans", [], 5000);
  const targets = useApi<Target[]>(projectId ? `/api/projects/${projectId}/targets` : null, [projectId]);
  const authProfiles = useApi<AuthProfile[]>(projectId ? `/api/projects/${projectId}/auth-profiles` : null, [projectId]);

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    target_id: "",
    name: "",
    seeds: "",
    profile: "conservative",
    auth: "anonymous",
    authProfileId: "",
    authState: "",
    loginUrl: "",
    successUrl: "",
    loginUserSel: "",
    loginPassSel: "",
    loginSubmitSel: "",
    quick: false,
    maxDepth: 0,
    maxPages: 0,
    maxEndpoints: 0,
    maxCandidates: 0,
    candidateProfile: "standard",
    evasion: false,
    library: false,
    rawQuery: "off",
    recon: "off",
    proxyPool: "",
    stopMode: "continue_all",
    stopN: 1,
    cfgDiscovery: 0,
    cfgHttp: 0,
    cfgBrowser: 0,
    cfgRate: 0,
  });
  const [error, setError] = useState("");
  const [projectScope, setProjectScope] = useState<Scope | null>(null);
  const [busy, setBusy] = useState(false);
  const [loginNote, setLoginNote] = useState("");

  const filtered = useMemo(() => {
    const list = scans.data ?? [];
    return projectId ? list.filter((s) => s.project_id === projectId) : list;
  }, [scans.data, projectId]);

  useEffect(() => {
    let alive = true;
    if (!projectId) {
      setProjectScope(null);
      return;
    }
    Promise.all([
      api<Scope>(`/api/projects/${projectId}/scope`).catch(() => null),
      api<Project>(`/api/projects/${projectId}`).catch(() => null),
    ]).then(([sc, project]) => {
      if (!alive) return;
      setProjectScope(sc);
      if (project?.auth_state_path) {
        setForm((f) =>
          f.auth === "anonymous"
            ? { ...f, auth: "existing", authState: project.auth_state_path as string }
            : f,
        );
        setLoginNote("Using the project's saved login session.");
      }
    });
    return () => {
      alive = false;
    };
  }, [projectId]);

  const selectedTarget = (targets.data ?? []).find((t) => t.id === form.target_id);
  const selectedProfile = (authProfiles.data ?? []).find((p) => p.id === selectedTarget?.auth_profile_id);
  const targetHost = (() => {
    if (!selectedTarget) return "";
    try {
      return new URL(selectedTarget.base_url).hostname.toLowerCase();
    } catch {
      return "";
    }
  })();
  const scopeCoversTarget = Boolean(
    targetHost &&
      projectScope?.include_hosts?.some(
        (h) => targetHost === h.toLowerCase() || (projectScope.allow_subdomains && targetHost.endsWith("." + h.toLowerCase())),
      ),
  );

  useEffect(() => {
    if (!selectedTarget) return;
    const profile = (authProfiles.data ?? []).find((p) => p.id === selectedTarget.auth_profile_id);
    if (profile?.state_path) {
      setForm((f) =>
        f.target_id === selectedTarget.id && (f.auth === "anonymous" || f.auth === "existing")
          ? { ...f, auth: "existing", authState: profile.state_path as string, authProfileId: profile.id }
          : f,
      );
      setLoginNote(`Using target auth session: ${profile.name}.`);
    }
  }, [selectedTarget, authProfiles.data]);

  const running = filtered.filter((s) => s.state === "running").length;
  const confirmed = filtered.reduce((n, s) => n + (s.stats?.findings_confirmed ?? 0), 0);

  async function create() {
    setError("");
    if (!projectId || !form.target_id) {
      setError("Pick a project and a target first.");
      return;
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = {
        project_id: projectId,
        target_id: form.target_id,
        name: form.name || undefined,
        profile: form.profile,
        seed_urls: form.seeds
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
        quick_scan: form.quick,
        max_depth: form.maxDepth,
        max_pages: form.maxPages,
        max_endpoints: form.maxEndpoints,
        candidate_profile: form.candidateProfile,
        enable_evasion: form.evasion,
        enable_xss_library: form.library,
        raw_query_injection: form.rawQuery,
        recon_level: form.recon,
      };
      if (form.maxCandidates > 0) body.max_candidates = form.maxCandidates;
      const proxies = form.proxyPool
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (proxies.length) body.proxy_pool = proxies;
      if (form.stopMode !== "continue_all") {
        body.stop = {
          mode: form.stopMode,
          confirmed_limit: form.stopMode === "after_n_confirmed" ? form.stopN : 0,
        };
      }
      if (form.cfgDiscovery || form.cfgHttp || form.cfgBrowser || form.cfgRate) {
        body.config = {
          discovery_concurrency: form.cfgDiscovery,
          http_concurrency: form.cfgHttp,
          browser_concurrency: form.cfgBrowser,
          requests_per_second: form.cfgRate,
        };
      }
      if (form.auth !== "anonymous") {
        body.auth_mode = form.auth;
        if (form.authProfileId) body.auth_profile_id = form.authProfileId;
        if (form.auth === "existing") body.auth_state_path = form.authState;
        if (form.auth === "interactive" || form.auth === "mfa" || form.auth === "password") {
          body.login_url = form.loginUrl;
          body.success_url = form.successUrl;
          if (form.loginUserSel) body.login_username_selector = form.loginUserSel;
          if (form.loginPassSel) body.login_password_selector = form.loginPassSel;
          if (form.loginSubmitSel) body.login_submit_selector = form.loginSubmitSel;
        }
      }
      const scan = await api<Scan>("/api/scans", { method: "POST", body });
      await api(`/api/scans/${scan.id}/start`, { method: "POST" });
      setOpen(false);
      refreshAll();
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageTitle
        title="Scans"
        subtitle="One bounded run against one target scope. Progress and evidence are per scan."
        actions={
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="size-4" /> New scan
              </Button>
            </DialogTrigger>
            <DialogContent
              title="New scan"
              description="Scans are bounded by the project scope and the chosen profile."
              className="max-w-2xl"
            >
              <div className="grid max-h-[65vh] gap-3 overflow-y-auto pr-1 sm:grid-cols-2">
                <Field label="Project">
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={projectId}
                    onChange={(e) => {
                      setProjectId(e.target.value);
                      setForm({ ...form, target_id: "" });
                    }}
                  >
                    <option value="">Select…</option>
                    {(projects.data ?? []).map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Target">
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={form.target_id}
                    onChange={(e) => setForm({ ...form, target_id: e.target.value })}
                  >
                    <option value="">Select…</option>
                    {(targets.data ?? []).map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name} — {t.base_url}
                      </option>
                    ))}
                  </select>
                </Field>
                {projectId ? (
                  <div className="sm:col-span-2 rounded-md border border-border bg-muted/30 p-2 text-[11px]">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-muted-foreground">
                        Scope:{" "}
                        {projectScope?.include_hosts?.length
                          ? `${projectScope.include_hosts.join(", ")}${projectScope.allow_subdomains ? " (+ subdomains)" : ""}`
                          : "no include hosts — this scan would match nothing"}
                      </span>
                      <button className="text-emerald-700 underline dark:text-emerald-400" onClick={() => navigate(`/projects/${projectId}`)}>
                        edit scope
                      </button>
                    </div>
                    {selectedTarget && !scopeCoversTarget ? (
                      <p className="mt-1 text-amber-700 dark:text-amber-400">
                        {targetHost} is not inside this project scope; the scan will refuse every request to it.
                      </p>
                    ) : null}
                  </div>
                ) : null}
                <Field label="Name" hint="Optional label shown in lists.">
                  <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                </Field>
                <Field label="Profile">
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={form.profile}
                    onChange={(e) => setForm({ ...form, profile: e.target.value })}
                  >
                    {PROFILES.map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Seeds" hint="One URL per line. Empty uses the target base URL." className="sm:col-span-2">
                  <Textarea
                    rows={2}
                    value={form.seeds}
                    onChange={(e) => setForm({ ...form, seeds: e.target.value })}
                    placeholder={"https://app.example.com/"}
                  />
                </Field>
                <div className="sm:col-span-2 rounded-md border border-border bg-muted/30 px-3 py-2 text-[11px]">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-muted-foreground">Authentication</span>
                    <span className="mono text-foreground">
                      {selectedProfile ? selectedProfile.name : form.auth === "existing" ? "project fallback session" : "anonymous"}
                    </span>
                  </div>
                  <p className="mt-1 text-muted-foreground">
                    Inherited from the selected target (or the project fallback when the target has none).
                    Change it on the project page: Targets → Login. A scan does not need another auth mode.
                  </p>
                  {selectedProfile && !selectedProfile.state_path ? (
                    <p className="mt-1 text-amber-700 dark:text-amber-400">
                      This profile has no saved session yet. Re-login it on the project page before starting.
                    </p>
                  ) : null}
                  {loginNote ? <p className="mt-1 text-emerald-700 dark:text-emerald-400">{loginNote}</p> : null}
                </div>
                <Field label="Candidate profile">
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={form.candidateProfile}
                    onChange={(e) => setForm({ ...form, candidateProfile: e.target.value })}
                  >
                    {["minimal", "standard", "thorough"].map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Raw query injection">
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={form.rawQuery}
                    onChange={(e) => setForm({ ...form, rawQuery: e.target.value })}
                  >
                    {["off", "auto", "always"].map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </Field>
                <Field
                  label="Recon level"
                  hint="standard reads security.txt / OpenID / OpenAPI documents; aggressive also queries the Wayback index (the target host is sent to archive.org)."
                >
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={form.recon}
                    onChange={(e) => setForm({ ...form, recon: e.target.value })}
                  >
                    {["off", "safe", "standard", "aggressive"].map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </Field>
                <div className="grid grid-cols-3 gap-2 sm:col-span-2">
                  <div className="flex flex-col gap-1.5">
                    <div className="flex items-center gap-1">
                      <Label>Max depth</Label>
                      <InfoTip text="How many link hops discovery follows from the seed. 0 = profile default; 1 = seed plus links on it; 3 = up to three hops. Example: /app → /app/admin (depth 1) → /app/admin/users (depth 2)." />
                    </div>
                    <Input type="number" value={form.maxDepth} onChange={(e) => setForm({ ...form, maxDepth: Number(e.target.value) })} />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <div className="flex items-center gap-1">
                      <Label>Max pages</Label>
                      <InfoTip text="Maximum HTML pages the crawler may fetch. 0 = profile default. Example: 50 stops after 50 pages, which keeps a large site bounded; 200 is a broader crawl." />
                    </div>
                    <Input type="number" value={form.maxPages} onChange={(e) => setForm({ ...form, maxPages: Number(e.target.value) })} />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <div className="flex items-center gap-1">
                      <Label>Max endpoints</Label>
                      <InfoTip text="Maximum discovered endpoints kept for testing. 0 = profile default. Example: 100 caps the job list on a huge application; raise it when you need wider coverage." />
                    </div>
                    <Input type="number" value={form.maxEndpoints} onChange={(e) => setForm({ ...form, maxEndpoints: Number(e.target.value) })} />
                  </div>
                </div>
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <Switch checked={form.quick} onCheckedChange={(v) => setForm({ ...form, quick: v })} />
                  Quick scan (seeds only)
                </label>
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <Switch checked={form.evasion} onCheckedChange={(v) => setForm({ ...form, evasion: v })} />
                  Eager evasion pack
                </label>
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <Switch checked={form.library} onCheckedChange={(v) => setForm({ ...form, library: v })} />
                  XSS payload library (PortSwigger families)
                </label>
                <p className="text-[10px] text-muted-foreground">
                  Adds the cheat-sheet families the canonical planner does not carry. Only vectors whose context and
                  required characters match the reflection are sent; the profile still caps the total.
                </p>
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center gap-1">
                    <Label>Max candidates</Label>
                    <InfoTip text="Maximum payload candidates sent per injection point. 0 = profile cap. Example: 5 sends at most five variants for one parameter; lower it for noisy apps, raise it for a WAF that blocks the first few." />
                  </div>
                  <Input
                    type="number"
                    min={0}
                    value={form.maxCandidates}
                    onChange={(e) => setForm({ ...form, maxCandidates: Number(e.target.value) })}
                  />
                  <p className="text-[11px] text-muted-foreground">0 = profile cap.</p>
                </div>
                <Field label="Stop policy">
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={form.stopMode}
                    onChange={(e) => setForm({ ...form, stopMode: e.target.value })}
                  >
                    <option value="continue_all">continue after confirmations</option>
                    <option value="first_confirmed">stop at the first confirmed</option>
                    <option value="after_n_confirmed">stop after N confirmed</option>
                    <option value="pause_and_ask">pause and ask</option>
                  </select>
                </Field>
                {form.stopMode === "after_n_confirmed" ? (
                  <Field label="Confirmed limit (N)">
                    <Input
                      type="number"
                      min={1}
                      value={form.stopN}
                      onChange={(e) => setForm({ ...form, stopN: Number(e.target.value) })}
                    />
                  </Field>
                ) : null}
                <Field label="Proxy pool" hint="One proxy URL per line; round-robin, direct when empty." className="sm:col-span-2">
                  <Textarea
                    rows={2}
                    placeholder={"http://127.0.0.1:8080\nsocks5://127.0.0.1:1080"}
                    value={form.proxyPool}
                    onChange={(e) => setForm({ ...form, proxyPool: e.target.value })}
                  />
                </Field>
                <div className="grid grid-cols-4 gap-2 sm:col-span-2">
                  <Field label="Discovery conc." hint="0 = profile.">
                    <Input
                      type="number"
                      min={0}
                      value={form.cfgDiscovery}
                      onChange={(e) => setForm({ ...form, cfgDiscovery: Number(e.target.value) })}
                    />
                  </Field>
                  <Field label="HTTP conc.">
                    <Input
                      type="number"
                      min={0}
                      value={form.cfgHttp}
                      onChange={(e) => setForm({ ...form, cfgHttp: Number(e.target.value) })}
                    />
                  </Field>
                  <Field label="Browser conc.">
                    <Input
                      type="number"
                      min={0}
                      value={form.cfgBrowser}
                      onChange={(e) => setForm({ ...form, cfgBrowser: Number(e.target.value) })}
                    />
                  </Field>
                  <Field label="Req/sec">
                    <Input
                      type="number"
                      min={0}
                      step="0.5"
                      value={form.cfgRate}
                      onChange={(e) => setForm({ ...form, cfgRate: Number(e.target.value) })}
                    />
                  </Field>
                </div>
              </div>
              {error ? <Alert>{error}</Alert> : null}
              <div className="flex items-center justify-between gap-2">
                <p className="text-[10px] text-muted-foreground">
                  State-changing probes (stored XSS, role writes) require the server's{" "}
                  <span className="mono">-allow-state-changing</span>.
                </p>
                <div className="flex gap-2">
                  <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
                    Cancel
                  </Button>
                  <Button size="sm" disabled={busy} onClick={create}>
                    <Play className="size-4" /> {busy ? "Starting…" : "Create & start"}
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        }
      />

      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Scans" value={filtered.length} />
        <Stat label="Running" value={running} tone={running ? "warn" : "default"} />
        <Stat label="Confirmed" value={confirmed} tone="danger" />
        <Stat
          label="Rejected"
          value={filtered.reduce((n, s) => n + (s.stats?.findings_rejected ?? 0), 0)}
          tone="success"
        />
      </div>

      <Card>
        <CardContent className="p-0">
          {scans.loading && !scans.data ? (
            <Loading />
          ) : filtered.length === 0 ? (
            <div className="p-4">
              <Empty>No scans in this project yet.</Empty>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Endpoints</TableHead>
                  <TableHead>Confirmed</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...filtered]
                  .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))
                  .map((s) => (
                    <TableRow key={s.id} className="cursor-pointer" onClick={() => navigate(`/scans/${s.id}`)}>
                      <TableCell>
                        <div className="mono text-[11px] text-muted-foreground">{shortId(s.id)}</div>
                        <div className="max-w-[26rem] truncate text-xs text-foreground">
                          {s.name || s.seed_urls?.[0] || "—"}
                        </div>
                      </TableCell>
                      <TableCell>
                        <StateBadge state={s.state} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{s.profile}</TableCell>
                      <TableCell className="tabular-nums">{s.stats?.endpoints_discovered ?? 0}</TableCell>
                      <TableCell className="tabular-nums">{s.stats?.findings_confirmed ?? 0}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatTime(s.created_at)}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-red-600 dark:text-red-400"
                          disabled={s.state === "running" || s.state === "canceling"}
                          onClick={async (e) => {
                            e.stopPropagation();
                            if (!confirm(`Delete scan ${shortId(s.id)}? Its evidence and reports are removed too.`)) return;
                            try {
                              await api(`/api/scans/${s.id}`, { method: "DELETE" });
                              refreshAll();
                            } catch (err) {
                              alert((err as Error).message);
                            }
                          }}
                        >
                          delete
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export function ScansHint() {
  return <Label>Scans</Label>;
}
