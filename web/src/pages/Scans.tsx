import { useMemo, useState } from "react";
import { LogIn, Play, Plus } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/controls";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/input";
import { Switch } from "@/components/ui/controls";
import { StateBadge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, Empty, Loading, Stat } from "@/components/ui/misc";
import { api, refreshAll, useApi } from "@/lib/api";
import type { Project, Scan, Target } from "@/lib/types";
import { navigate } from "@/lib/router";
import { formatTime, shortId } from "@/lib/utils";
import { selectedProject } from "@/components/Layout";

const PROFILES = ["conservative", "balanced", "fast"];

export default function Scans() {
  const [projectId, setProjectId] = useState(selectedProject());
  const projects = useApi<Project[]>("/api/projects");
  const scans = useApi<Scan[]>("/api/scans", [], 5000);
  const targets = useApi<Target[]>(projectId ? `/api/projects/${projectId}/targets` : null, [projectId]);

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    target_id: "",
    name: "",
    seeds: "",
    profile: "conservative",
    auth: "anonymous",
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
  const [busy, setBusy] = useState(false);
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginNote, setLoginNote] = useState("");

  const filtered = useMemo(() => {
    const list = scans.data ?? [];
    return projectId ? list.filter((s) => s.project_id === projectId) : list;
  }, [scans.data, projectId]);

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

  // Drives the server-side interactive login (POST /api/auth/login). The
  // endpoint blocks until the operator finishes, so the button stays busy and
  // the result is only the saved session PATH — never cookies or tokens.
  async function loginNow() {
    setError("");
    setLoginNote("");
    if (!projectId) {
      setError("Pick a project first — the login is scope-checked against it.");
      return;
    }
    if (!form.loginUrl.trim()) {
      setError("Login URL is required to start an interactive login.");
      return;
    }
    setLoginBusy(true);
    try {
      const res = await api<{ state_path: string; final_url: string }>("/api/auth/login", {
        method: "POST",
        body: {
          project_id: projectId,
          login_url: form.loginUrl.trim(),
          success_url: form.successUrl.trim(),
        },
      });
      setForm((f) => ({ ...f, auth: "existing", authState: res.state_path }));
      setLoginNote(`Session saved to ${res.state_path} (landed on ${res.final_url}). Auth mode is now "existing session state".`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoginBusy(false);
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
                <Field label="Auth mode">
                  <select
                    className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                    value={form.auth}
                    onChange={(e) => setForm({ ...form, auth: e.target.value })}
                  >
                    <option value="anonymous">anonymous</option>
                    <option value="existing">existing session state</option>
                    <option value="password">password (server env)</option>
                    <option value="interactive">interactive</option>
                    <option value="mfa">interactive + MFA</option>
                  </select>
                </Field>
                {form.auth === "existing" ? (
                  <Field label="Auth state path" hint="Absolute server-side path.">
                    <Input
                      value={form.authState}
                      onChange={(e) => setForm({ ...form, authState: e.target.value })}
                    />
                  </Field>
                ) : form.auth !== "anonymous" ? (
                  <>
                    <Field label="Login URL">
                      <Input value={form.loginUrl} onChange={(e) => setForm({ ...form, loginUrl: e.target.value })} />
                    </Field>
                    <Field label="Success URL glob" hint="e.g. **/my-account*">
                      <Input
                        value={form.successUrl}
                        onChange={(e) => setForm({ ...form, successUrl: e.target.value })}
                      />
                    </Field>
                    <Field label="Username selector" hint="Optional: the password mode fills the form itself.">
                      <Input
                        placeholder="#email"
                        value={form.loginUserSel}
                        onChange={(e) => setForm({ ...form, loginUserSel: e.target.value })}
                      />
                    </Field>
                    <Field label="Password selector">
                      <Input
                        placeholder="#password"
                        value={form.loginPassSel}
                        onChange={(e) => setForm({ ...form, loginPassSel: e.target.value })}
                      />
                    </Field>
                    <Field label="Submit selector">
                      <Input
                        placeholder="button[type=submit]"
                        value={form.loginSubmitSel}
                        onChange={(e) => setForm({ ...form, loginSubmitSel: e.target.value })}
                      />
                    </Field>
                    <div className="flex items-center gap-2 sm:col-span-2">
                      <Button size="sm" variant="secondary" onClick={loginNow} disabled={loginBusy}>
                        <LogIn className="size-4" /> {loginBusy ? "Waiting for login…" : "Login now (interactive)"}
                      </Button>
                      <span className="text-[11px] text-muted-foreground">
                        Needs the server running with <span className="mono">-browser</span>; the result is the saved session path.
                      </span>
                    </div>
                    {loginNote ? <p className="text-[11px] text-emerald-700 dark:text-emerald-400 sm:col-span-2">{loginNote}</p> : null}
                  </>
                ) : null}
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
                <Field label="Recon level">
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
                  <Field label="Max depth">
                    <Input
                      type="number"
                      value={form.maxDepth}
                      onChange={(e) => setForm({ ...form, maxDepth: Number(e.target.value) })}
                    />
                  </Field>
                  <Field label="Max pages">
                    <Input
                      type="number"
                      value={form.maxPages}
                      onChange={(e) => setForm({ ...form, maxPages: Number(e.target.value) })}
                    />
                  </Field>
                  <Field label="Max endpoints">
                    <Input
                      type="number"
                      value={form.maxEndpoints}
                      onChange={(e) => setForm({ ...form, maxEndpoints: Number(e.target.value) })}
                    />
                  </Field>
                </div>
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <Switch checked={form.quick} onCheckedChange={(v) => setForm({ ...form, quick: v })} />
                  Quick scan (seeds only)
                </label>
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <Switch checked={form.evasion} onCheckedChange={(v) => setForm({ ...form, evasion: v })} />
                  Eager evasion pack
                </label>
                <Field label="Max candidates" hint="0 = profile cap.">
                  <Input
                    type="number"
                    min={0}
                    value={form.maxCandidates}
                    onChange={(e) => setForm({ ...form, maxCandidates: Number(e.target.value) })}
                  />
                </Field>
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
