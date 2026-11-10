import { useEffect, useState } from "react";
import { Globe2, LogIn, Plus, Save, ShieldCheck } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { setSelectedProject } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Switch } from "@/components/ui/controls";
import { StateBadge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, Empty, Loading } from "@/components/ui/misc";
import { api, refreshAll, useApi } from "@/lib/api";
import type { Project, Scan, Scope, Target } from "@/lib/types";
import { navigate } from "@/lib/router";
import { formatTime, shortId } from "@/lib/utils";

function lines(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter(Boolean);
}

export default function ProjectDetail({ id }: { id: string }) {
  const project = useApi<Project>(`/api/projects/${id}`);
  const targets = useApi<Target[]>(`/api/projects/${id}/targets`);
  const scope = useApi<Scope>(`/api/projects/${id}/scope`);
  const scans = useApi<Scan[]>("/api/scans");

  const [target, setTarget] = useState({ name: "", base_url: "" });
  const [targetErr, setTargetErr] = useState("");
  const [scopeDraft, setScopeDraft] = useState({
    include: "",
    exclude: "",
    includePaths: "",
    excludePaths: "",
    subdomains: false,
  });
  const [scopeErr, setScopeErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [login, setLogin] = useState({ loginUrl: "", successUrl: "" });
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginErr, setLoginErr] = useState("");
  const [loginNote, setLoginNote] = useState("");
  const [hunting, setHunting] = useState({ ua: "", replace: false });
  const [huntingNote, setHuntingNote] = useState("");
  const [huntingErr, setHuntingErr] = useState("");
  const [targetPage, setTargetPage] = useState(1);

  useEffect(() => {
    if (!project.data) return;
    setHunting({
      ua: project.data.hunting_user_agent ?? "",
      replace: Boolean(project.data.hunting_user_agent_replace),
    });
  }, [project.data]);

  async function saveHunting() {
    setHuntingErr("");
    setHuntingNote("");
    try {
      await api(`/api/projects/${id}`, {
        method: "PUT",
        body: {
          hunting_user_agent: hunting.ua.trim(),
          hunting_user_agent_replace: hunting.replace,
        },
      });
      setHuntingNote("Saved. Scans started from now on use this User-Agent.");
      refreshAll();
    } catch (e) {
      setHuntingErr((e as Error).message);
    }
  }

  useEffect(() => {
    if (!scope.data) return;
    setScopeDraft({
      include: (scope.data.include_hosts ?? []).join("\n"),
      exclude: (scope.data.exclude_hosts ?? []).join("\n"),
      includePaths: (scope.data.include_path_prefixes ?? []).join("\n"),
      excludePaths: (scope.data.exclude_path_prefixes ?? []).join("\n"),
      subdomains: Boolean(scope.data.allow_subdomains),
    });
  }, [scope.data]);

  async function addTarget() {
    if (!target.name.trim() || !target.base_url.trim()) {
      setTargetErr("Both name and base URL are required.");
      return;
    }
    try {
      await api(`/api/projects/${id}/targets`, { method: "POST", body: target });
      setTarget({ name: "", base_url: "" });
      setTargetErr("");
      refreshAll();
    } catch (e) {
      setTargetErr((e as Error).message);
    }
  }

  async function loginAndSave() {
    setLoginErr("");
    setLoginNote("");
    if (!login.loginUrl.trim()) {
      setLoginErr("Login URL is required.");
      return;
    }
    setLoginBusy(true);
    try {
      const res = await api<{ state_path: string; final_url: string }>("/api/auth/login", {
        method: "POST",
        body: {
          project_id: id,
          login_url: login.loginUrl.trim(),
          success_url: login.successUrl.trim(),
        },
      });
      await api(`/api/projects/${id}`, {
        method: "PUT",
        body: { auth_state_path: res.state_path },
      });
      refreshAll();
      setLoginNote(`Session saved (${res.state_path}). New scans for this project pick it up automatically.`);
    } catch (e) {
      setLoginErr((e as Error).message);
    } finally {
      setLoginBusy(false);
    }
  }

  async function saveScope() {
    setScopeErr("");
    setSaved(false);
    try {
      await api(`/api/projects/${id}/scope`, {
        method: "PUT",
        body: {
          include_hosts: lines(scopeDraft.include),
          exclude_hosts: lines(scopeDraft.exclude),
          include_path_prefixes: lines(scopeDraft.includePaths),
          exclude_path_prefixes: lines(scopeDraft.excludePaths),
          allow_subdomains: scopeDraft.subdomains,
        },
      });
      setSaved(true);
      refreshAll();
    } catch (e) {
      setScopeErr((e as Error).message);
    }
  }

  const projectScans = (scans.data ?? []).filter((s) => s.project_id === id);
  const targetList = targets.data ?? [];
  const targetPageCount = Math.max(1, Math.ceil(targetList.length / 10));
  const pagedTargets = targetList.slice((targetPage - 1) * 10, targetPage * 10);

  // Keep the page valid after deleting targets or adding a new one.
  useEffect(() => {
    if (targetPage > targetPageCount) setTargetPage(targetPageCount);
  }, [targetPage, targetPageCount]);

  return (
    <div>
      <PageTitle
        title={project.data?.name ?? "Project"}
        subtitle={project.data ? `id ${project.data.id} · created ${formatTime(project.data.created_at)}` : undefined}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => navigate(`/findings?project=${id}`)}>
              Findings
            </Button>
            <Button size="sm" variant="outline" onClick={() => navigate(`/reports?project=${id}`)}>
              Reports
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setSelectedProject(id);
                navigate("/scans");
              }}
            >
              Open scans
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={async () => {
                if (!confirm("Delete this project? Its scans must be deleted first.")) return;
                try {
                  await api(`/api/projects/${id}`, { method: "DELETE" });
                  navigate("/projects");
                } catch (e) {
                  alert((e as Error).message);
                }
              }}
            >
              Delete project
            </Button>
          </div>
        }
      />

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe2 className="size-4 text-sky-700 dark:text-sky-400" /> Hunting User-Agent
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Field
              label="Program value"
              hint="Paste the exact value from the program's hunting requirements, e.g. -BugBounty-CyberGhost--31337. It is appended to Indago's User-Agent unless you choose to replace it."
            >
              <Input
                value={hunting.ua}
                onChange={(e) => setHunting((h) => ({ ...h, ua: e.target.value }))}
                placeholder="-BugBounty-Program--31337"
                spellCheck={false}
              />
            </Field>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <label className="flex items-center gap-2 text-sm">
                <Switch
                  checked={hunting.replace}
                  onCheckedChange={(v) => setHunting((h) => ({ ...h, replace: v }))}
                />
                Replace the default User-Agent
              </label>
              <Button size="sm" onClick={saveHunting}>
                <Save className="size-4" /> Save User-Agent
              </Button>
            </div>
            {huntingErr && <Alert className="border-red-200 text-red-700 dark:border-red-900 dark:text-red-400">{huntingErr}</Alert>}
            {huntingNote && <p className="text-xs text-emerald-700 dark:text-emerald-400">{huntingNote}</p>}
            <p className="text-xs text-muted-foreground">
              Most YesWeHack programs ask you to append a suffix; a few require a full replacement.
              Keep the exact casing and hyphens. Scans already running are not changed.
            </p>
          </CardContent>
        </Card>


      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe2 className="size-4 text-sky-700 dark:text-sky-400" /> Targets
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1.4fr_auto]">
              <Input
                placeholder="Name"
                value={target.name}
                onChange={(e) => setTarget({ ...target, name: e.target.value })}
              />
              <Input
                placeholder="https://app.example.com"
                value={target.base_url}
                onChange={(e) => setTarget({ ...target, base_url: e.target.value })}
              />
              <Button size="sm" onClick={addTarget}>
                <Plus className="size-4" /> Add
              </Button>
            </div>
            {targetErr ? <Alert>{targetErr}</Alert> : null}
            {targets.loading && !targets.data ? (
              <Loading />
            ) : (targets.data ?? []).length === 0 ? (
              <Empty>No targets yet. Add the base URL you are authorized to test.</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Base URL</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pagedTargets.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="text-foreground">{t.name}</TableCell>
                      <TableCell className="mono text-[11px] text-muted-foreground">{t.base_url}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button size="sm" variant="ghost" onClick={() => navigate(`/scans?target=${t.id}`)}>
                            Scan →
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={async () => {
                              const name = prompt("Target name", t.name);
                              if (name === null) return;
                              const base = prompt("Base URL", t.base_url);
                              if (base === null) return;
                              try {
                                await api(`/api/projects/${id}/targets/${t.id}`, {
                                  method: "PUT",
                                  body: { name, base_url: base },
                                });
                                refreshAll();
                              } catch (e) {
                                alert((e as Error).message);
                              }
                            }}
                          >
                            edit
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={async () => {
                              if (!confirm(`Delete target ${t.name}?`)) return;
                              try {
                                await api(`/api/projects/${id}/targets/${t.id}`, { method: "DELETE" });
                                refreshAll();
                              } catch (e) {
                                alert((e as Error).message);
                              }
                            }}
                          >
                            delete
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {targetList.length > 10 ? (
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2 text-[11px] text-muted-foreground">
                <span>
                  Showing {(targetPage - 1) * 10 + 1}–{Math.min(targetPage * 10, targetList.length)} of {targetList.length} targets
                </span>
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="outline" disabled={targetPage <= 1} onClick={() => setTargetPage((p) => p - 1)}>
                    Previous
                  </Button>
                  <span>
                    Page {targetPage} / {targetPageCount}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={targetPage >= targetPageCount}
                    onClick={() => setTargetPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-emerald-700 dark:text-emerald-400" /> Scope
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2">
              <Field label="Include hosts" hint="One per line. Hostnames only, no ports.">
                <Textarea
                  rows={4}
                  value={scopeDraft.include}
                  onChange={(e) => setScopeDraft({ ...scopeDraft, include: e.target.value })}
                  placeholder={"app.example.com\nexample.com"}
                />
              </Field>
              <Field label="Exclude hosts">
                <Textarea
                  rows={4}
                  value={scopeDraft.exclude}
                  onChange={(e) => setScopeDraft({ ...scopeDraft, exclude: e.target.value })}
                  placeholder="billing.example.com"
                />
              </Field>
              <Field label="Include path prefixes" hint="Optional. '/' means the whole host.">
                <Textarea
                  rows={3}
                  value={scopeDraft.includePaths}
                  onChange={(e) => setScopeDraft({ ...scopeDraft, includePaths: e.target.value })}
                  placeholder="/app"
                />
              </Field>
              <Field label="Exclude path prefixes">
                <Textarea
                  rows={3}
                  value={scopeDraft.excludePaths}
                  onChange={(e) => setScopeDraft({ ...scopeDraft, excludePaths: e.target.value })}
                  placeholder="/logout"
                />
              </Field>
            </div>
            <label className="flex items-center gap-2 text-xs text-foreground">
              <Switch
                checked={scopeDraft.subdomains}
                onCheckedChange={(v) => setScopeDraft({ ...scopeDraft, subdomains: v })}
              />
              Allow subdomains of the included hosts
            </label>
            {scopeErr ? <Alert>{scopeErr}</Alert> : null}
            {saved ? <p className="text-[11px] text-emerald-700 dark:text-emerald-400">Scope saved.</p> : null}
            <div className="flex justify-end">
              <Button size="sm" onClick={saveScope}>
                <Save className="size-4" /> Save scope
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <LogIn className="size-4 text-emerald-700 dark:text-emerald-400" /> Scan login
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              For targets that need an account. Indago opens a visible browser, you log in by hand,
              and the resulting Playwright storage state is saved on this project. New scans select
              it automatically as <span className="font-mono">existing session</span>.
            </p>
            <Field label="Login URL" hint="The page with the login form. Must be inside project scope.">
              <Input
                value={login.loginUrl}
                onChange={(e) => setLogin({ ...login, loginUrl: e.target.value })}
                placeholder="https://app.example.com/login"
              />
            </Field>
            <Field label="Success URL" hint="Optional. A URL only reachable after login; use it to confirm the session.">
              <Input
                value={login.successUrl}
                onChange={(e) => setLogin({ ...login, successUrl: e.target.value })}
                placeholder="https://app.example.com/dashboard"
              />
            </Field>
            {project.data?.auth_state_path ? (
              <p className="break-all text-[11px] text-emerald-700 dark:text-emerald-400">
                Session saved: {project.data.auth_state_path}
              </p>
            ) : (
              <p className="text-[11px] text-muted-foreground">No saved session for this project yet.</p>
            )}
            {loginErr ? <Alert>{loginErr}</Alert> : null}
            {loginNote ? <p className="break-all text-[11px] text-emerald-700 dark:text-emerald-400">{loginNote}</p> : null}
            <div className="flex justify-end">
              <Button size="sm" onClick={loginAndSave} disabled={loginBusy}>
                <LogIn className="size-4" /> {loginBusy ? "Waiting for browser…" : "Log in & save session"}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Scans in this project</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {projectScans.length === 0 ? (
            <div className="p-4">
              <Empty>No scans yet for this project.</Empty>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Confirmed</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {projectScans.map((s) => (
                  <TableRow key={s.id} className="cursor-pointer" onClick={() => navigate(`/scans/${s.id}`)}>
                    <TableCell>
                      <div className="mono text-[11px] text-muted-foreground">{shortId(s.id)}</div>
                      <div className="truncate text-xs text-foreground">{s.name || s.seed_urls?.[0]}</div>
                    </TableCell>
                    <TableCell>
                      <StateBadge state={s.state} />
                    </TableCell>
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
