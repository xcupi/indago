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
import type { AuthProfile, Project, Scan, Scope, Target } from "@/lib/types";
import { navigate } from "@/lib/router";
import { formatTime, shortId } from "@/lib/utils";
import { Pagination, usePagination } from "@/components/Pagination";

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
  const [login, setLogin] = useState({ profileId: "", profileName: "", loginUrl: "", successUrl: "" });
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
    if (!login.profileId && !login.profileName.trim()) {
      setLoginErr("Name this auth session so targets can share it.");
      return;
    }
    setLoginBusy(true);
    try {
      const body: Record<string, string> = {
        project_id: id,
        login_url: login.loginUrl.trim(),
        success_url: login.successUrl.trim(),
      };
      if (login.profileId) body.auth_profile_id = login.profileId;
      else body.profile_name = login.profileName.trim();
      const res = await api<{ state_path: string; final_url: string; auth_profile_id?: string }>("/api/auth/login", {
        method: "POST",
        body,
      });
      refreshAll();
      setLoginNote(`Session saved (${res.state_path}). Targets assigned to this auth session use it automatically.`);
      if (res.auth_profile_id) {
        setLogin((l) => ({ ...l, profileId: res.auth_profile_id as string }));
      }
    } catch (e) {
      setLoginErr((e as Error).message);
    } finally {
      setLoginBusy(false);
    }
  }

  function editAuthProfile(p: AuthProfile) {
    setLogin({
      profileId: p.id,
      profileName: p.name,
      loginUrl: p.login_url ?? "",
      successUrl: p.success_url ?? "",
    });
    setLoginNote(`Re-login for ${p.name}. The saved session will be refreshed for every target using it.`);
  }

  async function deleteAuthProfile(p: AuthProfile) {
    if (!confirm(`Delete auth session "${p.name}"? Targets using it will become anonymous.`)) return;
    try {
      await api(`/api/projects/${id}/auth-profiles/${p.id}`, { method: "DELETE" });
      refreshAll();
      if (login.profileId === p.id) setLogin({ profileId: "", profileName: "", loginUrl: "", successUrl: "" });
    } catch (e) {
      setLoginErr((e as Error).message);
    }
  }

  async function assignAuthProfile(t: Target, profileID: string) {
    try {
      await api(`/api/projects/${id}/targets/${t.id}`, {
        method: "PUT",
        body: { name: t.name, base_url: t.base_url, auth_profile_id: profileID },
      });
      refreshAll();
    } catch (e) {
      alert((e as Error).message);
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
  const pagedScans = usePagination(projectScans);
  useEffect(() => {
    pagedScans.setPage(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectScans.length]);
  const authProfiles = useApi<AuthProfile[]>(`/api/projects/${id}/auth-profiles`);
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

        <Card className="mb-4">
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
                    <TableHead>Login</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pagedTargets.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="text-foreground">{t.name}</TableCell>
                      <TableCell className="mono text-[11px] text-muted-foreground">{t.base_url}</TableCell>
                      <TableCell>
                        <select
                          className="h-8 max-w-40 rounded-md border border-border bg-background px-1.5 text-[11px]"
                          value={t.auth_profile_id ?? ""}
                          onChange={(e) => assignAuthProfile(t, e.target.value)}
                        >
                          <option value="">anonymous</option>
                          {(authProfiles.data ?? []).map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name}
                            </option>
                          ))}
                        </select>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              setSelectedProject(id);
                              navigate(`/scans?target=${t.id}`);
                            }}
                          >
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
                              if (!confirm(`Delete target ${t.name}? Its unstarted draft scan(s) will be removed too. Started scans block deletion.`)) return;
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
              <LogIn className="size-4 text-emerald-700 dark:text-emerald-400" /> Auth sessions
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              One saved login can be shared by many targets — useful for SSO such as HackTheBox.
              Assign a session per target in the Targets table. A target that needs another account
              can point at a different session.
            </p>
            {(authProfiles.data ?? []).length === 0 ? (
              <p className="text-[11px] text-muted-foreground">No auth sessions yet. Create one below.</p>
            ) : (
              <div className="space-y-1">
                {(authProfiles.data ?? []).map((p) => {
                  const used = targetList.filter((t) => t.auth_profile_id === p.id).length;
                  return (
                    <div key={p.id} className="flex flex-wrap items-center gap-2 rounded-md border border-border px-2.5 py-2 text-[11px]">
                      <div className="min-w-0 flex-1">
                        <div className="font-medium text-foreground">{p.name}</div>
                        <div className="text-muted-foreground">
                          {p.state_path ? "session saved" : "no session yet"} · used by {used} target{used === 1 ? "" : "s"}
                        </div>
                      </div>
                      <Button size="sm" variant="outline" onClick={() => editAuthProfile(p)}>
                        Re-login
                      </Button>
                      <Button size="sm" variant="ghost" className="text-red-600 dark:text-red-400" onClick={() => deleteAuthProfile(p)}>
                        Delete
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}
            <div className="border-t border-border pt-3">
              <Field label="Session name" hint="A label for this login, e.g. HackTheBox SSO. Targets can share it.">
                <Input
                  value={login.profileName}
                  onChange={(e) => setLogin({ ...login, profileName: e.target.value })}
                  placeholder="e.g. HackTheBox SSO"
                  disabled={Boolean(login.profileId)}
                />
              </Field>
              {login.profileId ? (
                <p className="text-[11px] text-muted-foreground">
                  Re-login mode. The saved session will be replaced for every target using it.{" "}
                  <button
                    className="underline"
                    onClick={() => setLogin({ profileId: "", profileName: "", loginUrl: "", successUrl: "" })}
                  >
                    cancel
                  </button>
                </p>
              ) : null}
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                <Field label="Login URL" hint="The SSO/login page. Must be inside project scope.">
                  <Input
                    value={login.loginUrl}
                    onChange={(e) => setLogin({ ...login, loginUrl: e.target.value })}
                    placeholder="https://app.example.com/login"
                  />
                </Field>
                <Field label="Success URL" hint="Optional. A URL only reachable after login.">
                  <Input
                    value={login.successUrl}
                    onChange={(e) => setLogin({ ...login, successUrl: e.target.value })}
                    placeholder="https://app.example.com/dashboard"
                  />
                </Field>
              </div>
            </div>
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
          <p className="text-[11px] text-muted-foreground">
            Per-scan attack selection lives in Scans → New scan → Attack capabilities.
          </p>
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
                {pagedScans.rows.map((s) => (
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
        {projectScans.length > 0 ? <Pagination {...pagedScans} /> : null}
      </Card>
    </div>
  );
}
