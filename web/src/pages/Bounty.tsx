import { useState } from "react";
import { ExternalLink, KeyRound, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Alert, Empty, Loading } from "@/components/ui/misc";
import { api, refreshAll, useApi } from "@/lib/api";

interface Program {
  slug: string;
  title: string;
  type: string;
  bounty: boolean;
  scopes_count: number;
  bounty_reward_min: number;
  bounty_reward_max: number;
}

interface ProvidersResponse {
  providers: { id: string; label: string; configured: boolean; public_browse: boolean; note: string }[];
}

interface Imported {
  slug: string;
  title: string;
  project_id: string;
  targets: string[];
  hosts: string[];
  skipped?: string[];
}

/**
 * Bug-bounty programs. The list is loaded ONLY when the operator presses Load:
 * a page that re-renders (or a tab left open) must not poll the platform. The
 * server caches the result for ten minutes as well, and Refresh asks it to
 * bypass that cache.
 */
export default function Bounty() {
  const providers = useApi<ProvidersResponse>("/api/bounty/providers");
  const [token, setToken] = useState("");
  const [tokenMsg, setTokenMsg] = useState("");
  const [saving, setSaving] = useState(false);

  const [search, setSearch] = useState("");
  const [programs, setPrograms] = useState<Program[] | null>(null);
  const [cached, setCached] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [importing, setImporting] = useState(false);
  const [imported, setImported] = useState<Imported[] | null>(null);

  const ywh = providers.data?.providers.find((p) => p.id === "yeswehack");
  const configured = Boolean(ywh?.configured);

  async function saveToken() {
    setSaving(true);
    setErr("");
    setTokenMsg("");
    try {
      await api("/api/bounty/providers/yeswehack/token", { method: "PUT", body: { token } });
      setToken("");
      setTokenMsg("Token saved. Scopes and report templates are now available.");
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function load(refresh: boolean) {
    setLoading(true);
    setErr("");
    setImported(null);
    try {
      const q = new URLSearchParams({ type: "bug-bounty", scope_type: "web-application" });
      if (search.trim()) q.set("search", search.trim());
      if (refresh) q.set("refresh", "1");
      const res = await api<{ items: Program[]; cached: boolean }>(`/api/bounty/programs?${q.toString()}`);
      setPrograms(res.items);
      setCached(res.cached);
    } catch (e) {
      setErr((e as Error).message);
      setPrograms([]);
    } finally {
      setLoading(false);
    }
  }

  async function runImport() {
    const slugs = Object.keys(picked).filter((s) => picked[s]);
    if (!slugs.length) return;
    setImporting(true);
    setErr("");
    try {
      const res = await api<{ imported: Imported[] }>("/api/bounty/import", { method: "POST", body: { slugs } });
      setImported(res.imported);
      setPicked({});
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setImporting(false);
    }
  }

  const pickedCount = Object.values(picked).filter(Boolean).length;

  return (
    <div className="space-y-4">
      <PageTitle
        title="Bug bounty"
        subtitle="Pull in-scope web applications from a platform, then scan them inside the scope it defines."
      />

      {err ? <Alert className="border-red-200 text-red-700 dark:border-red-900 dark:text-red-400">{err}</Alert> : null}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <KeyRound className="size-4" /> YesWeHack access
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {providers.loading && !providers.data ? (
            <Loading />
          ) : (
            <>
              <p className="text-xs text-muted-foreground">
                {configured
                  ? "A personal access token is stored. The API now also serves report templates and drafts."
                  : "No token is needed to browse or import: scopes are read from each program's public page. A token is only useful for report templates/drafts, and YesWeHack only lets Business Unit Owner/Manager or Program Manager roles create one — a hunter account has no such menu."}
              </p>
              <div className="flex flex-wrap items-end gap-2">
                <Field label="Personal access token" className="min-w-[280px] flex-1">
                  <Input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="paste token" />
                </Field>
                <Button onClick={saveToken} disabled={saving || !token.trim()}>
                  {saving ? <Loader2 className="size-3.5 animate-spin" /> : null} Save token
                </Button>
              </div>
              {tokenMsg ? <p className="text-[11px] text-emerald-700 dark:text-emerald-400">{tokenMsg}</p> : null}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldCheck className="size-4" /> Programs
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Search" className="min-w-[220px] flex-1">
              <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="company or program name" />
            </Field>
            <Button onClick={() => load(false)} disabled={loading}>
              {loading ? <Loader2 className="size-3.5 animate-spin" /> : null} Load programs
            </Button>
            <Button variant="outline" onClick={() => load(true)} disabled={loading || programs === null}>
              <RefreshCw className="size-3.5" /> Refresh
            </Button>
          </div>
          <p className="text-[11px] text-muted-foreground">
            Bounty programs filtered to <span className="mono">web-application</span> scope ({programs === null ? "not loaded yet" : `${programs.length} shown${cached ? ", cached" : ""}`}).
            Nothing is fetched until you press Load.
          </p>

          {programs === null ? (
            <Empty>Programs are not loaded. Press “Load programs” to query YesWeHack.</Empty>
          ) : programs.length === 0 ? (
            <Empty>No web-application bounty programs matched.</Empty>
          ) : (
            <div className="max-h-[420px] space-y-1 overflow-y-auto pr-1">
              {programs.map((p) => (
                <label key={p.slug} className="flex items-start gap-2 rounded-md border border-border px-2.5 py-2 text-xs hover:bg-muted/50">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={Boolean(picked[p.slug])}
                    onChange={(e) => setPicked({ ...picked, [p.slug]: e.target.checked })}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-foreground">{p.title}</span>
                      <span className="mono text-[10px] text-muted-foreground">{p.slug}</span>
                    </span>
                    <span className="mt-0.5 flex flex-wrap gap-2 text-[10px] text-muted-foreground">
                      <span className="mono">{p.type}</span>
                      <span>{p.scopes_count} scopes</span>
                      {p.bounty ? (
                        <span className="mono">
                          {p.bounty_reward_min}–{p.bounty_reward_max}
                        </span>
                      ) : null}
                    </span>
                  </span>
                  <a
                    href={`https://yeswehack.com/programs/${p.slug}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-muted-foreground hover:text-foreground"
                    title="Open on YesWeHack"
                  >
                    <ExternalLink className="size-3.5" />
                  </a>
                </label>
              ))}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={runImport} disabled={importing || pickedCount === 0}>
              {importing ? <Loader2 className="size-3.5 animate-spin" /> : null} Import {pickedCount || ""} selected
            </Button>
            <span className="text-[11px] text-muted-foreground">
              Import reads the program's scope table and creates a project with that scope — it does not start a scan.
            </span>
          </div>

          {imported ? (
            <div className="space-y-2 rounded-md border border-border p-2.5">
              <p className="text-[11px] text-muted-foreground">
                Imported as projects with the platform's scope. No scan was started — open a project and pick the targets you want to test.
              </p>
              {imported.map((it) => (
                <div key={it.slug} className="text-[11px]">
                  <a className="font-medium text-emerald-700 hover:underline dark:text-emerald-400" href={`#/projects/${it.project_id}`}>
                    {it.title}
                  </a>
                  <span className="ml-2 mono text-muted-foreground">{it.hosts.join(", ") || "no host"}</span>
                  {it.skipped?.length ? <span className="ml-2 text-muted-foreground">skipped: {it.skipped.join(", ")}</span> : null}
                </div>
              ))}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
