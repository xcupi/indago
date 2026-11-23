import { useRef, useState } from "react";
import { ArrowRight, ExternalLink, KeyRound, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { PageTitle, setSelectedProject } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Alert, Empty, Loading } from "@/components/ui/misc";
import { api, refreshAll, useApi } from "@/lib/api";

interface Program {
  slug: string;
  title: string;
  type: string;
  url?: string;
  bounty: boolean;
  scopes_count: number;
  bounty_reward_min: number;
  bounty_reward_max: number;
}

interface ProviderInfo {
  id: string;
  label: string;
  configured: boolean;
  public_browse: boolean;
  credential?: string;
  expires_at?: string;
  expired?: boolean;
  note: string;
}

const DEFAULT_PROVIDERS: ProviderInfo[] = [
  { id: "yeswehack", label: "YesWeHack", configured: false, public_browse: true, note: "" },
  { id: "hackerone", label: "HackerOne", configured: false, public_browse: false, note: "" },
  { id: "bugcrowd", label: "Bugcrowd", configured: false, public_browse: false, note: "" },
  { id: "intigriti", label: "Intigriti", configured: false, public_browse: false, note: "" },
];
const BULK_PAGE_LIMIT = 200;

interface ProvidersResponse {
  providers: ProviderInfo[];
}

interface ScopeRow {
  scope: string;
  scope_type: string;
  scope_type_name?: string;
  asset_value?: string;
}

interface Imported {
  slug: string;
  title: string;
  project_id: string;
  targets: string[];
  hosts: string[];
  scan_id?: string;
  scan_ids?: string[];
  scan_error?: string;
  hunting_user_agent?: string;
  skipped?: string[];
}

function formatExpiry(value?: string): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const formatted = d.toLocaleString("id-ID", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "Asia/Jakarta",
  });
  return `${formatted} WIB`;
}

/**
 * Bug-bounty programs. The list is loaded ONLY when the operator presses Load:
 * a page that re-renders (or a tab left open) must not poll the platform. The
 * server caches the result for ten minutes as well, and Refresh asks it to
 * bypass that cache.
 */
export default function Bounty() {
  const providers = useApi<ProvidersResponse>("/api/bounty/providers");
  const [selectedProvider, setSelectedProvider] = useState("yeswehack");
  const providerVersion = useRef(0);
  const [token, setToken] = useState("");
  const [tokenMsg, setTokenMsg] = useState("");
  const [saving, setSaving] = useState(false);

  const [search, setSearch] = useState("");
  const [loadedSearch, setLoadedSearch] = useState("");
  const [programs, setPrograms] = useState<Program[] | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [cached, setCached] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [importing, setImporting] = useState(false);
  const [imported, setImported] = useState<Imported[] | null>(null);
  const [detail, setDetail] = useState<{
    slug: string;
    title: string;
    rules?: string;
    scopes?: ScopeRow[];
    scopes_error?: string;
  } | null>(null);
  const [detailBusy, setDetailBusy] = useState("");
  const [selectingAll, setSelectingAll] = useState(false);
  const [selectAllNote, setSelectAllNote] = useState("");

  const providerList = providers.data?.providers?.length ? providers.data.providers : DEFAULT_PROVIDERS;
  const activeProvider = providers.data?.providers.find((p) => p.id === selectedProvider);
  const providerLabel =
    activeProvider?.label ?? DEFAULT_PROVIDERS.find((p) => p.id === selectedProvider)?.label ?? selectedProvider;
  const configured = Boolean(activeProvider?.configured);
  const expired =
    Boolean(activeProvider?.expired) ||
    Boolean(activeProvider?.expires_at && new Date(activeProvider.expires_at).getTime() <= Date.now());
  const connected = configured && !expired;

  function selectProvider(id: string) {
    if (id === selectedProvider || saving || importing) return;
    providerVersion.current++;
    setSelectedProvider(id);
    setToken("");
    setTokenMsg("");
    setShowToken(false);
    setPrograms(null);
    setPage(1);
    setTotal(0);
    setHasMore(false);
    setCached(false);
    setPicked({});
    setSelectAllNote("");
    setImported(null);
    setDetail(null);
    setDetailBusy("");
    setLoading(false);
    setSelectingAll(false);
    setErr("");
  }

  async function saveToken() {
    setSaving(true);
    setErr("");
    setTokenMsg("");
    try {
      await api(`/api/bounty/providers/${selectedProvider}/token`, { method: "PUT", body: { token } });
      setToken("");
      setShowToken(false);
      setTokenMsg(`${providerLabel} token saved. Scopes and report templates are now available.`);
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function disconnectToken() {
    setSaving(true);
    setErr("");
    setTokenMsg("");
    try {
      await api(`/api/bounty/providers/${selectedProvider}/token`, { method: "DELETE" });
      setToken("");
      setShowToken(false);
      setTokenMsg(`${providerLabel} credential disconnected.`);
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function load(refresh: boolean, nextPage = 1, query = search.trim()) {
    const version = providerVersion.current;
    setLoading(true);
    setErr("");
    setImported(null);
    try {
      const q = new URLSearchParams({
        provider: selectedProvider,
        type: "bug-bounty",
        scope_type: "web-application",
        page: String(nextPage),
      });
      if (query) q.set("search", query);
      if (refresh) q.set("refresh", "1");
      const res = await api<{ items: Program[]; cached: boolean; total: number; has_more: boolean; page: number }>(
        `/api/bounty/programs?${q.toString()}`,
      );
      if (version !== providerVersion.current) return;
      setPrograms(res.items);
      setCached(res.cached);
      setTotal(res.total);
      setHasMore(res.has_more);
      setPage(res.page);
      setLoadedSearch(query);
    } catch (e) {
      if (version !== providerVersion.current) return;
      setErr((e as Error).message);
      setPrograms([]);
    } finally {
      if (version === providerVersion.current) setLoading(false);
    }
  }

  const allOnPage = Boolean(programs?.length) && (programs ?? []).every((p) => picked[p.slug]);

  function toggleAllOnPage() {
    if (!programs) return;
    const next = { ...picked };
    for (const p of programs) next[p.slug] = !allOnPage;
    setPicked(next);
    setSelectAllNote("");
  }

  async function selectAllResults() {
    const version = providerVersion.current;
    setSelectingAll(true);
    setErr("");
    setSelectAllNote("");
    try {
      const slugs = new Set<string>();
      let p = 1;
      let more = true;
      while (more && p <= BULK_PAGE_LIMIT) {
        const q = new URLSearchParams({
          provider: selectedProvider,
          type: "bug-bounty",
          scope_type: "web-application",
          page: String(p),
        });
        if (loadedSearch) q.set("search", loadedSearch);
        const res = await api<{ items: Program[]; has_more: boolean }>(`/api/bounty/programs?${q.toString()}`);
        if (version !== providerVersion.current) return;
        for (const item of res.items) slugs.add(item.slug);
        more = res.has_more;
        p++;
      }
      if (more) throw new Error(`Bulk selection supports up to ${BULK_PAGE_LIMIT} pages. Narrow the search or select individual pages.`);
      setPicked((previous) => {
        const next = { ...previous };
        for (const slug of slugs) next[slug] = true;
        return next;
      });
      setSelectAllNote(`${slugs.size} program${slugs.size === 1 ? "" : "s"} selected across ${p - 1} page${p - 1 === 1 ? "" : "s"}.`);
    } catch (e) {
      if (version === providerVersion.current) setErr((e as Error).message);
    } finally {
      if (version === providerVersion.current) setSelectingAll(false);
    }
  }

  async function runImport() {
    const slugs = Object.keys(picked).filter((s) => picked[s]);
    if (!slugs.length) return;
    // Selections can span pages (and survive changing the program list), so
    // make the exact count explicit before a destructive intake action.
    if (slugs.length > 1) {
      const preview = slugs.slice(0, 8).join("\n");
      const more = slugs.length > 8 ? `\n… and ${slugs.length - 8} more` : "";
      if (!confirm(`Import ${slugs.length} selected programs?\n\n${preview}${more}\n\nThis is the entire selection, not only the visible page.`)) {
        return;
      }
    }
    setImporting(true);
    setErr("");
    try {
      const res = await api<{ imported: Imported[] }>("/api/bounty/import", {
        method: "POST",
        body: { provider: selectedProvider, slugs },
      });
      setImported(res.imported);
      // Make the imported project the active sidebar project so the Scans
      // page shows its auto-created drafts immediately.
      const firstProject = res.imported.find((i) => i.project_id);
      if (firstProject) setSelectedProject(firstProject.project_id);
      setPicked({});
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setImporting(false);
    }
  }

  async function preview(slug: string) {
    const version = providerVersion.current;
    setDetailBusy(slug);
    setErr("");
    try {
      const res = await api<{ program: { title: string; rules?: string }; scopes?: ScopeRow[]; scopes_error?: string }>(
        `/api/bounty/programs/${encodeURIComponent(slug)}?provider=${encodeURIComponent(selectedProvider)}`,
      );
      if (version !== providerVersion.current) return;
      setDetail({ slug, title: res.program.title, rules: res.program.rules, scopes: res.scopes, scopes_error: res.scopes_error });
    } catch (e) {
      if (version === providerVersion.current) setErr((e as Error).message);
    } finally {
      if (version === providerVersion.current) setDetailBusy("");
    }
  }

  const pickedCount = Object.values(picked).filter(Boolean).length;

  return (
    <div className="space-y-4">
      <PageTitle
        title="Bug bounty"
        subtitle="Program intake: import the program's scope, then scan it as a project. Submission stays manual."
      />

      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground">
        <span className="font-medium text-foreground">1. Find a program</span>
        <ArrowRight className="size-3" />
        <span className="font-medium text-foreground">2. Import scope → project</span>
        <ArrowRight className="size-3" />
        <span className="font-medium text-foreground">3. Scan targets</span>
        <ArrowRight className="size-3" />
        <span className="font-medium text-foreground">4. {providerLabel} report</span>
        <ArrowRight className="size-3" />
        <span className="font-medium text-foreground">5. Submit manually</span>
      </div>

      <div className="flex flex-wrap items-center gap-2" role="tablist" aria-label="Bug bounty provider">
        {providerList.map((p) => {
          const isSelected = p.id === selectedProvider;
          const isConnected = p.configured && !p.expired && !(p.expires_at && new Date(p.expires_at).getTime() <= Date.now());
          return (
            <Button
              key={p.id}
              type="button"
              size="sm"
              variant={isSelected ? "default" : "outline"}
              onClick={() => selectProvider(p.id)}
              disabled={saving || importing}
              aria-selected={isSelected}
              role="tab"
            >
              <span>{p.label}</span>
              {isConnected ? (
                <span
                  className="ml-1.5 inline-block size-1.5 rounded-full bg-emerald-400"
                  title="Connected"
                />
              ) : null}
            </Button>
          );
        })}
      </div>

      {err ? <Alert className="border-red-200 text-red-700 dark:border-red-900 dark:text-red-400">{err}</Alert> : null}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <KeyRound className="size-4" /> {providerLabel} access
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {providers.loading && !providers.data ? (
            <Loading />
          ) : (
            <>
              <p className="text-xs text-muted-foreground">
                {expired
                  ? `Your ${activeProvider?.credential === "session" ? "hunter session token" : "credential"} expired ${formatExpiry(activeProvider?.expires_at)}. API scopes and templates need a fresh token; public program browsing can continue.`
                  : connected
                    ? `Connected to ${providerLabel} with a ${activeProvider?.credential === "session" ? "hunter session token" : "personal access token"}${activeProvider?.expires_at ? `, valid until ${formatExpiry(activeProvider.expires_at)}` : ""}. Scopes, report templates and drafts are read from the API.`
                    : activeProvider?.note ||
                      `Connect a ${providerLabel} credential to load scopes and API-backed details.`}
              </p>
              {activeProvider?.note && (expired || connected) ? (
                <p className="text-[11px] text-muted-foreground">{activeProvider.note}</p>
              ) : null}
              {selectedProvider === "yeswehack" ? (
                <p className="rounded-md border border-border bg-muted/30 px-2.5 py-2 text-[11px] leading-relaxed text-muted-foreground">
                  <span className="font-medium text-foreground">What is a hunter session token?</span>{" "}
                  It is the short-lived access token from your logged-in yeswehack.com browser tab,
                  not your password and not a manager API key. Copy it with{" "}
                  <span className="mono">copy(localStorage.access_token)</span> in DevTools, paste it here, and
                  replace it when it expires. A personal access token is the alternative for manager accounts.
                </p>
              ) : null}
              {(connected || expired) && !showToken ? (
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  {connected ? (
                    <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                      connected · {activeProvider?.credential === "session" ? "hunter session" : "personal access token"}
                      {activeProvider?.expires_at ? ` · expires ${formatExpiry(activeProvider.expires_at)}` : ""}
                    </span>
                  ) : (
                    <span className="rounded bg-amber-100 px-1.5 py-0.5 text-amber-800 dark:bg-amber-950 dark:text-amber-300">
                      expired
                    </span>
                  )}
                  <Button size="sm" variant="outline" onClick={() => setShowToken(true)}>
                    Replace credential
                  </Button>
                  <Button size="sm" variant="ghost" onClick={disconnectToken} disabled={saving}>
                    Disconnect
                  </Button>
                </div>
              ) : (
                <div className="flex flex-wrap items-end gap-2">
                  <Field label="API token or credential" className="min-w-[280px] flex-1">
                    <Input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="paste token" />
                  </Field>
                  <Button onClick={saveToken} disabled={saving || !token.trim()}>
                    {saving ? <Loader2 className="size-3.5 animate-spin" /> : null} Connect
                  </Button>
                  {showToken ? (
                    <Button variant="ghost" onClick={() => setShowToken(false)} disabled={saving}>
                      Cancel
                    </Button>
                  ) : null}
                </div>
              )}
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
            <Button onClick={() => load(false)} disabled={loading || selectingAll}>
              {loading ? <Loader2 className="size-3.5 animate-spin" /> : null} Load programs
            </Button>
            <Button variant="outline" onClick={() => load(true, page, loadedSearch)} disabled={loading || selectingAll || programs === null}>
              <RefreshCw className="size-3.5" /> Refresh
            </Button>
          </div>
          <p className="text-[11px] text-muted-foreground">
            Bounty programs filtered to <span className="mono">web-application</span> scope (
            {programs === null ? "not loaded yet — press Load" : `page ${page}, ${programs.length} of ${total || programs.length}${cached ? ", cached" : ""}`}).
          </p>

          {programs !== null ? (
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/30 px-2.5 py-2">
              <label className="flex items-center gap-2 text-[11px] text-foreground">
                <input type="checkbox" checked={allOnPage} onChange={toggleAllOnPage} />
                Select all on this page
              </label>
              <Button size="sm" variant="outline" onClick={selectAllResults} disabled={selectingAll || loading || !total}>
                {selectingAll ? <Loader2 className="size-3.5 animate-spin" /> : null}
                Select all results ({total || "?"})
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setPicked({});
                  setSelectAllNote("");
                }}
                disabled={pickedCount === 0}
              >
                Clear
              </Button>
              <span className="ml-auto text-[11px] text-muted-foreground">{pickedCount} selected</span>
            </div>
          ) : null}
          {selectAllNote ? <p className="text-[11px] text-emerald-700 dark:text-emerald-400">{selectAllNote}</p> : null}

          {programs === null ? (
            <Empty>Programs are not loaded. Press “Load programs” to query {providerLabel}.</Empty>
          ) : programs.length === 0 ? (
            <Empty>No web-application bounty programs matched.</Empty>
          ) : (
            <div className="max-h-[420px] space-y-1 overflow-y-auto pr-1">
              {programs.map((p) => {
                const programUrl = p.url || (selectedProvider === "yeswehack" ? `https://yeswehack.com/programs/${p.slug}` : "");
                return (
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
                  <button
                    className="shrink-0 rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-muted"
                    onClick={(e) => {
                      e.preventDefault();
                      preview(p.slug);
                    }}
                    title="Preview scope and rules"
                    disabled={Boolean(detailBusy)}
                  >
                    {detailBusy === p.slug ? "…" : "scope"}
                  </button>
                  {programUrl ? (
                    <a
                      href={programUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="text-muted-foreground hover:text-foreground"
                      title={`Open on ${providerLabel}`}
                    >
                      <ExternalLink className="size-3.5" />
                    </a>
                  ) : null}
                </label>
                );
              })}
            </div>
          )}

          {programs !== null ? (
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" disabled={loading || selectingAll || page <= 1} onClick={() => load(false, page - 1, loadedSearch)}>
                Previous
              </Button>
              <Button size="sm" variant="outline" disabled={loading || selectingAll || !hasMore} onClick={() => load(false, page + 1, loadedSearch)}>
                Next
              </Button>
            </div>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={runImport} disabled={importing || pickedCount === 0}>
              {importing ? <Loader2 className="size-3.5 animate-spin" /> : null} Import {pickedCount || ""} selected
            </Button>
            <span className="text-[11px] text-muted-foreground">
              Import reads the program's scope table, creates a project with that scope, and one draft scan
              per in-scope web target (anonymous auth, balanced defaults). It does not start the scans.
            </span>
          </div>

          {detail ? (
            <div className="space-y-2 rounded-md border border-border p-2.5 text-[11px]">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-foreground">{detail.title}</span>
                <button className="text-muted-foreground hover:text-foreground" onClick={() => setDetail(null)}>
                  close
                </button>
              </div>
              <div>
                <span className="text-muted-foreground">Scopes ({detail.scopes?.length ?? 0})</span>
                <div className="mono mt-1 max-h-32 space-y-0.5 overflow-y-auto">
                  {(detail.scopes ?? []).slice(0, 40).map((sc, i) => (
                    <div key={i}>
                      <span className="text-muted-foreground">{sc.scope_type}</span> {sc.scope}
                    </div>
                  ))}
                  {detail.scopes_error ? <div className="text-amber-700 dark:text-amber-400">{detail.scopes_error}</div> : null}
                </div>
              </div>
              {detail.rules ? (
                <details>
                  <summary className="cursor-pointer text-muted-foreground">Rules (from the program)</summary>
                  <pre className="mt-1 max-h-72 overflow-y-auto whitespace-pre-wrap text-[10px] text-muted-foreground">{detail.rules}</pre>
                </details>
              ) : null}
              <p className="text-muted-foreground">Import creates a project whose include list is the web-application assets above.</p>
            </div>
          ) : null}

          {imported ? (
            <div className="space-y-2 rounded-md border border-border p-2.5">
              <p className="text-[11px] text-muted-foreground">
                Imported as projects with the platform's scope and one draft scan per in-scope target with anonymous
                auth. Review the scope and User-Agent, then start each scan. No scan was started automatically.
              </p>
              {imported.map((it) => (
                <div key={it.slug} className="text-[11px]">
                  <a className="font-medium text-emerald-700 hover:underline dark:text-emerald-400" href={`#/projects/${it.project_id}`}>
                    {it.title}
                  </a>
                  <span className="ml-2 mono text-muted-foreground">{(it.hosts ?? []).join(", ") || "no host"}</span>
                  {(it.scan_ids?.length ? it.scan_ids : it.scan_id ? [it.scan_id] : []).map((scanID, i) => (
                    <a key={scanID} className="ml-2 text-muted-foreground hover:underline" href={`#/scans/${scanID}`}>
                      draft scan {i + 1}
                    </a>
                  ))}
                  {it.scan_error ? <span className="ml-2 text-amber-700 dark:text-amber-400">scan: {it.scan_error}</span> : null}
                  {it.hunting_user_agent ? <span className="ml-2 mono text-muted-foreground">UA: {it.hunting_user_agent}</span> : null}
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
