import { useEffect, useState } from "react";
import { KeyRound, RefreshCw, Save, Server, Trash2, Zap } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Alert, Code, Loading } from "@/components/ui/misc";
import { Switch } from "@/components/ui/controls";
import { api, getToken, refreshAll, setToken, useApi } from "@/lib/api";
import { formatTime } from "@/lib/utils";

interface LLMStatus {
  configured: boolean;
  enabled?: boolean;
  max_attempts?: number;
  provider?: string;
  model?: string;
  base_url?: string;
  key_hint?: string;
  key_set?: boolean;
  providers?: Array<Record<string, unknown>>;
}

function sourceLabel(source?: string): string {
  switch (source) {
    case "hermes":
      return "Hermes session (borrowed)";
    case "indago":
      return "Indago session";
    case "environment":
      return "environment";
    case "settings":
      return "Settings";
    default:
      return source || "configured";
  }
}

export default function Settings() {
  const status = useApi<LLMStatus>("/api/llm/config");
  const availability = useApi<{
    providers: { provider: string; label: string; configured: boolean; model?: string; source?: string }[];
    default?: string;
  }>("/api/llm/providers");
  const caps = useApi<Record<string, unknown>>("/api/capabilities");
  const version = useApi<{ version?: string }>("/api/version");

  const [form, setForm] = useState({ provider: "", model: "", base_url: "", api_key: "", enabled: true, max_attempts: 10 });
  const [token, setLocalToken] = useState(getToken());
  const [msg, setMsg] = useState("");
  const [probe, setProbe] = useState<Record<string, string>>({});
  const cg = useApi<{ logged_in: boolean; source: string; account?: string; plan?: string; expires_at?: string }>(
    "/api/llm/chatgpt/session",
  );
  const claude = useApi<{ connected: boolean; expires_at?: string }>("/api/llm/claude/session");
  const [cgLogin, setCgLogin] = useState<{ device_auth_id: string; user_code: string; url: string; interval_seconds: number } | null>(null);
  const [claudeUrl, setClaudeUrl] = useState("");
  const [claudeState, setClaudeState] = useState("");
  const [claudeCode, setClaudeCode] = useState("");
  const [claudeMsg, setClaudeMsg] = useState("");
  const [cgMsg, setCgMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [modelBusy, setModelBusy] = useState(false);
  const [modelNote, setModelNote] = useState("");

  // POST /api/llm/models asks the SAVED provider for its model list. The
  // endpoint returns {models, error} with 200 even when discovery fails, so
  // the note carries the provider's message instead of throwing.
  async function discoverModels() {
    setModelBusy(true);
    setModelNote("");
    setErr("");
    try {
      const res = await api<{ models: string[]; error?: string }>("/api/llm/models", {
        method: "POST",
        body: {},
      });
      setModels(res.models ?? []);
      if (!res.models?.length) {
        setModelNote(res.error ? `No models: ${res.error}` : "The provider returned no models.");
      } else {
        setModelNote(`${res.models.length} models discovered — pick one.`);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setModelBusy(false);
    }
  }

  useEffect(() => {
    if (!status.data) return;
    setForm((f) => ({
      ...f,
      provider: status.data?.provider ?? f.provider,
      model: status.data?.model ?? f.model,
      base_url: status.data?.base_url ?? f.base_url,
      enabled: status.data?.enabled ?? f.enabled,
      max_attempts: status.data?.max_attempts ?? f.max_attempts,
    }));
  }, [status.data?.provider, status.data?.model, status.data?.base_url]);

  // Poll the device-code login until OpenAI confirms it, then refresh the
  // provider list so "chatgpt" flips to configured without a reload.
  useEffect(() => {
    if (!cgLogin) return;
    const ms = Math.max(3, cgLogin.interval_seconds || 5) * 1000;
    const timer = setInterval(async () => {
      try {
        const res = await api<{ state: string; account?: string }>("/api/llm/chatgpt/login/poll", {
          method: "POST",
          body: { device_auth_id: cgLogin.device_auth_id },
        });
        if (res.state === "done") {
          setCgLogin(null);
          setCgMsg(`Logged in${res.account ? ` as ${res.account}` : ""}.`);
          refreshAll();
        }
      } catch (e) {
        setCgLogin(null);
        setCgMsg((e as Error).message);
      }
    }, ms);
    return () => clearInterval(timer);
  }, [cgLogin]);

  async function save() {
    setBusy("save");
    setErr("");
    setMsg("");
    try {
      await api("/api/llm/config", {
        method: "PUT",
        body: {
          provider: form.provider,
          model: form.model,
          base_url: form.base_url,
          api_key: form.api_key, // empty keeps the stored key
          enabled: form.enabled,
          max_attempts: Number(form.max_attempts) || 0,
        },
      });
      setForm({ ...form, api_key: "" });
      setMsg("LLM configuration saved.");
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  async function test() {
    setBusy("test");
    setErr("");
    setMsg("");
    try {
      const res = await api<Record<string, unknown>>("/api/llm/test", { method: "POST", body: {} });
      setMsg("LLM test OK: " + JSON.stringify(res));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  async function remove() {
    setBusy("delete");
    setErr("");
    setMsg("");
    try {
      await api("/api/llm/config", { method: "DELETE" });
      setMsg("LLM configuration cleared.");
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  const providers = (status.data?.providers ?? []).map((p) => String((p as { id?: string }).id ?? p));

  return (
    <div>
      <PageTitle title="Settings" subtitle="AI Gateway, control-plane token, and server build information." />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="size-4 text-amber-700 dark:text-amber-400" /> AI Gateway
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {status.loading && !status.data ? (
              <Loading />
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                  <span>status:</span>
                  <span className={status.data?.configured ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>
                    {status.data?.configured ? "configured" : "not configured"}
                  </span>
                  {status.data?.key_set ? (
                    <span className="mono">key {status.data?.key_hint}</span>
                  ) : null}
                </div>
                <div className="space-y-1 rounded-md border border-border bg-muted/30 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Usable providers</div>
                  {(availability.data?.providers ?? []).map((p) => (
                    <div key={p.provider} className="flex items-center justify-between gap-2 text-[11px]">
                      <span className="text-foreground">{p.label}</span>
                      <span className="flex items-center gap-2">
                        <span className={p.configured ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>
                          {p.configured ? `${p.model || "model: auto"} · ${sourceLabel(p.source)}` : "no credential"}
                        </span>
                        {p.configured ? (
                          <button
                            className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground hover:text-foreground"
                            onClick={async () => {
                              try {
                                const res = await api<{ ok: boolean; latency_ms?: number; error?: string }>(
                                  `/api/llm/test?provider=${p.provider}`,
                                  { method: "POST", body: {} },
                                );
                                setProbe((prev) => ({
                                  ...prev,
                                  [p.provider]: res.ok ? `ok ${res.latency_ms ?? 0}ms` : res.error || "failed",
                                }));
                              } catch (e) {
                                setProbe((prev) => ({ ...prev, [p.provider]: (e as Error).message }));
                              }
                            }}
                          >
                            test
                          </button>
                        ) : null}
                        {probe[p.provider] ? (
                          <span className="text-[10px] text-muted-foreground">{probe[p.provider]}</span>
                        ) : null}
                      </span>
                    </div>
                  ))}
                  <p className="text-[10px] text-muted-foreground">
                    Add a second provider without moving the stored key: start the server with
                    INDAGO_LLM_KEY_&lt;PROVIDER&gt; (e.g. INDAGO_LLM_KEY_OPENAI). Scans and reports can then pick either.
                  </p>
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Field label="Provider">
                    <select
                      className="h-9 rounded-md border border-border bg-card px-2 text-sm"
                      value={form.provider}
                      onChange={(e) => setForm({ ...form, provider: e.target.value })}
                    >
                      <option value="">Select…</option>
                      {providers.map((p) => (
                        <option key={p}>{p}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Model" hint="Empty saves no model; discovery reads the saved provider.">
                    <div className="flex gap-2">
                      <Input value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} />
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={discoverModels}
                        disabled={modelBusy}
                        title="Ask the saved provider for its model list"
                      >
                        <RefreshCw className="size-3.5" /> {modelBusy ? "…" : "Discover"}
                      </Button>
                    </div>
                    {models.length ? (
                      <select
                        className="mt-1 h-9 w-full rounded-md border border-border bg-card px-2 text-sm"
                        value={models.includes(form.model) ? form.model : ""}
                        onChange={(e) => e.target.value && setForm({ ...form, model: e.target.value })}
                      >
                        <option value="">Pick a discovered model…</option>
                        {models.map((m) => (
                          <option key={m}>{m}</option>
                        ))}
                      </select>
                    ) : null}
                    {modelNote ? <p className="text-[11px] text-muted-foreground">{modelNote}</p> : null}
                  </Field>
                  <Field label="Base URL" hint="Optional for providers with a default endpoint." className="sm:col-span-2">
                    <Input
                      value={form.base_url}
                      onChange={(e) => setForm({ ...form, base_url: e.target.value })}
                      placeholder="https://api.example.com/v1"
                    />
                  </Field>
                  <Field
                    label="AI advisory"
                    hint="Master switch. Off means no advisory call at all — scanning and reports keep working without a model."
                    className="sm:col-span-2"
                  >
                    <div className="flex items-center gap-3">
                      <Switch checked={form.enabled} onCheckedChange={(v) => setForm({ ...form, enabled: v })} />
                      <span className="text-xs text-muted-foreground">
                        {form.enabled ? "Enabled — payload diagnosis and report narration may run" : "Disabled — no LLM call is made"}
                      </span>
                    </div>
                  </Field>
                  <Field
                    label="Attempts per parameter"
                    hint="Advisory budget. After this many failed model calls for one parameter, Indago stops asking and continues with its own testing. Applies to every provider."
                  >
                    <Input
                      type="number"
                      min={1}
                      max={50}
                      value={form.max_attempts}
                      onChange={(e) => setForm({ ...form, max_attempts: Number(e.target.value) })}
                    />
                  </Field>
                  <Field label="API key" hint="Empty keeps the stored key. Never echoed back." className="sm:col-span-2">
                    <Input
                      type="password"
                      value={form.api_key}
                      onChange={(e) => setForm({ ...form, api_key: e.target.value })}
                      placeholder={status.data?.key_set ? "•••• stored" : "paste a key"}
                    />
                  </Field>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" onClick={save} disabled={busy === "save"}>
                    <Save className="size-4" /> Save
                  </Button>
                  <Button size="sm" variant="secondary" onClick={test} disabled={busy === "test"}>
                    <Zap className="size-4" /> Test
                  </Button>
                  <Button size="sm" variant="destructive" onClick={remove} disabled={busy === "delete"}>
                    <Trash2 className="size-4" /> Clear
                  </Button>
                </div>
              </>
            )}
            {err ? <Alert>{err}</Alert> : null}
            {msg ? <p className="text-[11px] text-emerald-700 dark:text-emerald-400">{msg}</p> : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="size-4 text-emerald-700 dark:text-emerald-400" /> Claude OAuth session
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-[11px]">
            {claude.data?.connected ? (
              <p className="text-foreground">
                connected{claude.data.expires_at ? ` · expires ${formatTime(claude.data.expires_at)}` : ""} · token refreshed automatically
              </p>
            ) : (
              <p className="text-muted-foreground">
                No session yet. Connect your Claude account without an API key (PKCE, same flow Claude Code uses).
              </p>
            )}
            {claudeUrl ? (
              <div className="space-y-1 rounded-md border border-border bg-muted/30 p-2">
                <p>
                  Open{" "}
                  <a className="break-all text-emerald-700 underline dark:text-emerald-400" href={claudeUrl} target="_blank" rel="noreferrer">
                    the authorization page
                  </a>{" "}
                  and approve. Copy the code it shows, paste it below.
                </p>
                <div className="flex gap-2">
                  <Input value={claudeCode} onChange={(e) => setClaudeCode(e.target.value)} placeholder="code (or code#state)" />
                  <Button
                    size="sm"
                    onClick={async () => {
                      setClaudeMsg("");
                      try {
                        await api("/api/llm/claude/login/finish", {
                          method: "POST",
                          body: { code: claudeCode, state: claudeState },
                        });
                        setClaudeMsg("Claude connected.");
                        setClaudeCode("");
                        setClaudeUrl("");
                        refreshAll();
                      } catch (e) {
                        setClaudeMsg((e as Error).message);
                      }
                    }}
                  >
                    Finish
                  </Button>
                </div>
              </div>
            ) : null}
            {claudeMsg ? <p className="text-muted-foreground">{claudeMsg}</p> : null}
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={async () => {
                  setClaudeMsg("");
                  try {
                    const d = await api<{ url: string; state: string }>("/api/llm/claude/login/start", { method: "POST", body: {} });
                    setClaudeUrl(d.url);
                    setClaudeState(d.state);
                  } catch (e) {
                    setClaudeMsg((e as Error).message);
                  }
                }}
              >
                Connect Claude
              </Button>
              {claude.data?.connected ? (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={async () => {
                    try {
                      await api("/api/llm/claude/session", { method: "DELETE" });
                      setClaudeMsg("Disconnected.");
                      refreshAll();
                    } catch (e) {
                      setClaudeMsg((e as Error).message);
                    }
                  }}
                >
                  Disconnect
                </Button>
              ) : null}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="size-4 text-emerald-700 dark:text-emerald-400" /> ChatGPT OAuth session
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-[11px]">
            {cg.data?.logged_in ? (
              <p className="text-foreground">
                signed in{cg.data.account ? ` as ${cg.data.account}` : ""}
                {cg.data.plan ? ` · plan ${cg.data.plan}` : ""} · {sourceLabel(cg.data.source)}
                {cg.data.expires_at ? ` · expires ${formatTime(cg.data.expires_at)}` : ""}
              </p>
            ) : (
              <p className="text-muted-foreground">No session yet. Log in with a device code — no API key.</p>
            )}
            {cg.data?.logged_in && cg.data.source === "hermes" ? (
              <p className="text-amber-700 dark:text-amber-400">
                Indago has no ChatGPT session of its own, so it is borrowing the Hermes credential (read-only).
                Log in here to connect directly to ChatGPT and let Indago own the session.
              </p>
            ) : null}
            {cgLogin ? (
              <div className="space-y-1 rounded-md border border-border bg-muted/30 p-2">
                <p>
                  Open{" "}
                  <a className="text-emerald-700 underline dark:text-emerald-400" href={cgLogin.url} target="_blank" rel="noreferrer">
                    {cgLogin.url}
                  </a>{" "}
                  and enter:
                </p>
                <p className="mono text-base tracking-widest text-foreground">{cgLogin.user_code}</p>
                <p className="text-muted-foreground">Waiting for sign-in…</p>
              </div>
            ) : null}
            {cgMsg ? <p className="text-muted-foreground">{cgMsg}</p> : null}
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={async () => {
                  setCgMsg("");
                  try {
                    const d = await api<{ device_auth_id: string; user_code: string; url: string; interval_seconds: number }>(
                      "/api/llm/chatgpt/login",
                      { method: "POST", body: {} },
                    );
                    setCgLogin(d);
                  } catch (e) {
                    setCgMsg((e as Error).message);
                  }
                }}
              >
                Log in with ChatGPT
              </Button>
              {cg.data?.source === "indago" ? (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={async () => {
                    await api("/api/llm/chatgpt/session", { method: "DELETE" });
                    setCgMsg("Indago session cleared.");
                    refreshAll();
                  }}
                >
                  Log out
                </Button>
              ) : null}
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <KeyRound className="size-4 text-sky-700 dark:text-sky-400" /> Control-plane token
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Field
                label="Bearer token"
                hint="Only needed when the server runs with INDAGO_API_TOKEN. Stored in this browser only."
              >
                <Input
                  type="password"
                  value={token}
                  onChange={(e) => setLocalToken(e.target.value)}
                  placeholder="token"
                />
              </Field>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => {
                    setToken(token);
                    refreshAll();
                    setMsg("Token stored for this browser.");
                  }}
                >
                  Save token
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setToken("");
                    setLocalToken("");
                    refreshAll();
                  }}
                >
                  Clear
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="size-4 text-muted-foreground" /> Server
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-foreground">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Version</span>
                <span className="mono">{version.data?.version ?? "—"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Now</span>
                <span>{formatTime(new Date().toISOString())}</span>
              </div>
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">Capabilities</div>
                <Code className="max-h-56">
                  {caps.data ? JSON.stringify(caps.data, null, 2) : "—"}
                </Code>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
