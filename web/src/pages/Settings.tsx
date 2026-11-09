import { useEffect, useState } from "react";
import { KeyRound, RefreshCw, Save, Server, Trash2, Zap } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Alert, Code, Loading } from "@/components/ui/misc";
import { api, getToken, refreshAll, setToken, useApi } from "@/lib/api";
import { formatTime } from "@/lib/utils";

interface LLMStatus {
  configured: boolean;
  provider?: string;
  model?: string;
  base_url?: string;
  key_hint?: string;
  key_set?: boolean;
  providers?: Array<Record<string, unknown>>;
}

export default function Settings() {
  const status = useApi<LLMStatus>("/api/llm/config");
  const availability = useApi<{
    providers: { provider: string; label: string; configured: boolean; model?: string; source?: string }[];
    default?: string;
  }>("/api/llm/providers");
  const caps = useApi<Record<string, unknown>>("/api/capabilities");
  const version = useApi<{ version?: string }>("/api/version");

  const [form, setForm] = useState({ provider: "", model: "", base_url: "", api_key: "" });
  const [token, setLocalToken] = useState(getToken());
  const [msg, setMsg] = useState("");
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
    }));
  }, [status.data?.provider, status.data?.model, status.data?.base_url]);

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
                      <span className={p.configured ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>
                        {p.configured ? `${p.model ?? "model?"} · ${p.source ?? "configured"}` : "no credential"}
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
