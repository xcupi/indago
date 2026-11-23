import { useEffect, useRef, useState, type ReactNode } from "react";
import { ChevronDown, KeyRound, Layers, RefreshCw, Save, Server, Trash2, Zap } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Alert, Code, LoadError, Loading } from "@/components/ui/misc";
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
  providers?: { id: string; label: string; default_model?: string; default_base_url?: string }[];
}

interface ProviderAvailability {
  provider: string;
  label: string;
  configured: boolean;
  report_only?: boolean;
  model?: string;
  base_url?: string;
  key_hint?: string;
  source?: string;
}

const defaultForm = { provider: "", model: "", base_url: "", api_key: "", enabled: true, max_attempts: 10 };

interface LLMTestResult {
  ok: boolean;
  latency_ms?: number;
  error?: string;
}

function testResultMessage(result: LLMTestResult) {
  if (!result.ok) return result.error || "Connection test failed.";
  return `Model test succeeded (${result.latency_ms ?? 0} ms).`;
}

function sourceLabel(source?: string): string {
  switch (source) {
    case "environment":
      return "environment";
    case "settings":
      return "Settings";
    default:
      return source || "configured";
  }
}

function CollapsibleSection({
  title,
  description,
  icon,
  badge,
  defaultOpen = true,
  children,
}: {
  title: string;
  description: string;
  icon: ReactNode;
  badge?: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 border-b border-border py-2 text-left"
      >
        <span className="grid size-8 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">{icon}</span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-foreground">{title}</span>
          <span className="block truncate text-[11px] text-muted-foreground">{description}</span>
        </span>
        {badge ? (
          <span className="hidden shrink-0 rounded-full border border-border px-2 py-0.5 text-[10px] text-muted-foreground sm:inline">
            {badge}
          </span>
        ) : null}
        <ChevronDown className={`size-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open ? <div className="pt-3">{children}</div> : null}
    </section>
  );
}

export default function Settings() {
  const status = useApi<LLMStatus>("/api/llm/config");
  const availability = useApi<{
    providers: ProviderAvailability[];
    default?: string;
  }>("/api/llm/providers");
  const caps = useApi<Record<string, unknown>>("/api/capabilities");
  const version = useApi<{ version?: string }>("/api/version");

  const [form, setForm] = useState(defaultForm);
  const [token, setLocalToken] = useState(getToken());
  const [msg, setMsg] = useState("");
  const [probe, setProbe] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [manualModel, setManualModel] = useState(false);
  const [modelBusy, setModelBusy] = useState(false);
  const [modelNote, setModelNote] = useState("");
  const modelRequest = useRef(0);
  const providerInfo = availability.data?.providers.find((p) => p.provider === form.provider);

  // POST /api/llm/models asks the selected provider for its model list. The
  // endpoint returns {models, error} with 200 even when discovery fails, so
  // the note carries the provider's message instead of throwing.
  async function discoverModels(providerOverride?: string) {
    const request = ++modelRequest.current;
    setModelBusy(true);
    setModelNote("");
    setErr("");
    try {
      const res = await api<{ models: string[]; error?: string }>("/api/llm/models", {
        method: "POST",
        body: { provider: providerOverride ?? form.provider },
      });
      if (request !== modelRequest.current) return;
      setModels(res.models ?? []);
      if (!res.models?.length) {
        setModelNote(res.error ? `No models: ${res.error}` : "The provider returned no models.");
      } else {
        setModelNote(`${res.models.length} models discovered — pick one.`);
      }
    } catch (e) {
      if (request === modelRequest.current) setErr((e as Error).message);
    } finally {
      if (request === modelRequest.current) setModelBusy(false);
    }
  }

  // Auto-discover models whenever the selected provider already has a usable
  // credential (a saved key or environment variable).
  const selectedProviderReady = Boolean(providerInfo?.configured);
  const usesEnvironmentKey = providerInfo?.source === "environment";
  const hasStoredKey = providerInfo?.source === "settings";
  const storedKeyHint = hasStoredKey ? providerInfo.key_hint : undefined;
  const providerStatus = availability.data
    ? (selectedProviderReady ? "configured" : "not configured")
    : (availability.loading ? "loading credentials…" : "credentials unavailable");

  useEffect(() => {
    if (form.provider && selectedProviderReady) {
      void discoverModels(form.provider);
    } else {
      setModels([]);
      setModelBusy(false);
      setModelNote("");
    }
    return () => { modelRequest.current++; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.provider, selectedProviderReady]);

  useEffect(() => {
    if (!status.data) return;
    const saved = status.data;
    const provider = saved.provider === "custom" ? "" : saved.provider ?? "";
    setForm((f) => ({
      provider,
      model: provider ? saved.model ?? "" : "",
      base_url: provider ? saved.base_url ?? "" : "",
      api_key: f.provider === provider ? f.api_key : "",
      enabled: saved.enabled ?? defaultForm.enabled,
      max_attempts: saved.max_attempts ?? defaultForm.max_attempts,
    }));
  }, [status.data?.provider, status.data?.model, status.data?.base_url, status.data?.enabled, status.data?.max_attempts]);

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
          api_key: form.api_key,
          enabled: form.enabled,
          max_attempts: Number(form.max_attempts) || 0,
        },
      });
      setForm((current) => ({ ...current, api_key: "" }));
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
      const res = await api<LLMTestResult>(`/api/llm/test?provider=${encodeURIComponent(form.provider)}`, { method: "POST" });
      if (res.ok) setMsg(testResultMessage(res));
      else setErr(testResultMessage(res));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  async function remove() {
    if (!window.confirm("Clear all stored provider credentials and AI settings?")) return;
    setBusy("delete");
    setErr("");
    setMsg("");
    try {
      await api("/api/llm/config", { method: "DELETE" });
      setForm(defaultForm);
      setProbe({});
      setManualModel(false);
      setMsg("Saved AI configuration cleared.");
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  const providers = (status.data?.providers ?? []).filter((p) => p.id !== "custom");
  const providerList = (availability.data?.providers ?? []).filter((p) => p.provider !== "custom");
  const readyProviders = providerList.filter((p) => p.configured).length;
  const savedProvider = status.data?.provider === "custom" ? undefined : status.data?.provider;

  return (
    <div>
      <PageTitle title="Settings" subtitle="AI Gateway, control-plane token, and server build information." />

      <div className="space-y-6">
        <CollapsibleSection
          title="1. Provider Credentials"
          description="Check which AI providers have an API key configured."
          icon={<KeyRound className="size-4" />}
          badge={availability.data ? `${readyProviders} of ${providerList.length} ready` : undefined}
          defaultOpen
        >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Layers className="size-4 text-sky-700 dark:text-sky-400" /> Usable providers{availability.data ? ` (${readyProviders}/${providerList.length})` : ""}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {availability.error ? (
              <LoadError resource="AI provider credentials" error={availability.error} />
            ) : availability.loading && !availability.data ? (
              <Loading />
            ) : (
              <div className="space-y-1 rounded-md border border-border bg-muted/30 p-2">
                {providerList.map((p) => (
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
                              const res = await api<LLMTestResult>(
                                `/api/llm/test?provider=${p.provider}`,
                                { method: "POST", body: {} },
                              );
                              setProbe((prev) => ({
                                ...prev,
                                [p.provider]: testResultMessage(res),
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
                <p className="pt-1 text-[10px] text-muted-foreground">
                  Credentials and models are saved per provider. A provider can also use a server
                  key set through INDAGO_LLM_KEY_&lt;PROVIDER&gt;.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
        </CollapsibleSection>

        <CollapsibleSection
          title="2. Default Gateway & Model Selection"
          description="Choose a provider and its default model."
          icon={<Zap className="size-4" />}
          badge={status.data ? (savedProvider ? `${savedProvider}${status.data.model ? ` · ${status.data.model}` : ""}` : "not set") : undefined}
          defaultOpen
        >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="size-4 text-amber-700 dark:text-amber-400" /> AI Gateway
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {status.error ? (
              <LoadError resource="AI gateway settings" error={status.error} />
            ) : status.loading && !status.data ? (
              <Loading />
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                  <span>status:</span>
                  <span className={providerInfo?.configured ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>
                    {providerStatus}
                  </span>
                  {storedKeyHint ? <span className="mono">key {storedKeyHint}</span> : null}
                  {usesEnvironmentKey ? <span>key from environment</span> : null}
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Field label="Provider" className="sm:col-span-2">
                    <select
                      className="h-9 w-full rounded-md border border-border bg-card px-2 text-sm"
                      aria-label="Provider"
                      value={form.provider}
                      disabled={!availability.data || Boolean(busy)}
                      onChange={(e) => {
                        const provider = e.target.value;
                        const def = status.data?.providers?.find((p) => p.id === provider);
                        const selected = providerList.find((p) => p.provider === provider);
                        setModels([]);
                        setManualModel(false);
                        setModelNote("");
                        setModelBusy(false);
                        modelRequest.current++;
                        setForm({
                          ...form,
                          provider,
                          model: selected?.model ?? def?.default_model ?? "",
                          base_url: selected?.base_url ?? def?.default_base_url ?? "",
                          api_key: "",
                        });
                      }}
                    >
                      <option value="">Select…</option>
                      {providers.map((p) => (
                        <option key={p.id} value={p.id}>{p.label}</option>
                      ))}
                    </select>
                  </Field>
                  {form.provider ? (
                    <>
                      <Field label="Base URL" hint="Optional for providers with a default endpoint." className="sm:col-span-2">
                        <Input
                          aria-label="Base URL"
                          value={form.base_url}
                          onChange={(e) => setForm({ ...form, base_url: e.target.value })}
                          placeholder="https://api.example.com/v1"
                        />
                      </Field>
                      <Field
                        label="API key"
                        hint={usesEnvironmentKey ? "Leave blank to use the server environment key." : "Leave blank to keep this provider’s stored key."}
                        className="sm:col-span-2"
                      >
                        <Input
                          aria-label="API key"
                          type="password"
                          value={form.api_key}
                          onChange={(e) => setForm({ ...form, api_key: e.target.value })}
                          placeholder={hasStoredKey ? "•••• stored" : usesEnvironmentKey ? "server environment" : "paste a key"}
                        />
                      </Field>
                    </>
                  ) : null}
                  <Field
                    label="Default Model"
                    hint="Choose a text model from the API catalog or enter a model ID. Save it before testing."
                    className="sm:col-span-2"
                  >
                    <div className="flex gap-2">
                      {models.length > 0 && !manualModel ? (
                        <select
                          aria-label="Default model"
                          className="h-9 min-w-0 flex-1 rounded-md border border-border bg-card px-2 text-sm"
                          value={form.model}
                          onChange={(e) => setForm({ ...form, model: e.target.value })}
                        >
                          <option value="">Select a model…</option>
                          {form.model && !models.includes(form.model) ? <option value={form.model}>{form.model}</option> : null}
                          {models.map((m) => <option key={m} value={m}>{m}</option>)}
                        </select>
                      ) : <Input aria-label="Default model" value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} />}
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => discoverModels()}
                        disabled={modelBusy || !selectedProviderReady || Boolean(busy)}
                        title="Ask the selected provider for its model list"
                      >
                        <RefreshCw className="size-3.5" /> {modelBusy ? "…" : "Discover"}
                      </Button>
                    </div>
                    {models.length > 0 ? (
                      <button
                        type="button"
                        onClick={() => setManualModel(!manualModel)}
                        className="text-[11px] text-muted-foreground underline-offset-2 hover:underline"
                      >
                        {manualModel ? "Use catalog" : "Enter model ID"}
                      </button>
                    ) : null}
                    {modelNote ? <p className="text-[11px] text-muted-foreground">{modelNote}</p> : null}
                  </Field>
                  {providerInfo?.report_only ? (
                    <p className="text-[11px] text-muted-foreground sm:col-span-2">This provider is available for executive report summaries.</p>
                  ) : null}
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
                    className="sm:col-span-2"
                  >
                    <Input
                      type="number"
                      min={1}
                      max={50}
                      value={form.max_attempts}
                      onChange={(e) => setForm({ ...form, max_attempts: Number(e.target.value) })}
                    />
                  </Field>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" onClick={save} disabled={Boolean(busy) || !form.provider || !availability.data}>
                    <Save className="size-4" /> Save
                  </Button>
                  <Button size="sm" variant="secondary" onClick={test} disabled={Boolean(busy) || !selectedProviderReady}>
                    <Zap className="size-4" /> Test
                  </Button>
                  <Button size="sm" variant="destructive" onClick={remove} disabled={Boolean(busy) || !status.data?.configured || !availability.data}>
                    <Trash2 className="size-4" /> Clear all
                  </Button>
                </div>
              </>
            )}
            {err ? <Alert>{err}</Alert> : null}
            {msg ? <p className="text-[11px] text-emerald-700 dark:text-emerald-400">{msg}</p> : null}
          </CardContent>
        </Card>
        </CollapsibleSection>

        <CollapsibleSection
          title="Workspace"
          description="Browser token and the running server build."
          icon={<Server className="size-4" />}
          defaultOpen={false}
        >
        <div className="grid gap-4 lg:grid-cols-2">
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
              {version.error ? <LoadError resource="server version" error={version.error} /> : (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Version</span>
                  <span className="mono">{version.data?.version ?? "—"}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-muted-foreground">Now</span>
                <span>{formatTime(new Date().toISOString())}</span>
              </div>
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">Capabilities</div>
                {caps.data?.target_read_only ? (
                  <p className="mb-1 text-xs text-muted-foreground">Targets are read-only. Capture approved URLs from Projects.</p>
                ) : null}
                {caps.error ? <LoadError resource="server capabilities" error={caps.error} /> : (
                  <Code className="max-h-56">
                    {caps.data ? JSON.stringify(caps.data, null, 2) : "—"}
                  </Code>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
        </CollapsibleSection>
      </div>
    </div>
  );
}
