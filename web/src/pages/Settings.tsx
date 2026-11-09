import { useEffect, useState } from "react";
import { KeyRound, Save, Server, Trash2, Zap } from "lucide-react";
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
  const caps = useApi<Record<string, unknown>>("/api/capabilities");
  const version = useApi<{ version?: string }>("/api/version");

  const [form, setForm] = useState({ provider: "", model: "", base_url: "", api_key: "" });
  const [token, setLocalToken] = useState(getToken());
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");

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
              <Zap className="size-4 text-amber-400" /> AI Gateway
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {status.loading && !status.data ? (
              <Loading />
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-zinc-500">
                  <span>status:</span>
                  <span className={status.data?.configured ? "text-emerald-400" : "text-zinc-400"}>
                    {status.data?.configured ? "configured" : "not configured"}
                  </span>
                  {status.data?.key_set ? (
                    <span className="mono">key {status.data?.key_hint}</span>
                  ) : null}
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Field label="Provider">
                    <select
                      className="h-9 rounded-md border border-zinc-700 bg-zinc-950/60 px-2 text-sm"
                      value={form.provider}
                      onChange={(e) => setForm({ ...form, provider: e.target.value })}
                    >
                      <option value="">Select…</option>
                      {providers.map((p) => (
                        <option key={p}>{p}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Model">
                    <Input value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} />
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
            {msg ? <p className="text-[11px] text-emerald-400">{msg}</p> : null}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <KeyRound className="size-4 text-sky-400" /> Control-plane token
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
                <Server className="size-4 text-zinc-400" /> Server
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-zinc-300">
              <div className="flex justify-between">
                <span className="text-zinc-500">Version</span>
                <span className="mono">{version.data?.version ?? "—"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Now</span>
                <span>{formatTime(new Date().toISOString())}</span>
              </div>
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wide text-zinc-500">Capabilities</div>
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
