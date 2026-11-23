import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Alert, Code } from "@/components/ui/misc";
import { api, refreshAll } from "@/lib/api";
import type { AuthProfile } from "@/lib/types";
import { formatTime } from "@/lib/utils";

interface Snapshot {
  source: "target_read_only";
  method: "GET";
  url: string;
  status: number;
  captured_at: string;
  size: number;
  sha256: string;
  media_type: string;
  truncated: boolean;
  body_text: string;
  redirect_not_followed: boolean;
}

export function ReadSnapshot({ projectId, profiles }: { projectId: string; profiles: AuthProfile[] }) {
  const [url, setURL] = useState("");
  const [profile, setProfile] = useState("");
  const [approved, setApproved] = useState(false);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [localCopy, setLocalCopy] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sessionName, setSessionName] = useState("");
  const [statePath, setStatePath] = useState("");

  const root = `/api/projects/${encodeURIComponent(projectId)}`;

  async function saveSession() {
    setError("");
    setBusy(true);
    setApproved(false);
    try {
      const saved = await api<AuthProfile>(root + "/auth-profiles" + (profile ? `/${encodeURIComponent(profile)}` : ""), {
        method: profile ? "PUT" : "POST",
        body: { name: sessionName.trim(), state_path: statePath.trim() },
      });
      setStatePath("");
      setSessionName("");
      setProfile(saved.id);
      refreshAll();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function capture() {
    setError("");
    setSnapshot(null);
    setBusy(true);
    setApproved(false);
    try {
      const data = await api<Snapshot>(root + "/read-snapshot", {
        method: "POST",
        body: { url: url.trim(), approved_read_only: approved, auth_profile_id: profile },
      });
      setSnapshot(data);
      setLocalCopy(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function openSnapshot(file: File) {
    setError("");
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error("Snapshot exceeds the local file size limit.");
      const data: unknown = JSON.parse(await file.text());
      if (!data || typeof data !== "object") throw new Error("Invalid snapshot file.");
      const value = data as Partial<Snapshot>;
      if (value.source !== "target_read_only" || value.method !== "GET" ||
          typeof value.url !== "string" || typeof value.status !== "number" ||
          typeof value.size !== "number" || typeof value.captured_at !== "string" ||
          typeof value.sha256 !== "string" || typeof value.body_text !== "string") {
        throw new Error("Invalid snapshot file.");
      }
      setSnapshot(value as Snapshot);
      setLocalCopy(true);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function download() {
    if (!snapshot) return;
    const href = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = href;
    link.download = "indago-read-snapshot.json";
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(href), 1000);
  }

  return (
    <Card>
      <CardHeader><CardTitle>Read-only snapshot</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Capture a single approved URL inside this project scope. Redirects and assets will require separate approval.
        </p>
        <Field label="Read-only URL">
          <Input type="url" aria-label="Read-only URL" placeholder="https://app.example.com/status"
            value={url} onChange={(e) => { setURL(e.target.value); setApproved(false); }} disabled={busy} />
        </Field>
        <Field label="Session">
          <select aria-label="Session" value={profile} disabled={busy}
            className="h-9 rounded-md border border-border bg-card px-2 text-sm"
            onChange={(e) => { setProfile(e.target.value); setApproved(false); }}>
            <option value="">Anonymous</option>
            {profiles.filter((p) => p.state_path).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </Field>
        <details className="space-y-2 text-xs">
          <summary className="cursor-pointer">Import or replace a saved read-only session</summary>
          {!profile ? <Field label="Session name">
            <Input aria-label="Session name" value={sessionName} disabled={busy} onChange={(e) => setSessionName(e.target.value)} />
          </Field> : null}
          <Field label="Local storage-state path" hint="Use an existing browser session from a read-only account.">
            <Input aria-label="Local storage-state path" value={statePath} disabled={busy} onChange={(e) => setStatePath(e.target.value)} />
          </Field>
          <Button size="sm" variant="outline" onClick={saveSession} disabled={busy || !statePath.trim() || (!profile && !sessionName.trim())}>
            {profile ? "Replace selected session" : "Import session"}
          </Button>
        </details>
        <label className="flex gap-2 text-xs">
          <input type="checkbox" checked={approved} disabled={busy} onChange={(e) => setApproved(e.target.checked)} />
          I verified that this exact URL and any selected account are read-only.
        </label>
        <Button size="sm" onClick={capture} disabled={busy || !approved || !url.trim()}>
          {busy ? "Working…" : "Capture snapshot"}
        </Button>
        <Field label="Open a saved snapshot" hint="The file is read in this browser.">
          <Input type="file" accept=".json,application/json" aria-label="Open a saved snapshot" disabled={busy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = "";
              if (file) void openSnapshot(file);
            }} />
        </Field>
        {error ? <Alert>{error}</Alert> : null}
        {snapshot ? (
          <div className="space-y-2 rounded-md border border-border p-3">
            <p className="break-all text-xs" role="status">{localCopy ? "Local snapshot" : "Target read"} · GET {snapshot.status} · {formatTime(snapshot.captured_at)} · {snapshot.url}</p>
            {snapshot.redirect_not_followed ? <p className="text-xs">The redirect destination was not requested.</p> : null}
            {snapshot.status === 401 || snapshot.status === 403 ? <p className="text-xs">If access is required, import an updated read-only session.</p> : null}
            <p className="break-all text-xs text-muted-foreground">{snapshot.size} captured bytes{snapshot.truncated ? " (truncated)" : ""} · SHA-256 {snapshot.sha256}</p>
            {snapshot.body_text ? <Code className="max-h-80 whitespace-pre-wrap break-all">{snapshot.body_text}</Code>
              : <p className="text-xs text-muted-foreground">No readable text body in this capture.</p>}
            <Button size="sm" variant="outline" onClick={download}>Download snapshot</Button>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
