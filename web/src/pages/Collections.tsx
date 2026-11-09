import { useState } from "react";
import { PageTitle } from "@/components/Layout";
import { FindingsPanel, ReportsPanel } from "@/components/panels";
import { Card, CardContent } from "@/components/ui/card";
import { Empty, Loading } from "@/components/ui/misc";
import { StateBadge } from "@/components/ui/badge";
import { useApi } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { formatTime, shortId } from "@/lib/utils";

function ScanPicker({
  scans,
  value,
  onChange,
}: {
  scans: Scan[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <Card className="mb-4">
      <CardContent className="flex flex-wrap items-center gap-2 p-3">
        <span className="text-[11px] uppercase tracking-wide text-zinc-500">Scan</span>
        <select
          className="h-8 min-w-[22rem] rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs"
          value={value}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">Select a scan…</option>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              {shortId(s.id)} — {s.name || s.seed_urls?.[0] || "scan"} ({s.state})
            </option>
          ))}
        </select>
        {value ? (
          <a href={`#/scans/${value}`} className="text-[11px] text-emerald-300 hover:underline">
            open scan →
          </a>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function FindingsPage() {
  const scans = useApi<Scan[]>("/api/scans");
  const [scanId, setScanId] = useState("");
  return (
    <div>
      <PageTitle
        title="Findings"
        subtitle="Findings are stored per scan. Pick a scan to review verdicts, evidence and the exact candidate."
      />
      {scans.loading && !scans.data ? (
        <Loading />
      ) : !(scans.data ?? []).length ? (
        <Empty>No scans yet.</Empty>
      ) : (
        <>
          <ScanPicker scans={scans.data ?? []} value={scanId} onChange={setScanId} />
          {scanId ? (
            <FindingsPanel scanId={scanId} />
          ) : (
            <Empty>Select a scan to see its findings.</Empty>
          )}
        </>
      )}
    </div>
  );
}

export function ReportsPage() {
  const scans = useApi<Scan[]>("/api/scans");
  const [scanId, setScanId] = useState("");
  const selected = (scans.data ?? []).find((s) => s.id === scanId);
  return (
    <div>
      <PageTitle
        title="Reports"
        subtitle="Deterministic reports rendered from stored findings — the scan's evidence stays the source of truth."
      />
      {scans.loading && !scans.data ? (
        <Loading />
      ) : !(scans.data ?? []).length ? (
        <Empty>No scans yet.</Empty>
      ) : (
        <>
          <ScanPicker scans={scans.data ?? []} value={scanId} onChange={setScanId} />
          {scanId ? (
            <>
              {selected ? (
                <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-zinc-500">
                  <StateBadge state={selected.state} />
                  <span>{selected.stats?.findings_confirmed ?? 0} confirmed</span>
                  <span>·</span>
                  <span>{formatTime(selected.created_at)}</span>
                </div>
              ) : null}
              <ReportsPanel scanId={scanId} />
            </>
          ) : (
            <Empty>Select a scan to generate or open its reports.</Empty>
          )}
        </>
      )}
    </div>
  );
}
