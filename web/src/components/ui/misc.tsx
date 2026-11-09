import * as React from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

export function Alert({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      role="alert"
      className={cn(
        "flex items-start gap-2 rounded-md border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 px-3 py-2 text-xs text-red-700 dark:text-red-400",
        className,
      )}
    >
      <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
      <div className="min-w-0 break-words">{children}</div>
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("size-4 animate-spin text-muted-foreground", className)} />;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-3 py-6 text-xs text-muted-foreground">
      <Spinner /> {label}
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-border px-4 py-10 text-center text-xs text-muted-foreground">
      {children}
    </div>
  );
}

export function Stat({
  label,
  value,
  tone = "default",
  hint,
}: {
  label: string;
  value: React.ReactNode;
  tone?: "default" | "danger" | "success" | "warn";
  hint?: string;
}) {
  const toneClass =
    tone === "danger"
      ? "text-red-700 dark:text-red-400"
      : tone === "success"
        ? "text-emerald-700 dark:text-emerald-400"
        : tone === "warn"
          ? "text-amber-700 dark:text-amber-400"
          : "text-foreground";
  return (
    <div className="rounded-lg border border-border bg-muted p-3">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={cn("mt-1 text-xl font-semibold tabular-nums", toneClass)}>{value}</div>
      {hint ? <div className="mt-0.5 text-[11px] text-muted-foreground">{hint}</div> : null}
    </div>
  );
}

export function Code({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <pre
      className={cn(
        "mono max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background/95 p-3 text-[11px] leading-relaxed text-foreground",
        className,
      )}
    >
      {children}
    </pre>
  );
}
