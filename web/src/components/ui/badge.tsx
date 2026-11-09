import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium leading-none",
  {
    variants: {
      tone: {
        neutral: "border-zinc-700 bg-zinc-800/60 text-zinc-300",
        success: "border-emerald-800/60 bg-emerald-950/50 text-emerald-300",
        danger: "border-red-800/60 bg-red-950/50 text-red-300",
        warn: "border-amber-800/60 bg-amber-950/50 text-amber-300",
        info: "border-sky-800/60 bg-sky-950/50 text-sky-300",
        violet: "border-violet-800/60 bg-violet-950/50 text-violet-300",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

const VERDICT_TONE: Record<string, BadgeProps["tone"]> = {
  confirmed: "danger",
  rejected: "neutral",
  inconclusive: "warn",
  pending: "info",
};

const STATE_TONE: Record<string, BadgeProps["tone"]> = {
  running: "info",
  completed: "success",
  paused: "warn",
  failed: "danger",
  canceled: "neutral",
  cancelled: "neutral",
  queued: "violet",
  draft: "neutral",
};

const SEVERITY_TONE: Record<string, BadgeProps["tone"]> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "info",
  info: "neutral",
};

export function VerdictBadge({ verdict }: { verdict: string }) {
  return <Badge tone={VERDICT_TONE[verdict] ?? "neutral"}>{verdict || "—"}</Badge>;
}

export function StateBadge({ state }: { state: string }) {
  return <Badge tone={STATE_TONE[state] ?? "neutral"}>{state || "—"}</Badge>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge tone={SEVERITY_TONE[severity] ?? "neutral"}>{severity || "—"}</Badge>;
}
