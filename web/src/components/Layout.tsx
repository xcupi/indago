import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  BarChart3,
  FileText,
  FolderKanban,
  LayoutDashboard,
  RefreshCw,
  ScanLine,
  Settings as SettingsIcon,
  ShieldCheck,
  Sun,
  Moon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { api, refreshAll, useApi } from "@/lib/api";
import type { Capabilities, Project } from "@/lib/types";
import { navigate } from "@/lib/router";
import { cn, shortId } from "@/lib/utils";

const NAV = [
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard, href: "#/dashboard" },
  { key: "projects", label: "Projects", icon: FolderKanban, href: "#/projects" },
  { key: "scans", label: "Scans", icon: ScanLine, href: "#/scans" },
  { key: "findings", label: "Findings", icon: ShieldCheck, href: "#/findings" },
  { key: "reports", label: "Reports", icon: FileText, href: "#/reports" },
  { key: "settings", label: "Settings", icon: SettingsIcon, href: "#/settings" },
];

const PROJECT_KEY = "indago.project";
const THEME_KEY = "indago.theme";

export function currentTheme(): "light" | "dark" {
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

/** Swap the theme class and remember the choice; the inline script in
 *  index.html applies it before the first paint on the next visit. */
export function setTheme(theme: "light" | "dark") {
  document.documentElement.classList.toggle("dark", theme === "dark");
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* private mode: the class still applies for this visit */
  }
}

export function selectedProject(): string {
  return localStorage.getItem(PROJECT_KEY) ?? "";
}

export function setSelectedProject(id: string) {
  if (id) localStorage.setItem(PROJECT_KEY, id);
  else localStorage.removeItem(PROJECT_KEY);
  refreshAll();
}

export default function Layout({ route, children }: { route: string[]; children: React.ReactNode }) {
  const [project, setProject] = useState(selectedProject());
  const projects = useApi<Project[]>("/api/projects");
  const caps = useApi<Capabilities>("/api/version");
  const [live, setLive] = useState(Number(localStorage.getItem("indago.liveMs") ?? 0));
  const [theme, setThemeState] = useState<"light" | "dark">(currentTheme());

  const active = route[0] ?? "dashboard";
  const version = useMemo(() => (caps.data as { version?: string } | undefined)?.version, [caps.data]);

  useEffect(() => {
    const onChange = () => setProject(selectedProject());
    window.addEventListener("indago:refresh", onChange);
    return () => window.removeEventListener("indago:refresh", onChange);
  }, []);

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-border bg-background/95 px-3 py-4 md:flex">
        <button
          onClick={() => navigate("/dashboard")}
          className="mb-5 flex items-center gap-2 px-2 text-left"
        >
          <span className="grid size-8 place-items-center rounded-md border border-emerald-200 dark:border-emerald-800/60 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-400">
            <Activity className="size-4" />
          </span>
          <span>
            <span className="block text-sm font-semibold tracking-wide text-foreground">INDAGO</span>
            <span className="mono block text-[10px] text-muted-foreground">{version ?? "—"}</span>
          </span>
        </button>

        <nav className="flex flex-col gap-0.5">
          {NAV.map((item) => {
            const Icon = item.icon;
            const isActive = active === item.key || (item.key === "projects" && active === "project");
            return (
              <a
                key={item.key}
                href={item.href}
                className={cn(
                  "flex items-center gap-2 rounded-md px-2.5 py-2 text-[13px] transition-colors",
                  isActive
                    ? "bg-emerald-50 font-medium text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <Icon className="size-4" />
                {item.label}
              </a>
            );
          })}
        </nav>

        <div className="mt-auto space-y-2 border-t border-border pt-3 text-[11px] text-muted-foreground">
          <label className="block text-[10px] uppercase tracking-wide text-muted-foreground">Project</label>
          <select
            value={project}
            onChange={(e) => {
              setSelectedProject(e.target.value);
              setProject(e.target.value);
            }}
            className="h-8 w-full rounded-md border border-border bg-muted px-2 text-xs text-foreground"
          >
            <option value="">All projects</option>
            {(projects.data ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <div className="mono truncate">id {project ? shortId(project) : "—"}</div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background px-4 backdrop-blur">
          <div className="flex items-center gap-1 md:hidden">
            <BarChart3 className="size-4 text-emerald-700 dark:text-emerald-400" />
            <span className="text-sm font-semibold">INDAGO</span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <select
              value={live}
              onChange={(e) => {
                const ms = Number(e.target.value);
                setLive(ms);
                localStorage.setItem("indago.liveMs", String(ms));
                refreshAll();
              }}
              className="h-8 rounded-md border border-border bg-muted px-2 text-[11px] text-muted-foreground"
              title="Auto-refresh interval"
            >
              <option value={0}>Live: off</option>
              <option value={3000}>Live: 3s</option>
              <option value={5000}>Live: 5s</option>
              <option value={15000}>Live: 15s</option>
            </select>
            <Button
              variant="outline"
              size="icon"
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              aria-pressed={theme === "dark"}
              onClick={() => {
                const next = theme === "dark" ? "light" : "dark";
                setTheme(next);
                setThemeState(next);
              }}
            >
              {theme === "dark" ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
            </Button>
            <Button variant="outline" size="sm" onClick={() => refreshAll()}>
              <RefreshCw className="size-3.5" /> Refresh
            </Button>
          </div>
        </header>

        <main className="min-w-0 flex-1 px-4 py-5 md:px-6">{children}</main>

        <footer className="border-t border-border px-4 py-3 text-[10px] leading-relaxed text-muted-foreground">
          Indago — local-first web application security hunting. Authorized use only. Reflected and DOM
          XSS are confirmed in a real browser when the server runs with <span className="mono">-browser</span>;
          without it DOM probes are skipped and nothing is confirmed. Findings are backed by stored evidence.
        </footer>
      </div>
    </div>
  );
}

export function LivePoller({ ms, onTick }: { ms: number; onTick: () => void }) {
  useEffect(() => {
    if (!ms) return;
    const id = window.setInterval(onTick, ms);
    return () => window.clearInterval(id);
  }, [ms, onTick]);
}

export function PageTitle({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-foreground">{title}</h1>
        {subtitle ? <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}
