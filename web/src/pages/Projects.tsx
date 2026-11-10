import { useEffect, useState } from "react";
import { FolderPlus, Trash2 } from "lucide-react";
import { PageTitle } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/controls";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, Loading } from "@/components/ui/misc";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, refreshAll, useApi } from "@/lib/api";
import type { Project } from "@/lib/types";
import { navigate } from "@/lib/router";
import { formatTime, shortId } from "@/lib/utils";
import { Alert } from "@/components/ui/misc";

export default function Projects() {
  const projects = useApi<Project[]>("/api/projects");
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkErr, setBulkErr] = useState("");
  const [bulkNote, setBulkNote] = useState("");
  const [pageSize, setPageSize] = useState(10);
  const [page, setPage] = useState(1);

  const projectsList = projects.data ?? [];
  const selectedIDs = Object.keys(selected).filter((id) => selected[id]);
  const pageCount = Math.max(1, Math.ceil(projectsList.length / pageSize));
  const pageStart = (page - 1) * pageSize;
  const pagedProjects = projectsList.slice(pageStart, pageStart + pageSize);
  const allOnPage = pagedProjects.length > 0 && pagedProjects.every((p) => selected[p.id]);

  useEffect(() => {
    if (page > pageCount) setPage(pageCount);
  }, [page, pageCount]);

  function togglePage(checked: boolean) {
    setSelected((prev) => {
      const next = { ...prev };
      for (const p of pagedProjects) {
        if (checked) next[p.id] = true;
        else delete next[p.id];
      }
      return next;
    });
  }

  async function deleteSelected() {
    if (!selectedIDs.length) return;
    if (
      !confirm(
        `Delete ${selectedIDs.length} project(s) and all their scans, findings, evidence and reports? ` +
          "This cannot be undone. Projects with a running scan are skipped.",
      )
    ) {
      return;
    }
    setBulkBusy(true);
    setBulkErr("");
    setBulkNote("");
    try {
      const res = await api<{
        results: { project_id: string; deleted: boolean; scans_deleted?: number; error?: string }[];
        deleted: number;
        failed: number;
      }>("/api/projects/bulk-delete", {
        method: "POST",
        body: { project_ids: selectedIDs, delete_scans: true },
      });
      setBulkNote(
        `Deleted ${res.deleted} project(s)${res.failed ? `; ${res.failed} skipped` : ""}.`,
      );
      const failures = res.results.filter((r) => r.error);
      if (failures.length) setBulkErr(failures.map((r) => `${shortId(r.project_id)}: ${r.error}`).join(" · "));
      setSelected({});
      refreshAll();
    } catch (e) {
      setBulkErr((e as Error).message);
    } finally {
      setBulkBusy(false);
    }
  }

  async function create() {
    if (!name.trim()) {
      setError("Project name is required.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const p = await api<Project>("/api/projects", { method: "POST", body: { name, notes } });
      setOpen(false);
      setName("");
      setNotes("");
      refreshAll();
      navigate(`/projects/${p.id}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageTitle
        title="Projects"
        subtitle="A project owns one scope, its targets and every scan run against them."
        actions={
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <FolderPlus className="size-4" /> New project
              </Button>
            </DialogTrigger>
            <DialogContent title="New project" description="The scope is configured on the project page.">
              <div className="space-y-3">
                <Field label="Name">
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Acme bounty" />
                </Field>
                <Field label="Notes" hint="Optional context kept with the project.">
                  <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} />
                </Field>
                {error ? <Alert>{error}</Alert> : null}
                <div className="flex justify-end gap-2">
                  <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
                    Cancel
                  </Button>
                  <Button size="sm" disabled={busy} onClick={create}>
                    {busy ? "Creating…" : "Create project"}
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        }
      />

      <Card>
        <CardContent className="p-0">
          {projects.loading && !projects.data ? (
            <Loading />
          ) : projectsList.length === 0 ? (
            <div className="p-4">
              <Empty>No projects yet. Create one to define a scope and add targets.</Empty>
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-2">
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <input
                    type="checkbox"
                    checked={allOnPage}
                    onChange={(e) => togglePage(e.target.checked)}
                  />
                  Select all on this page
                </label>
                {selectedIDs.length > 0 ? (
                  <>
                    <Button size="sm" variant="destructive" onClick={deleteSelected} disabled={bulkBusy}>
                      {bulkBusy ? "Deleting…" : <><Trash2 className="size-4" /> Delete selected ({selectedIDs.length})</>}
                    </Button>
                    <button className="text-[11px] text-muted-foreground hover:text-foreground" onClick={() => setSelected({})}>
                      Clear
                    </button>
                  </>
                ) : (
                  <span className="text-[11px] text-muted-foreground">Select projects to delete them together.</span>
                )}
                {bulkNote ? <span className="text-[11px] text-emerald-700 dark:text-emerald-400">{bulkNote}</span> : null}
                <label className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
                  Per page
                  <select
                    className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground"
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setPage(1);
                    }}
                  >
                    <option value={10}>10</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                  </select>
                </label>
              </div>
              {bulkErr ? <div className="px-3 pt-2"><Alert className="border-amber-200 text-amber-800 dark:border-amber-900 dark:text-amber-300">{bulkErr}</Alert></div> : null}
              <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8">
                    <input
                      type="checkbox"
                      aria-label="Select all projects"
                      checked={allOnPage}
                      onChange={(e) => togglePage(e.target.checked)}
                    />
                  </TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {pagedProjects.map((p) => (
                  <TableRow key={p.id} className="cursor-pointer" onClick={() => navigate(`/projects/${p.id}`)}>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${p.name}`}
                        checked={Boolean(selected[p.id])}
                        onChange={(e) => setSelected((prev) => ({ ...prev, [p.id]: e.target.checked }))}
                      />
                    </TableCell>
                    <TableCell className="font-medium text-foreground">{p.name}</TableCell>
                    <TableCell className="mono text-[11px] text-muted-foreground">{shortId(p.id)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatTime(p.created_at)}</TableCell>
                    <TableCell className="text-right text-[11px] text-emerald-700 dark:text-emerald-400">open →</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-[11px] text-muted-foreground">
              <span>
                Showing {projectsList.length ? pageStart + 1 : 0}–{Math.min(pageStart + pageSize, projectsList.length)} of {projectsList.length} projects
              </span>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <span>
                  Page {page} / {pageCount}
                </span>
                <Button size="sm" variant="outline" disabled={page >= pageCount} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
