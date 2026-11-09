import { useState } from "react";
import { FolderPlus } from "lucide-react";
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
          ) : (projects.data ?? []).length === 0 ? (
            <div className="p-4">
              <Empty>No projects yet. Create one to define a scope and add targets.</Empty>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(projects.data ?? []).map((p) => (
                  <TableRow key={p.id} className="cursor-pointer" onClick={() => navigate(`/projects/${p.id}`)}>
                    <TableCell className="font-medium text-zinc-200">{p.name}</TableCell>
                    <TableCell className="mono text-[11px] text-zinc-500">{shortId(p.id)}</TableCell>
                    <TableCell className="text-xs text-zinc-500">{formatTime(p.created_at)}</TableCell>
                    <TableCell className="text-right text-[11px] text-emerald-400">open →</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
