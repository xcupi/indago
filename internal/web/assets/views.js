// Top-level views and the route table. Each render(params, view) populates the
// #view container and may return a refresh function the router calls on an
// interval. Thin client only.

"use strict";

// ---------------------------------------------------------------------------
// Dashboard — high-level summary + active scans only
// ---------------------------------------------------------------------------
async function renderDashboard(_params, view) {
  view.appendChild(pageHead("Dashboard", [button("New scan", openNewScanModal, "primary")]));

  const summary = card("Summary", el("div", "loading…", "hint"));
  const active = card("Active scans", el("div", "loading…", "hint"));
  view.append(summary, active);

  async function refresh() {
    let statuses;
    try { statuses = await scanStatuses(); } catch (e) { return; }
    const agg = { running: 0, paused: 0, awaiting_auth: 0, completed: 0, other: 0, confirmed: 0, pending: 0 };
    statuses.forEach((st) => {
      const k = ["running", "paused", "awaiting_auth", "completed"].includes(st.scan.state) ? st.scan.state : "other";
      agg[k]++;
      agg.confirmed += st.findings.confirmed;
      agg.pending += st.findings.pending;
    });
    const m = el("div", undefined, "metrics");
    m.append(
      metric("Projects", ctx.projects.length),
      metric("Scans", statuses.length, null, currentProject() ? "in " + currentProject().name : "all projects"),
      metric("Running", agg.running), metric("Paused / awaiting auth", agg.paused + agg.awaiting_auth),
      metric("Confirmed findings", agg.confirmed), metric("Pending findings", agg.pending),
    );
    summary.replaceChildren(el("h2", "Summary"), m);

    const activeStatuses = statuses.filter((st) => ["running", "paused", "awaiting_auth", "canceling"].includes(st.scan.state));
    const rows = activeStatuses.map((st) => scanListRow(st, refresh));
    const t = table(["Name", "State", "Discovery", "Endpoints", "Jobs (q/run/done)", "Findings (C/P/R/I)", ""],
      rows, "No active scans right now.", null);
    active.replaceChildren(el("h2", "Active scans"), t);
  }
  await refresh();
  return refresh;
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------
async function renderProjects(_params, view) {
  view.appendChild(pageHead("Projects", [button("New project", openNewProjectModal, "primary")]));
  const projects = ctx.projects;
  if (!projects.length) {
    view.appendChild(emptyState("No projects yet. A project groups a target, its scope, and its scans.", "Create your first project", openNewProjectModal));
    return;
  }
  const rows = projects.map((p) => {
    const tr = el("tr");
    const nameTd = el("td"); nameTd.appendChild(link(p.name, "#/targets"));
    nameTd.firstChild.addEventListener("click", () => setProject(p.id));
    tr.appendChild(nameTd);
    tr.appendChild(cell(p.id, "mono"));
    tr.appendChild(cell(fmtTime(p.created_at)));
    const actTd = el("td");
    actTd.appendChild(button(ctx.projectId === p.id ? "Selected" : "Select", () => setProject(p.id), ctx.projectId === p.id ? "" : "primary"));
    actTd.lastChild.disabled = ctx.projectId === p.id;
    tr.appendChild(actTd);
    return tr;
  });
  view.appendChild(card(null, table(["Name", "ID", "Created", ""], rows, "No projects yet.")));
}

function openNewProjectModal() {
  const body = el("div");
  const err = el("div", undefined, "err");
  const name = input("p_name", "text", "Acme pentest");
  const create = button("Create project", async () => {
    if (!name.value.trim()) { setMsg(err, "Project name is required."); return; }
    const res = await mutate("POST", "/api/projects", { name: name.value.trim() });
    if (!res.ok) { setMsg(err, errMsg(res, "create project failed")); return; }
    await loadProjects();
    setProject(res.data.id);
    closeModal();
    navigate("#/targets");
  }, "primary");
  const actions = el("div", undefined, "form-actions");
  actions.append(create, button("Cancel", closeModal));
  body.append(field("Project name", name), actions, err);
  openModal("New project", body);
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------
async function renderTargets(_params, view) {
  const project = currentProject();
  if (!project) { needProject(view, "Targets"); return; }
  view.appendChild(pageHead("Targets", [button("Add target", openNewTargetModal, "primary")]));
  let targets = [];
  try { targets = (await getJSON(api.project(project.id) + "/targets")) || []; } catch (e) { /* none */ }
  if (!targets.length) {
    view.appendChild(emptyState("No targets in " + project.name + " yet.", "Add a target", openNewTargetModal));
    return;
  }
  const rows = targets.map((t) => {
    const tr = el("tr");
    tr.append(cell(t.name), cell(t.base_url, "mono"), cell(fmtTime(t.created_at)));
    const td = el("td");
    let detailRow = null;
    td.appendChild(button("Details", async () => {
      if (detailRow) { detailRow.remove(); detailRow = null; return; }
      detailRow = el("tr");
      const dtd = el("td"); dtd.colSpan = 4;
      try {
        const full = await getJSON(api.project(project.id) + "/targets/" + encodeURIComponent(t.id));
        const dl = el("dl", undefined, "detail");
        [["Name", full.name], ["Base URL", full.base_url], ["ID", full.id], ["Created", fmtTime(full.created_at)]].forEach(([k, v]) => { dl.append(el("dt", k), el("dd", v)); });
        dtd.appendChild(dl);
      } catch (e) { dtd.appendChild(el("div", "failed to load target", "err")); }
      detailRow.appendChild(dtd); tr.after(detailRow);
    }));
    tr.appendChild(td);
    return tr;
  });
  view.appendChild(card(null, table(["Name", "Base URL", "Created", ""], rows, "No targets yet.")));
}

function openNewTargetModal() {
  const project = currentProject();
  if (!project) { navigate("#/projects"); return; }
  const body = el("div");
  const err = el("div", undefined, "err");
  const name = input("t_name", "text", "web app");
  const url = input("t_url", "url", "https://app.example.com");
  const create = button("Add target", async () => {
    const res = await mutate("POST", api.project(project.id) + "/targets", { name: name.value.trim(), base_url: url.value.trim() });
    if (!res.ok) { setMsg(err, errMsg(res, "add target failed")); return; }
    closeModal(); route();
  }, "primary");
  const actions = el("div", undefined, "form-actions");
  actions.append(create, button("Cancel", closeModal));
  body.append(rowOf(field("Target name", name), field("Base URL", url)), actions, err);
  openModal("Add target", body);
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------
async function renderScope(_params, view) {
  const project = currentProject();
  if (!project) { needProject(view, "Scope"); return; }
  view.appendChild(pageHead("Scope — " + project.name));
  view.appendChild(el("p", "The safety boundary: every request a scan makes is checked against it, and a scan cannot start without one.", "hint"));

  const incHosts = textarea("s_inchosts", 3, "app.example.com");
  const excHosts = textarea("s_exchosts", 3);
  const incPaths = textarea("s_incpaths", 2);
  const excPaths = textarea("s_excpaths", 2, "/logout");
  const subs = el("input"); subs.type = "checkbox"; subs.id = "s_subs";
  const err = el("div", undefined, "err");
  const currentBox = el("div");

  function render(sc) {
    const dl = el("dl", undefined, "detail");
    const add = (k, arr) => { if (!arr || !arr.length) return; dl.append(el("dt", k), el("dd", arr.join(", "))); };
    add("Include hosts", sc.include_hosts); add("Exclude hosts", sc.exclude_hosts);
    add("Include paths", sc.include_path_prefixes); add("Exclude paths", sc.exclude_path_prefixes);
    dl.append(el("dt", "Allow subdomains"), el("dd", sc.allow_subdomains ? "yes" : "no"));
    currentBox.replaceChildren(el("h2", "Current scope"), dl);
  }

  try {
    const sc = await getJSON(api.project(project.id) + "/scope");
    incHosts.value = (sc.include_hosts || []).join("\n");
    excHosts.value = (sc.exclude_hosts || []).join("\n");
    incPaths.value = (sc.include_path_prefixes || []).join("\n");
    excPaths.value = (sc.exclude_path_prefixes || []).join("\n");
    subs.checked = !!sc.allow_subdomains;
    render(sc);
  } catch (e) {
    currentBox.replaceChildren(el("p", "No scope configured yet — save one below before scanning.", "hint"));
  }

  const save = button("Save scope", async () => {
    const res = await mutate("PUT", api.project(project.id) + "/scope", {
      include_hosts: lines(incHosts), exclude_hosts: lines(excHosts),
      include_path_prefixes: lines(incPaths), exclude_path_prefixes: lines(excPaths),
      allow_subdomains: subs.checked,
    });
    if (!res.ok) { setMsg(err, errMsg(res, "save scope failed")); return; }
    setMsg(err, "Scope saved.", true); render(res.data);
  }, "primary");

  const form = el("div");
  form.append(
    rowOf(field("Include hosts (one per line)", incHosts), field("Exclude hosts (one per line)", excHosts)),
    rowOf(field("Include path prefixes (one per line)", incPaths), field("Exclude path prefixes (one per line)", excPaths)),
    labelInline(subs, "Allow subdomains of included hosts"),
    (function () { const a = el("div", undefined, "form-actions"); a.appendChild(save); return a; })(),
    err,
  );
  view.append(card("Edit scope", form), card(null, currentBox));
}

// ---------------------------------------------------------------------------
// Scans list
// ---------------------------------------------------------------------------
async function renderScansList(_params, view) {
  view.appendChild(pageHead("Scans", [button("New scan", openNewScanModal, "primary")]));
  const headers = ["Name", "State", "Discovery", "Endpoints", "Jobs (q/run/done)", "Findings (C/P/R/I)", ""];
  const body = card(null, el("div", "loading…", "hint"));
  view.appendChild(body);
  let primed = false;
  async function refresh() {
    let statuses;
    try { statuses = await scanStatuses(); } catch (e) { return; }
    if (!statuses.length && !primed) {
      body.replaceChildren(emptyState(
        currentProject() ? "No scans in " + currentProject().name + " yet." : "No scans yet.",
        "Create a scan", openNewScanModal));
      primed = true;
      return;
    }
    primed = true;
    body.replaceChildren(table(headers, statuses.map((st) => scanListRow(st, refresh)), "No scans yet.", null));
  }
  await refresh();
  return refresh;
}

// ---------------------------------------------------------------------------
// Findings (project-level, aggregated across the project's scans)
// ---------------------------------------------------------------------------
async function renderFindings(_params, view) {
  if (!currentProject()) { needProject(view, "Findings"); return; }
  view.appendChild(pageHead("Findings — " + currentProject().name));
  const body = card(null, el("div", "loading…", "hint"));
  view.appendChild(body);

  const scans = await projectScans();
  const rows = [];
  for (const s of scans) {
    let findings = [];
    try { findings = (await getJSON(api.scan(s.id) + "/findings")) || []; } catch (e) { continue; }
    findings.forEach((f) => {
      const tr = findingRow(f, s.id, null);
      const scanCell = el("td"); scanCell.appendChild(link(s.name || "(unnamed)", "#/scans/" + encodeURIComponent(s.id) + "/findings"));
      tr.insertBefore(scanCell, tr.firstChild);
      rows.push(tr);
    });
  }
  body.replaceChildren(table(["Scan", "Title", "Verdict", "Severity", "Parameter", "Context"], rows,
    "No findings in this project yet.", null));
}

// ---------------------------------------------------------------------------
// Reports (project-level list; generation happens per-scan on its detail view)
// ---------------------------------------------------------------------------
async function renderReports(_params, view) {
  if (!currentProject()) { needProject(view, "Reports"); return; }
  view.appendChild(pageHead("Reports — " + currentProject().name));
  view.appendChild(el("p", "Reports are generated per scan. Open a scan's Reports tab to generate one; all of this project's reports are listed here.", "hint"));
  const body = card(null, el("div", "loading…", "hint"));
  view.appendChild(body);

  const scans = await projectScans();
  const rows = [];
  for (const s of scans) {
    let reports = [];
    try { reports = (await getJSON(api.scan(s.id) + "/reports")) || []; } catch (e) { continue; }
    reports.forEach((r) => {
      const tr = reportRow(r);
      const scanCell = el("td"); scanCell.appendChild(link(s.name || "(unnamed)", "#/scans/" + encodeURIComponent(s.id) + "/reports"));
      tr.insertBefore(scanCell, tr.firstChild);
      rows.push(tr);
    });
  }
  body.replaceChildren(table(["Scan", "Created", "Format", "Findings", "Confirmed", "Open"], rows, "No reports in this project yet.", null));
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
async function renderSettings(_params, view) {
  view.appendChild(pageHead("Settings"));

  const interval = select("set_refresh", [["1000", "1 second"], ["2000", "2 seconds"], ["5000", "5 seconds"], ["10000", "10 seconds"]], prefs.get("refreshMs", "2000"));
  interval.style.width = "200px";
  interval.addEventListener("change", () => { prefs.set("refreshMs", interval.value); route(); });
  view.appendChild(card("Live refresh interval", field("How often live views poll for updates", interval),
    el("p", "A per-browser preference only; it changes nothing on the server.", "hint")));

  let login = "unknown";
  try {
    const res = await mutate("POST", "/api/auth/login", {}); // probe: 400 means available, 501 means not
    login = res.status === 501 ? "unavailable (start the server with -browser)" : "available";
  } catch (e) { login = "unknown"; }
  const dl = el("dl", undefined, "detail");
  [["Version", $("version").textContent],
   ["Interactive login", login],
   ["Control-plane protection", "CSRF (X-Indago-Client header) + DNS-rebinding guard; local-first, no authentication"],
   ["Scope", "Mandatory and enforced server-side on every request; the UI cannot bypass it"],
   ["Secrets", "Session material (cookies/tokens) is never returned by the API or shown in the UI"],
  ].forEach(([k, v]) => { dl.append(el("dt", k), el("dd", v)); });
  view.appendChild(card("About this instance", dl));
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
defineRoute("dashboard", /^\/dashboard$/, renderDashboard);
defineRoute("projects", /^\/projects$/, renderProjects);
defineRoute("targets", /^\/targets$/, renderTargets);
defineRoute("scope", /^\/scope$/, renderScope);
defineRoute("scans", /^\/scans$/, renderScansList);
defineRoute("scans", /^\/scans\/([^/]+)\/([^/]+)$/, renderScanDetail);
defineRoute("scans", /^\/scans\/([^/]+)$/, (p) => { navigate("#/scans/" + encodeURIComponent(p[0]) + "/overview"); });
defineRoute("findings", /^\/findings$/, renderFindings);
defineRoute("reports", /^\/reports$/, renderReports);
defineRoute("settings", /^\/settings$/, renderSettings);

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
async function init() {
  try { const v = await getJSON("/api/version"); $("version").textContent = "v" + (v.version || "dev"); } catch (e) { /* ignore */ }
  $("projectSelect").addEventListener("change", (e) => setProject(e.target.value));
  $("modalClose").addEventListener("click", closeModal);
  $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  window.addEventListener("hashchange", route);
  await loadProjects();
  route();
  // Keep the project list fresh for the header without disturbing the view.
  setInterval(loadProjects, 10000);
}
init();
