// Indago operational dashboard.
//
// This file is a thin client over the HTTP API: it never implements scan,
// scope, or verification logic itself — every decision is made server-side and
// surfaced here. All operator-supplied text (project/target/scan names, URLs,
// findings) is rendered through textContent, never innerHTML, so it cannot be
// interpreted as markup. Every state-changing request carries the
// X-Indago-Client header (CSRF protection); the server also enforces
// DNS-rebinding and scope.

"use strict";

// ---- DOM helpers (textContent only) ----
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function cell(text, cls) { return el("td", text, cls); }
function $(id) { return document.getElementById(id); }

function setBody(id, rows, emptyText, cols) {
  const body = $(id);
  body.replaceChildren();
  if (!rows.length) {
    const tr = el("tr");
    const td = cell(emptyText, "empty");
    td.colSpan = cols;
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  rows.forEach((r) => body.appendChild(r));
}

function lines(textarea) {
  return textarea.value.split("\n").map((s) => s.trim()).filter((s) => s.length > 0);
}
function setLines(textarea, arr) { textarea.value = (arr || []).join("\n"); }

// ---- HTTP ----
async function j(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(url + " -> " + r.status);
  return r.json();
}

// mutate issues a state-changing request with the CSRF header and returns
// { ok, status, data }. It never throws on an HTTP error so callers can show
// the server's validation message.
async function mutate(method, url, body) {
  const opts = { method, headers: { "X-Indago-Client": "ui" } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch (e) { /* no body */ }
  return { ok: r.ok, status: r.status, data };
}

function errMsg(res, fallback) {
  if (res && res.data && res.data.error) return res.data.error;
  return fallback + " (HTTP " + (res ? res.status : "?") + ")";
}

function showError(msg) {
  const box = $("error");
  box.textContent = msg;
  setTimeout(() => { if (box.textContent === msg) box.textContent = ""; }, 8000);
}
function setMsg(id, msg, cls) {
  const box = $(id);
  box.textContent = msg || "";
  box.className = cls || "err";
}

// ---- selection state ----
let selectedProjectId = null;
let selectedProjectName = null;
let selectedScanId = null;
let selectedFindingIds = new Set();

// =====================================================================
// Projects
// =====================================================================
async function loadProjects() {
  try {
    const projects = (await j("/api/projects")) || [];
    setBody("projects", projects.map(projectRow), "No projects yet — create one above to begin.", 4);
  } catch (e) {
    setBody("projects", [], "error loading projects", 4);
  }
}

function projectRow(p) {
  const tr = el("tr");
  const selTd = el("td");
  const btn = el("button", selectedProjectId === p.id ? "Selected" : "Select");
  btn.disabled = selectedProjectId === p.id;
  btn.addEventListener("click", () => selectProject(p.id, p.name));
  selTd.appendChild(btn);
  tr.appendChild(selTd);
  tr.appendChild(cell(p.name));
  tr.appendChild(cell(p.id, "mono"));
  tr.appendChild(cell((p.created_at || "").slice(0, 19).replace("T", " ")));
  return tr;
}

async function createProject() {
  const name = $("projName").value.trim();
  if (!name) { setMsg("projErr", "Project name is required."); return; }
  const res = await mutate("POST", "/api/projects", { name });
  if (!res.ok) { setMsg("projErr", errMsg(res, "create project failed")); return; }
  setMsg("projErr", "");
  $("projName").value = "";
  await loadProjects();
  selectProject(res.data.id, res.data.name);
}

function selectProject(id, name) {
  selectedProjectId = id;
  selectedProjectName = name;
  $("context").replaceChildren(document.createTextNode("Project: "), el("b", name));
  loadProjects();
  loadTargets();
  loadScope();
}

// =====================================================================
// Targets
// =====================================================================
async function loadTargets() {
  if (!selectedProjectId) {
    setBody("targets", [], "Select a project first.", 3);
    $("scanTarget").replaceChildren();
    return;
  }
  $("targetsProjLabel").textContent = "— " + selectedProjectName;
  try {
    const targets = (await j("/api/projects/" + encodeURIComponent(selectedProjectId) + "/targets")) || [];
    setBody("targets", targets.map(targetRow), "No targets yet — add one above.", 3);
    const sel = $("scanTarget");
    sel.replaceChildren();
    targets.forEach((t) => {
      const o = el("option", t.name + " — " + t.base_url);
      o.value = t.id;
      sel.appendChild(o);
    });
  } catch (e) {
    setBody("targets", [], "error loading targets", 3);
  }
}

function targetRow(t) {
  const tr = el("tr");
  tr.appendChild(cell(t.name));
  tr.appendChild(cell(t.base_url, "mono"));
  const detailsTd = el("td");
  const btn = el("button", "Details");
  let detailRow = null;
  btn.addEventListener("click", async () => {
    if (detailRow) { detailRow.remove(); detailRow = null; return; }
    detailRow = el("tr");
    const td = el("td"); td.colSpan = 3;
    try {
      const full = await j("/api/projects/" + encodeURIComponent(selectedProjectId) + "/targets/" + encodeURIComponent(t.id));
      const box = el("div", undefined, "detail");
      const dl = document.createElement("dl");
      const add = (k, v) => { dl.appendChild(el("dt", k)); dl.appendChild(el("dd", v)); };
      add("Name", full.name);
      add("Base URL", full.base_url);
      add("ID", full.id);
      add("Created", (full.created_at || "").slice(0, 19).replace("T", " "));
      box.appendChild(dl);
      td.appendChild(box);
    } catch (e) {
      td.appendChild(el("div", "failed to load target", "err"));
    }
    detailRow.appendChild(td);
    tr.after(detailRow);
  });
  detailsTd.appendChild(btn);
  tr.appendChild(detailsTd);
  return tr;
}

async function addTarget() {
  if (!selectedProjectId) { setMsg("tgtErr", "Select a project first."); return; }
  const name = $("tgtName").value.trim();
  const base_url = $("tgtURL").value.trim();
  if (!name || !base_url) { setMsg("tgtErr", "Target name and base URL are required."); return; }
  const res = await mutate("POST", "/api/projects/" + encodeURIComponent(selectedProjectId) + "/targets", { name, base_url });
  if (!res.ok) { setMsg("tgtErr", errMsg(res, "add target failed")); return; }
  setMsg("tgtErr", "");
  $("tgtName").value = ""; $("tgtURL").value = "";
  loadTargets();
}

// =====================================================================
// Scope
// =====================================================================
async function loadScope() {
  const current = $("scopeCurrent");
  if (!selectedProjectId) { current.classList.add("hidden"); return; }
  try {
    const sc = await j("/api/projects/" + encodeURIComponent(selectedProjectId) + "/scope");
    setLines($("scIncludeHosts"), sc.include_hosts);
    setLines($("scExcludeHosts"), sc.exclude_hosts);
    setLines($("scIncludePaths"), sc.include_path_prefixes);
    setLines($("scExcludePaths"), sc.exclude_path_prefixes);
    $("scSubdomains").checked = !!sc.allow_subdomains;
    renderScope(sc);
  } catch (e) {
    // 404 = no scope yet; leave the form empty and show an empty state.
    current.replaceChildren(el("span", "No scope configured yet — a scan cannot start until one is saved.", "muted"));
    current.classList.remove("hidden");
  }
}

function renderScope(sc) {
  const box = $("scopeCurrent");
  const dl = document.createElement("dl");
  const add = (k, arr) => {
    if (!arr || !arr.length) return;
    dl.appendChild(el("dt", k));
    dl.appendChild(el("dd", arr.join(", ")));
  };
  add("Include hosts", sc.include_hosts);
  add("Exclude hosts", sc.exclude_hosts);
  add("Include paths", sc.include_path_prefixes);
  add("Exclude paths", sc.exclude_path_prefixes);
  dl.appendChild(el("dt", "Allow subdomains"));
  dl.appendChild(el("dd", sc.allow_subdomains ? "yes" : "no"));
  box.replaceChildren(dl);
  box.classList.remove("hidden");
}

async function saveScope() {
  if (!selectedProjectId) { setMsg("scopeErr", "Select a project first."); return; }
  const body = {
    include_hosts: lines($("scIncludeHosts")),
    exclude_hosts: lines($("scExcludeHosts")),
    include_path_prefixes: lines($("scIncludePaths")),
    exclude_path_prefixes: lines($("scExcludePaths")),
    allow_subdomains: $("scSubdomains").checked,
  };
  const res = await mutate("PUT", "/api/projects/" + encodeURIComponent(selectedProjectId) + "/scope", body);
  if (!res.ok) { setMsg("scopeErr", errMsg(res, "save scope failed")); return; }
  setMsg("scopeErr", "Scope saved.", "ok-msg");
  renderScope(res.data);
}

// =====================================================================
// New scan
// =====================================================================
function scanTypeIsQuick() {
  const r = document.querySelector('input[name="scanType"]:checked');
  return r && r.value === "quick";
}

function syncScanForm() {
  $("crawlLimits").classList.toggle("hidden", scanTypeIsQuick());
  $("customConfig").classList.toggle("hidden", $("scanProfile").value !== "custom");
  $("stopNWrap").classList.toggle("hidden", $("scanStop").value !== "after_n_confirmed");
  const existing = $("scanAuth").value === "existing";
  $("authExistingWrap").classList.toggle("hidden", !existing);
}

function intOrZero(id) {
  const v = parseInt($(id).value, 10);
  return Number.isFinite(v) && v > 0 ? v : 0;
}

async function createScan() {
  if (!selectedProjectId) { setMsg("scanErr", "Select a project first."); return; }
  const targetId = $("scanTarget").value;
  if (!targetId) { setMsg("scanErr", "Add and choose a target first."); return; }

  const profile = $("scanProfile").value;
  const req = {
    project_id: selectedProjectId,
    target_id: targetId,
    name: $("scanName").value.trim(),
    profile,
    seed_urls: lines($("scanSeeds")),
    quick_scan: scanTypeIsQuick(),
    max_depth: scanTypeIsQuick() ? 0 : intOrZero("scanDepth"),
    max_pages: intOrZero("scanMaxPages"),
    max_endpoints: intOrZero("scanMaxEndpoints"),
  };
  if (profile === "custom") {
    req.config = {
      discovery_concurrency: intOrZero("cfgDiscovery"),
      http_concurrency: intOrZero("cfgHTTP"),
      browser_concurrency: parseInt($("cfgBrowser").value, 10) || 0,
      requests_per_second: parseFloat($("cfgRate").value) || 0,
    };
  }
  const stop = $("scanStop").value;
  if (stop !== "continue_all") {
    req.stop = { mode: stop };
    if (stop === "after_n_confirmed") req.stop.confirmed_limit = parseInt($("scanStopN").value, 10) || 1;
  }
  if ($("scanAuth").value === "existing") {
    req.auth_mode = "existing";
    req.auth_state_path = $("scanAuthState").value.trim();
  }

  const res = await mutate("POST", "/api/scans", req);
  if (!res.ok) { setMsg("scanErr", errMsg(res, "create scan failed")); return; }
  setMsg("scanErr", "Scan created — start it from the Scans list below.", "ok-msg");
  $("scanName").value = "";
  loadScans();
}

// ---- interactive login ----
async function runLogin() {
  const login_url = $("loginURL").value.trim();
  if (!login_url) { $("loginStatus").textContent = "Enter the login page URL first."; return; }
  const success_url = $("loginSuccess").value.trim();
  const status = $("loginStatus");
  status.className = "muted";
  status.style.fontSize = "12px";
  status.textContent = "Opening a browser window on the server… log in there (complete any MFA). Waiting for success…";
  $("runLogin").disabled = true;
  try {
    const res = await mutate("POST", "/api/auth/login", { login_url, success_url });
    if (!res.ok) {
      status.textContent = errMsg(res, "interactive login failed");
      return;
    }
    $("scanAuthState").value = res.data.state_path || "";
    status.textContent = "Login captured. Session saved; its path has been filled in above. The contents are never shown.";
  } catch (e) {
    status.textContent = "interactive login failed: " + e;
  } finally {
    $("runLogin").disabled = false;
  }
}

// =====================================================================
// Scans list + control
// =====================================================================
const CONTROLS = {
  created: ["start", "cancel"],
  running: ["pause", "cancel"],
  paused: ["resume", "cancel"],
  awaiting_auth: ["resume", "cancel"],
};

async function act(scanId, action) {
  if (action === "cancel" && !window.confirm("Cancel this scan? In-flight work stops and the scan cannot be resumed.")) {
    return;
  }
  const res = await mutate("POST", "/api/scans/" + encodeURIComponent(scanId) + "/" + action);
  if (!res.ok) showError(action + " failed: " + errMsg(res, action));
  loadScans();
  if (scanId === selectedScanId) refreshMonitor();
}

function controlButtons(st) {
  const id = st.scan.id;
  const allowed = CONTROLS[st.scan.state] || [];
  const frag = document.createDocumentFragment();
  ["start", "pause", "resume", "cancel"].forEach((action) => {
    if (!allowed.includes(action)) return;
    const b = el("button", action.charAt(0).toUpperCase() + action.slice(1), action === "cancel" ? "danger" : "");
    b.addEventListener("click", () => act(id, action));
    frag.appendChild(b);
  });
  const monitor = el("button", selectedScanId === id ? "Monitoring" : "Monitor");
  monitor.disabled = selectedScanId === id;
  monitor.addEventListener("click", () => selectScan(id, st.scan.name || id));
  frag.appendChild(monitor);
  return frag;
}

function scanRow(st) {
  const tr = el("tr");
  tr.appendChild(cell(st.scan.name || "(unnamed)"));
  const stateTd = el("td");
  stateTd.appendChild(el("span", st.scan.state, "pill " + st.scan.state));
  tr.appendChild(stateTd);
  tr.appendChild(cell(st.discovery.state));
  tr.appendChild(cell(st.discovery.endpoints));
  tr.appendChild(cell(st.discovery.parameters));
  const jobs = st.jobs;
  tr.appendChild(cell(jobs.queued + " / " + (jobs.running + jobs.leased) + " / " + jobs.succeeded, "mono"));
  const f = st.findings;
  tr.appendChild(cell(f.confirmed + " / " + f.pending + " / " + f.rejected + " / " + f.inconclusive, "mono"));
  const actions = el("td");
  actions.appendChild(controlButtons(st));
  tr.appendChild(actions);
  return tr;
}

async function loadScans() {
  try {
    const scans = (await j("/api/scans")) || [];
    const statuses = await Promise.all(scans.map((s) => j("/api/scans/" + encodeURIComponent(s.id) + "/status")));
    setBody("scans", statuses.map(scanRow), "No scans yet — create one above.", 8);
    $("refreshed").textContent = "updated " + new Date().toLocaleTimeString();
  } catch (e) {
    setBody("scans", [], "error loading scans", 8);
  }
}

// =====================================================================
// Live monitor
// =====================================================================
function selectScan(id, label) {
  selectedScanId = id;
  selectedFindingIds = new Set();
  $("monitorCard").classList.remove("hidden");
  $("reportsCard").classList.remove("hidden");
  $("monitorLabel").textContent = "— " + label;
  $("findingsScanLabel").textContent = "— " + label;
  $("reportsScanLabel").textContent = "— " + label;
  loadScans();
  refreshMonitor();
  loadFindings();
  loadReports();
}

function metric(k, v, pillCls) {
  const d = el("div", undefined, "metric");
  d.appendChild(el("div", k, "k"));
  if (pillCls) {
    const vEl = el("div", undefined, "v");
    vEl.appendChild(el("span", v, "pill " + pillCls));
    d.appendChild(vEl);
  } else {
    d.appendChild(el("div", v, "v"));
  }
  return d;
}

async function refreshMonitor() {
  if (!selectedScanId) return;
  let st;
  try {
    st = await j("/api/scans/" + encodeURIComponent(selectedScanId) + "/status");
  } catch (e) {
    return; // scan may have been removed; leave last view
  }
  const m = $("monitorMetrics");
  const cfg = st.scan.config || {};
  const rate = cfg.requests_per_second > 0 ? cfg.requests_per_second + " req/s" : "unlimited";
  const w = st.workers;
  const workers = w ? (w.discovery + " / " + w.http + " / " + w.browser) : "—";
  const sess = st.session;
  const tests = st.tests || {};
  const cards = [
    metric("Scan state", st.scan.state, st.scan.state),
    metric("Discovery", st.discovery.state + (st.discovery.paused ? " (paused)" : "")),
    metric("Endpoints", st.discovery.endpoints),
    metric("Parameters", st.discovery.parameters),
    metric("Injection points", st.discovery.injection_points),
    metric("Jobs queued", st.jobs.queued),
    metric("Jobs running", st.jobs.running + st.jobs.leased),
    metric("Jobs completed", st.jobs.succeeded),
    metric("Findings", "C " + st.findings.confirmed + "  P " + st.findings.pending + "  R " + st.findings.rejected + "  I " + st.findings.inconclusive),
    metric("Request rate", rate),
    metric("Active workers (d/h/b)", workers),
    metric("Errors / timeouts", (tests.error || 0) + " / " + (tests.timeout || 0)),
    metric("429 / 5xx", (tests.rate_limited || 0) + " / " + (tests.server_error || 0)),
  ];
  if (sess) {
    let label = sess.mode + " · " + sess.state + (sess.has_state ? " · session on file" : "");
    cards.push(metric("Auth / session", label, sess.state));
    if (sess.state === "expired" || st.scan.state === "awaiting_auth") {
      const note = el("div", undefined, "metric");
      note.appendChild(el("div", "Re-authentication", "k"));
      const v = el("div", undefined, "v");
      v.appendChild(el("span", "action needed", "pill awaiting_auth"));
      note.appendChild(v);
      note.appendChild(el("div", "Capture a fresh session (interactive login), update the scan's state file, then Resume.", "hint"));
      cards.push(note);
    }
  }
  if (st.scan.error) cards.push(metric("Error", st.scan.error));
  m.replaceChildren(...cards);

  // Pre-fill the runtime tuning inputs only when not focused (so typing is not
  // clobbered by the poll).
  const active = document.activeElement;
  [["rcDiscovery", cfg.discovery_concurrency], ["rcHTTP", cfg.http_concurrency],
   ["rcBrowser", cfg.browser_concurrency], ["rcRate", cfg.requests_per_second]].forEach(([id, val]) => {
    const input = $(id);
    if (input !== active && input.value === "") input.value = val;
  });
  const terminal = ["completed", "canceled", "failed"].includes(st.scan.state);
  $("applyConfig").disabled = terminal;
}

async function applyConfig() {
  if (!selectedScanId) return;
  const body = {
    discovery_concurrency: parseInt($("rcDiscovery").value, 10) || 0,
    http_concurrency: parseInt($("rcHTTP").value, 10) || 0,
    browser_concurrency: parseInt($("rcBrowser").value, 10) || 0,
    requests_per_second: parseFloat($("rcRate").value) || 0,
  };
  const res = await mutate("POST", "/api/scans/" + encodeURIComponent(selectedScanId) + "/config", body);
  if (!res.ok) { setMsg("rcErr", errMsg(res, "reconfigure failed")); return; }
  setMsg("rcErr", "Applied.", "ok-msg");
  refreshMonitor();
}

// =====================================================================
// Findings (behavior preserved from the previous dashboard)
// =====================================================================
function decodeDetail(raw) {
  try { return JSON.parse(atob(raw)); } catch (e) { return {}; }
}

function findingDetailEl(f) {
  const box = el("div", undefined, "detail");
  const dl = document.createElement("dl");
  const row = (label, value) => {
    if (!value) return;
    dl.appendChild(el("dt", label));
    dl.appendChild(el("dd", value));
  };
  row("Verdict", f.verdict + "   (confidence: " + f.confidence + ")");
  if (f.endpoint) row("Endpoint", f.endpoint.method + " " + f.endpoint.url);
  if (f.parameter) row("Parameter", f.parameter.name + " (" + f.parameter.location + ")");
  else if (f.parsed_detail && f.parsed_detail.parameter_name) row("Parameter", f.parsed_detail.parameter_name);

  const cands = (f.parsed_detail && f.parsed_detail.candidates) || [];
  if (cands.length) {
    dl.appendChild(el("dt", "Candidates (" + cands.length + ", " + (f.parsed_detail.occurrences || 0) + " occurrence(s))"));
    const dd = document.createElement("dd");
    const ul = document.createElement("ul");
    cands.forEach((c) => ul.appendChild(el("li", "[" + c.category + "/" + c.context + "] " + c.value + " — " + c.rationale)));
    dd.appendChild(ul);
    dl.appendChild(dd);
  }
  if (f.provenance) {
    let p = f.provenance.engine + ", discovered via " + f.provenance.discovery_source;
    if (f.provenance.ai_assisted) p += " (AI-assisted; advisory only, not the verdict authority)";
    row("Provenance", p);
  }
  if (f.evidence && f.evidence.length) {
    dl.appendChild(el("dt", "Evidence (" + f.evidence.length + ") — opening fetches the stored content"));
    const dd = document.createElement("dd");
    const ul = document.createElement("ul");
    f.evidence.forEach((ev) => {
      const li = document.createElement("li");
      li.appendChild(document.createTextNode(ev.kind + " · " + (ev.media_type || "") + " · " + ev.size + " bytes · "));
      const a = document.createElement("a");
      a.href = "/api/evidence/" + encodeURIComponent(ev.id) + "/content";
      a.target = "_blank"; a.rel = "noopener";
      a.textContent = "open";
      li.appendChild(a);
      ul.appendChild(li);
    });
    dd.appendChild(ul);
    dl.appendChild(dd);
  }
  box.appendChild(dl);
  return box;
}

function findingRow(f) {
  const tr = el("tr");
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.title = "include in next generated report";
  cb.addEventListener("change", () => {
    if (cb.checked) selectedFindingIds.add(f.id); else selectedFindingIds.delete(f.id);
  });
  const cbTd = el("td"); cbTd.appendChild(cb); tr.appendChild(cbTd);

  const titleTd = cell(f.title || "(untitled)", "clickable");
  tr.appendChild(titleTd);
  const vTd = el("td");
  vTd.appendChild(el("span", f.verdict, "pill " + f.verdict));
  tr.appendChild(vTd);
  tr.appendChild(cell(f.severity));
  const detail = decodeDetail(f.detail || "");
  tr.appendChild(cell(detail.parameter_name || ""));
  const firstCand = (detail.candidates || [])[0];
  tr.appendChild(cell(firstCand ? firstCand.context : ""));

  let detailRow = null;
  titleTd.addEventListener("click", async () => {
    if (detailRow) { detailRow.remove(); detailRow = null; return; }
    detailRow = el("tr");
    const td = el("td"); td.colSpan = 6;
    td.appendChild(el("div", "loading…", "muted"));
    detailRow.appendChild(td);
    tr.after(detailRow);
    try {
      const full = await j("/api/scans/" + encodeURIComponent(selectedScanId) + "/findings/" + encodeURIComponent(f.id));
      td.replaceChildren(findingDetailEl(full));
    } catch (e) {
      td.replaceChildren(el("div", "failed to load detail", "err"));
    }
  });
  return tr;
}

async function loadFindings() {
  if (!selectedScanId) return;
  try {
    const findings = (await j("/api/scans/" + encodeURIComponent(selectedScanId) + "/findings")) || [];
    setBody("findings", findings.map(findingRow), "No findings for this scan yet.", 6);
  } catch (e) {
    setBody("findings", [], "error loading findings", 6);
  }
}

// =====================================================================
// Reports (behavior preserved)
// =====================================================================
function reportRow(r) {
  const tr = el("tr");
  tr.appendChild(cell((r.created_at || "").slice(0, 19).replace("T", " ")));
  tr.appendChild(cell(r.format));
  tr.appendChild(cell(String((r.summary && r.summary.total_findings) || 0)));
  tr.appendChild(cell(String((r.summary && r.summary.confirmed_count) || 0)));
  const openTd = el("td");
  const view = document.createElement("a");
  view.href = "/api/reports/" + encodeURIComponent(r.id) + "/content";
  view.target = "_blank"; view.rel = "noopener";
  view.textContent = "view";
  const dl = document.createElement("a");
  dl.href = "/api/reports/" + encodeURIComponent(r.id) + "/content?download";
  dl.textContent = "download";
  dl.style.marginLeft = "10px";
  openTd.appendChild(view); openTd.appendChild(dl);
  tr.appendChild(openTd);
  return tr;
}

async function loadReports() {
  if (!selectedScanId) return;
  try {
    const reports = (await j("/api/scans/" + encodeURIComponent(selectedScanId) + "/reports")) || [];
    setBody("reports", reports.map(reportRow), "No reports yet.", 5);
  } catch (e) {
    setBody("reports", [], "error loading reports", 5);
  }
}

async function generateReport() {
  if (!selectedScanId) return;
  const format = $("reportFormat").value;
  const res = await mutate("POST", "/api/scans/" + encodeURIComponent(selectedScanId) + "/reports",
    { format, finding_ids: Array.from(selectedFindingIds) });
  if (!res.ok) { setMsg("reportErr", errMsg(res, "generate report failed")); return; }
  setMsg("reportErr", "");
  loadReports();
}

// =====================================================================
// Init
// =====================================================================
async function init() {
  try {
    const v = await j("/api/version");
    $("version").textContent = "v" + (v.version || "dev");
  } catch (e) { /* ignore */ }

  $("createProject").addEventListener("click", createProject);
  $("addTarget").addEventListener("click", addTarget);
  $("saveScope").addEventListener("click", saveScope);
  $("createScan").addEventListener("click", createScan);
  $("scanProfile").addEventListener("change", syncScanForm);
  $("scanStop").addEventListener("change", syncScanForm);
  $("scanAuth").addEventListener("change", syncScanForm);
  document.querySelectorAll('input[name="scanType"]').forEach((r) => r.addEventListener("change", syncScanForm));
  $("startLogin").addEventListener("click", () => $("loginPanel").classList.toggle("hidden"));
  $("runLogin").addEventListener("click", runLogin);
  $("applyConfig").addEventListener("click", applyConfig);
  $("generateReport").addEventListener("click", generateReport);
  syncScanForm();

  loadProjects();
  loadScans();
  setInterval(loadScans, 2500);
  setInterval(refreshMonitor, 1500);
}
init();
