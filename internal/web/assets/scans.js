// Scan-related UI: the create-scan modal, lifecycle controls, the scan-detail
// view with its six tabs, and the shared finding/report/evidence renderers used
// both here and by the top-level Findings/Reports views. Thin client only — all
// decisions are the server's.

"use strict";

// ---------------------------------------------------------------------------
// Lifecycle controls
// ---------------------------------------------------------------------------
const SCAN_CONTROLS = {
  created: ["start", "cancel"],
  running: ["pause", "cancel"],
  paused: ["resume", "cancel"],
  awaiting_auth: ["resume", "cancel"],
};

async function scanAction(id, action, after) {
  if (action === "cancel" && !window.confirm("Cancel this scan? In-flight work stops and the scan cannot be resumed.")) return;
  const res = await mutate("POST", api.scan(id) + "/" + action);
  if (!res.ok) { showError(action + " failed: " + errMsg(res, action)); return; }
  if (after) after();
}

// scanControls renders the state-appropriate buttons (invalid actions omitted).
function scanControls(scan, after) {
  const frag = document.createDocumentFragment();
  const allowed = SCAN_CONTROLS[scan.state] || [];
  ["start", "pause", "resume", "cancel"].forEach((action) => {
    if (!allowed.includes(action)) return;
    const label = action.charAt(0).toUpperCase() + action.slice(1);
    frag.appendChild(button(label, () => scanAction(scan.id, action, after), action === "cancel" ? "danger" : ""));
  });
  return frag;
}

// ---------------------------------------------------------------------------
// Create-scan modal
// ---------------------------------------------------------------------------
async function openNewScanModal() {
  const project = currentProject();
  if (!project) { navigate("#/projects"); return; }
  let targets = [];
  try { targets = (await getJSON(api.project(project.id) + "/targets")) || []; } catch (e) { /* none */ }

  const body = el("div");
  const errBox = el("div", undefined, "err");
  if (!targets.length) {
    body.appendChild(el("p", "This project has no targets yet. Add one on the Targets page first.", "hint"));
    body.appendChild(el("div", undefined, "form-actions"));
    body.querySelector(".form-actions").appendChild(button("Go to Targets", () => { closeModal(); navigate("#/targets"); }, "primary"));
    openModal("New scan", body);
    return;
  }

  const name = input("f_name", "text", "initial sweep");
  const target = select("f_target", targets.map((t) => [t.id, t.name + " — " + t.base_url]));
  const seeds = textarea("f_seeds", 2, "one URL per line; default: the target base URL");
  const profile = select("f_profile", [["conservative", "Conservative"], ["balanced", "Balanced"], ["fast", "Fast"], ["custom", "Custom"]], "balanced");
  const depth = input("f_depth", "number", "default"); depth.min = 0; depth.max = 20;
  const maxPages = input("f_maxpages", "number", "default"); maxPages.min = 0;
  const maxEndpoints = input("f_maxendpoints", "number", "default"); maxEndpoints.min = 0;
  const cfgD = input("f_cfgD", "number", "", "4"); cfgD.min = 0; cfgD.max = 64;
  const cfgH = input("f_cfgH", "number", "", "10"); cfgH.min = 0; cfgH.max = 64;
  const cfgB = input("f_cfgB", "number", "", "2"); cfgB.min = 0; cfgB.max = 64;
  const cfgR = input("f_cfgR", "number", "", "10"); cfgR.min = 0; cfgR.max = 1000; cfgR.step = "0.1";
  const stop = select("f_stop", [["continue_all", "Continue (test everything)"], ["first_confirmed", "Stop at first confirmed"], ["after_n_confirmed", "Stop after N confirmed"], ["pause_and_ask", "Pause & ask on confirmed"]], "continue_all");
  const stopN = input("f_stopn", "number", "", "1"); stopN.min = 1;
  const auth = select("f_auth", [["anonymous", "Anonymous (no login)"], ["existing", "Existing session (import saved state)"]], "anonymous");
  const authState = input("f_authstate", "text", "/data/sessions/login-….json"); authState.className = "mono";

  // scan type
  const typeCrawl = el("input"); typeCrawl.type = "radio"; typeCrawl.name = "f_type"; typeCrawl.value = "crawl"; typeCrawl.checked = true;
  const typeQuick = el("input"); typeQuick.type = "radio"; typeQuick.name = "f_type"; typeQuick.value = "quick";
  const typeRow = el("div", undefined, "row");
  typeRow.append(labelInline(typeCrawl, "Crawl scan (follow links)"), labelInline(typeQuick, "Quick scan (seeds only)"));

  const crawlLimits = el("div", undefined, "row");
  crawlLimits.append(field("Crawl depth", depth), field("Max pages", maxPages), field("Max endpoints", maxEndpoints));
  const customCfg = el("div", undefined, "row");
  customCfg.append(field("Discovery concurrency", cfgD), field("HTTP concurrency", cfgH), field("Browser concurrency", cfgB), field("Requests / second", cfgR));
  customCfg.classList.add("hidden");
  const stopNWrap = field("N confirmed", stopN); stopNWrap.classList.add("hidden");
  const authWrap = el("div");
  const loginBtn = button("Interactive login…", () => openLoginModal((p) => { authState.value = p; }), "");
  authWrap.append(field("Session state file (absolute server-side path)", authState),
    el("div", "Capture one with interactive login, or point at a Playwright storage-state file. Its contents are never shown.", "hint"),
    el("div", undefined, "form-actions"));
  authWrap.querySelector(".form-actions").appendChild(loginBtn);
  authWrap.classList.add("hidden");

  const typeFs = el("fieldset"); typeFs.append(legend("Scan type & discovery"), typeRow, field("Seed URLs", seeds), crawlLimits);
  const perfFs = el("fieldset"); perfFs.append(legend("Performance profile"), field("Profile", profile), customCfg);
  const stopFs = el("fieldset"); stopFs.append(legend("Stop policy"), rowOf(field("When to stop", stop), stopNWrap));
  const authFs = el("fieldset"); authFs.append(legend("Authentication"), field("Mode", auth), authWrap);

  const sync = () => {
    crawlLimits.classList.toggle("hidden", typeQuick.checked);
    customCfg.classList.toggle("hidden", profile.value !== "custom");
    stopNWrap.classList.toggle("hidden", stop.value !== "after_n_confirmed");
    authWrap.classList.toggle("hidden", auth.value !== "existing");
  };
  [typeCrawl, typeQuick, profile, stop, auth].forEach((x) => x.addEventListener("change", sync));
  sync();

  const create = button("Create scan", async () => {
    const req = {
      project_id: project.id, target_id: target.value, name: name.value.trim(), profile: profile.value,
      seed_urls: lines(seeds), quick_scan: typeQuick.checked,
      max_depth: typeQuick.checked ? 0 : numOrZero(depth), max_pages: numOrZero(maxPages), max_endpoints: numOrZero(maxEndpoints),
    };
    if (profile.value === "custom") {
      req.config = { discovery_concurrency: numOrZero(cfgD), http_concurrency: numOrZero(cfgH), browser_concurrency: parseInt(cfgB.value, 10) || 0, requests_per_second: parseFloat(cfgR.value) || 0 };
    }
    if (stop.value !== "continue_all") {
      req.stop = { mode: stop.value };
      if (stop.value === "after_n_confirmed") req.stop.confirmed_limit = parseInt(stopN.value, 10) || 1;
    }
    if (auth.value === "existing") { req.auth_mode = "existing"; req.auth_state_path = authState.value.trim(); }
    const res = await mutate("POST", "/api/scans", req);
    if (!res.ok) { setMsg(errBox, errMsg(res, "create scan failed")); return; }
    closeModal();
    navigate("#/scans/" + encodeURIComponent(res.data.id) + "/overview");
  }, "primary");

  const actions = el("div", undefined, "form-actions");
  actions.append(create, button("Cancel", closeModal));
  body.append(rowOf(field("Scan name", name), field("Target", target)), typeFs, perfFs, stopFs, authFs, actions, errBox);
  openModal("New scan", body);
}

function labelInline(inputEl, text) {
  const l = el("label", undefined, "inline");
  l.append(inputEl, document.createTextNode(" " + text));
  return l;
}
function legend(text) { return el("legend", text); }
function rowOf(...children) { const r = el("div", undefined, "row"); children.forEach((c) => r.appendChild(c)); return r; }
function numOrZero(inputEl) { const v = parseInt(inputEl.value, 10); return Number.isFinite(v) && v > 0 ? v : 0; }

// ---------------------------------------------------------------------------
// Interactive login modal
// ---------------------------------------------------------------------------
function openLoginModal(onPath) {
  const body = el("div");
  const loginURL = input("l_url", "url", "https://app.example.com/login");
  const success = input("l_success", "text", "**/dashboard"); success.className = "mono";
  const status = el("div", undefined, "hint");
  const run = button("Open browser & wait", async () => {
    const u = loginURL.value.trim();
    if (!u) { status.textContent = "Enter the login page URL first."; return; }
    run.disabled = true;
    status.textContent = "Opening a browser window on the server… log in there (complete any MFA). Waiting for success…";
    const res = await mutate("POST", "/api/auth/login", { login_url: u, success_url: success.value.trim() });
    run.disabled = false;
    if (!res.ok) { status.textContent = errMsg(res, "interactive login failed"); return; }
    onPath(res.data.state_path || "");
    status.textContent = "Login captured. The saved session path has been filled in. Its contents are never shown.";
    setTimeout(closeModal, 1200);
  }, "primary");
  const actions = el("div", undefined, "form-actions");
  actions.append(run, button("Cancel", closeModal));
  body.append(field("Login page URL", loginURL), field("Success URL glob (optional)", success), actions, status);
  openModal("Interactive login", body);
}

// openTuneModal changes a scan's concurrency/rate at runtime. It sends only the
// four runtime fields; the server preserves the crawl extent set at creation.
function openTuneModal(scan) {
  const cfg = scan.config || {};
  const body = el("div");
  const err = el("div", undefined, "err");
  const d = input("tune_d", "number", "", String(cfg.discovery_concurrency || 0)); d.min = 0; d.max = 64;
  const h = input("tune_h", "number", "", String(cfg.http_concurrency || 0)); h.min = 0; h.max = 64;
  const b = input("tune_b", "number", "", String(cfg.browser_concurrency || 0)); b.min = 0; b.max = 64;
  const r = input("tune_r", "number", "", String(cfg.requests_per_second || 0)); r.min = 0; r.max = 1000; r.step = "0.1";
  const apply = button("Apply", async () => {
    const res = await mutate("POST", api.scan(scan.id) + "/config", {
      discovery_concurrency: parseInt(d.value, 10) || 0, http_concurrency: parseInt(h.value, 10) || 0,
      browser_concurrency: parseInt(b.value, 10) || 0, requests_per_second: parseFloat(r.value) || 0,
    });
    if (!res.ok) { setMsg(err, errMsg(res, "reconfigure failed")); return; }
    closeModal(); route();
  }, "primary");
  const actions = el("div", undefined, "form-actions");
  actions.append(apply, button("Cancel", closeModal));
  body.append(el("p", "Applies live to a running scan. Crawl depth/limits are fixed at creation and unchanged here.", "hint"),
    rowOf(field("Discovery", d), field("HTTP", h), field("Browser", b), field("Requests / second", r)), actions, err);
  openModal("Tune concurrency", body);
}

// ---------------------------------------------------------------------------
// Scans list (used by the Scans view)
// ---------------------------------------------------------------------------
async function scanStatuses() {
  const scans = await projectScans();
  const statuses = await Promise.all(scans.map((s) => getJSON(api.scan(s.id) + "/status").catch(() => null)));
  return statuses.filter(Boolean);
}

function scanListRow(st, after) {
  const s = st.scan;
  const tr = el("tr");
  const nameTd = el("td");
  nameTd.appendChild(link(s.name || "(unnamed)", "#/scans/" + encodeURIComponent(s.id) + "/overview"));
  tr.appendChild(nameTd);
  const stateTd = el("td"); stateTd.appendChild(pill(s.state)); tr.appendChild(stateTd);
  tr.appendChild(cell(st.discovery.state));
  tr.appendChild(cell(st.discovery.endpoints));
  tr.appendChild(cell(st.jobs.queued + " / " + (st.jobs.running + st.jobs.leased) + " / " + st.jobs.succeeded, "mono"));
  const f = st.findings;
  tr.appendChild(cell(f.confirmed + " / " + f.pending + " / " + f.rejected + " / " + f.inconclusive, "mono"));
  const actions = el("td");
  actions.appendChild(scanControls(s, after));
  tr.appendChild(actions);
  return tr;
}

// ---------------------------------------------------------------------------
// Findings & reports renderers (shared)
// ---------------------------------------------------------------------------
function decodeDetail(raw) { try { return JSON.parse(atob(raw)); } catch (e) { return {}; } }

function findingDetailEl(f) {
  const box = el("div", undefined, "detail");
  const dl = el("dl");
  const row = (k, v) => { if (!v) return; dl.appendChild(el("dt", k)); dl.appendChild(el("dd", v)); };
  row("Verdict", f.verdict + "   (confidence: " + f.confidence + ")");
  if (f.endpoint) row("Endpoint", f.endpoint.method + " " + f.endpoint.url);
  if (f.parameter) row("Parameter", f.parameter.name + " (" + f.parameter.location + ")");
  else if (f.parsed_detail && f.parsed_detail.parameter_name) row("Parameter", f.parsed_detail.parameter_name);
  const cands = (f.parsed_detail && f.parsed_detail.candidates) || [];
  if (cands.length) {
    dl.appendChild(el("dt", "Candidates (" + cands.length + ", " + (f.parsed_detail.occurrences || 0) + " occurrence(s))"));
    const dd = el("dd"); const ul = el("ul");
    cands.forEach((c) => ul.appendChild(el("li", "[" + c.category + "/" + c.context + "] " + c.value + " — " + c.rationale)));
    dd.appendChild(ul); dl.appendChild(dd);
  }
  if (f.provenance) {
    let p = f.provenance.engine + ", discovered via " + f.provenance.discovery_source;
    if (f.provenance.ai_assisted) p += " (AI-assisted; advisory only, not the verdict authority)";
    row("Provenance", p);
  }
  if (f.evidence && f.evidence.length) {
    dl.appendChild(el("dt", "Evidence (" + f.evidence.length + ") — opening fetches the stored content"));
    const dd = el("dd"); const ul = el("ul");
    f.evidence.forEach((ev) => ul.appendChild(evidenceLine(ev)));
    dd.appendChild(ul); dl.appendChild(dd);
  }
  box.appendChild(dl);
  return box;
}

function evidenceLine(ev) {
  const li = el("li");
  li.appendChild(document.createTextNode(ev.kind + " · " + (ev.media_type || "") + " · " + ev.size + " bytes · "));
  const a = link("open", "/api/evidence/" + encodeURIComponent(ev.id) + "/content");
  a.target = "_blank"; a.rel = "noopener";
  li.appendChild(a);
  return li;
}

function findingRow(f, scanId, selectedIds) {
  const tr = el("tr");
  tr.dataset.fid = f.id;      // identity, for in-place reconcile during refresh
  tr.dataset.verdict = f.verdict; // compared to detect a verdict change
  if (selectedIds) {
    const cb = el("input"); cb.type = "checkbox"; cb.title = "include in next generated report";
    cb.addEventListener("change", () => { if (cb.checked) selectedIds.add(f.id); else selectedIds.delete(f.id); });
    const td = el("td"); td.appendChild(cb); tr.appendChild(td);
  }
  const titleTd = cell(f.title || "(untitled)", "clickable");
  tr.appendChild(titleTd);
  const vTd = el("td"); const verdictPill = pill(f.verdict); vTd.appendChild(verdictPill); tr.appendChild(vTd);
  tr.appendChild(cell(f.severity));
  const detail = decodeDetail(f.detail || "");
  tr.appendChild(cell(detail.parameter_name || ""));
  tr.appendChild(cell((detail.candidates || [])[0] ? detail.candidates[0].context : ""));
  let detailRow = null;
  const cols = selectedIds ? 6 : 5;
  // setVerdict lets a refresh update a promoted verdict (e.g. pending →
  // confirmed) in place, without rebuilding the row or disturbing an expanded
  // detail or the operator's scroll.
  tr._setVerdict = (v) => { verdictPill.textContent = v; verdictPill.className = "pill " + v; tr.dataset.verdict = v; };
  titleTd.addEventListener("click", async () => {
    if (detailRow) { detailRow.remove(); detailRow = null; return; }
    detailRow = el("tr", undefined, "finding-detail");
    const td = el("td"); td.colSpan = cols; td.appendChild(el("div", "loading…", "hint"));
    detailRow.appendChild(td); tr.after(detailRow);
    try {
      const full = await getJSON(api.scan(scanId) + "/findings/" + encodeURIComponent(f.id));
      td.replaceChildren(findingDetailEl(full));
    } catch (e) { td.replaceChildren(el("div", "failed to load detail", "err")); }
  });
  return tr;
}

// reconcileFindingRows updates a findings <tbody> in place from a fresh list:
// new findings are appended, a changed verdict is patched on its existing row,
// gone findings (and any expanded detail row) are removed, and unchanged rows
// — including an open detail row and the scroll position — are left untouched.
function reconcileFindingRows(tbody, findings, scanId, selectedIds, emptyText, cols) {
  const existing = new Map();
  tbody.querySelectorAll("tr[data-fid]").forEach((tr) => existing.set(tr.dataset.fid, tr));
  const emptyRow = tbody.querySelector("tr[data-empty]");

  if (!findings.length) {
    existing.forEach((tr) => { const d = tr.nextElementSibling; if (d && d.classList.contains("finding-detail")) d.remove(); tr.remove(); });
    if (!emptyRow) {
      const tr = el("tr"); tr.dataset.empty = "1";
      const td = cell(emptyText, "empty"); td.colSpan = cols; tr.appendChild(td); tbody.appendChild(tr);
    }
    return;
  }
  if (emptyRow) emptyRow.remove();

  const seen = new Set();
  findings.forEach((f) => {
    seen.add(f.id);
    const tr = existing.get(f.id);
    if (!tr) { tbody.appendChild(findingRow(f, scanId, selectedIds)); return; }
    if (tr.dataset.verdict !== f.verdict) tr._setVerdict(f.verdict);
  });
  existing.forEach((tr, id) => {
    if (seen.has(id)) return;
    const d = tr.nextElementSibling; if (d && d.classList.contains("finding-detail")) d.remove();
    tr.remove();
  });
}

// findingsSignature is a cheap fingerprint of what the findings table renders;
// when it is unchanged a refresh touches no DOM at all (the common case for a
// completed scan), so there is nothing to flicker.
function findingsSignature(findings) {
  return (findings || []).map((f) => f.id + ":" + f.verdict).join("|");
}

function reportRow(r) {
  const tr = el("tr");
  tr.appendChild(cell(fmtTime(r.created_at)));
  tr.appendChild(cell(r.format));
  tr.appendChild(cell(String((r.summary && r.summary.total_findings) || 0)));
  tr.appendChild(cell(String((r.summary && r.summary.confirmed_count) || 0)));
  const openTd = el("td");
  const view = link("view", "/api/reports/" + encodeURIComponent(r.id) + "/content"); view.target = "_blank"; view.rel = "noopener";
  const dl = link("download", "/api/reports/" + encodeURIComponent(r.id) + "/content?download"); dl.style.marginLeft = "10px";
  openTd.append(view, dl);
  tr.appendChild(openTd);
  return tr;
}

// reportsPanel renders the report list + generator for a scan. selectedIds (a
// Set) is optional and, when given, scopes "generate" to the checked findings.
function reportsPanel(scanId, selectedIds) {
  const wrap = el("div");
  const errBox = el("div", undefined, "err");
  const fmt = select("r_fmt", [["json", "JSON"], ["markdown", "Markdown"], ["html", "HTML"]], "json");
  fmt.style.width = "auto";
  const tbody = el("tbody"); tbody.id = "reportsBody";
  const t = el("table");
  const thead = el("thead"); const hr = el("tr");
  ["Created", "Format", "Findings", "Confirmed", "Open"].forEach((h) => hr.appendChild(el("th", h)));
  thead.appendChild(hr); t.append(thead, tbody);

  async function reload() {
    try {
      const reports = (await getJSON(api.scan(scanId) + "/reports")) || [];
      fillBody(tbody, reports.map(reportRow), "No reports yet.", 5);
    } catch (e) { fillBody(tbody, [], "error loading reports", 5); }
  }
  const gen = button("Generate report", async () => {
    const body = { format: fmt.value, finding_ids: selectedIds ? Array.from(selectedIds) : [] };
    const res = await mutate("POST", api.scan(scanId) + "/reports", body);
    if (!res.ok) { setMsg(errBox, errMsg(res, "generate report failed")); return; }
    setMsg(errBox, "");
    reload();
  }, "primary");
  const controls = el("p");
  controls.append(fmt, document.createTextNode(" "), gen);
  if (selectedIds) wrap.appendChild(el("p", "Check findings above to scope the report, or leave all unchecked to include every finding.", "hint"));
  wrap.append(controls, errBox, t);
  reload();
  return wrap;
}

// ---------------------------------------------------------------------------
// Scan detail view (tabs)
// ---------------------------------------------------------------------------
const SCAN_TABS = ["overview", "discovery", "jobs", "findings", "evidence", "reports"];

// metric builds a one-off metric card (used by the dashboard summary, which
// rebuilds its small card set wholesale). The scan-detail tabs use metricGrid
// instead, which updates values in place.
function metric(k, v, pillCls, hint) {
  const d = el("div", undefined, "metric");
  d.appendChild(el("div", k, "k"));
  if (pillCls) { const ve = el("div", undefined, "v"); ve.appendChild(pill(v)); d.appendChild(ve); }
  else d.appendChild(el("div", v, "v"));
  if (hint) d.appendChild(el("div", hint, "hint"));
  return d;
}

// metricGrid builds a grid of metric cards that update in place: set() reuses a
// card for a given key and only writes text/class that actually changed, so a
// refresh causes no flicker and preserves scroll. begin()/end() add or remove
// only the cards that appeared or disappeared.
function metricGrid() {
  const grid = el("div", undefined, "metrics");
  const nodes = new Map();
  return {
    el: grid,
    begin() { nodes.forEach((n) => { n.seen = false; }); },
    set(key, value, pillCls, hint) {
      let n = nodes.get(key);
      if (!n) {
        const cardEl = el("div", undefined, "metric");
        cardEl.appendChild(el("div", key, "k"));
        const v = el("div", undefined, "v");
        cardEl.appendChild(v);
        const h = el("div", undefined, "hint");
        cardEl.appendChild(h);
        n = { card: cardEl, v, h, hadPill: false };
        nodes.set(key, n);
        grid.appendChild(cardEl);
      }
      n.seen = true;
      value = String(value);
      if (pillCls) {
        let span = n.v.firstChild;
        if (!span || span.nodeName !== "SPAN") { span = el("span"); n.v.replaceChildren(span); }
        if (span.textContent !== value) span.textContent = value;
        const cls = "pill " + pillCls;
        if (span.className !== cls) span.className = cls;
      } else if (n.v.textContent !== value || n.v.firstChild) {
        n.v.textContent = value;
      }
      const hv = hint || "";
      if (n.h.textContent !== hv) n.h.textContent = hv;
      n.h.style.display = hv ? "" : "none";
    },
    end() { nodes.forEach((n, k) => { if (!n.seen) { n.card.remove(); nodes.delete(k); } }); },
  };
}

// dlGrid builds a definition list whose values update in place.
function dlGrid() {
  const dl = el("dl", undefined, "detail");
  const nodes = new Map();
  return {
    el: dl,
    begin() { nodes.forEach((n) => { n.seen = false; }); },
    set(key, value) {
      value = value === undefined || value === null ? "" : String(value);
      if (!value) { const n = nodes.get(key); if (n) { n.seen = true; n.dt.style.display = "none"; n.dd.style.display = "none"; } return; }
      let n = nodes.get(key);
      if (!n) { n = { dt: el("dt", key), dd: el("dd") }; nodes.set(key, n); dl.append(n.dt, n.dd); }
      n.seen = true;
      n.dt.style.display = ""; n.dd.style.display = "";
      if (n.dd.textContent !== value) n.dd.textContent = value;
    },
    end() { nodes.forEach((n, k) => { if (!n.seen) { n.dt.remove(); n.dd.remove(); nodes.delete(k); } }); },
  };
}

// --- tab builders: each returns { el, update(status) } and patches in place ---

function overviewTab(scanId) {
  const wrap = el("div");
  const grid = metricGrid();
  const details = dlGrid();
  wrap.append(card("Overview", grid.el), card("Details", details.el));
  return {
    el: wrap,
    update(st) {
      const s = st.scan, cfg = s.config || {};
      grid.begin();
      grid.set("State", s.state, s.state);
      grid.set("Profile", s.profile);
      grid.set("Discovery", st.discovery.state + (st.discovery.paused ? " (paused)" : ""));
      grid.set("Request rate", cfg.requests_per_second > 0 ? cfg.requests_per_second + " req/s" : "unlimited");
      grid.set("Active workers (d/h/b)", st.workers ? (st.workers.discovery + " / " + st.workers.http + " / " + st.workers.browser) : "—");
      grid.set("Findings", "C " + st.findings.confirmed + "  P " + st.findings.pending + "  R " + st.findings.rejected + "  I " + st.findings.inconclusive);
      if (st.session) {
        const sess = st.session;
        grid.set("Auth / session", sess.mode + " · " + sess.state + (sess.has_state ? " · on file" : ""), sess.state);
        if (sess.state === "expired" || s.state === "awaiting_auth") {
          grid.set("Re-authentication", "action needed", "awaiting_auth", "Capture a fresh session (interactive login), update the scan's state file, then Resume.");
        }
      }
      grid.end();
      details.begin();
      details.set("Scan ID", s.id);
      details.set("Created", fmtTime(s.created_at));
      details.set("Started", fmtTime(s.started_at));
      details.set("Stop policy", s.stop ? (s.stop.mode + (s.stop.confirmed_limit ? " (" + s.stop.confirmed_limit + ")" : "")) : "continue_all");
      details.set("Seeds", (s.seed_urls || []).join(", "));
      details.set("Error", s.error);
      details.end();
    },
  };
}

function discoveryTab() {
  const wrap = el("div");
  const grid = metricGrid();
  const srcBody = el("tbody");
  const srcTable = el("table");
  const thead = el("thead"); const hr = el("tr"); ["Source", "Count"].forEach((h) => hr.appendChild(el("th", h))); thead.appendChild(hr);
  srcTable.append(thead, srcBody);
  wrap.append(card("Discovery", grid.el), card("Endpoints by source", srcTable));
  return {
    el: wrap,
    update(st) {
      const d = st.discovery, cfg = st.scan.config || {};
      grid.begin();
      grid.set("Discovery state", d.state);
      grid.set("Endpoints", d.endpoints);
      grid.set("Parameters", d.parameters);
      grid.set("Injection points", d.injection_points);
      grid.set("Mode", cfg.quick_scan ? "quick (seeds only)" : "crawl");
      grid.set("Depth / pages / endpoints", (cfg.max_depth || "default") + " / " + (cfg.max_pages || "default") + " / " + (cfg.max_endpoints || "default"));
      grid.end();
      const by = d.endpoints_by_source || {};
      const keys = Object.keys(by).sort();
      const existing = new Map();
      srcBody.querySelectorAll("tr[data-src]").forEach((tr) => existing.set(tr.dataset.src, tr));
      const seen = new Set();
      keys.forEach((k) => {
        seen.add(k);
        let tr = existing.get(k);
        if (!tr) { tr = el("tr"); tr.dataset.src = k; tr.append(cell(k), cell(String(by[k]))); srcBody.appendChild(tr); }
        else if (tr.lastChild.textContent !== String(by[k])) tr.lastChild.textContent = String(by[k]);
      });
      existing.forEach((tr, k) => { if (!seen.has(k)) tr.remove(); });
      if (!keys.length && !srcBody.querySelector("tr[data-empty]")) {
        const tr = el("tr"); tr.dataset.empty = "1"; const td = cell("Nothing discovered yet.", "empty"); td.colSpan = 2; tr.appendChild(td); srcBody.appendChild(tr);
      } else if (keys.length) { const e = srcBody.querySelector("tr[data-empty]"); if (e) e.remove(); }
    },
  };
}

function jobsTab() {
  const wrap = el("div");
  const jg = metricGrid(); const tg = metricGrid();
  wrap.append(card("Jobs", jg.el), card("Test outcomes", tg.el));
  return {
    el: wrap,
    update(st) {
      const j = st.jobs, t = st.tests;
      jg.begin();
      jg.set("Queued", j.queued); jg.set("Running", j.running + j.leased); jg.set("Succeeded", j.succeeded);
      jg.set("Failed", j.failed); jg.set("Canceled", j.canceled); jg.set("Dead", j.dead);
      jg.end();
      tg.begin();
      tg.set("Reflected", t.reflected); tg.set("Not reflected", t.not_reflected);
      tg.set("Errors", t.error); tg.set("Timeouts", t.timeout); tg.set("Skipped", t.skipped);
      tg.set("429 rate-limited", t.rate_limited); tg.set("5xx server error", t.server_error);
      tg.end();
    },
  };
}

// findingsTab owns its own data (the /findings endpoint). update() re-fetches,
// but reconciles the table in place and does nothing at all when the data is
// unchanged — so an open detail row, scroll, and report-selection checkboxes
// survive every refresh. owns() lets the view token guard against a stale write
// after the operator navigates away.
function findingsTab(scanId, aliveToken) {
  const wrap = el("div");
  const selected = new Set();
  const tbody = el("tbody"); tbody.id = "findingsBody";
  const headers = ["", "Title", "Verdict", "Severity", "Parameter", "Context"];
  const t = el("table");
  const thead = el("thead"); const hr = el("tr"); headers.forEach((h) => hr.appendChild(el("th", h))); thead.appendChild(hr);
  t.append(thead, tbody);
  // initial loading placeholder (shown once, on open — not on refresh)
  const loading = el("tr"); loading.dataset.empty = "1"; const ltd = cell("loading…", "empty"); ltd.colSpan = 6; loading.appendChild(ltd); tbody.appendChild(loading);
  wrap.append(card("Findings", t), card("Generate report from selection", reportsPanel(scanId, selected)));
  let lastSig = null, inflight = false;
  const pull = async () => {
    if (inflight) return; inflight = true;
    try {
      const findings = (await getJSON(api.scan(scanId) + "/findings")) || [];
      if (!aliveToken()) return; // navigated away mid-fetch
      const sig = findingsSignature(findings);
      if (sig === lastSig) return; // nothing changed → touch no DOM
      lastSig = sig;
      reconcileFindingRows(tbody, findings, scanId, selected, "No findings for this scan yet.", 6);
    } catch (e) { /* keep last */ } finally { inflight = false; }
  };
  pull();
  return { el: wrap, update() { pull(); } };
}

// evidenceTab aggregates evidence across the scan's findings. It refetches only
// when the findings' signature (id+updated_at) changes, and reconciles rows by
// evidence id, so a static completed scan never re-renders.
function evidenceTab(scanId, aliveToken) {
  const wrap = el("div");
  const tbody = el("tbody"); tbody.id = "evidenceBody";
  const t = el("table");
  const thead = el("thead"); const hr = el("tr"); ["Finding", "Kind", "Type", "Size", "Open"].forEach((h) => hr.appendChild(el("th", h))); thead.appendChild(hr);
  t.append(thead, tbody);
  const loading = el("tr"); loading.dataset.empty = "1"; const ltd = cell("loading…", "empty"); ltd.colSpan = 5; loading.appendChild(ltd); tbody.appendChild(loading);
  wrap.append(card("Evidence — stored request/response/browser evidence for this scan's findings", t));
  let lastSig = null, inflight = false;
  const pull = async () => {
    if (inflight) return; inflight = true;
    try {
      const findings = (await getJSON(api.scan(scanId) + "/findings")) || [];
      if (!aliveToken()) return;
      const sig = findings.map((f) => f.id + ":" + (f.updated_at || "")).join("|");
      if (sig === lastSig) return;
      const details = await Promise.all(findings.map((f) =>
        getJSON(api.scan(scanId) + "/findings/" + encodeURIComponent(f.id)).catch(() => null)));
      if (!aliveToken()) return;
      lastSig = sig;
      const rows = [];
      findings.forEach((f, i) => {
        const full = details[i]; if (!full) return;
        (full.evidence || []).forEach((ev) => {
          const tr = el("tr"); tr.dataset.eid = ev.id;
          const openTd = el("td"); const a = link("open", "/api/evidence/" + encodeURIComponent(ev.id) + "/content"); a.target = "_blank"; a.rel = "noopener"; openTd.appendChild(a);
          tr.append(cell(f.title || "(untitled)"), cell(ev.kind), cell(ev.media_type || ""), cell(ev.size + " bytes"), openTd);
          rows.push([ev.id, tr]);
        });
      });
      // reconcile by evidence id
      const existing = new Map();
      tbody.querySelectorAll("tr[data-eid]").forEach((tr) => existing.set(tr.dataset.eid, tr));
      const emptyRow = tbody.querySelector("tr[data-empty]");
      if (!rows.length) {
        existing.forEach((tr) => tr.remove());
        if (!emptyRow) { const tr = el("tr"); tr.dataset.empty = "1"; const td = cell("No evidence yet — evidence appears once candidates are executed and verified.", "empty"); td.colSpan = 5; tr.appendChild(td); tbody.appendChild(tr); }
        return;
      }
      if (emptyRow) emptyRow.remove();
      const seen = new Set();
      rows.forEach(([id, tr]) => { seen.add(id); if (!existing.has(id)) tbody.appendChild(tr); });
      existing.forEach((tr, id) => { if (!seen.has(id)) tr.remove(); });
    } catch (e) { /* keep last */ } finally { inflight = false; }
  };
  pull();
  return { el: wrap, update() { pull(); } };
}

function reportsTab(scanId) {
  // reportsPanel manages its own list and only reloads on an explicit generate,
  // so there is nothing to update on a refresh tick.
  const wrap = card("Reports", reportsPanel(scanId, null));
  return { el: wrap, update() {} };
}

function buildTab(tab, scanId, aliveToken) {
  switch (tab) {
    case "discovery": return discoveryTab();
    case "jobs": return jobsTab();
    case "findings": return findingsTab(scanId, aliveToken);
    case "evidence": return evidenceTab(scanId, aliveToken);
    case "reports": return reportsTab(scanId);
    default: return overviewTab(scanId);
  }
}

async function renderScanDetail(params, view) {
  const scanId = params[0];
  let tab = params[1] || "overview";
  if (!SCAN_TABS.includes(tab)) tab = "overview";
  const myView = currentView; // router token: async writes stop once we navigate away
  const alive = () => myView === currentView;

  let st;
  try { st = await getJSON(api.scan(scanId) + "/status"); }
  catch (e) {
    view.appendChild(pageHead("Scan"));
    view.appendChild(emptyState("Scan not found.", "Back to Scans", () => navigate("#/scans")));
    return;
  }

  // --- shell, built once ---
  const statePill = pill(st.scan.state); statePill.style.marginRight = "10px";
  const title = el("h1"); title.append(statePill, document.createTextNode(st.scan.name || "(unnamed scan)"));
  const head = el("div", undefined, "page-head");
  head.appendChild(title);
  const actions = el("div", undefined, "actions");
  head.appendChild(actions);
  view.appendChild(head);

  const tabsNav = el("nav", undefined, "tabs");
  SCAN_TABS.forEach((name) => {
    tabsNav.appendChild(link(name.charAt(0).toUpperCase() + name.slice(1),
      "#/scans/" + encodeURIComponent(scanId) + "/" + name, name === tab ? "active" : ""));
  });
  view.appendChild(tabsNav);

  const panel = el("div"); panel.id = "tabPanel";
  view.appendChild(panel);

  const active = buildTab(tab, scanId, alive);
  panel.appendChild(active.el);
  if (tab === "overview" || tab === "discovery" || tab === "jobs") active.update(st);

  // syncHead rebuilds the state pill + controls only when the scan state
  // changes, so the control buttons do not flicker or lose hover on every tick.
  let lastState = null;
  const syncHead = (s) => {
    if (s.state === lastState) return;
    lastState = s.state;
    statePill.textContent = s.state; statePill.className = "pill " + s.state; statePill.style.marginRight = "10px";
    actions.replaceChildren();
    actions.appendChild(scanControls(s, () => route()));
    if (!["completed", "canceled", "failed"].includes(s.state)) {
      actions.appendChild(button("Tune concurrency", () => openTuneModal(s), ""));
    }
    actions.appendChild(button("Refresh", () => { if (currentView.refresh) currentView.refresh(); }, ""));
  };
  syncHead(st.scan);

  // The single refresh entry point (timer + manual button both call it).
  return async () => {
    let fresh;
    try { fresh = await getJSON(api.scan(scanId) + "/status"); } catch (e) { return; }
    if (!alive()) return;
    syncHead(fresh.scan);
    active.update(fresh);
  };
}
