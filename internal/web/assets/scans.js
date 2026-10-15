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

  const candProfile = select("f_candprofile", [["standard", "Standard — up to 8 candidates per injection point"], ["minimal", "Minimal — up to 3, load-trigger only"], ["thorough", "Thorough — up to 16"]], "standard");
  const maxCand = input("f_maxcand", "number", "profile default"); maxCand.min = 0; maxCand.max = 32;
  const enableEvasion = el("input"); enableEvasion.type = "checkbox"; enableEvasion.id = "f_evasion";
  const candFs = el("fieldset");
  candFs.append(legend("XSS candidates"), rowOf(field("Candidate profile", candProfile), field("Max candidates per injection point", maxCand)),
    el("div", "Selects among the built-in benign-marker candidates by the site's execution context and encoding. Never changes how a finding is confirmed (always a browser-observed execution signal).", "hint"),
    labelInline(enableEvasion, "Also try WAF/filter-bypass variants (case variation, alternate separators, double URL-encoding)"),
    el("div", "Off by default. Adds these ON TOP OF the candidates above for an authorized engagement where a bypass is itself the reportable finding — still benign-marker-only and scope-enforced the same as every other request. See AGENTS.md §2 and docs/reflection-candidates.md.", "hint"));

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
      candidate_profile: candProfile.value, max_candidates: numOrZero(maxCand),
      enable_evasion: enableEvasion.checked,
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
  body.append(rowOf(field("Scan name", name), field("Target", target)), typeFs, candFs, perfFs, stopFs, authFs, actions, errBox);
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

// Per-scan UI state that must outlive any one render: the scan-detail view's
// live refresh re-renders tabs, and the operator moves between tabs/routes, but
// the findings they checked, the detail rows they opened, the findings filter,
// and the report mode and format they picked must stay put. Lives for the
// page's lifetime.
const scanUIState = new Map();
function uiState(scanId) {
  let s = scanUIState.get(scanId);
  if (!s) {
    s = {
      selected: new Set(), expanded: new Set(),
      view: "confirmed",                       // findings filter: confirmed | review | diagnostic | all
      mode: "confirmed", modeExplicit: false,  // report mode
      format: "json", visible: [], listeners: [],
    };
    scanUIState.set(scanId, s);
  }
  return s;
}
// onSelectionChange registers fn for selection/filter changes while node stays
// in the document; listeners of detached (re-rendered) nodes are dropped lazily.
function onSelectionChange(state, node, fn) { state.listeners.push({ node, fn }); }
function notifySelection(state) {
  // A report mode the operator never chose follows the selection: checking
  // findings means "report these", clearing them goes back to confirmed-only.
  if (!state.modeExplicit) state.mode = state.selected.size ? "selected" : "confirmed";
  state.listeners = state.listeners.filter((l) => l.node.isConnected);
  state.listeners.forEach((l) => l.fn());
}

// Which findings each filter shows. "Confirmed" is the default: rejected
// attempts are diagnostics, not vulnerabilities, and stay out of the main view.
const FINDING_VIEWS = [
  ["confirmed", "Confirmed vulnerabilities", (f) => f.section === "confirmed"],
  ["review", "Needs review", (f) => f.section === "needs_review"],
  ["diagnostic", "Diagnostics (rejected)", (f) => f.section === "diagnostic"],
  ["all", "All", () => true],
];
function viewPredicate(name) { return (FINDING_VIEWS.find((v) => v[0] === name) || FINDING_VIEWS[0])[2]; }
function sectionCountsOf(findings) {
  return { confirmed: findings.filter((f) => f.section === "confirmed").length,
           review: findings.filter((f) => f.section === "needs_review").length,
           diagnostic: findings.filter((f) => f.section === "diagnostic").length, all: findings.length };
}

// filterBar renders the findings filter (segmented buttons with live counts).
function filterBar(counts, current, onChange) {
  const bar = el("div", undefined, "filter-bar"); bar.setAttribute("role", "group"); bar.setAttribute("aria-label", "Findings view");
  FINDING_VIEWS.forEach(([name, label]) => {
    const b = button(label + " (" + counts[name] + ")", () => onChange(name), name === current ? "seg active" : "seg", "view_" + name);
    b.setAttribute("aria-pressed", name === current ? "true" : "false");
    bar.appendChild(b);
  });
  return bar;
}

// endpointLabel mirrors the server's finding titles: path plus sorted
// parameter NAMES, which is how discovery tells endpoints apart.
function endpointLabel(method, rawURL) {
  if (!rawURL) return "";
  try {
    const u = new URL(rawURL);
    const names = [...new Set([...u.searchParams.keys()])].sort();
    return (method ? method + " " : "") + u.pathname + (names.length ? "?" + names.join("&") : "");
  } catch (e) { return (method ? method + " " : "") + rawURL; }
}

function findingsSignature(findings) {
  return findings.map((f) => f.id + ":" + f.verdict + ":" + f.updated_at + ":" + (f.attempt_count || 0)).join("|");
}

const VERDICT_ORDER = ["confirmed", "inconclusive", "rejected", "pending"];
function verdictBreakdown(by) {
  const parts = VERDICT_ORDER.filter((v) => by && by[v] > 0).map((v) => v + " " + by[v]);
  return parts.length ? parts.join(", ") : "no findings";
}

const ROLE_LABELS = {
  browser: "browser verification",
  candidate: "candidate request/response",
  baseline: "baseline reference — the unmodified request, not a payload",
};

// evidenceLinks opens/downloads evidence content. The server serves it under a
// script-less CSP sandbox (captured markup is the target's), so "open" is safe
// to view; rel=noopener keeps the new tab from reaching back into this one.
function evidenceLinks(ev) {
  const frag = document.createDocumentFragment();
  const view = link("open", "/api/evidence/" + encodeURIComponent(ev.id) + "/content", "act");
  view.target = "_blank"; view.rel = "noopener noreferrer";
  const dl = link("download", "/api/evidence/" + encodeURIComponent(ev.id) + "/content?download", "act");
  dl.rel = "noopener noreferrer"; dl.style.marginLeft = "8px";
  frag.append(view, dl);
  return frag;
}

function evidenceLine(ev) {
  const li = el("li", undefined, ev.role === "baseline" ? "baseline" : "");
  li.appendChild(document.createTextNode((ROLE_LABELS[ev.role] || ev.role) + " · " + ev.kind + " · " + (ev.media_type || "") + " · " + ev.size + " bytes · "));
  li.appendChild(evidenceLinks(ev));
  return li;
}

// payloadBox shows a candidate value verbatim and safely: textContent only,
// wrapping inside its box however long or unbroken the value is.
function payloadBox(value) {
  const pre = el("pre", value, "payload");
  pre.title = "candidate value";
  return pre;
}

function sectionNote(f) {
  switch (f.section) {
    case "confirmed": return null;
    case "diagnostic": return "Not a vulnerability: the candidate(s) reflected, but browser verification observed no execution. Kept as a diagnostic.";
    default:
      // review_reason_label (set by the API when the review is specific — an
      // interaction-only candidate, or every candidate was filtered) is the
      // accurate reason; fall back to a generic one only when it's absent
      // (verdict pending/inconclusive with no specific reason recorded).
      if (f.review_reason_label) return f.review_reason_label;
      return f.verdict === "inconclusive"
        ? "Not yet a confirmed vulnerability: the marker could not be re-observed during browser verification."
        : "Not yet a confirmed vulnerability: awaiting browser verification (or it cannot be verified, e.g. a POST/body-carrying request).";
  }
}

function findingDetailEl(f) {
  const box = el("div", undefined, "detail");
  const dl = el("dl");
  const row = (k, v) => { if (!v) return; dl.appendChild(el("dt", k)); dl.appendChild(el("dd", v)); };
  const pd = f.parsed_detail || {};
  const cands = pd.candidates || [];
  // candidateByValue finds the PLANNED candidate matching a verification
  // attempt's value, so a confirmed/attempted candidate can show its
  // Technique (set only when the scan opted into evasion candidates) even
  // though AttemptView itself doesn't carry one.
  const candidateByValue = (value) => cands.find((c) => c.value === value);
  const techniqueNote = (c) => c && c.technique
    ? el("div", "Bypass technique: " + c.technique + " — " + (c.rationale || ""), "hint")
    : null;

  if (f.verified_candidate) {
    // The candidate whose browser verification produced the deterministic
    // execution signal: shown first, prominently, with its own evidence.
    const v = f.verified_candidate;
    const hero = el("div", undefined, "verified");
    hero.appendChild(el("div", "Verified candidate — confirmed by browser verification", "verified-title"));
    hero.appendChild(payloadBox(v.candidate_value));
    const tn = techniqueNote(candidateByValue(v.candidate_value));
    if (tn) hero.appendChild(tn);
    if (v.notes) hero.appendChild(el("div", "Signal: " + v.notes, "hint"));
    const own = (v.evidence || []).filter((e) => e.role !== "baseline");
    if (own.length) {
      const ul = el("ul"); own.forEach((e) => ul.appendChild(evidenceLine(e)));
      hero.appendChild(ul);
    }
    box.appendChild(hero);
  } else {
    const note = sectionNote(f);
    if (note) box.appendChild(el("div", note, "section-note"));
  }

  row("Verdict", f.verdict + "   (confidence: " + f.confidence + ")");
  if (f.endpoint) row("Endpoint", f.endpoint.method + " " + f.endpoint.url);
  if (f.parameter) row("Parameter", f.parameter.name + " (" + f.parameter.location + ")");
  else if (pd.parameter_name) row("Parameter", pd.parameter_name);
  if (cands.length && cands[0].context) row("Execution context", cands[0].context + (cands[0].context_sub ? " (" + cands[0].context_sub + ")" : ""));

  const attempts = (f.attempts || []).filter((a) => !(f.verified_candidate && a.verify_test_case_id === f.verified_candidate.verify_test_case_id));
  if (attempts.length) {
    dl.appendChild(el("dt", (f.verified_candidate ? "Other attempts" : "Attempts") + " (" + attempts.length + ") — kept as diagnostics"));
    const dd = el("dd"); const ul = el("ul", undefined, "attempts");
    attempts.forEach((a) => {
      const li = el("li");
      li.appendChild(pill(a.verdict));
      li.appendChild(document.createTextNode(" "));
      li.appendChild(el("code", a.candidate_value, "wrap"));
      const c = candidateByValue(a.candidate_value);
      if (c && c.technique) li.appendChild(el("span", " [bypass: " + c.technique + "]", "hint"));
      if (a.notes) li.appendChild(el("div", a.notes, "hint"));
      ul.appendChild(li);
    });
    dd.appendChild(ul); dl.appendChild(dd);
  } else if (!f.verified_candidate && cands.length) {
    dl.appendChild(el("dt", "Candidates that reflected (" + cands.length + ") — not yet verified"));
    const dd = el("dd"); const ul = el("ul");
    cands.forEach((c) => {
      const li = el("li");
      li.appendChild(el("code", c.value, "wrap"));
      if (c.technique) li.appendChild(el("span", " [bypass: " + c.technique + "]", "hint"));
      ul.appendChild(li);
    });
    dd.appendChild(ul); dl.appendChild(dd);
  }

  if (f.provenance) {
    let p = f.provenance.engine + ", discovered via " + f.provenance.discovery_source;
    if (f.provenance.ai_assisted) p += " (AI-assisted; advisory only, not the verdict authority)";
    row("Provenance", p);
  }

  const evs = f.evidence || [];
  dl.appendChild(el("dt", "Evidence (" + evs.length + ")"));
  const evdd = el("dd");
  if (evs.length) {
    const ul = el("ul"); evs.forEach((e) => ul.appendChild(evidenceLine(e))); evdd.appendChild(ul);
  } else {
    evdd.appendChild(el("span", "none recorded yet", "hint"));
  }
  dl.appendChild(evdd);
  box.appendChild(dl);
  return box;
}

// toggleDetail opens/closes a finding's detail row under tr. The colspan is
// taken from the row itself so callers that add columns stay correct.
async function toggleDetail(tr, f, scanId, state, forceOpen) {
  const open = tr._detailRow;
  if (open && !forceOpen) {
    open.remove(); tr._detailRow = null;
    if (state) state.expanded.delete(f.id);
    return;
  }
  if (open) return;
  const detailRow = el("tr", undefined, "detail-row");
  const td = el("td"); td.colSpan = tr.children.length; td.appendChild(el("div", "loading…", "hint"));
  detailRow.appendChild(td); tr.after(detailRow);
  tr._detailRow = detailRow;
  if (state) state.expanded.add(f.id);
  try {
    const full = await getJSON(api.scan(scanId) + "/findings/" + encodeURIComponent(f.id));
    td.replaceChildren(findingDetailEl(full));
  } catch (e) { td.replaceChildren(el("div", "failed to load detail", "err")); }
}

function findingRow(f, scanId, state) {
  const tr = el("tr");
  tr.dataset.findingId = f.id;
  if (state) {
    const cb = el("input"); cb.type = "checkbox"; cb.className = "finding-select";
    cb.title = "include in a 'Selected findings' report";
    cb.checked = state.selected.has(f.id);
    cb.addEventListener("change", () => {
      if (cb.checked) state.selected.add(f.id); else state.selected.delete(f.id);
      notifySelection(state);
    });
    const td = el("td"); td.appendChild(cb); tr.appendChild(td);
  }
  const titleTd = cell(f.title || "(untitled)", "clickable c-title");
  tr.appendChild(titleTd);
  const vTd = el("td"); vTd.appendChild(pill(f.verdict)); tr.appendChild(vTd);
  tr.appendChild(cell(f.severity));
  tr.appendChild(cell(endpointLabel(f.endpoint_method, f.endpoint_url), "mono c-endpoint"));
  tr.appendChild(cell(f.parameter_name || "", "c-ident"));
  tr.appendChild(cell(f.context || "", "c-ident c-words"));
  // Only a confirmed finding has a verified candidate to show.
  const vc = el("td", undefined, "mono verified-cell");
  if (f.verified_candidate) {
    // Clamped in the table (the full value is the first thing in the detail row).
    const val = f.verified_candidate.candidate_value;
    vc.textContent = val.length > 140 ? val.slice(0, 140) + "…" : val;
    vc.title = val;
  }
  tr.appendChild(vc);
  // Labels for the stacked (phone-width) layout, where the header row is hidden.
  const cells = Array.from(tr.children).slice(state ? 1 : 0);
  cells.forEach((td, i) => { td.dataset.label = FINDING_HEADERS[i]; });
  titleTd.addEventListener("click", () => toggleDetail(tr, f, scanId, state));
  return tr;
}

const FINDING_HEADERS = ["Title", "Verdict", "Severity", "Endpoint", "Parameter", "Context", "Verified candidate"];

// findingsTable renders the findings list for a view filter. With a state it
// adds selection: a header checkbox (checked / indeterminate / clear), Select
// all and Clear selection actions, and a live "N of M shown selected" count.
// "Select all" applies to the findings SHOWN (the current filter); Clear
// selection clears everything, including selections made in other views.
function findingsTable(findings, scanId, state, emptyText) {
  emptyText = emptyText || "No findings in this view.";
  if (!state) {
    const t = table(FINDING_HEADERS, findings.map((f) => findingRow(f, scanId, null)), emptyText, "findingsBody");
    t.classList.add("findings-table");
    return t;
  }

  state.visible = findings.map((f) => f.id);
  const wrap = el("div");
  const toolbar = el("div", undefined, "selection-bar");
  const count = el("span", undefined, "hint"); count.id = "selectionCount";
  const all = button("Select all", () => { state.visible.forEach((id) => state.selected.add(id)); notifySelection(state); }, "", "selectAll");
  const clear = button("Clear selection", () => { state.selected.clear(); notifySelection(state); }, "", "clearSelection");
  toolbar.append(all, clear, count);

  const t = table(["", ...FINDING_HEADERS], findings.map((f) => findingRow(f, scanId, state)), emptyText, "findingsBody");
  t.classList.add("findings-table");
  const headCb = el("input"); headCb.type = "checkbox"; headCb.id = "selectAllBox"; headCb.title = "select / clear all findings shown";
  t.querySelector("thead th").appendChild(headCb);
  headCb.addEventListener("change", () => {
    if (headCb.checked) state.visible.forEach((id) => state.selected.add(id));
    else state.visible.forEach((id) => state.selected.delete(id));
    notifySelection(state);
  });

  const sync = () => {
    const shown = state.visible.length;
    const selShown = state.visible.filter((id) => state.selected.has(id)).length;
    const hiddenSel = state.selected.size - selShown;
    count.textContent = selShown + " of " + shown + " selected" + (hiddenSel > 0 ? " · " + hiddenSel + " more selected in other views" : "");
    headCb.checked = shown > 0 && selShown === shown;
    headCb.indeterminate = selShown > 0 && selShown < shown;
    headCb.disabled = shown === 0;
    all.disabled = shown === 0 || selShown === shown;
    clear.disabled = state.selected.size === 0;
    t.querySelectorAll("input.finding-select").forEach((cb) => {
      cb.checked = state.selected.has(cb.closest("tr").dataset.findingId);
    });
  };
  onSelectionChange(state, wrap, sync);
  wrap.append(toolbar, t);
  sync();
  // Re-open rows the operator had expanded before this render.
  t.querySelectorAll("tbody tr[data-finding-id]").forEach((tr) => {
    const f = findings.find((x) => x.id === tr.dataset.findingId);
    if (f && state.expanded.has(f.id)) toggleDetail(tr, f, scanId, state, true);
  });
  return wrap;
}

function reportRow(r) {
  const tr = el("tr");
  const s = r.summary || {};
  tr.appendChild(cell(fmtTime(r.created_at), "c-words"));
  tr.appendChild(cell(r.format, "c-words"));
  tr.appendChild(cell(s.selection || "—", "c-words"));
  tr.appendChild(cell(String(s.total_findings || 0) + (s.scan_findings ? " of " + s.scan_findings : ""), "c-words"));
  tr.appendChild(cell(verdictBreakdown(s.by_verdict), "c-words"));
  const openTd = el("td");
  const view = link("view", "/api/reports/" + encodeURIComponent(r.id) + "/content", "act"); view.target = "_blank"; view.rel = "noopener noreferrer";
  const dl = link("download", "/api/reports/" + encodeURIComponent(r.id) + "/content?download", "act"); dl.style.marginLeft = "10px";
  openTd.append(view, dl);
  tr.appendChild(openTd);
  return tr;
}

// reportsPanel renders the report generator and the scan's report list. The
// mode is explicit — Confirmed only / Selected findings / All findings — and
// before generating it shows exactly what the server will include (count and
// verdict breakdown), fetched from the same selection logic generation uses.
// The selection is the scan's shared one (uiState), so findings checked on the
// Findings tab carry over here.
function reportsPanel(scanId) {
  const state = uiState(scanId);
  const wrap = el("div");
  const errBox = el("div", undefined, "err");

  const modes = [["confirmed", "Confirmed only"], ["selected", "Selected findings"], ["all", "All findings (incl. unconfirmed and rejected diagnostics)"]];
  const modeRow = el("div", undefined, "row report-modes");
  const radios = {};
  modes.forEach(([value, label]) => {
    const r = el("input"); r.type = "radio"; r.name = "r_mode_" + scanId; r.value = value; r.id = "r_mode_" + value;
    r.addEventListener("change", () => { state.mode = value; state.modeExplicit = true; update(); });
    radios[value] = r;
    modeRow.appendChild(labelInline(r, label));
  });
  const fmt = select("r_fmt", [["json", "JSON"], ["markdown", "Markdown"], ["html", "HTML"]], state.format);
  fmt.style.width = "auto";
  fmt.addEventListener("change", () => { state.format = fmt.value; });
  const preview = el("div", undefined, "hint"); preview.id = "reportPreview";

  let previewTotal = null;
  let previewSeq = 0;
  async function refreshPreview() {
    const seq = ++previewSeq;
    if (state.mode === "selected" && state.selected.size === 0) {
      previewTotal = 0;
      preview.textContent = "Select findings on the Findings tab to use this mode.";
      syncGenerate();
      return;
    }
    let q = "?mode=" + encodeURIComponent(state.mode);
    if (state.mode === "selected") [...state.selected].sort().forEach((id) => { q += "&finding_id=" + encodeURIComponent(id); });
    try {
      const p = await getJSON(api.scan(scanId) + "/reports/preview" + q);
      if (seq !== previewSeq) return; // a newer request superseded this one
      previewTotal = p.total_findings;
      preview.textContent = "Will include " + p.total_findings + " of " + p.scan_findings + " finding(s): " + verdictBreakdown(p.by_verdict) + "."
        + (p.total_findings === 0 ? " Nothing matches this mode yet." : "");
    } catch (e) {
      if (seq === previewSeq) { previewTotal = null; preview.textContent = "Could not compute the report preview."; }
    }
    syncGenerate();
  }

  const gen = button("Generate report", async () => {
    const body = { format: state.format, mode: state.mode };
    if (state.mode === "selected") body.finding_ids = [...state.selected].sort();
    gen.disabled = true;
    const res = await mutate("POST", api.scan(scanId) + "/reports", body);
    syncGenerate();
    if (!res.ok) { setMsg(errBox, errMsg(res, "generate report failed")); return; }
    const s = res.data.summary || {};
    setMsg(errBox, "Report created: " + s.total_findings + " finding(s) (" + verdictBreakdown(s.by_verdict) + ").", true);
    reload();
  }, "primary", "generateReport");
  const syncGenerate = () => { gen.disabled = (state.mode === "selected" && state.selected.size === 0) || previewTotal === 0; };

  const update = () => {
    radios.selected.parentElement.lastChild.textContent = " Selected findings (" + state.selected.size + ")";
    Object.entries(radios).forEach(([v, r]) => { r.checked = v === state.mode; });
    syncGenerate();
    refreshPreview();
  };
  onSelectionChange(state, wrap, update);

  const tbody = el("tbody"); tbody.id = "reportsBody";
  const t = el("table");
  const thead = el("thead"); const hr = el("tr");
  ["Created", "Format", "Selection", "Findings", "Verdicts", "Open"].forEach((h) => hr.appendChild(el("th", h)));
  thead.appendChild(hr); t.append(thead, tbody);
  let reportsSig = null;
  async function reload() {
    try {
      const reports = (await getJSON(api.scan(scanId) + "/reports")) || [];
      const sig = reports.map((r) => r.id).join("|");
      if (sig === reportsSig) return;
      reportsSig = sig;
      fillBody(tbody, reports.map(reportRow), "No reports yet.", 6);
    } catch (e) { fillBody(tbody, [], "error loading reports", 6); }
  }

  const controls = el("div", undefined, "form-actions");
  controls.append(fmt, gen);
  wrap.append(modeRow, preview, controls, errBox, t);
  wrap.live = () => { reload(); refreshPreview(); };
  update();
  reload();
  return wrap;
}

// ---------------------------------------------------------------------------
// Scan detail view (tabs)
// ---------------------------------------------------------------------------
const SCAN_TABS = ["overview", "discovery", "jobs", "findings", "evidence", "reports"];

async function renderScanDetail(params, view) {
  const scanId = params[0];
  let tab = params[1] || "overview";
  if (!SCAN_TABS.includes(tab)) tab = "overview";

  let st;
  try { st = await getJSON(api.scan(scanId) + "/status"); }
  catch (e) {
    view.appendChild(pageHead("Scan"));
    view.appendChild(emptyState("Scan not found.", "Back to Scans", () => navigate("#/scans")));
    return;
  }
  const s = st.scan;

  const headActions = [scanControls(s, () => route())];
  if (!["completed", "canceled", "failed"].includes(s.state)) {
    headActions.push(button("Tune concurrency", () => openTuneModal(s), ""));
  }
  const head = pageHead(s.name || "(unnamed scan)", headActions);
  head.querySelector("h1").prepend(/* state pill before title */ (function () { const sp = pill(s.state); sp.style.marginRight = "10px"; return sp; })());
  view.appendChild(head);

  const tabsNav = el("nav", undefined, "tabs");
  SCAN_TABS.forEach((name) => {
    const a = link(name.charAt(0).toUpperCase() + name.slice(1), "#/scans/" + encodeURIComponent(scanId) + "/" + name, name === tab ? "active" : "");
    tabsNav.appendChild(a);
  });
  view.appendChild(tabsNav);

  const panel = el("div"); panel.id = "tabPanel";
  view.appendChild(panel);

  // Status-only tabs (overview/discovery/jobs) are cheap and stateless, so a
  // refresh rebuilds them. Findings/evidence/reports carry operator state
  // (selection, open detail rows, chosen report mode) and expose a live()
  // that patches in new data instead: rebuilding them every tick used to
  // reset the selection and collapse open rows every couple of seconds.
  const renderTab = (status, isRefresh) => {
    const cur = SCAN_TABS.includes((location.hash.split("/")[3] || "overview")) ? (location.hash.split("/")[3] || "overview") : "overview";
    if (cur !== tab) return; // tab changed; router will re-render
    const existing = panel.firstChild;
    if (isRefresh && existing && typeof existing.live === "function") { existing.live(status); return; }
    panel.replaceChildren(scanTabPanel(cur, status, scanId));
  };
  renderTab(st, false);

  // Live refresh of the active tab.
  return async () => {
    try { const fresh = await getJSON(api.scan(scanId) + "/status"); renderTab(fresh, true); } catch (e) { /* keep last */ }
  };
}

function scanTabPanel(tab, st, scanId) {
  switch (tab) {
    case "overview": return overviewPanel(st, scanId);
    case "discovery": return discoveryPanel(st);
    case "jobs": return jobsPanel(st);
    case "findings": return findingsTabPanel(scanId);
    case "evidence": return evidencePanel(scanId);
    case "reports": {
      const rp = reportsPanel(scanId);
      const c = card("Reports", rp);
      c.live = rp.live;
      return c;
    }
    default: return el("div");
  }
}

function metric(k, v, pillCls, hint) {
  const d = el("div", undefined, "metric");
  d.appendChild(el("div", k, "k"));
  if (pillCls) { const ve = el("div", undefined, "v"); ve.appendChild(pill(v)); d.appendChild(ve); }
  else d.appendChild(el("div", v, "v"));
  if (hint) d.appendChild(el("div", hint, "hint"));
  return d;
}

function overviewPanel(st, scanId) {
  const s = st.scan, cfg = s.config || {};
  const wrap = el("div");
  const m = el("div", undefined, "metrics");
  m.append(
    metric("State", s.state, s.state),
    metric("Profile", s.profile),
    metric("Discovery", st.discovery.state + (st.discovery.paused ? " (paused)" : "")),
    metric("Request rate", cfg.requests_per_second > 0 ? cfg.requests_per_second + " req/s" : "unlimited"),
    metric("Candidate profile", (cfg.candidate_profile || "standard") + (cfg.max_candidates ? " (max " + cfg.max_candidates + ")" : "")),
    metric("Active workers (d/h/b)", st.workers ? (st.workers.discovery + " / " + st.workers.http + " / " + st.workers.browser) : "—"),
    metric("Findings", st.findings.confirmed + " confirmed", undefined,
      st.findings.pending + " pending · " + st.findings.inconclusive + " inconclusive · " + st.findings.rejected + " rejected"),
  );
  if (cfg.enable_evasion) {
    m.appendChild(metric("Evasion candidates", "ON", undefined,
      "Also tried WAF/filter-bypass variants (case variation, alt separators, double URL-encoding) on top of the canonical candidates — look for a \"bypass: …\" tag on a candidate."));
  }
  if (st.session) {
    const sess = st.session;
    m.appendChild(metric("Auth / session", sess.mode + " · " + sess.state + (sess.has_state ? " · on file" : ""), sess.state));
    if (sess.state === "expired" || s.state === "awaiting_auth") {
      m.appendChild(metric("Re-authentication", "action needed", "awaiting_auth", "Capture a fresh session (interactive login), update the scan's state file, then Resume."));
    }
  }
  wrap.appendChild(card("Overview", m));

  const dl = el("dl", undefined, "detail");
  const row = (k, v) => { if (v === undefined || v === null || v === "") return; dl.appendChild(el("dt", k)); dl.appendChild(el("dd", String(v))); };
  row("Scan ID", s.id);
  row("Created", fmtTime(s.created_at));
  row("Started", fmtTime(s.started_at));
  row("Stop policy", s.stop ? (s.stop.mode + (s.stop.confirmed_limit ? " (" + s.stop.confirmed_limit + ")" : "")) : "continue_all");
  row("Seeds", (s.seed_urls || []).join(", "));
  if (s.error) row("Error", s.error);
  wrap.appendChild(card("Details", dl));
  return wrap;
}

function discoveryPanel(st) {
  const d = st.discovery, cfg = st.scan.config || {};
  const wrap = el("div");
  const m = el("div", undefined, "metrics");
  m.append(
    metric("Discovery state", d.state),
    metric("Endpoints", d.endpoints),
    metric("Parameters", d.parameters),
    metric("Injection points", d.injection_points),
    metric("Mode", cfg.quick_scan ? "quick (seeds only)" : "crawl"),
    metric("Depth / pages / endpoints", (cfg.max_depth || "default") + " / " + (cfg.max_pages || "default") + " / " + (cfg.max_endpoints || "default")),
  );
  wrap.appendChild(card("Discovery", m));
  const bySource = d.endpoints_by_source || {};
  const rows = Object.keys(bySource).sort().map((k) => { const tr = el("tr"); tr.append(cell(k), cell(bySource[k])); return tr; });
  wrap.appendChild(card("Endpoints by source", table(["Source", "Count"], rows, "Nothing discovered yet.")));
  return wrap;
}

function jobsPanel(st) {
  const j = st.jobs, t = st.tests;
  const wrap = el("div");
  const jm = el("div", undefined, "metrics");
  jm.append(
    metric("Queued", j.queued), metric("Running", j.running + j.leased), metric("Succeeded", j.succeeded),
    metric("Failed", j.failed), metric("Canceled", j.canceled), metric("Dead", j.dead),
  );
  wrap.appendChild(card("Jobs", jm));
  const tm = el("div", undefined, "metrics");
  tm.append(
    metric("Reflected", t.reflected), metric("Not reflected", t.not_reflected),
    metric("Errors", t.error), metric("Timeouts", t.timeout), metric("Skipped", t.skipped),
    metric("429 rate-limited", t.rate_limited), metric("5xx server error", t.server_error),
  );
  wrap.appendChild(card("Test outcomes", tm));
  return wrap;
}

// findingsTabPanel lists a scan's findings through a filter that defaults to
// confirmed vulnerabilities. Rejected attempts are diagnostics: reachable via
// their own filter, never mixed into the default view.
function findingsTabPanel(scanId) {
  const state = uiState(scanId);
  const wrap = el("div");
  const body = el("div");
  body.appendChild(el("div", "loading…", "hint"));
  let all = null, sig = null, shownView = null;

  function render() {
    const counts = sectionCountsOf(all);
    const shown = all.filter(viewPredicate(state.view));
    state.visible = shown.map((f) => f.id);
    const hidden = all.length - counts.confirmed;
    let empty = "No findings in this view.";
    if (state.view === "confirmed") {
      empty = all.length
        ? "No confirmed vulnerabilities yet. " + hidden + " other finding(s) — unconfirmed or rejected diagnostics — are hidden in this view."
        : "No findings for this scan yet.";
    }
    const bar = filterBar(counts, state.view, (name) => { state.view = name; render(); notifySelection(state); });
    body.replaceChildren(bar, findingsTable(shown, scanId, state, empty));
    shownView = state.view;
  }
  async function load() {
    try {
      const findings = (await getJSON(api.scan(scanId) + "/findings")) || [];
      const next = findingsSignature(findings);
      if (next === sig && shownView === state.view) return; // nothing changed: keep the DOM (and open rows)
      sig = next;
      all = findings;
      // Drop selections/open rows for findings that no longer exist.
      const known = new Set(findings.map((f) => f.id));
      [...state.selected].forEach((id) => { if (!known.has(id)) state.selected.delete(id); });
      [...state.expanded].forEach((id) => { if (!known.has(id)) state.expanded.delete(id); });
      render();
      notifySelection(state); // counts may have changed (pruned/added findings)
    } catch (e) {
      if (sig === null) body.replaceChildren(el("div", "error loading findings", "err"));
    }
  }
  const rp = reportsPanel(scanId);
  wrap.append(card("Findings", body), card("Generate report", rp));
  wrap.live = () => { load(); rp.live(); };
  load();
  return wrap;
}

// evidencePanel lists every finding's evidence (metadata only) from one
// request, grouped by finding with confirmed findings first; each item is
// labelled by role so the baseline (the unmodified request, e.g. q=hello) is
// never mistaken for a payload. Content opens sandboxed (see evidenceLinks).
function evidencePanel(scanId) {
  const wrap = el("div");
  const body = el("div"); body.id = "evidenceBody";
  body.appendChild(el("div", "loading…", "hint"));
  wrap.appendChild(card("Evidence — request/response and browser evidence linked to this scan's findings", body));
  let sig = null;
  async function load() {
    try {
      const groups = (await getJSON(api.scan(scanId) + "/evidence")) || [];
      const next = groups.map((g) => g.finding_id + ":" + g.verdict + ":" + g.evidence.map((e) => e.id).join(",")).join("|");
      if (next === sig) return;
      sig = next;
      const total = groups.reduce((n, g) => n + g.evidence.length, 0);
      if (!total) {
        body.replaceChildren(el("div", groups.length
          ? "These findings have no stored evidence yet — evidence appears as candidates are executed and verified."
          : "No findings yet — evidence appears once candidates are executed and verified.", "empty"));
        return;
      }
      const rows = [];
      groups.forEach((g) => {
        g.evidence.forEach((ev, i) => {
          const tr = el("tr", undefined, ev.role === "baseline" ? "baseline" : "");
          const ftd = el("td");
          if (i === 0) {
            ftd.append(pill(g.verdict), document.createTextNode(" " + (g.finding_title || "(untitled)")));
            if (g.verified_candidate) ftd.appendChild(el("div", "verified: " + g.verified_candidate, "hint mono wrap"));
          }
          tr.append(ftd, cell(ROLE_LABELS[ev.role] || ev.role, "c-words"), cell(ev.kind, "c-words"), cell(ev.media_type || "", "c-words"),
            cell(ev.size + " bytes", "c-words"), cell((ev.sha256 || "").slice(0, 12), "mono"), cell(fmtTime(ev.created_at), "c-words"));
          const openTd = el("td"); openTd.appendChild(evidenceLinks(ev)); tr.appendChild(openTd);
          rows.push(tr);
        });
      });
      body.replaceChildren(el("p", total + " evidence item(s) across " + groups.filter((g) => g.evidence.length).length + " finding(s). Content opens sandboxed: scripts in captured pages never run.", "hint"),
        table(["Finding", "Role", "Kind", "Type", "Size", "SHA-256", "Captured", "Open"], rows, ""));
    } catch (e) {
      if (sig === null) body.replaceChildren(el("div", "error loading evidence", "err"));
    }
  }
  wrap.live = load;
  load();
  return wrap;
}
