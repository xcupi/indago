// Indago dashboard — core: DOM helpers, HTTP, hash router, modal, and the
// header project context. Views live in views.js.
//
// The UI is a thin client over the HTTP API: it holds no scan, scope, or
// verification logic of its own. All operator-supplied text is rendered with
// textContent (never innerHTML). Every state-changing request carries the
// X-Indago-Client header (CSRF protection); the server additionally enforces
// DNS-rebinding protection and scope.

"use strict";

// ---------------------------------------------------------------------------
// DOM helpers (textContent only)
// ---------------------------------------------------------------------------
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function $(id) { return document.getElementById(id); }
function cell(text, cls) { return el("td", text, cls); }
function link(text, href, cls) { const a = el("a", text, cls); a.href = href; return a; }
function button(text, onClick, cls, id) {
  const b = el("button", text, cls);
  if (id) b.id = id;
  b.addEventListener("click", onClick);
  return b;
}
function pill(text) { return el("span", text, "pill " + text); }
function fmtTime(s) { return (s || "").slice(0, 19).replace("T", " "); }

function table(headers, rows, emptyText, bodyId) {
  const t = el("table");
  const thead = el("thead");
  const hr = el("tr");
  headers.forEach((h) => hr.appendChild(el("th", h)));
  thead.appendChild(hr);
  t.appendChild(thead);
  const tb = el("tbody");
  if (bodyId) tb.id = bodyId;
  fillBody(tb, rows, emptyText, headers.length);
  t.appendChild(tb);
  return t;
}
function fillBody(tb, rows, emptyText, cols) {
  tb.replaceChildren();
  if (!rows.length) {
    const tr = el("tr");
    const td = cell(emptyText, "empty");
    td.colSpan = cols;
    tr.appendChild(td);
    tb.appendChild(tr);
    return;
  }
  rows.forEach((r) => tb.appendChild(r));
}

function field(labelText, input) {
  const d = el("div");
  const l = el("label", labelText);
  if (input.id) l.htmlFor = input.id;
  d.appendChild(l);
  d.appendChild(input);
  return d;
}
function input(id, type, placeholder, value) {
  const i = el("input");
  i.id = id;
  i.type = type || "text";
  if (placeholder) i.placeholder = placeholder;
  if (value !== undefined) i.value = value;
  return i;
}
function textarea(id, rows, placeholder) {
  const t = el("textarea");
  t.id = id;
  t.rows = rows || 3;
  if (placeholder) t.placeholder = placeholder;
  return t;
}
function select(id, options, selected) {
  const s = el("select");
  s.id = id;
  options.forEach(([value, text]) => {
    const o = el("option", text);
    o.value = value;
    if (value === selected) o.selected = true;
    s.appendChild(o);
  });
  return s;
}
function lines(ta) { return ta.value.split("\n").map((s) => s.trim()).filter(Boolean); }

function emptyState(text, actionText, onAction) {
  const d = el("div", undefined, "empty-state");
  d.appendChild(el("p", text));
  if (actionText) d.appendChild(button(actionText, onAction, "primary"));
  return d;
}

function pageHead(title, actions) {
  const h = el("div", undefined, "page-head");
  h.appendChild(el("h1", title));
  if (actions && actions.length) {
    const a = el("div", undefined, "actions");
    actions.forEach((x) => a.appendChild(x));
    h.appendChild(a);
  }
  return h;
}

function card(title, ...children) {
  const c = el("section", undefined, "card");
  if (title) c.appendChild(el("h2", title));
  children.forEach((x) => x && c.appendChild(x));
  return c;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------
async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) {
    const err = new Error(url + " -> " + r.status);
    err.status = r.status;
    throw err;
  }
  return r.json();
}

// mutate issues a state-changing request with the CSRF header. It never throws
// on an HTTP error, so callers can show the server's validation message.
async function mutate(method, url, body) {
  const opts = { method, headers: { "X-Indago-Client": "ui" } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let r;
  try {
    r = await fetch(url, opts);
  } catch (e) {
    return { ok: false, status: 0, data: { error: "network error: " + e } };
  }
  let data = null;
  try { data = await r.json(); } catch (e) { /* no body */ }
  return { ok: r.ok, status: r.status, data };
}

function errMsg(res, fallback) {
  if (res && res.data && res.data.error) return res.data.error;
  return fallback + " (HTTP " + (res ? res.status : "?") + ")";
}
function setMsg(node, msg, ok) {
  node.textContent = msg || "";
  node.className = ok ? "ok-msg" : "err";
}
function showError(msg) {
  const box = $("error");
  box.textContent = msg;
  setTimeout(() => { if (box.textContent === msg) box.textContent = ""; }, 8000);
}

const api = {
  scan: (id) => "/api/scans/" + encodeURIComponent(id),
  project: (id) => "/api/projects/" + encodeURIComponent(id),
};

// ---------------------------------------------------------------------------
// Preferences (per-viewer conveniences only; never security-relevant state)
// ---------------------------------------------------------------------------
const prefs = {
  get(key, def) {
    try { const v = localStorage.getItem("indago." + key); return v === null ? def : v; } catch (e) { return def; }
  },
  set(key, val) {
    try { if (val === null || val === undefined) localStorage.removeItem("indago." + key); else localStorage.setItem("indago." + key, String(val)); } catch (e) { /* ignore */ }
  },
};
// Live-refresh interval in milliseconds, or 0 for "Off". Stored per-browser.
// Default 10s. Legacy/invalid values fall back to the default; 0 is a valid,
// explicit "Off".
const REFRESH_OPTIONS = [["0", "Off"], ["5000", "5 seconds"], ["10000", "10 seconds"], ["30000", "30 seconds"], ["60000", "60 seconds"]];
function refreshMs() {
  const raw = prefs.get("refreshMs", "10000");
  const v = parseInt(raw, 10);
  if (v === 0) return 0; // Off
  return REFRESH_OPTIONS.some(([val]) => val === String(v)) ? v : 10000;
}

// ---------------------------------------------------------------------------
// Project context (header selector)
// ---------------------------------------------------------------------------
const ctx = { projects: [], projectId: prefs.get("project", "") };

function currentProject() { return ctx.projects.find((p) => p.id === ctx.projectId) || null; }

async function loadProjects() {
  try {
    ctx.projects = (await getJSON("/api/projects")) || [];
  } catch (e) {
    ctx.projects = [];
  }
  if (ctx.projectId && !currentProject()) ctx.projectId = "";
  renderProjectSelect();
  return ctx.projects;
}

function renderProjectSelect() {
  const sel = $("projectSelect");
  sel.replaceChildren();
  const none = el("option", ctx.projects.length ? "— select a project —" : "— no projects yet —");
  none.value = "";
  sel.appendChild(none);
  ctx.projects.forEach((p) => {
    const o = el("option", p.name);
    o.value = p.id;
    if (p.id === ctx.projectId) o.selected = true;
    sel.appendChild(o);
  });
}

function setProject(id) {
  ctx.projectId = id || "";
  prefs.set("project", ctx.projectId || null);
  renderProjectSelect();
  route(); // re-render the current view for the new context
}

// Scans belonging to the current project (all scans when none is selected).
async function projectScans() {
  const scans = (await getJSON("/api/scans")) || [];
  return ctx.projectId ? scans.filter((s) => s.project_id === ctx.projectId) : scans;
}

// ---------------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------------
function openModal(title, body) {
  $("modalTitle").textContent = title;
  $("modalBody").replaceChildren(body);
  $("modal").classList.remove("hidden");
  const first = body.querySelector("input, select, textarea");
  if (first) first.focus();
}
function closeModal() {
  $("modal").classList.add("hidden");
  $("modalBody").replaceChildren();
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
// Routes are hash-based (#/scans/<id>/findings), so navigation never reloads
// the page and the server needs no route of its own beyond "/".
const routes = []; // { name, pattern: RegExp, render(params, view) }
let currentView = { name: "", refresh: null, timer: null };

function defineRoute(name, pattern, render) { routes.push({ name, pattern, render }); }

// manualRefreshButton triggers the current view's refresh once. It is how a
// view stays usable when the live-refresh setting is Off (no timer runs).
function manualRefreshButton() {
  return button("Refresh", () => { if (currentView.refresh) currentView.refresh(); }, "");
}
function navigate(hash) {
  if (location.hash === hash) route(); else location.hash = hash;
}

async function route() {
  const hash = location.hash || "#/dashboard";
  if (currentView.timer) clearInterval(currentView.timer);
  currentView = { name: "", refresh: null, timer: null };
  closeModal();

  const path = hash.replace(/^#/, "");
  let match = null, params = null;
  for (const r of routes) {
    const m = path.match(r.pattern);
    if (m) { match = r; params = m.slice(1).map(decodeURIComponent); break; }
  }
  if (!match) { location.hash = "#/dashboard"; return; }

  // Sidebar highlight: the first path segment names the section.
  const section = path.split("/")[1] || "dashboard";
  document.querySelectorAll("#sidebar a").forEach((a) => a.classList.toggle("active", a.dataset.nav === section));

  const view = $("view");
  view.replaceChildren();
  view.dataset.view = match.name;
  currentView.name = match.name;
  const token = currentView; // a newer navigation replaces currentView
  try {
    const refresh = await match.render(params, view);
    if (token !== currentView) return; // navigated away while rendering
    if (typeof refresh === "function") {
      currentView.refresh = refresh; // also invoked by any manual "Refresh" control
      const ms = refreshMs();
      if (ms > 0) {
        currentView.timer = setInterval(() => {
          if (token === currentView && $("modal").classList.contains("hidden")) refresh();
        }, ms);
      }
      // ms === 0 (Off): no timer runs; the view's manual Refresh button still works.
    }
  } catch (e) {
    if (token !== currentView) return;
    view.replaceChildren(card("Error", el("p", "Could not load this view: " + e.message, "err")));
  }
}

// Views that need a project show this instead of their content.
function needProject(view, what) {
  view.appendChild(pageHead(what));
  view.appendChild(emptyState(
    ctx.projects.length ? "Select a project in the header to see its " + what.toLowerCase() + "."
                        : "Create a project first.",
    ctx.projects.length ? null : "Go to Projects",
    () => navigate("#/projects")));
}
