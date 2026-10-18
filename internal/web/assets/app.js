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

// collapsible wraps body in a native <details>: closed content stays in the
// DOM (so querySelectorAll / Ctrl-F still reach it) but is not painted —
// exactly "shorten the page, don't throw the data away". summary is prepended
// with an extra hint span when given, right-aligned (see CSS).
function collapsible(summaryContent, body, open, hint) {
  const d = el("details", undefined, "collapsible");
  if (open) d.open = true;
  const s = el("summary");
  if (typeof summaryContent === "string") s.appendChild(el("span", summaryContent));
  else s.appendChild(summaryContent);
  if (hint) s.appendChild(el("span", hint, "hint"));
  const bodyWrap = el("div", undefined, "collapsible-body");
  bodyWrap.appendChild(body);
  d.append(s, bodyWrap);
  return d;
}

// pagedList renders `items` pageSize at a time: renderPage(pageItems) builds
// the visible content for the current page. Only the current page's items
// are ever in the DOM — for a handful of items (the common case) `pages` is 1
// and no pager controls appear at all.
function pagedList(items, pageSize, renderPage, emptyText) {
  const wrap = el("div");
  const body = el("div");
  const pager = el("div", undefined, "pager");
  let page = 0;
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  function show() {
    const start = page * pageSize;
    const slice = items.slice(start, start + pageSize);
    body.replaceChildren(slice.length ? renderPage(slice) : el("div", emptyText || "nothing to show", "empty"));
    pager.replaceChildren();
    if (pages > 1) {
      const prev = button("‹ Prev", () => { page = Math.max(0, page - 1); show(); }, "small");
      const next = button("Next ›", () => { page = Math.min(pages - 1, page + 1); show(); }, "small");
      prev.disabled = page === 0; next.disabled = page >= pages - 1;
      pager.append(prev, el("span", "Page " + (page + 1) + " of " + pages + " (" + items.length + " item(s))", "hint"), next);
    }
  }
  show();
  wrap.append(body, pager);
  return wrap;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------
// The control API may require a bearer token (INDAGO_API_TOKEN on the server).
// The token is kept in sessionStorage only: never localStorage, never a
// cookie, never rendered into the DOM. It is cleared when the tab closes.
const TOKEN_KEY = "indago.apiToken";
let tokenDeclinedAt = 0; // a cancelled prompt is not repeated for a minute

function storedToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch (e) { return ""; }
}
function storeToken(tok) {
  try { if (tok) sessionStorage.setItem(TOKEN_KEY, tok); else sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
}

// withToken returns copy of fetch options carrying the bearer token, if any.
function withToken(opts, tok) {
  const o = Object.assign({}, opts, { headers: Object.assign({}, opts.headers || {}) });
  if (tok) o.headers["Authorization"] = "Bearer " + tok;
  return o;
}

// askToken prompts the operator for the API token. It returns the entered
// token, or "" when cancelled (a cancel is not re-prompted for a minute).
function askToken() {
  if (Date.now() - tokenDeclinedAt < 60000) return "";
  const v = window.prompt("This Indago server requires its API token (INDAGO_API_TOKEN). Enter it to continue; it is kept for this browser tab only.", "");
  const tok = (v || "").trim();
  if (!tok) { tokenDeclinedAt = Date.now(); return ""; }
  storeToken(tok);
  return tok;
}

// One cooldown for all API helpers in this console tab. Read requests retry at
// most twice; writes are never replayed after a 429.
let apiCooldownUntil = 0;
let apiCooldownWait = null;
function apiCoolingDown() { return Date.now() < apiCooldownUntil; }
function retryAfterMs(header) {
  const value = (header || "").trim();
  let ms = 2000; // conservative fallback for missing/invalid values
  if (/^\d+$/.test(value)) ms = Number(value) * 1000;
  else if (/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) {
    ms = Date.parse(value) - Date.now();
  }
  return Number.isFinite(ms) && ms >= 0 ? Math.max(1000, Math.min(60000, ms)) : 2000;
}
function noteAPIThrottle(r) {
  const ms = retryAfterMs(r.headers.get("Retry-After"));
  apiCooldownUntil = Math.max(apiCooldownUntil, Date.now() + ms);
  $("apiStatus").textContent = "API throttled — waiting " + Math.ceil(ms / 1000) + "s before retrying reads. Actions are not retried; wait, then try again.";
}
async function waitAPICooldown() {
  while (apiCoolingDown()) {
    if (!apiCooldownWait) {
      apiCooldownWait = new Promise((resolve) => setTimeout(resolve, apiCooldownUntil - Date.now()))
        .finally(() => { apiCooldownWait = null; });
    }
    await apiCooldownWait;
  }
}
async function tokenFetch(url, opts) {
  const sent = storedToken();
  const r = await fetch(url, withToken(opts, sent));
  if (r.status !== 401) return r;
  let tok = storedToken();
  if (tok === sent) tok = askToken();
  if (!tok) return r;
  return fetch(url, withToken(opts, tok));
}
const API_THROTTLE_ERROR = "API throttled. Wait for the cooldown, then try again. The action was not retried.";
function throttleResponse(read) {
  const error = read ? "API throttled. Automatic read retries exhausted; wait, then use Refresh." : API_THROTTLE_ERROR;
  return new Response(JSON.stringify({ error }), { status: 429, headers: { "Content-Type": "application/json" } });
}
async function authedFetch(url, opts) {
  const read = ["GET", "HEAD"].includes((opts && opts.method || "GET").toUpperCase());
  const view = currentView;
  const checkView = () => { if (read && view !== currentView) throw new Error("navigation changed; request discarded"); };
  if (!read && apiCoolingDown()) return throttleResponse();
  for (let attempt = 0; ; attempt++) {
    await waitAPICooldown();
    checkView();
    const r = await tokenFetch(url, opts);
    checkView();
    if (r.status !== 429) {
      if (r.ok && !apiCoolingDown()) $("apiStatus").textContent = "";
      return r;
    }
    noteAPIThrottle(r);
    if (!read || attempt >= 2) {
      if (read) $("apiStatus").textContent = "API throttled — waiting for cooldown. Automatic retries exhausted; use Refresh or the next live poll.";
      return throttleResponse(read);
    }
  }
}

// errorText extracts the server's {"error": ...} message from a response.
async function errorText(r) {
  try { const j = await r.json(); return j && j.error ? String(j.error) : ""; } catch (e) { return ""; }
}

// Share a decoded GET, not a Response whose body can only be consumed once.
const pendingJSON = new Map();
function getJSON(url) {
  const view = currentView;
  const existing = pendingJSON.get(url);
  if (existing && existing.view === view) return existing.promise;
  const entry = { view, promise: null };
  entry.promise = loadJSON(url).finally(() => { if (pendingJSON.get(url) === entry) pendingJSON.delete(url); });
  pendingJSON.set(url, entry);
  return entry.promise;
}
async function loadJSON(url) {
  const view = currentView;
  const r = await authedFetch(url, { method: "GET" });
  if (!r.ok) {
    const detail = await errorText(r);
    const err = new Error(url + " -> " + r.status + (detail ? ": " + detail : ""));
    err.status = r.status;
    throw err;
  }
  const data = await r.json();
  if (view !== currentView) throw new Error("navigation changed; data discarded");
  return data;
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
    r = await authedFetch(url, opts);
  } catch (e) {
    return { ok: false, status: 0, data: { error: "network error: " + e } };
  }
  let data = null;
  try { data = await r.json(); } catch (e) { /* no body */ }
  return { ok: r.ok, status: r.status, data };
}

// contentLink links to protected content (evidence/report bytes, PoC files). A
// plain navigation cannot carry the Authorization header, so when a token is
// stored the click is routed through openProtected. Without a token it is an
// ordinary link.
function contentLink(text, href, cls, asDownload) {
  const a = link(text, href, cls);
  a.addEventListener("click", (e) => {
    if (!storedToken()) return;
    e.preventDefault();
    openProtected(href, asDownload);
  });
  return a;
}

// The CSP the server sends with evidence and report content. The artifact
// frame repeats it (the iframe csp attribute, where the browser supports it),
// since a blob URL carries no server headers.
const ARTIFACT_CSP = "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'";

// openProtected fetches protected content with the token. "Download" saves the
// original bytes. "Open" depends on the type: HTML, SVG and XML (script-capable)
// render in a sandboxed frame (see showArtifact), never as this console's own
// origin and never as text; other types open in a new tab, with JavaScript
// shown as plain text.
async function openProtected(href, asDownload) {
  let r;
  try {
    r = await authedFetch(href, { method: "GET" });
  } catch (e) {
    showError("network error: " + e);
    return;
  }
  if (!r.ok) {
    const detail = await errorText(r);
    showError(href + " -> " + r.status + (detail ? ": " + detail : ""));
    return;
  }
  const type = r.headers.get("Content-Type") || "application/octet-stream";
  const body = await r.blob();
  const disp = r.headers.get("Content-Disposition") || "";
  const m = /filename="([^"]+)"/.exec(disp);
  const name = m ? m[1] : "download";
  if (asDownload) {
    const u = URL.createObjectURL(new Blob([body], { type }));
    const a = document.createElement("a");
    a.href = u; a.download = name; a.rel = "noopener noreferrer";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(u), 10000);
    return;
  }
  if (/html|svg|xml/i.test(type)) {
    showArtifact(body, type, name);
    return;
  }
  const safeType = /javascript|ecmascript/i.test(type) ? "text/plain; charset=utf-8" : type;
  const u = URL.createObjectURL(new Blob([body], { type: safeType }));
  const w = window.open(u, "_blank", "noopener,noreferrer");
  if (!w) showError("the browser blocked the new tab; allow pop-ups for this console or use download");
  setTimeout(() => URL.revokeObjectURL(u), 60000);
}

// showArtifact shows script-capable content (HTML, SVG, XML) in a full-window
// frame with sandbox="": no scripts, no forms, no same-origin access. The
// document gets an opaque origin, so the captured markup cannot read this
// console or drive its API. The frame is the same protection the server gives
// the same content when it is opened directly (see docs/finding-correlation.md).
let artifactURL = null;
function showArtifact(body, type, name) {
  closeArtifact();
  artifactURL = URL.createObjectURL(new Blob([body], { type }));
  const bar = el("div", undefined, "artifact-bar");
  bar.appendChild(el("span", name, "artifact-name"));
  const close = button("Close", closeArtifact, "artifact-close");
  bar.appendChild(close);
  const frame = document.createElement("iframe");
  frame.className = "artifact-frame";
  frame.setAttribute("sandbox", "");
  frame.setAttribute("csp", ARTIFACT_CSP);
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.title = name;
  frame.src = artifactURL;
  const viewer = el("div", undefined, "artifact-viewer");
  viewer.id = "artifactViewer";
  viewer.append(bar, frame);
  document.body.appendChild(viewer);
  close.focus();
}
function closeArtifact() {
  const v = $("artifactViewer");
  if (v) v.remove();
  if (artifactURL) { URL.revokeObjectURL(artifactURL); artifactURL = null; }
}
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $("artifactViewer")) closeArtifact(); });

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
// refreshMs is the live-refresh interval; 0 means "off" (the operator
// refreshes by hand with the header's Refresh button).
function refreshMs() {
  const raw = prefs.get("refreshMs", "2000");
  if (raw === "off") return 0;
  const v = parseInt(raw, 10);
  return Number.isFinite(v) && v >= 500 ? v : 2000;
}

// updateLiveCtl reflects the interval and whether the current view is live in
// the header: "Live · 2s" / "Live off", plus a manual Refresh button whenever
// the view has something to refresh.
function updateLiveCtl() {
  const ms = refreshMs();
  const state = $("liveState");
  state.textContent = ms > 0 ? "Live · " + (ms / 1000) + "s" : "Live off";
  state.classList.toggle("off", ms === 0);
  $("refreshNow").classList.toggle("hidden", !currentView.refresh);
}

// Drop duplicate refresh invocations instead of accumulating awaiters every
// poll tick. The original invocation owns completion/rendering.
function singleFlight(fn) {
  let pending = false;
  return async (...args) => {
    if (pending) return;
    pending = true;
    try { return await fn(...args); } finally { pending = false; }
  };
}

async function refreshNow() {
  const btn = $("refreshNow");
  btn.disabled = true;
  try {
    await loadProjects();
    if (currentView.refresh) await currentView.refresh();
  } finally { btn.disabled = false; }
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
    return ctx.projects; // a failed/throttled load is not an empty project list
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
function navigate(hash) {
  if (location.hash === hash) route(); else location.hash = hash;
}

async function route() {
  const hash = location.hash || "#/dashboard";
  if (currentView.timer) clearInterval(currentView.timer);
  currentView = { name: "", refresh: null, timer: null };
  updateLiveCtl();
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

  // Detach the previous container. Late render/catch continuations may still
  // update their own nodes, but can never append into the new route.
  const view = el("div");
  view.id = "view";
  $("view").replaceWith(view);
  view.dataset.view = match.name;
  currentView.name = match.name;
  const token = currentView; // a newer navigation replaces currentView
  try {
    const refresh = await match.render(params, view);
    if (token !== currentView) return; // navigated away while rendering
    if (typeof refresh === "function") {
      currentView.refresh = singleFlight(refresh);
      const ms = refreshMs();
      if (ms > 0) {
        currentView.timer = setInterval(() => {
          if (token === currentView && !apiCoolingDown() && $("modal").classList.contains("hidden")) currentView.refresh();
        }, ms);
      }
    } else if ($("apiStatus").textContent) {
      currentView.refresh = () => route(); // retry a throttled initial load manually
    }
    updateLiveCtl();
  } catch (e) {
    if (token !== currentView) return;
    view.replaceChildren(card("Error", el("p", "Could not load this view: " + e.message, "err")));
    currentView.refresh = () => route();
    updateLiveCtl();
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
