// Dashboard. Every value from the API is inserted with textContent, never as HTML.
const $ = (id) => document.getElementById(id);
const KEY = "domainwatch.token";
let token = "";
try { token = sessionStorage.getItem(KEY) || ""; } catch { /* storage blocked: sign in each time */ }
let timer;

class AuthError extends Error {}

async function api(path, options = {}) {
  const res = await fetch(path, { ...options, headers: { authorization: `Bearer ${token}`, ...(options.body ? { "content-type": "application/json" } : {}) } });
  if (res.status === 401 || res.status === 429) {
    const body = await res.json().catch(() => ({}));
    throw new AuthError(body.error || "Not authorised");
  }
  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
  return body;
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

const ago = (ts, now) => {
  const s = Math.max(0, now - ts);
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

function sparkline(results) {
  const bars = el("div", { class: "spark", role: "img", "aria-label": `Last ${results.length} checks` });
  const latencies = results.map((r) => r.latencyMs ?? 0);
  const max = Math.max(1, ...latencies);
  for (const r of [...results].reverse()) {
    const bar = el("i", { class: r.status === "ok" ? "" : r.status, title: `${new Date(r.ts * 1000).toLocaleString()}: ${r.summary}` });
    bar.style.height = `${Math.max(18, Math.round(((r.latencyMs ?? 0) / max) * 100))}%`;
    bars.append(bar);
  }
  return bars;
}

async function renderMonitor(entry, now) {
  const { monitor: m, state, last, uptime24h } = entry;
  const unconfirmed = m.enabled && state && state.status === "ok" && state.failures > 0; // failing, but not yet confirmed by a second check
  const status = m.enabled ? (unconfirmed ? "failing (unconfirmed)" : state ? state.status : "pending") : "paused";
  const item = el("li", { class: `monitor${m.enabled ? "" : " paused"}` });
  item.append(
    el("div", { class: "head" }, el("span", { class: `dot ${unconfirmed ? "unconfirmed" : state && m.enabled ? state.status : ""}`, title: status }), el("span", { class: "name" }, m.name), el("span", { class: "kind" }, m.kind)),
    el("div", { class: "target" }, m.target),
    el("p", { class: "summary" }, last ? last.summary : m.enabled ? "Waiting for the first check..." : "Paused"),
  );
  const meta = el("div", { class: "meta" });
  if (last) meta.append(el("span", {}, `checked ${ago(last.ts, now)}`));
  if (unconfirmed) meta.append(el("span", {}, "last check failed; an alert follows if the next one fails too"));
  else if (state && state.since) meta.append(el("span", {}, `${status} since ${ago(state.since, now)}`));
  if (uptime24h !== null) meta.append(el("span", {}, `${uptime24h}% up (24h)`));
  meta.append(el("span", {}, `every ${m.intervalS}s`));
  item.append(meta);

  if (last) {
    try {
      const results = await api(`/api/monitors/${m.id}/results?limit=60`);
      if (results.length > 1) item.append(sparkline(results));
    } catch (e) { if (e instanceof AuthError) throw e; }
  }

  const run = el("button", { type: "button", class: "ghost small" }, "Check now");
  run.addEventListener("click", async () => {
    run.disabled = true;
    try { await api(`/api/monitors/${m.id}/run`, { method: "POST", body: "{}" }); } catch (e) { alert(e.message); }
    refresh();
  });
  const pause = el("button", { type: "button", class: "ghost small" }, m.enabled ? "Pause" : "Resume");
  pause.addEventListener("click", async () => {
    try { await api(`/api/monitors/${m.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !m.enabled }) }); } catch (e) { alert(e.message); }
    refresh();
  });
  const del = el("button", { type: "button", class: "ghost small danger" }, "Delete");
  del.addEventListener("click", async () => {
    if (!confirm(`Delete "${m.name}" and its history?`)) return;
    try { await api(`/api/monitors/${m.id}`, { method: "DELETE" }); } catch (e) { alert(e.message); }
    refresh();
  });
  item.append(el("div", { class: "actions" }, run, pause, del));
  return item;
}

function renderAlerts(alerts, now) {
  const list = $("alerts");
  list.replaceChildren();
  $("no-alerts").hidden = alerts.length > 0;
  for (const a of alerts) {
    const li = el("li", { class: a.kind }, a.message, el("time", { datetime: new Date(a.ts * 1000).toISOString() }, `${ago(a.ts, now)}`));
    if (!a.delivered) li.append(el("span", { class: "undelivered" }, " (not delivered to any webhook)"));
    list.append(li);
  }
}

async function refresh() {
  try {
    const summary = await api("/api/summary");
    $("n-ok").textContent = summary.counts.ok;
    $("n-warn").textContent = summary.counts.warn;
    $("n-fail").textContent = summary.counts.fail;
    $("n-other").textContent = summary.counts.paused + summary.counts.pending;
    const rendered = await Promise.all(summary.monitors.map((m) => renderMonitor(m, summary.now)));
    $("monitors").replaceChildren(...rendered);
    $("empty").hidden = summary.monitors.length > 0;
    renderAlerts(summary.alerts, summary.now);
    $("updated").textContent = `updated ${new Date().toLocaleTimeString()}`;
    document.title = summary.counts.fail > 0 ? `(${summary.counts.fail}) domainwatch` : "domainwatch";
  } catch (e) {
    if (e instanceof AuthError) return signOut(e.message);
    $("updated").textContent = `error: ${e.message}`;
  }
}

function show(signedIn) {
  $("login").hidden = signedIn;
  $("app").hidden = !signedIn;
  $("logout").hidden = !signedIn;
  $("refresh").hidden = !signedIn;
}

function signOut(message) {
  clearInterval(timer);
  token = "";
  try { sessionStorage.removeItem(KEY); } catch { /* ignore */ }
  show(false);
  const error = $("login-error");
  error.textContent = message || "";
  error.hidden = !message;
}

function start() {
  show(true);
  refresh();
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden) refresh(); }, 10_000);
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  token = $("token").value.trim();
  $("token").value = "";
  try {
    await api("/api/summary");
    try { sessionStorage.setItem(KEY, token); } catch { /* ignore */ }
    start();
  } catch (e) {
    signOut(e instanceof AuthError ? e.message : `Could not reach the server: ${e.message}`);
  }
});
$("logout").addEventListener("click", () => signOut(""));
$("refresh").addEventListener("click", refresh);

const kindHints = { http: "https://example.com/", tls: "example.com or example.com:8443", dns: "example.com", mail: "example.com" };
$("f-kind").addEventListener("change", () => { $("f-target").placeholder = kindHints[$("f-kind").value]; });
$("toggle-add").addEventListener("click", () => { $("add-form").hidden = !$("add-form").hidden; $("f-target").focus(); });
$("cancel-add").addEventListener("click", () => { $("add-form").hidden = true; $("add-error").textContent = ""; });
$("add-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = { kind: $("f-kind").value, target: $("f-target").value };
  if ($("f-name").value.trim()) body.name = $("f-name").value.trim();
  if ($("f-interval").value) body.intervalS = Number($("f-interval").value);
  try {
    const created = await api("/api/monitors", { method: "POST", body: JSON.stringify(body) });
    $("add-form").reset();
    $("add-form").hidden = true;
    $("add-error").textContent = "";
    api(`/api/monitors/${created.id}/run`, { method: "POST", body: "{}" }).catch(() => {}).finally(refresh);
    refresh();
  } catch (e) {
    $("add-error").textContent = e.message;
  }
});

$("metrics-link").addEventListener("click", async (event) => {
  event.preventDefault();
  try {
    const res = await fetch("/metrics", { headers: { authorization: `Bearer ${token}` } });
    const url = URL.createObjectURL(await res.blob());
    window.open(url, "_blank", "noopener");
  } catch { /* ignore */ }
});

(async () => {
  $("version").textContent = "";
  try { const h = await (await fetch("/healthz")).json(); $("version").textContent = `v${h.version}`; } catch { /* ignore */ }
  if (token) { try { await api("/api/summary"); return start(); } catch { /* fall through to login */ } }
  show(false);
})();
