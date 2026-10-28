/* ExplainIDS console. Plain JS + ECharts, no build step. All API paths are relative so the app
   works at any base URL (localhost, a container, or a hosted Space). */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const BENIGN = "BENIGN";
const SEV_RANK = { Info: 0, Medium: 1, High: 2, Critical: 3 };
const fmt = n => Number(n).toLocaleString("en-AU");
const pct = (n, d = 1) => (n == null || isNaN(n) ? "—" : (n * 100).toFixed(d) + "%");
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode: ignore */ } },
};

const STATIC = window.EXPLAINIDS_STATIC;  // set by scripts/export_static.py for server-free hosting

async function api(path, opts) {
  if (STATIC) return staticApi(path);
  const r = await fetch(path, opts);
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch { /* not JSON */ }
    throw new Error(`${r.status}: ${detail}`);
  }
  return r.json();
}

/* Static build: the same responses, read from pre-scored JSON chunks instead of the live API. */
const staticCache = {};
function staticJson(file) {
  return staticCache[file] ??= fetch(STATIC.data + file).then(r => {
    if (!r.ok) throw new Error(`${r.status}: ${file}`);
    return r.json();
  });
}
async function staticApi(path) {
  const [route, query] = path.split("?");
  if (route === "health" || route === "model") return staticJson(route + ".json");
  if (route !== "replay") {
    throw new Error(STATIC.fullApp ? `file scoring needs the live app: ${STATIC.fullApp}` : "file scoring needs the live API");
  }
  const q = new URLSearchParams(query), h = await staticJson("health.json");
  const total = h.replay_flows, n = Math.max(1, Math.min(+q.get("n") || 40, 500));
  const cursor = ((+q.get("cursor") || 0) % total + total) % total, flows = [], alerts = [];
  for (let j = 0; j < n; ) {
    const i = (cursor + j) % total, chunk = Math.floor(i / h.chunk), end = Math.min((chunk + 1) * h.chunk, total, i + n - j);
    const c = await staticJson(`replay/${String(chunk).padStart(3, "0")}.json`);
    flows.push(...c.flows.filter(f => f.i >= i && f.i < end));
    alerts.push(...c.alerts.filter(a => a.flow_index >= i && a.flow_index < end));
    j += end - i;
  }
  return { cursor: (cursor + n) % total, total, wrapped: cursor + n >= total, flows, alerts };
}

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

/* ---------------- theme + charts registry ---------------- */
const charts = {};
const redrawers = {};
function chart(id) {
  const el = document.getElementById(id);
  if (!charts[id]) charts[id] = echarts.init(el, null, { renderer: "canvas" });
  return charts[id];
}
function palette() {
  return { text: css("--text"), muted: css("--muted"), line: css("--line"), benign: css("--benign"), attack: css("--attack"),
           high: css("--high"), medium: css("--medium"), accent: css("--accent"), accent2: css("--accent2"),
           missed: css("--missed"), panel: css("--panel2") };
}
const SEV_COLOR = () => { const p = palette(); return { Critical: p.attack, High: p.high, Medium: p.medium, Info: p.muted }; };
function base() {
  const p = palette();
  return { textStyle: { color: p.text, fontFamily: "system-ui, Segoe UI, sans-serif" }, animationDuration: 700,
           grid: { left: 8, right: 16, top: 24, bottom: 8, containLabel: true },
           tooltip: { backgroundColor: p.panel, borderColor: p.line, textStyle: { color: p.text } } };
}
function axis(extra = {}) {
  const p = palette();
  return Object.assign({ axisLine: { lineStyle: { color: p.line } }, axisLabel: { color: p.muted },
                         splitLine: { lineStyle: { color: p.line, type: "dashed" } } }, extra);
}
function setTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  Object.values(redrawers).forEach(f => f());
}
$("#theme").onclick = () => {
  const dark = getComputedStyle(document.documentElement).colorScheme.includes("dark");
  const next = dark ? "light" : "dark";
  store.set("theme", next); setTheme(next);
};
const savedTheme = store.get("theme", null);
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
window.addEventListener("resize", () => { Object.values(charts).forEach(c => c.resize()); map.resize(); });

/* ---------------- tabs ---------------- */
function showView(name) {
  $$(".tabs button").forEach(b => { b.classList.toggle("active", b.dataset.view === name); b.setAttribute("aria-selected", b.dataset.view === name); });
  $$(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + name));
  store.set("view", name);
  requestAnimationFrame(() => {
    Object.values(charts).forEach(c => c.resize());
    if (name === "lab") renderLab();
    if (name === "incidents") renderIncidents();
    if (name === "attack") renderAttack();
    if (name === "research") renderResearch();
    if (name === "live") map.resize();
  });
}
$$(".tabs button").forEach(b => (b.onclick = () => showView(b.dataset.view)));

/* ---------------- session state ---------------- */
const S = {
  card: null, health: null,
  alerts: [],                      // every alert seen this session (live + uploads)
  triage: store.get("triage", {}), // alert_id -> status
  cursor: 0, running: false, n: 40, timer: null, busy: false,
  flows: 0, tp: 0, fp: 0, fn: 0, tn: 0, startedAt: 0, flowTimes: [],
  classCounts: {}, timeline: [],
};

/* Sensor data never enters replay counters or its labelled scorecard. Keys stay in memory. */
const sensor = { enabled: false, key: "", cursor: 0, timer: null, controller: null,
  alerts: new Map(), rows: [], receivedAt: null, generation: 0 };
function disconnectSensor(message = "Feed disconnected") {
  sensor.enabled = false; sensor.generation++; sensor.key = "";
  clearTimeout(sensor.timer); sensor.controller?.abort();
  $("#sensor-key").value = "";
  $("#sensor-connect").disabled = false; $("#sensor-disconnect").disabled = true;
  $("#sensor-status").textContent = message;
}
async function pollSensor(generation) {
  if (!sensor.enabled || generation !== sensor.generation) return;
  sensor.controller = new AbortController();
  const timeout = setTimeout(() => sensor.controller?.abort(), 10000);
  try {
    const response = await fetch(`sensor/feed?after=${sensor.cursor}&limit=200`, {
      headers: sensor.key ? { "X-API-Key": sensor.key } : {}, cache: "no-store",
      signal: sensor.controller.signal });
    if (!response.ok) {
      if (response.status === 401) { disconnectSensor("API key required or incorrect"); return; }
      throw new Error(`Feed unavailable (${response.status})`);
    }
    const feed = await response.json();
    if (!sensor.enabled || generation !== sensor.generation) return;
    // A restarted server has a new in-memory cursor/history.
    if (feed.latest_cursor < sensor.cursor) { sensor.cursor = 0; sensor.rows = []; sensor.alerts.clear(); }
    else {
      sensor.cursor = feed.cursor;
      sensor.rows = [...sensor.rows, ...feed.flows].slice(-200);
      feed.alerts.forEach(a => sensor.alerts.set(a.alert_id, a));
      while (sensor.alerts.size > 200) sensor.alerts.delete(sensor.alerts.keys().next().value);
    }
    $("#sensor-access").textContent = feed.key_required
      ? "API key accepted · kept only in memory until disconnect. Use localhost or a trusted HTTPS connection."
      : "No server API key configured · open local development access. Keep this app bound to localhost.";
    const summary = feed.summary;
    const age = summary ? (Date.now() - Date.parse(summary.received_at)) / 1000 : Infinity;
    $("#sensor-status").textContent = !summary ? "No sensor connected"
      : age > 30 ? "Collector idle · no recent batch" : "Receiving sensor observations";
    $("#sensor-flows").textContent = fmt(summary?.total_flows || 0);
    $("#sensor-alert-count").textContent = fmt(summary?.total_alerts || 0);
    $("#sensor-last").textContent = summary ? new Date(summary.received_at).toLocaleTimeString() : "—";
    $("#sensor-session").textContent = summary ? `Session ${summary.sensor_session} · ${summary.model}` : "Waiting for a collector";
    const queue = $("#sensor-alerts"); queue.replaceChildren();
    [...sensor.alerts.values()].reverse().slice(0, 80).forEach(a => queue.appendChild(alertCard(a)));
    if (!queue.children.length) {
      const empty = document.createElement("div"); empty.className = "empty";
      empty.textContent = summary ? "No candidate alerts in received batches" : "No sensor connected";
      queue.appendChild(empty);
    }
    $("#sensor-rows").innerHTML = [...sensor.rows].reverse().slice(0, 100).map(r => `<tr>
      <td>${esc(String(r.time).slice(0, 19))}</td><td>${esc(r.src)}</td><td>${esc(r.dst)}</td>
      <td>${esc(r.predicted)}</td><td>${r.outlier ? "yes" : "no"}</td></tr>`).join("");
    if (feed.history_truncated) $("#sensor-access").textContent += " Earlier history expired from the bounded server queue.";
  } catch (e) {
    if (sensor.enabled && generation === sensor.generation) $("#sensor-status").textContent = e.name === "AbortError" ? "Feed request timed out" : "Feed unavailable; retrying";
  } finally {
    clearTimeout(timeout);
    if (sensor.enabled && generation === sensor.generation) sensor.timer = setTimeout(() => pollSensor(generation), 3000);
  }
}
$("#sensor-connect").onclick = () => {
  if (STATIC) { $("#sensor-status").textContent = "Sensor feed requires the live local app"; return; }
  const key = $("#sensor-key").value;
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
  if (!loopback && !key) { $("#sensor-status").textContent = "Remote feed requires an API key and a trusted connection"; return; }
  if (!loopback && location.protocol !== "https:") { $("#sensor-status").textContent = "Use localhost or HTTPS before entering an API key"; return; }
  sensor.key = key; $("#sensor-key").value = ""; sensor.enabled = true;
  $("#sensor-connect").disabled = true; $("#sensor-disconnect").disabled = false;
  $("#sensor-status").textContent = "Connecting to sensor feed…";
  pollSensor(++sensor.generation);
};
$("#sensor-disconnect").onclick = () => disconnectSensor();
window.addEventListener("pagehide", () => disconnectSensor());

/* ---------------- network map (canvas) ---------------- */
const map = (() => {
  const cv = $("#netmap"), ctx = cv.getContext("2d"), tip = $("#map-tip");
  const nodes = new Map(); // ip -> {ip, x, y, tx, ty, flows, alerts, last, pulse, internal}
  const particles = [];
  let W = 0, H = 0, dpr = 1, hover = null;
  const isInternal = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip || "");

  function resize() {
    dpr = window.devicePixelRatio || 1;
    W = cv.clientWidth; H = cv.clientHeight;
    cv.width = W * dpr; cv.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    layout();
  }
  function layout() {
    const inner = [...nodes.values()].filter(n => n.internal), outer = [...nodes.values()].filter(n => !n.internal);
    // internal hosts on an inner ellipse, external hosts on an outer one, both filling the canvas
    const cx = W / 2, cy = H / 2;
    const place = (arr, rx, ry, rot) => arr.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))
      .forEach((n, i) => { const a = rot + (i / Math.max(arr.length, 1)) * Math.PI * 2;
        n.tx = cx + Math.cos(a) * rx; n.ty = cy + Math.sin(a) * ry; if (n.x == null) { n.x = cx; n.y = cy; } });
    place(inner, W * 0.22, H * 0.26, -Math.PI / 2);
    place(outer, W * 0.44, H * 0.43, -Math.PI / 2 + 0.2);
  }
  function node(ip) {
    if (!ip) return null;
    let n = nodes.get(ip);
    if (!n) {
      if (nodes.size >= 40) { // evict the stalest host so the map stays readable
        const old = [...nodes.values()].sort((a, b) => a.last - b.last)[0]; nodes.delete(old.ip);
      }
      n = { ip, flows: 0, alerts: 0, last: 0, pulse: 0, internal: isInternal(ip) };
      nodes.set(ip, n); layout();
    }
    return n;
  }
  function add(flow, kind, delay) {
    const a = node(flow.src), b = node(flow.dst);
    if (!a || !b || a === b) return;
    const now = performance.now();
    a.flows++; b.flows++; a.last = b.last = now;
    if (kind !== "benign") { a.alerts += kind === "attack" ? 1 : 0; }
    if (particles.length > 500) particles.splice(0, particles.length - 500);
    particles.push({ a, b, t0: now + delay, dur: kind === "benign" ? 1100 : 1500, kind });
  }
  let prev = performance.now();
  function frame(now) {
    const p = palette(), k = 1 - Math.pow(0.92, Math.min(60, (now - prev) / 16.7)); // time-based easing
    prev = now;
    ctx.clearRect(0, 0, W, H);
    const col = { benign: p.benign, attack: p.attack, missed: p.missed };
    // edges glow for recent attacks
    for (const n of nodes.values()) { n.x += (n.tx - n.x) * k; n.y += (n.ty - n.y) * k; }
    // particles
    for (let i = particles.length - 1; i >= 0; i--) {
      const q = particles[i], t = (now - q.t0) / q.dur;
      if (t < 0) continue;
      if (t > 1) { if (q.kind !== "benign") q.b.pulse = 1; particles.splice(i, 1); continue; }
      const { a, b } = q, mx = (a.x + b.x) / 2 + (b.y - a.y) * 0.15, my = (a.y + b.y) / 2 - (b.x - a.x) * 0.15;
      const e = t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
      const x = (1 - e) ** 2 * a.x + 2 * (1 - e) * e * mx + e * e * b.x, y = (1 - e) ** 2 * a.y + 2 * (1 - e) * e * my + e * e * b.y;
      if (q.kind !== "benign") {
        ctx.strokeStyle = col[q.kind]; ctx.globalAlpha = 0.18 * (1 - t); ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.quadraticCurveTo(mx, my, b.x, b.y); ctx.stroke();
      }
      ctx.globalAlpha = q.kind === "benign" ? 0.55 : 1;
      ctx.fillStyle = col[q.kind];
      ctx.shadowColor = col[q.kind]; ctx.shadowBlur = q.kind === "benign" ? 0 : 12;
      ctx.beginPath(); ctx.arc(x, y, q.kind === "benign" ? 1.8 : 3.4, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
    }
    ctx.globalAlpha = 1;
    // nodes
    ctx.font = "10.5px ui-monospace, Consolas, monospace"; ctx.textAlign = "center";
    for (const n of nodes.values()) {
      const r = 4 + Math.min(9, Math.log2(1 + n.flows));
      if (n.pulse > 0) {
        ctx.strokeStyle = p.attack; ctx.globalAlpha = n.pulse; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(n.x, n.y, r + (1 - n.pulse) * 22, 0, Math.PI * 2); ctx.stroke();
        n.pulse = Math.max(0, n.pulse - 0.025); ctx.globalAlpha = 1;
      }
      ctx.fillStyle = n.alerts ? p.attack : (n.internal ? p.accent : p.muted);
      ctx.globalAlpha = n === hover ? 1 : 0.9;
      ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1;
      if (n.alerts || n === hover || (n.internal && nodes.size <= 14)) { ctx.fillStyle = n.alerts ? p.text : p.muted; ctx.fillText(n.ip, n.x, n.y + r + 12); }
    }
    if (!nodes.size) { ctx.fillStyle = p.muted; ctx.font = "13px system-ui"; ctx.fillText("Start replay", W / 2, H / 2); }
    requestAnimationFrame(frame);
  }
  cv.addEventListener("mousemove", ev => {
    const r = cv.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
    hover = [...nodes.values()].find(n => Math.hypot(n.x - x, n.y - y) < 12) || null;
    if (hover) {
      tip.style.opacity = 1; tip.style.left = (x + 14) + "px"; tip.style.top = (y + 8) + "px";
      tip.innerHTML = `${esc(hover.ip)}<br>${hover.internal ? "internal" : "external"} · ${fmt(hover.flows)} flows · ${fmt(hover.alerts)} alerts`;
    } else tip.style.opacity = 0;
  });
  cv.addEventListener("mouseleave", () => { hover = null; tip.style.opacity = 0; });
  resize(); requestAnimationFrame(frame);
  new ResizeObserver(() => resize()).observe(cv);
  return { add, resize, clear() { nodes.clear(); particles.length = 0; } };
})();

/* ---------------- live replay ---------------- */
function isFlagged(f) { return f.predicted !== BENIGN || f.outlier; }
function isAttack(f) { return f.truth != null && f.truth !== BENIGN; }

async function tick() {
  if (S.busy) return;
  S.busy = true;
  try {
    const res = await api(`replay?cursor=${S.cursor}&n=${S.n}`);
    S.cursor = res.cursor;
    if (res.wrapped) toast("Replay restarted from the first flow");
    ingest(res.flows, res.alerts);
  } catch (e) {
    toast("Replay paused: " + e.message); stop();
  } finally { S.busy = false; }
}

function ingest(flows, alerts) {
  const now = performance.now();
  let flagged = 0, benign = 0;
  flows.forEach((f, i) => {
    const fl = isFlagged(f), at = isAttack(f);
    if (fl) flagged++; else benign++;
    if (f.truth != null) { if (fl && at) S.tp++; else if (fl) S.fp++; else if (at) S.fn++; else S.tn++; }
    map.add(f, fl ? "attack" : (at ? "missed" : "benign"), (i / flows.length) * 950);
    if (f.predicted !== BENIGN) S.classCounts[f.predicted] = (S.classCounts[f.predicted] || 0) + 1;
  });
  S.flows += flows.length;
  S.flowTimes.push([now, flows.length]);
  S.flowTimes = S.flowTimes.filter(([t]) => now - t < 5000);
  const last = flows[flows.length - 1];
  if (last && last.time) $("#clock").textContent = last.time.replace("T", " ").slice(0, 19);
  S.timeline.push({ t: fmt(S.flows), benign, flagged });
  if (S.timeline.length > 60) S.timeline.shift();
  // Show only the most important new alerts per batch; the rest are counted and grouped in Incidents.
  alerts.forEach(a => addAlert(a, false, "live"));
  const top = [...alerts].sort((x, y) => SEV_RANK[y.severity] - SEV_RANK[x.severity] || y.confidence - x.confidence).slice(0, 4);
  top.reverse().forEach((a, i) => setTimeout(() => showCard(a), i * 180));
  if (alerts.length > top.length) setTimeout(() => showMore(alerts.length - top.length), top.length * 180);
  updateKpis(alerts.length > 0);
  drawTimeline(); drawClasses(); drawMatrix();
  if ($("#view-incidents").classList.contains("active")) renderIncidents();
  if ($("#view-attack").classList.contains("active")) renderAttack();
}

function updateKpis(flash) {
  const rate = S.flowTimes.reduce((s, [, n]) => s + n, 0) / 5;
  $("#k-flows").textContent = fmt(S.flows);
  $("#k-rate").textContent = `${fmt(Math.round(rate))} / s`;
  $("#k-alerts").textContent = fmt(S.alerts.length);
  const open = S.alerts.filter(a => statusOf(a) === "open").length;
  $("#k-open").textContent = `${fmt(open)} open`;
  const recall = S.tp + S.fn ? S.tp / (S.tp + S.fn) : null, prec = S.tp + S.fp ? S.tp / (S.tp + S.fp) : null;
  $("#k-recall").textContent = pct(recall);
  $("#k-recall-sub").textContent = S.tp + S.fn ? `${fmt(S.tp)} / ${fmt(S.tp + S.fn)} attacks` : "—";
  $("#k-missed").textContent = fmt(S.fn);
  $("#k-missed-sub").textContent = S.tp + S.fn ? `${pct(S.fn / (S.tp + S.fn))} of attacks` : "—";
  $("#k-precision").textContent = pct(prec);
  $("#k-fp").textContent = `${fmt(S.fp)} false alarm${S.fp === 1 ? "" : "s"}`;
  if (flash) { const k = $("#k-alerts").closest(".kpi"); k.classList.remove("flash"); void k.offsetWidth; k.classList.add("flash"); }
}

function start() {
  S.running = true;
  const b = $("#play"); b.classList.add("running"); $(".ico", b).textContent = "❚❚"; $(".lbl", b).textContent = "Pause";
  tick(); S.timer = setInterval(tick, 1000);
}
function stop() {
  S.running = false; clearInterval(S.timer);
  const b = $("#play"); b.classList.remove("running"); $(".ico", b).textContent = "▶"; $(".lbl", b).textContent = "Resume replay";
}
$("#play").onclick = () => (S.running ? stop() : start());
$("#reset").onclick = () => {
  stop(); Object.assign(S, { cursor: 0, flows: 0, tp: 0, fp: 0, fn: 0, tn: 0, classCounts: {}, timeline: [], flowTimes: [] });
  S.alerts = S.alerts.filter(a => a.origin !== "live");
  map.clear(); $("#queue").innerHTML = '<div class="empty">Start replay</div>';
  $(".lbl", $("#play")).textContent = "Start replay"; $("#clock").textContent = "—";
  updateKpis(false); drawTimeline(); drawClasses(); drawMatrix();
};
$$("#speed button").forEach(b => (b.onclick = () => {
  $$("#speed button").forEach(x => x.classList.toggle("active", x === b)); S.n = +b.dataset.n;
}));

/* ---------------- alert queue ---------------- */
function statusOf(a) { return S.triage[a.alert_id] || a.status || "open"; }
function verdictTag(a) {
  if (!a.verdict) return "";
  const cls = a.verdict === "correct" ? "correct" : a.verdict === "false positive" ? "fp" : "other";
  const txt = a.verdict === "correct" ? "✓ match" : a.verdict === "false positive" ? "✗ false alarm" : "≈ other class";
  return `<span class="tag ${cls}" title="Dataset label: ${esc(a.truth)}">${txt}</span>`;
}
function alertCard(a) {
  const el = document.createElement("div");
  el.className = "alert-card" + (statusOf(a) !== "open" ? " triaged" : "");
  el.dataset.id = a.alert_id;
  const tech = a.attack.technique_id || (a.outlier ? "outlier" : "unmapped");
  el.innerHTML = `<div class="sev sev-${esc(a.severity)}"></div>
    <div><div class="title">${esc(a.display || a.predicted_class)}</div>
      <div class="meta">${esc(a.source)} → ${esc(a.dst || "?")}${a.dport != null ? ":" + esc(a.dport) : ""}</div></div>
    <div class="right"><span class="tag tech">${esc(tech)}</span>${verdictTag(a)}</div>`;
  el.onclick = () => openDrawer(a);
  el.tabIndex = 0; el.setAttribute("role", "button");
  el.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(a); } };
  return el;
}
function addAlert(a, show, origin = "upload") {
  a.origin = origin;
  a.display = a.summary.replace(/^Possible /, "").split(/[(,]/)[0].trim();
  S.alerts.push(a);
  if (S.alerts.length > 20000) S.alerts.splice(0, 5000);
  if (show) showCard(a);
}
function showCard(a) {
  const q = $("#queue"); $(".empty", q)?.remove();
  if (!passesFilter(a)) return;
  q.prepend(alertCard(a));
  while (q.children.length > 80) q.lastChild.remove();
}
function showMore(n) {
  const q = $("#queue"), el = document.createElement("div");
  el.className = "more-chip"; el.textContent = `+${fmt(n)} grouped`; el.title = "Open Incidents";
  el.onclick = () => showView("incidents");
  q.prepend(el);
}
function passesFilter(a) {
  const f = $("#queue-filter").value;
  return f === "all" || (f === "open" ? statusOf(a) === "open" : a.severity === f);
}
$("#queue-filter").onchange = () => {
  const q = $("#queue"); q.innerHTML = "";
  // filtered view lists matching alerts directly (newest first)
  S.alerts.filter(a => a.origin === "live" && passesFilter(a)).slice(-120).reverse().forEach(a => q.appendChild(alertCard(a)));
  if (!q.children.length) q.innerHTML = '<div class="empty">No matching alerts</div>';
};

/* ---------------- live charts ---------------- */
function drawTimeline() {
  const p = palette();
  chart("c-timeline").setOption({ ...base(), animation: false, grid: { left: 8, right: 16, top: 34, bottom: 8, containLabel: true },
    legend: { data: ["benign", "flagged"], textStyle: { color: p.muted }, right: 0, top: 0 },
    xAxis: axis({ type: "category", data: S.timeline.map(d => d.t), boundaryGap: false, splitLine: { show: false }, name: "flows replayed", nameLocation: "middle", nameGap: 28, nameTextStyle: { color: palette().muted } }),
    yAxis: axis({ type: "value", name: "flows / batch", nameTextStyle: { color: p.muted } }),
    series: [
      { name: "benign", type: "line", stack: "a", smooth: true, symbol: "none", areaStyle: { opacity: .25 }, color: p.benign, data: S.timeline.map(d => d.benign) },
      { name: "flagged", type: "line", stack: "a", smooth: true, symbol: "none", areaStyle: { opacity: .45 }, color: p.attack, data: S.timeline.map(d => d.flagged) },
    ] }, true);
}
function drawClasses() {
  const p = palette(), data = Object.entries(S.classCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  chart("c-classes").setOption({ ...base(), grid: { left: 8, right: 52, top: 8, bottom: 8, containLabel: true },
    xAxis: axis({ type: "value", show: false }),
    yAxis: axis({ type: "category", inverse: true, data: data.map(d => d[0]), axisLabel: { color: p.text, interval: 0 }, axisTick: { show: false } }),
    series: [{ type: "bar", barWidth: "55%", barMaxWidth: 22, data: data.map(d => d[1]),
      itemStyle: { borderRadius: 4, color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: p.attack }, { offset: 1, color: p.high }]) },
      label: { show: true, position: "right", color: p.muted, formatter: d => fmt(d.value) } }],
    graphic: data.length ? [] : [{ type: "text", left: "center", top: "middle", style: { text: "No attacks yet", fill: p.muted, fontSize: 13 } }] }, true);
}
function drawMatrix() {
  const has = S.tp + S.fp + S.fn + S.tn > 0;
  const d = 2 * S.tp + S.fp + S.fn, f1 = d ? (2 * S.tp) / d : null, fpr = S.fp + S.tn ? S.fp / (S.fp + S.tn) : null;
  $("#mini-matrix").innerHTML = `<span></span><span class="h">Flagged</span><span class="h">Not flagged</span>
    <span class="rh">Attack</span><div class="cell tp"><b>${fmt(S.tp)}</b>caught</div><div class="cell fn"><b>${fmt(S.fn)}</b>missed</div>
    <span class="rh">Benign</span><div class="cell fp"><b>${fmt(S.fp)}</b>false alarm</div><div class="cell tn"><b>${fmt(S.tn)}</b>quiet</div>
    <div class="foot"><span>F1 <b>${has ? pct(f1) : "—"}</b></span><span>False alarms <b>${has ? pct(fpr, 2) : "—"}</b></span></div>`;
}
Object.assign(redrawers, { drawTimeline, drawClasses });

/* ---------------- investigation drawer ---------------- */
function openDrawer(a) {
  const med = (S.card && S.card.benign_median) || {};
  const att = a.attack, status = statusOf(a);
  const steps = (att.guidance || "").split(/;\s*/).filter(Boolean);
  const vb = a.verdict ? `<div class="verdict-banner ${a.verdict === "correct" ? "correct" : a.verdict === "false positive" ? "fp" : "other"}">
      <b>${a.verdict === "correct" ? "Dataset match" : a.verdict === "false positive" ? "False alarm" : "Other attack class"}</b> · label <code>${esc(a.truth)}</code></div>` : "";
  $("#drawer-body").innerHTML = `
    <span class="tag sev-${esc(a.severity)}">${esc(a.severity)}</span>
    <h2>${esc(a.display || a.predicted_class)}</h2>
    <section>${vb}</section>
    <section><h4>Flow</h4><div class="facts">
      <div><span>Source</span><b>${esc(a.source)}</b></div><div><span>Destination</span><b>${esc(a.dst || "—")}${a.dport != null ? ":" + esc(a.dport) : ""}</b></div>
      <div><span>Captured</span><b>${esc(String(a.time).replace("T", " ").slice(0, 19))}</b></div>
      <div><span>Model class</span><b>${esc(a.predicted_class)}</b></div><div><span>Confidence</span><b>${pct(a.confidence)}</b></div>
      <div><span tabindex="0" data-tip="Isolation Forest trained on benign traffic only. Unusual does not prove an attack.">Unusual</span><b>${a.outlier ? "yes" : "no"}</b></div></div></section>
    <section><h4 tabindex="0" data-tip="SHAP: how much each feature pushed this flow towards (red) or away from (blue) the predicted class. Evidence about the model's decision, not proof of an attack.">Why this alert</h4>${a.explanation.length ? '<div id="c-shap"></div>' +
      `<table class="tbl"><tr><th>Feature</th><th>This flow</th><th>Benign median</th></tr>${a.explanation.map(e =>
        `<tr><td>${esc(e.feature)}</td><td class="mono">${fmt(+e.value.toPrecision(4))}</td><td class="mono">${med[e.feature] != null ? fmt(+Number(med[e.feature]).toPrecision(4)) : "—"}</td></tr>`).join("")}</table>`
      : '<p class="hint">Anomaly only · needs a human look</p>'}</section>
    <section><h4 tabindex="0" data-tip="Flow features show network symptoms, not intent, so this mapping is a starting point for the analyst.">Candidate technique</h4>
      <div class="technique hot" style="--heat:12">${att.url ? `<a href="${esc(att.url)}" target="_blank" rel="noopener">` : ""}
        <div class="id">${esc(att.technique_id || "unmapped")} · ${esc(att.tactic)}</div><div class="name">${esc(att.technique)}</div>${att.url ? "</a>" : ""}</div></section>
    <section><h4>Response</h4><ol class="steps">${steps.map(s => `<li>${esc(s.charAt(0).toUpperCase() + s.slice(1).replace(/\.$/, ""))}</li>`).join("")}</ol></section>
    <section><h4>Triage</h4><div class="triage">
      <button class="btn good" data-s="confirmed">✓ Confirm</button>
      <button class="btn bad" data-s="dismissed">✗ Dismiss</button>
      <button class="btn ghost" data-s="open">Reopen</button>
      <span class="hint">Status <b id="cur-status">${esc(status)}</b></span></div></section>`;
  $$("#drawer-body .triage button").forEach(b => (b.onclick = () => {
    S.triage[a.alert_id] = b.dataset.s; store.set("triage", S.triage);
    $("#cur-status").textContent = b.dataset.s;
    $$(`.alert-card[data-id="${a.alert_id}"]`).forEach(c => c.classList.toggle("triaged", b.dataset.s !== "open"));
    updateKpis(false);
  }));
  if (!$("#drawer").classList.contains("open")) drawerReturn = document.activeElement;
  const dr = $("#drawer"); dr.inert = false; dr.classList.add("open"); dr.setAttribute("aria-hidden", "false");
  $("#scrim").classList.add("open"); $$("header, main").forEach(el => (el.inert = true));
  $("#drawer-close").focus({ preventScroll: true });
  if (a.explanation.length) requestAnimationFrame(() => drawShap(a));
}
function drawShap(a) {
  const p = palette(), ex = [...a.explanation].reverse();
  if (charts["c-shap"]) { charts["c-shap"].dispose(); delete charts["c-shap"]; }
  chart("c-shap").setOption({ ...base(), grid: { left: 8, right: 64, top: 10, bottom: 30, containLabel: true },
    xAxis: axis({ type: "value", name: "SHAP contribution", nameLocation: "middle", nameGap: 26, nameTextStyle: { color: p.muted } }),
    yAxis: axis({ type: "category", data: ex.map(e => e.feature), axisLabel: { color: p.text, width: 170, overflow: "truncate" } }),
    series: [{ type: "bar", barWidth: "58%", animationDelay: i => i * 90,
      data: ex.map(e => ({ value: +e.contribution.toFixed(4), itemStyle: { color: e.contribution > 0 ? p.attack : p.accent, borderRadius: 4 } })),
      label: { show: true, position: "right", color: p.muted, formatter: d => (d.value > 0 ? "+" : "") + d.value.toFixed(2) } }],
    tooltip: { ...base().tooltip, formatter: d => `${esc(d.name)}<br>${d.value > 0 ? "pushes towards" : "pushes away from"} ${esc(a.predicted_class)}` } });
}
let drawerReturn = null;
function closeDrawer() {
  const dr = $("#drawer"); if (!dr.classList.contains("open")) return;
  dr.classList.remove("open"); dr.setAttribute("aria-hidden", "true"); dr.inert = true;
  $("#scrim").classList.remove("open"); $$("header, main").forEach(el => (el.inert = false));
  (drawerReturn?.isConnected ? drawerReturn : $("#play")).focus({ preventScroll: true });
}
$("#drawer-close").onclick = closeDrawer; $("#scrim").onclick = closeDrawer;
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

/* ---------------- incidents ---------------- */
function incidents() {
  const groups = new Map();
  for (const a of S.alerts) {
    // bucket on the capture's own clock (no timezone conversion): "2017-07-07 13:07:42" -> "2017-07-07 13:00"
    const ts = String(a.time).replace("T", " ");
    const win = /^\d{4}-\d\d-\d\d \d\d:\d/.test(ts) ? ts.slice(0, 15) + "0" : "unknown";
    const tech = a.attack.technique_id || (a.outlier ? "outlier" : "unmapped");
    const key = `${a.source}|${tech}|${win}`;
    const g = groups.get(key) || { source: a.source, tech, technique: a.attack.technique, win, count: 0, sev: "Info", classes: new Set(), alerts: [], targets: new Set() };
    g.count++; g.classes.add(a.predicted_class); g.alerts.push(a); if (a.dst) g.targets.add(a.dst);
    if (SEV_RANK[a.severity] > SEV_RANK[g.sev]) g.sev = a.severity;
    groups.set(key, g);
  }
  return [...groups.values()].sort((x, y) => SEV_RANK[y.sev] - SEV_RANK[x.sev] || y.count - x.count);
}
function renderIncidents() {
  const inc = incidents(), p = palette(), sc = SEV_COLOR();
  $("#inc-count").textContent = `${fmt(inc.length)} groups · ${fmt(S.alerts.length)} alerts`;
  const techs = [...new Set(inc.map(g => g.tech))];
  chart("c-incidents").setOption({ ...base(), grid: { left: 8, right: 20, top: 20, bottom: 10, containLabel: true },
    xAxis: axis({ type: "category", data: [...new Set(inc.map(g => g.win))].sort(), axisLabel: { color: p.muted, formatter: v => v.slice(5) } }),
    yAxis: axis({ type: "category", data: techs, axisLabel: { color: p.muted, formatter: t => {
      const g = inc.find(x => x.tech === t); return t.startsWith("T") && g ? `${t} ${g.technique}` : t; } } }),
    tooltip: { ...base().tooltip, formatter: d => `${esc(d.data.g.technique)}<br>${esc(d.data.g.source)} · ${d.data.g.count} alerts<br>${esc(d.data.g.win)}` },
    series: [{ type: "scatter", data: inc.map(g => ({ value: [g.win, g.tech], g, symbolSize: Math.min(44, 10 + Math.sqrt(g.count) * 3),
      itemStyle: { color: sc[g.sev], opacity: .85 } })) }],
    graphic: inc.length ? [] : [{ type: "text", left: "center", top: "middle", style: { text: "No incidents yet", fill: p.muted, fontSize: 13 } }] }, true);
  const list = $("#incident-list");
  list.innerHTML = inc.length ? "" : '<div class="empty">No incidents yet</div>';
  inc.slice(0, 60).forEach(g => {
    const el = document.createElement("div"); el.className = "incident";
    el.innerHTML = `<div class="top"><span class="tag sev-${esc(g.sev)}">${esc(g.sev)}</span><span class="count">${g.count}</span></div>
      <b>${esc(g.technique)}</b><span class="src">${esc(g.source)} → ${[...g.targets].slice(0, 3).map(esc).join(", ") || "?"}</span>
      <small title="${esc([...g.classes].join(", "))}">${esc(g.win)}</small>
      <button class="btn small">Investigate</button>`;
    $("button", el).onclick = () => openDrawer(g.alerts[0]);
    list.appendChild(el);
  });
}
redrawers.renderIncidents = () => $("#view-incidents").classList.contains("active") && renderIncidents();

/* ---------------- ATT&CK matrix ---------------- */
const TACTICS = [
  ["Discovery", [["T1046", "Network Service Discovery"]]],
  ["Credential Access", [["T1110", "Brute Force"]]],
  ["Initial Access", [["T1190", "Exploit Public-Facing Application"]]],
  ["Command and Control", [["T1071", "Application Layer Protocol"]]],
  ["Impact", [["T1499", "Endpoint Denial of Service"], ["T1498", "Network Denial of Service"]]],
  ["Needs analyst", [["unmapped", "No candidate technique"], ["outlier", "Statistical outlier"]]],
];
function renderAttack() {
  const counts = {}, classes = {};
  for (const a of S.alerts) {
    const k = a.attack.technique_id || (a.outlier ? "outlier" : "unmapped");
    counts[k] = (counts[k] || 0) + 1; (classes[k] = classes[k] || new Set()).add(a.predicted_class);
  }
  const max = Math.max(1, ...Object.values(counts));
  $("#attack-matrix").innerHTML = TACTICS.map(([tactic, techs]) => `<div class="tactic"><h4>${tactic}</h4>${techs.map(([id, name]) => {
    const n = counts[id] || 0, url = id.startsWith("T") ? `https://attack.mitre.org/techniques/${id}/` : null;
    return `<div class="technique ${n ? "hot" : ""}" style="--heat:${Math.round(8 + 30 * n / max)}">${url ? `<a href="${url}" target="_blank" rel="noopener">` : ""}
      <div class="id">${id}</div><div class="name">${name}</div>${url ? "</a>" : ""}<span class="n">${fmt(n)}</span>
      ${n ? `<div class="classes">${[...classes[id]].map(esc).join(", ")}</div>` : ""}</div>`; }).join("")}</div>`).join("");
  drawSankey();
}
function drawSankey() {
  const p = palette(), links = new Map(), add = (a, b) => links.set(a + "|" + b, (links.get(a + "|" + b) || 0) + 1);
  for (const a of S.alerts) {
    const tech = a.attack.technique_id ? `${a.attack.technique_id} ${a.attack.technique}` : (a.outlier ? "Statistical outlier" : "Unmapped");
    const tactic = a.attack.tactic && a.attack.tactic !== "-" ? a.attack.tactic : "Needs analyst";
    add(a.predicted_class === BENIGN ? "Unusual (no class)" : a.predicted_class, tech); add(tech, "▸ " + tactic);
  }
  const names = new Set();
  const data = [...links].map(([k, value]) => { const [source, target] = k.split("|"); names.add(source); names.add(target); return { source, target, value }; });
  const colors = [p.attack, p.high, p.medium, p.accent2, p.accent, p.missed, "#f472b6", "#2dd4bf", "#a3e635", "#60a5fa"];
  chart("c-sankey").setOption({ ...base(), tooltip: { ...base().tooltip, trigger: "item" },
    series: [{ type: "sankey", left: 8, right: 150, top: 10, bottom: 10, nodeGap: 10, nodeWidth: 14, draggable: true,
      emphasis: { focus: "adjacency" }, lineStyle: { color: "gradient", opacity: 0.35, curveness: 0.5 },
      label: { color: p.text, fontSize: 12 },
      data: [...names].map((name, i) => ({ name, itemStyle: { color: colors[i % colors.length], borderWidth: 0 } })),
      links: data }] }, true);
  if (!data.length) chart("c-sankey").setOption({ title: { text: "No alerts yet", left: "center", top: "middle", textStyle: { color: p.muted, fontSize: 13, fontWeight: 400 } } });
}

/* ---------------- model lab ---------------- */
function renderLab() {
  const c = S.card; if (!c) return;
  const p = palette(), models = c.models || {}, names = Object.keys(models), sel = c.selected_model;
  const m = models[sel];
  const scope = m ? `${c.dataset} · ${fmt(c.split.train)} training flows (max ${fmt(c.split.train_cap_per_class)} per class) · ${fmt(c.split.test)} test flows · ${c.split.method}. Chosen on validation macro F1. Accuracy is not shown: benign traffic dominates.` : "";
  $("#lab-intro").innerHTML = m ? `
    <div class="stat"><span tabindex="0" data-tip="${esc(scope)}">Model</span><strong>${esc(sel.toUpperCase())}</strong></div>
    <div class="stat"><span tabindex="0" data-tip="F1 per class, averaged with every class weighted equally, so rare attacks count as much as common ones.">Macro F1</span><strong>${pct(m.macro.f1)}</strong></div>
    <div class="stat"><span tabindex="0" data-tip="Benign test flows wrongly flagged as an attack.">False alarms</span><strong>${pct(m.benign_fpr, 2)}</strong></div>
    <div class="stat"><span tabindex="0" data-tip="Classifier prediction time per flow on a 5,000-flow batch; excludes SHAP and network time.">Classifier time</span><strong>${m.latency_ms.toFixed(3)} ms</strong></div>`
    : `<div class="stat"><span>Model</span><strong>Synthetic demo</strong></div>`;
  if (!m) return;
  const metrics = [["Macro F1", x => x.macro.f1], ["Macro precision", x => x.macro.precision], ["Macro recall", x => x.macro.recall], ["Attack PR-AUC", x => x.pr_auc]];
  chart("c-compare").setOption({ ...base(), legend: { textStyle: { color: p.muted }, top: 0 }, tooltip: { ...base().tooltip, trigger: "axis", valueFormatter: v => v.toFixed(3) },
    grid: { left: 8, right: 16, top: 34, bottom: 8, containLabel: true },
    xAxis: axis({ type: "category", data: metrics.map(x => x[0]) }), yAxis: axis({ type: "value", min: 0, max: 1, axisLabel: { color: p.muted, formatter: v => pct(v, 0) } }),
    color: [p.accent, p.accent2, p.high],
    series: names.map(n => ({ name: n.toUpperCase() + (n === sel ? " ★" : ""), type: "bar", barGap: "10%", itemStyle: { borderRadius: [4, 4, 0, 0] },
      data: metrics.map(([, f]) => +f(models[n]).toFixed(4)) })) }, true);
  const imp = [...(c.global_importance || [])].reverse();
  chart("c-importance").setOption({ ...base(), xAxis: axis({ type: "value" }),
    yAxis: axis({ type: "category", data: imp.map(x => x.feature), axisLabel: { color: p.text, width: 160, overflow: "truncate", interval: 0, fontSize: 11 } }),
    series: [{ type: "bar", data: imp.map(x => +x.importance.toFixed(4)), animationDelay: i => i * 40,
      itemStyle: { borderRadius: 4, color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: p.accent2 }, { offset: 1, color: p.accent }]) } }] }, true);
  const pc = m.per_class.filter(r => r.support > 0);
  chart("c-perclass").setOption({ ...base(), tooltip: { ...base().tooltip, trigger: "axis" }, legend: { textStyle: { color: p.muted }, top: 0 },
    grid: { left: 8, right: 16, top: 34, bottom: 8, containLabel: true },
    xAxis: axis({ type: "category", data: pc.map(r => r.class), axisLabel: { color: p.muted, rotate: 30, interval: 0 } }), yAxis: axis({ type: "value", min: 0, max: 1, axisLabel: { color: p.muted, formatter: v => pct(v, 0) } }),
    series: [["precision", p.accent2], ["recall", p.accent], ["f1", p.benign]].map(([k, col]) => ({ name: k, type: "bar", color: col,
      itemStyle: { borderRadius: [3, 3, 0, 0] }, data: pc.map(r => +r[k].toFixed(3)),
      label: k === "f1" ? { show: true, position: "top", color: p.muted, fontSize: 10, formatter: d => fmt(pc[d.dataIndex].support) } : undefined })) }, true);
  drawConfusion("c-confusion", c.classes, m.confusion);
}
function drawConfusion(id, labels, mat) {
  const p = palette(), data = [];
  mat.forEach((row, i) => row.forEach((v, j) => data.push([j, i, v])));
  const keep = labels.map((_, i) => mat[i].some(v => v) || mat.some(r => r[i]));
  const idx = labels.map((_, i) => i).filter(i => keep[i]);
  const remap = new Map(idx.map((v, k) => [v, k]));
  const d2 = data.filter(([j, i]) => remap.has(i) && remap.has(j)).map(([j, i, v]) => [remap.get(j), remap.get(i), v, v ? Math.log10(v + 1) : 0]);
  const ls = idx.map(i => labels[i]);
  chart(id).setOption({ ...base(), grid: { left: 8, right: 70, top: 10, bottom: 24, containLabel: true },
    tooltip: { ...base().tooltip, formatter: d => `true <b>${esc(ls[d.value[1]])}</b><br>predicted <b>${esc(ls[d.value[0]])}</b><br>${fmt(d.value[2])} flows` },
    xAxis: axis({ type: "category", data: ls, name: "Predicted", nameLocation: "middle", nameGap: 62, nameTextStyle: { color: p.muted }, axisLabel: { color: p.muted, rotate: 40, fontSize: 10, interval: 0 }, splitArea: { show: false } }),
    yAxis: axis({ type: "category", data: ls, inverse: true, name: "Actual", nameTextStyle: { color: p.muted }, axisLabel: { color: p.muted, fontSize: 10, interval: 0 } }),
    visualMap: { min: 0, max: Math.max(1, ...d2.map(d => d[3])), dimension: 3, calculable: false, orient: "vertical", right: 0, top: "middle",
      inRange: { color: [css("--panel2"), p.accent2, p.accent] }, textStyle: { color: p.muted }, formatter: v => fmt(Math.round(10 ** v - 1)) },
    series: [{ type: "heatmap", data: d2, label: { show: ls.length <= 16, color: p.text, fontSize: 10, textBorderColor: css("--panel"), textBorderWidth: 2,
        formatter: d => (d.value[2] ? fmt(d.value[2]) : "") },
      itemStyle: { borderColor: css("--panel"), borderWidth: 1 } }] }, true);
}
redrawers.renderLab = () => $("#view-lab").classList.contains("active") && renderLab();

/* ---------------- upload ---------------- */
const dz = $("#dropzone"), fileInput = $("#file");
["dragenter", "dragover"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add("over"); }));
["dragleave", "drop"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.remove("over"); }));
dz.addEventListener("drop", ev => ev.dataTransfer.files[0] && upload(ev.dataTransfer.files[0]));
fileInput.onchange = () => fileInput.files[0] && upload(fileInput.files[0]);
dz.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } };
if (STATIC) {  // the static build has no API to score files: link to the live app instead of a dead dropzone
  const live = /^https?:\/\//.test(STATIC.fullApp || "") ? STATIC.fullApp : null;
  dz.replaceWith(Object.assign(document.createElement("p"), { className: "dropzone",
    innerHTML: live ? `<a href="${esc(live)}" target="_blank" rel="noopener">Open the live app to analyse a file</a>` : "File analysis needs the API" }));
}

async function upload(file) {
  const st = $("#upload-status"), out = $("#upload-results");
  st.innerHTML = `<p>Scoring <b>${esc(file.name)}</b>…</p><div class="progress"><i></i></div>`;
  out.innerHTML = "";
  const fd = new FormData(); fd.append("file", file);
  const t0 = performance.now();
  try {
    const r = await api("score-csv", { method: "POST", body: fd });
    st.innerHTML = `<p>✓ <b>${fmt(r.rows)}</b> flows · ${((performance.now() - t0) / 1000).toFixed(1)} s${r.dropped_invalid_rows ? ` · ${fmt(r.dropped_invalid_rows)} invalid rows skipped` : ""}</p>`;
    r.top_alerts.forEach(a => addAlert(a, false, "upload"));
    renderUpload(r);
  } catch (e) { st.innerHTML = `<p style="color:var(--attack)">✗ ${esc(e.message)}</p>`; }
}
function renderUpload(r) {
  const out = $("#upload-results"), ev = r.evaluation;
  ["u-classes", "u-confusion"].forEach(id => { charts[id]?.dispose(); delete charts[id]; });
  out.innerHTML = `<div class="kpis" style="margin-bottom:14px">
      <div class="kpi card"><span>Flows</span><strong>${fmt(r.rows)}</strong></div>
      <div class="kpi card"><span>Alerts</span><strong>${fmt(r.alerts)}</strong><small>${pct(r.alerts / r.rows)} of flows</small></div>
      <div class="kpi card"><span>Incidents</span><strong>${fmt(r.incidents.length)}</strong></div>
      <div class="kpi card good"><span>Macro F1</span><strong>${ev ? pct(ev.macro.f1) : "—"}</strong><small>${ev ? `P ${pct(ev.macro.precision)} · R ${pct(ev.macro.recall)}` : "unlabelled"}</small></div>
      <div class="kpi card"><span>False alarms</span><strong>${ev ? pct(ev.benign_fpr, 2) : "—"}</strong></div></div>
    <div class="result-grid">
      <div class="card"><div class="card-head"><h3>${ev ? "Per-class scores" : "Predicted classes"}</h3></div><div id="u-classes" class="chart"></div></div>
      <div class="card"><div class="card-head"><h3 tabindex="0" data-tip="The most severe alerts of each class first. Select a row to investigate.">Alerts by class</h3></div>
        <div class="scroll"><table class="tbl"><tr><th>Severity</th><th>Class</th><th>Source</th><th>Conf.</th><th>Label</th></tr>
        ${r.top_alerts.slice(0, 150).map((a, i) => `<tr class="click" data-i="${i}" tabindex="0"><td><span class="tag sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
          <td>${a.predicted_class === BENIGN ? "Unusual (outlier)" : esc(a.predicted_class)}</td><td class="mono">${esc(a.source)}</td><td>${pct(a.confidence, 0)}</td><td>${a.truth ? verdictTag(a) : "—"}</td></tr>`).join("")}</table></div></div>
      ${ev ? `<div class="card wide"><div class="card-head"><h3>Confusion matrix</h3></div><div id="u-confusion" class="chart tall"></div></div>` : ""}
    </div>`;
  $$("#upload-results tr.click").forEach(tr => {
    tr.onclick = () => openDrawer(r.top_alerts[+tr.dataset.i]);
    tr.onkeydown = e => { if (e.key === "Enter") tr.onclick(); };
  });
  const p = palette();
  if (ev) {
    const pc = ev.per_class.filter(x => x.support > 0);
    chart("u-classes").setOption({ ...base(), legend: { textStyle: { color: p.muted }, top: 0 }, tooltip: { ...base().tooltip, trigger: "axis" },
      grid: { left: 8, right: 16, top: 34, bottom: 8, containLabel: true },
      xAxis: axis({ type: "category", data: pc.map(x => x.class), axisLabel: { color: p.muted, rotate: 30, interval: 0 } }),
      yAxis: axis({ type: "value", min: 0, max: 1, axisLabel: { color: p.muted, formatter: v => pct(v, 0) } }),
      series: [["precision", p.accent2], ["recall", p.accent], ["f1", p.benign]].map(([k, col]) => ({ name: k, type: "bar", color: col,
        itemStyle: { borderRadius: [3, 3, 0, 0] }, data: pc.map(x => +x[k].toFixed(3)) })) });
    drawConfusion("u-confusion", ev.labels, ev.confusion);
  } else {
    const pc = Object.entries(r.predicted_counts).sort((a, b) => a[1] - b[1]);
    chart("u-classes").setOption({ ...base(), xAxis: axis({ type: "log", min: 1, name: "flows (log)", nameTextStyle: { color: p.muted } }),
      yAxis: axis({ type: "category", data: pc.map(x => x[0]), axisLabel: { color: p.muted, interval: 0, fontSize: 11 } }),
      series: [{ type: "bar", data: pc.map(([k, v]) => ({ value: v, itemStyle: { color: k === BENIGN ? p.benign : p.attack, borderRadius: 4 } })),
        label: { show: true, position: "right", color: p.muted, formatter: d => fmt(d.value) } }] });
  }
}

/* ---------------- research findings: one question, one number, one chart ---------------- */
let research = null;
const PENDING = { RQ1: "Does it work on a new network?", RQ2: "Do explanations stay the same?", RQ3: "Can it catch attacks it never saw?" };
async function renderResearch() {
  if (!research) {
    try { research = await (await fetch("data/research.json", { cache: "no-cache" })).json(); }
    catch { $("#findings").innerHTML = '<div class="card empty">Findings unavailable</div>'; return; }
  }
  const R = research, p = palette(), card = (id, rq, f) => f ? `<div class="card finding">
      <span class="rq">${rq}</span><span class="q" tabindex="0" data-tip="${esc(f.tip)}">${esc(f.question)}</span>
      <strong class="big">${esc(f.headline)}</strong><span class="what">${esc(f.label)}</span><div id="${id}" class="chart"></div></div>`
    : `<div class="card finding"><span class="rq">${rq}</span><span class="q">${PENDING[rq]}</span><strong class="big">—</strong><span class="what">experiment running</span></div>`;
  $("#findings").innerHTML = card("r-transfer", "RQ1", R.transfer) + card("r-stable", "RQ2", R.stability) + card("r-unseen", "RQ3", R.unseen);
  $("#sources").innerHTML = (R.sources || []).map(s => `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.label)}</a>`).join(" · ");
  ["r-transfer", "r-unseen", "r-stable"].forEach(id => { charts[id]?.dispose(); delete charts[id]; });
  const yPct = { type: "value", min: 0, max: 1, axisLabel: { color: p.muted, formatter: v => pct(v, 0) } };
  if (R.transfer) {
    const t = R.transfer;
    chart("r-transfer").setOption({ ...base(), legend: { top: 0, textStyle: { color: p.muted } },
      tooltip: { ...base().tooltip, trigger: "axis", valueFormatter: v => pct(v) }, grid: { left: 8, right: 8, top: 52, bottom: 8, containLabel: true },
      xAxis: axis({ type: "category", data: t.targets.map(x => "Test on " + x) }), yAxis: axis(yPct),
      series: [["Trained on the same network", p.benign, "same"], ["Trained on the other network", p.attack, "other"]].map(([name, color, k]) => ({
        name, type: "bar", color, barGap: "12%", itemStyle: { borderRadius: [4, 4, 0, 0] },
        label: { show: true, position: "top", color: p.text, formatter: d => pct(d.value, 0) }, data: t.targets.map((_, i) => t[k][i]) })) });
  }
  if (R.unseen) {
    const u = R.unseen.classes;
    chart("r-unseen").setOption({ ...base(), legend: { top: 0, textStyle: { color: p.muted } },
      tooltip: { ...base().tooltip, trigger: "axis", valueFormatter: v => pct(v) }, grid: { left: 8, right: 12, top: 34, bottom: 8, containLabel: true },
      xAxis: axis({ ...yPct, splitNumber: 2 }), yAxis: axis({ type: "category", inverse: true, data: u.map(x => x.class), axisLabel: { color: p.muted, fontSize: 10, interval: 0 } }),
      series: [["Any alert", p.accent, "either"], ["Classifier only", p.accent2, "classifier"]].map(([name, color, k]) => ({
        name, type: "bar", color, barGap: "-100%", barWidth: "62%", z: k === "either" ? 1 : 2, itemStyle: { borderRadius: 3, opacity: k === "either" ? 0.45 : 1 },
        data: u.map(x => x[k]) })) });
  }
  if (R.stability) {
    const s = R.stability.classes;
    chart("r-stable").setOption({ ...base(), tooltip: { ...base().tooltip, trigger: "axis", valueFormatter: v => v.toFixed(2) },
      grid: { left: 8, right: 34, top: 10, bottom: 8, containLabel: true },
      xAxis: axis({ type: "value", min: 0, max: 1, splitNumber: 2 }), yAxis: axis({ type: "category", inverse: true, data: s.map(x => x.class), axisLabel: { color: p.muted, fontSize: 10, interval: 0 } }),
      series: [{ type: "bar", barWidth: "55%", data: s.map(x => x.median), label: { show: true, position: "right", color: p.muted, fontSize: 10, formatter: d => d.value.toFixed(2) },
        itemStyle: { borderRadius: 3, color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: p.accent2 }, { offset: 1, color: p.accent }]) } }] });
  }
}
redrawers.renderResearch = () => $("#view-research").classList.contains("active") && research && renderResearch();

/* ---------------- boot ---------------- */
async function boot() {
  const pill = $("#model-pill");
  try {
    const [h, c] = await Promise.all([api("health"), api("model")]);
    S.health = h; S.card = c;
    const synthetic = !c.models || !Object.keys(c.models).length;
    pill.className = "pill ok";
    $("span", pill).textContent = synthetic ? "Synthetic model · replay only" : `${h.classifier.toUpperCase()} · model ready`;
    pill.title = `${h.classifier.toUpperCase()} trained on ${c.dataset}`;
    if (synthetic) { $("#replay-hint").textContent = "Synthetic demo flows"; $("#replay-hint").dataset.tip = "Generated flows from the demo model; not benchmark evidence."; }
    $("#play").disabled = false;
  } catch (e) {
    pill.className = "pill err"; $("span", pill).textContent = "Replay unavailable"; pill.title = e.message;
  }
  updateKpis(false); drawTimeline(); drawClasses(); drawMatrix();
  showView(store.get("view", "sensor"));
}
boot();
