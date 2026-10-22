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

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch { /* not JSON */ }
    throw new Error(`${r.status}: ${detail}`);
  }
  return r.json();
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
  classCounts: {}, timeline: [], threat: 0,
};

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
    if (!nodes.size) { ctx.fillStyle = p.muted; ctx.font = "13px system-ui"; ctx.fillText("Hosts appear here as traffic streams in", W / 2, H / 2); }
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
    if (res.wrapped) toast("Reached the end of the held-out test traffic; looping from the start.");
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
  const weight = alerts.reduce((s, a) => s + (SEV_RANK[a.severity] || 0), 0) / Math.max(flows.length, 1);
  S.threat = S.threat * 0.7 + Math.min(100, weight * 60) * 0.3;
  // Show only the most important new alerts per batch; the rest are counted and grouped in Incidents.
  alerts.forEach(a => addAlert(a, false, "live"));
  const top = [...alerts].sort((x, y) => SEV_RANK[y.severity] - SEV_RANK[x.severity] || y.confidence - x.confidence).slice(0, 4);
  top.reverse().forEach((a, i) => setTimeout(() => showCard(a), i * 180));
  if (alerts.length > top.length) setTimeout(() => showMore(alerts.length - top.length), top.length * 180);
  updateKpis(alerts.length > 0);
  drawTimeline(); drawClasses(); drawGauge(); drawMatrix();
}

function updateKpis(flash) {
  const rate = S.flowTimes.reduce((s, [, n]) => s + n, 0) / 5;
  $("#k-flows").textContent = fmt(S.flows);
  $("#k-rate").textContent = `${fmt(Math.round(rate))} flows/s`;
  $("#k-alerts").textContent = fmt(S.alerts.length);
  const open = S.alerts.filter(a => statusOf(a) === "open").length;
  $("#k-open").textContent = `${fmt(open)} awaiting triage`;
  const recall = S.tp + S.fn ? S.tp / (S.tp + S.fn) : null, prec = S.tp + S.fp ? S.tp / (S.tp + S.fp) : null;
  $("#k-recall").textContent = pct(recall);
  $("#k-recall-sub").textContent = `${fmt(S.tp)} of ${fmt(S.tp + S.fn)} attack flows`;
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
  stop(); Object.assign(S, { cursor: 0, flows: 0, tp: 0, fp: 0, fn: 0, tn: 0, classCounts: {}, timeline: [], threat: 0, flowTimes: [] });
  S.alerts = S.alerts.filter(a => a.origin !== "live");
  map.clear(); $("#queue").innerHTML = '<div class="empty">Press <b>Start replay</b> to stream traffic.</div>';
  $(".lbl", $("#play")).textContent = "Start replay"; $("#clock").textContent = "—";
  updateKpis(false); drawTimeline(); drawClasses(); drawGauge(); drawMatrix();
};
$$("#speed button").forEach(b => (b.onclick = () => {
  $$("#speed button").forEach(x => x.classList.toggle("active", x === b)); S.n = +b.dataset.n;
}));

/* ---------------- alert queue ---------------- */
function statusOf(a) { return S.triage[a.alert_id] || a.status || "open"; }
function verdictTag(a) {
  if (!a.verdict) return "";
  const cls = a.verdict === "correct" ? "correct" : a.verdict === "false positive" ? "fp" : "other";
  const txt = a.verdict === "correct" ? "✓ matches label" : a.verdict === "false positive" ? "✗ benign in dataset" : "≈ different attack";
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
  el.className = "more-chip"; el.textContent = `+${fmt(n)} related alerts grouped into incidents`;
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
  if (!q.children.length) q.innerHTML = '<div class="empty">No alerts match this filter.</div>';
};

/* ---------------- live charts ---------------- */
function drawTimeline() {
  const p = palette();
  chart("c-timeline").setOption({ ...base(), animation: false,
    legend: { data: ["benign", "flagged"], textStyle: { color: p.muted }, right: 0, top: 0 },
    xAxis: axis({ type: "category", data: S.timeline.map(d => d.t), boundaryGap: false, splitLine: { show: false }, name: "flows replayed", nameLocation: "middle", nameGap: 28, nameTextStyle: { color: palette().muted } }),
    yAxis: axis({ type: "value" }),
    series: [
      { name: "benign", type: "line", stack: "a", smooth: true, symbol: "none", areaStyle: { opacity: .25 }, color: p.benign, data: S.timeline.map(d => d.benign) },
      { name: "flagged", type: "line", stack: "a", smooth: true, symbol: "none", areaStyle: { opacity: .45 }, color: p.attack, data: S.timeline.map(d => d.flagged) },
    ] }, true);
}
function drawClasses() {
  const p = palette(), data = Object.entries(S.classCounts).sort((a, b) => b[1] - a[1]).map(([name, value]) => ({ name, value }));
  chart("c-classes").setOption({ ...base(), tooltip: { ...base().tooltip, trigger: "item" },
    color: [p.attack, p.high, p.medium, p.accent2, p.accent, p.missed, "#f472b6", "#2dd4bf", "#a3e635", "#60a5fa"],
    series: [{ type: "pie", radius: ["48%", "78%"], itemStyle: { borderColor: css("--panel"), borderWidth: 2, borderRadius: 5 },
      label: { color: p.muted, fontSize: 11 }, data: data.length ? data : [{ name: "no attacks yet", value: 1, itemStyle: { color: p.line } }] }] });
}
function drawGauge() {
  const p = palette(), v = Math.round(S.threat);
  chart("g-threat").setOption({ series: [{ type: "gauge", startAngle: 200, endAngle: -20, min: 0, max: 100, radius: "118%", center: ["50%", "72%"],
    progress: { show: true, width: 9, itemStyle: { color: v > 60 ? p.attack : v > 30 ? p.high : p.benign } },
    axisLine: { lineStyle: { width: 9, color: [[1, p.line]] } }, axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
    pointer: { show: false }, anchor: { show: false }, title: { show: false },
    detail: { valueAnimation: true, offsetCenter: [0, "-6%"], color: p.text,
      formatter: x => `{v|${Math.round(x)}}\n{l|${x > 60 ? "High" : x > 30 ? "Elevated" : "Low"}}`,
      rich: { v: { fontSize: 20, fontWeight: 700, color: p.text, lineHeight: 22 }, l: { fontSize: 11, color: p.muted } } },
    data: [{ value: v }] }] });
}
function drawMatrix() {
  const has = S.tp + S.fp + S.fn + S.tn > 0;
  const f1 = S.tp ? (2 * S.tp) / (2 * S.tp + S.fp + S.fn) : null, fpr = S.fp + S.tn ? S.fp / (S.fp + S.tn) : null;
  $("#mini-matrix").innerHTML = `<span></span><span class="h">Flagged</span><span class="h">Not flagged</span>
    <span class="rh">Attack</span><div class="cell tp"><b>${fmt(S.tp)}</b>caught</div><div class="cell fn"><b>${fmt(S.fn)}</b>missed</div>
    <span class="rh">Benign</span><div class="cell fp"><b>${fmt(S.fp)}</b>false alarm</div><div class="cell tn"><b>${fmt(S.tn)}</b>correctly quiet</div>
    <div class="foot"><span>F1 <b>${has ? pct(f1) : "—"}</b></span><span>False-positive rate <b>${has ? pct(fpr, 2) : "—"}</b></span></div>`;
}
Object.assign(redrawers, { drawTimeline, drawClasses, drawGauge });

/* ---------------- investigation drawer ---------------- */
function openDrawer(a) {
  const med = (S.card && S.card.benign_median) || {};
  const att = a.attack, status = statusOf(a);
  const steps = (att.guidance || "").split(/;\s*/).filter(Boolean);
  const vb = a.verdict ? `<div class="verdict-banner ${a.verdict === "correct" ? "correct" : a.verdict === "false positive" ? "fp" : "other"}">
      <b>Ground truth:</b> dataset label is <code>${esc(a.truth)}</code> — ${a.verdict === "correct" ? "the model is right." :
      a.verdict === "false positive" ? "this is a false alarm." : "an attack, but a different class."}</div>` : "";
  $("#drawer-body").innerHTML = `
    <span class="tag sev-${esc(a.severity)}" style="color:#fff;border:0">${esc(a.severity)}</span>
    <h2>${esc(a.display || a.predicted_class)}</h2>
    <div class="summary">${esc(a.summary)}</div>
    <section>${vb}</section>
    <section><h4>Flow</h4><div class="facts">
      <div><span>Source</span><b>${esc(a.source)}</b></div><div><span>Destination</span><b>${esc(a.dst || "—")}${a.dport != null ? ":" + esc(a.dport) : ""}</b></div>
      <div><span>Seen</span><b>${esc(String(a.time).replace("T", " ").slice(0, 19))}</b></div>
      <div><span>Model class</span><b>${esc(a.predicted_class)}</b></div><div><span>Confidence</span><b>${pct(a.confidence)}</b></div>
      <div><span>Anomaly detector</span><b>${a.outlier ? "outlier" : "normal"}</b></div></div></section>
    <section><h4>Why the model flagged it</h4>${a.explanation.length ? '<div id="c-shap"></div>' +
      `<table class="tbl"><tr><th>Feature</th><th>This flow</th><th>Typical benign</th></tr>${a.explanation.map(e =>
        `<tr><td>${esc(e.feature)}</td><td class="mono">${fmt(+e.value.toPrecision(4))}</td><td class="mono">${med[e.feature] != null ? fmt(+Number(med[e.feature]).toPrecision(4)) : "—"}</td></tr>`).join("")}</table>`
      : '<p class="hint">Flagged by the anomaly detector only: no single class explains it, so it needs a human look.</p>'}</section>
    <section><h4>Candidate MITRE ATT&amp;CK technique</h4>
      <div class="technique hot" style="--heat:12">${att.url ? `<a href="${esc(att.url)}" target="_blank" rel="noopener">` : ""}
        <div class="id">${esc(att.technique_id || "unmapped")} · ${esc(att.tactic)}</div><div class="name">${esc(att.technique)}</div>${att.url ? "</a>" : ""}</div>
      <p class="hint">Flow features show network symptoms, not intent, so this mapping is a starting point for the analyst.</p></section>
    <section><h4>Recommended response</h4><ol class="steps">${steps.map(s => `<li>${esc(s.charAt(0).toUpperCase() + s.slice(1).replace(/\.$/, ""))}</li>`).join("")}</ol></section>
    <section><h4>Triage</h4><div class="triage">
      <button class="btn good" data-s="confirmed">✓ Confirm incident</button>
      <button class="btn bad" data-s="dismissed">✗ Dismiss as false positive</button>
      <button class="btn ghost" data-s="open">Reopen</button></div>
      <p class="hint">Current status: <b id="cur-status">${esc(status)}</b></p></section>`;
  $$("#drawer-body .triage button").forEach(b => (b.onclick = () => {
    S.triage[a.alert_id] = b.dataset.s; store.set("triage", S.triage);
    $("#cur-status").textContent = b.dataset.s;
    $$(`.alert-card[data-id="${a.alert_id}"]`).forEach(c => c.classList.toggle("triaged", b.dataset.s !== "open"));
    updateKpis(false); toast(`Alert marked ${b.dataset.s}`);
  }));
  $("#drawer").classList.add("open"); $("#scrim").classList.add("open"); $("#drawer").setAttribute("aria-hidden", "false");
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
      label: { show: true, position: "right", color: p.muted, formatter: d => (d.value > 0 ? "+" : "") + d.value } }],
    tooltip: { ...base().tooltip, formatter: d => `${esc(d.name)}<br>${d.value > 0 ? "pushes towards" : "pushes away from"} ${esc(a.predicted_class)}` } });
}
function closeDrawer() { $("#drawer").classList.remove("open"); $("#scrim").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); }
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
  $("#inc-count").textContent = `${fmt(inc.length)} incidents from ${fmt(S.alerts.length)} alerts — ${S.alerts.length ? ((1 - inc.length / S.alerts.length) * 100).toFixed(0) : 0}% less noise to triage`;
  const techs = [...new Set(inc.map(g => g.tech))];
  chart("c-incidents").setOption({ ...base(), grid: { left: 8, right: 20, top: 20, bottom: 10, containLabel: true },
    xAxis: axis({ type: "category", data: [...new Set(inc.map(g => g.win))].sort() }),
    yAxis: axis({ type: "category", data: techs, axisLabel: { color: p.muted, formatter: t => {
      const g = inc.find(x => x.tech === t); return t.startsWith("T") && g ? `${t} ${g.technique}` : t; } } }),
    tooltip: { ...base().tooltip, formatter: d => `${esc(d.data.g.technique)}<br>${esc(d.data.g.source)} · ${d.data.g.count} alerts<br>${esc(d.data.g.win)}` },
    series: [{ type: "scatter", data: inc.map(g => ({ value: [g.win, g.tech], g, symbolSize: 10 + Math.sqrt(g.count) * 4,
      itemStyle: { color: sc[g.sev], opacity: .8, shadowBlur: 10, shadowColor: sc[g.sev] } })) }] }, true);
  const list = $("#incident-list");
  list.innerHTML = inc.length ? "" : '<div class="empty">No incidents yet. Start the live replay or analyse a file.</div>';
  inc.slice(0, 60).forEach(g => {
    const el = document.createElement("div"); el.className = "incident";
    el.innerHTML = `<div class="top"><span class="tag sev-${esc(g.sev)}" style="color:#fff;border:0">${esc(g.sev)}</span><span class="count">${g.count}</span></div>
      <b>${esc(g.technique)}</b><span class="src">${esc(g.source)} → ${[...g.targets].slice(0, 3).map(esc).join(", ") || "?"}</span>
      <small>${esc(g.win)} · ${[...g.classes].map(esc).join(", ")}</small>
      <button class="btn small">Investigate first alert</button>`;
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
      <div class="id">${id}</div><div class="name">${name}</div>${url ? "</a>" : ""}<span class="n">${n ? fmt(n) : ""}</span>
      ${n ? `<div class="classes">${[...classes[id]].map(esc).join(", ")}</div>` : ""}</div>`; }).join("")}</div>`).join("");
  drawSankey();
}
function drawSankey() {
  const p = palette(), links = new Map(), add = (a, b) => links.set(a + " " + b, (links.get(a + " " + b) || 0) + 1);
  for (const a of S.alerts) {
    const tech = a.attack.technique_id ? `${a.attack.technique_id} ${a.attack.technique}` : (a.outlier ? "Statistical outlier" : "Unmapped");
    const tactic = a.attack.tactic && a.attack.tactic !== "-" ? a.attack.tactic : "Needs analyst";
    add(a.predicted_class === BENIGN ? "Unusual (no class)" : a.predicted_class, tech); add(tech, "▸ " + tactic);
  }
  const names = new Set();
  const data = [...links].map(([k, value]) => { const [source, target] = k.split(" "); names.add(source); names.add(target); return { source, target, value }; });
  const colors = [p.attack, p.high, p.medium, p.accent2, p.accent, p.missed, "#f472b6", "#2dd4bf", "#a3e635", "#60a5fa"];
  chart("c-sankey").setOption({ ...base(), tooltip: { ...base().tooltip, trigger: "item" },
    series: [{ type: "sankey", left: 8, right: 150, top: 10, bottom: 10, nodeGap: 10, nodeWidth: 14, draggable: true,
      emphasis: { focus: "adjacency" }, lineStyle: { color: "gradient", opacity: 0.35, curveness: 0.5 },
      label: { color: p.text, fontSize: 12 },
      data: [...names].map((name, i) => ({ name, itemStyle: { color: colors[i % colors.length], borderWidth: 0 } })),
      links: data }] }, true);
  if (!data.length) chart("c-sankey").setOption({ title: { text: "No alerts yet — start the live replay or analyse a file", left: "center", top: "middle", textStyle: { color: p.muted, fontSize: 13, fontWeight: 400 } } });
}

/* ---------------- model lab ---------------- */
function renderLab() {
  const c = S.card; if (!c) return;
  const p = palette(), models = c.models || {}, names = Object.keys(models), sel = c.selected_model;
  const m = models[sel];
  $("#lab-intro").innerHTML = m ? `
    <div class="stat"><span>Selected model</span><strong>${esc(sel.toUpperCase())}</strong></div>
    <div class="stat"><span>Macro F1 (test)</span><strong>${pct(m.macro.f1)}</strong></div>
    <div class="stat"><span>Benign false-positive rate</span><strong>${pct(m.benign_fpr, 3)}</strong></div>
    <div class="stat"><span>Latency</span><strong>${m.latency_ms.toFixed(3)} ms/flow</strong></div>
    <p class="note">Trained on <b>${esc(c.dataset)}</b> (${fmt(c.split.train)} training flows, capped at ${fmt(c.split.train_cap_per_class)} per class) and tested on
      ${fmt(c.split.test)} held-out flows. Split: ${esc(c.split.method)} — each attack's later flows are predicted from its earlier ones, so the test set is never seen in training.
      The model was chosen on validation macro F1, not on test results. Accuracy is not shown because benign traffic dominates.</p>`
    : `<p class="note">Running the synthetic demo model. Train on real data with <code>scripts/train_baseline.py</code> to populate this page.</p>`;
  if (!m) return;
  const metrics = [["Macro F1", x => x.macro.f1], ["Macro precision", x => x.macro.precision], ["Macro recall", x => x.macro.recall], ["Attack PR-AUC", x => x.pr_auc]];
  chart("c-compare").setOption({ ...base(), legend: { textStyle: { color: p.muted }, top: 0 }, tooltip: { ...base().tooltip, trigger: "axis", valueFormatter: v => v.toFixed(3) },
    grid: { left: 8, right: 16, top: 34, bottom: 8, containLabel: true },
    xAxis: axis({ type: "category", data: metrics.map(x => x[0]) }), yAxis: axis({ type: "value", min: v => Math.max(0, Math.floor(v.min * 10) / 10), max: 1 }),
    color: [p.accent, p.accent2, p.high],
    series: names.map(n => ({ name: n.toUpperCase() + (n === sel ? " ★" : ""), type: "bar", barGap: "10%", itemStyle: { borderRadius: [4, 4, 0, 0] },
      data: metrics.map(([, f]) => +f(models[n]).toFixed(4)) })) }, true);
  const imp = [...(c.global_importance || [])].reverse();
  chart("c-importance").setOption({ ...base(), xAxis: axis({ type: "value" }),
    yAxis: axis({ type: "category", data: imp.map(x => x.feature), axisLabel: { color: p.text, width: 160, overflow: "truncate", interval: 0, fontSize: 11 } }),
    series: [{ type: "bar", data: imp.map(x => +x.importance.toFixed(4)), animationDelay: i => i * 40,
      itemStyle: { borderRadius: 4, color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: p.accent2 }, { offset: 1, color: p.accent }]) } }] }, true);
  const pc = m.per_class.filter(r => r.support > 0);
  $("#perclass-sub").textContent = `${sel.toUpperCase()} on the test split; bar label = number of test flows`;
  chart("c-perclass").setOption({ ...base(), tooltip: { ...base().tooltip, trigger: "axis" }, legend: { textStyle: { color: p.muted }, top: 0 },
    grid: { left: 8, right: 16, top: 34, bottom: 8, containLabel: true },
    xAxis: axis({ type: "category", data: pc.map(r => r.class), axisLabel: { color: p.muted, rotate: 30 } }), yAxis: axis({ type: "value", max: 1 }),
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
  chart(id).setOption({ ...base(), grid: { left: 8, right: 70, top: 10, bottom: 8, containLabel: true },
    tooltip: { ...base().tooltip, formatter: d => `true <b>${esc(ls[d.value[1]])}</b><br>predicted <b>${esc(ls[d.value[0]])}</b><br>${fmt(d.value[2])} flows` },
    xAxis: axis({ type: "category", data: ls, axisLabel: { color: p.muted, rotate: 40, fontSize: 10 }, splitArea: { show: false } }),
    yAxis: axis({ type: "category", data: ls, inverse: true, axisLabel: { color: p.muted, fontSize: 10 } }),
    visualMap: { min: 0, max: Math.max(1, ...d2.map(d => d[3])), dimension: 3, calculable: false, orient: "vertical", right: 0, top: "middle",
      inRange: { color: [css("--panel2"), p.accent2, p.accent] }, textStyle: { color: p.muted }, formatter: v => fmt(Math.round(10 ** v - 1)) },
    series: [{ type: "heatmap", data: d2, label: { show: ls.length <= 16, color: p.text, fontSize: 10, formatter: d => (d.value[2] ? fmt(d.value[2]) : "") },
      itemStyle: { borderColor: css("--panel"), borderWidth: 1 } }] }, true);
}
redrawers.renderLab = () => $("#view-lab").classList.contains("active") && renderLab();

/* ---------------- upload ---------------- */
const dz = $("#dropzone"), fileInput = $("#file");
["dragenter", "dragover"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add("over"); }));
["dragleave", "drop"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.remove("over"); }));
dz.addEventListener("drop", ev => ev.dataTransfer.files[0] && upload(ev.dataTransfer.files[0]));
fileInput.onchange = () => fileInput.files[0] && upload(fileInput.files[0]);

async function upload(file) {
  const st = $("#upload-status"), out = $("#upload-results");
  st.innerHTML = `<p>Scoring <b>${esc(file.name)}</b> (${(file.size / 1048576).toFixed(1)} MB)…</p><div class="progress"><i></i></div>`;
  out.innerHTML = "";
  const fd = new FormData(); fd.append("file", file);
  const t0 = performance.now();
  try {
    const r = await api("score-csv", { method: "POST", body: fd });
    st.innerHTML = `<p>✓ Scored <b>${fmt(r.rows)}</b> flows in ${((performance.now() - t0) / 1000).toFixed(1)} s.</p>`;
    r.top_alerts.forEach(a => addAlert(a, false, "upload"));
    renderUpload(r);
  } catch (e) { st.innerHTML = `<p style="color:var(--attack)">✗ ${esc(e.message)}</p>`; }
}
function renderUpload(r) {
  const out = $("#upload-results"), ev = r.evaluation;
  out.innerHTML = `<div class="kpis" style="margin-bottom:14px">
      <div class="kpi card"><span>Flows</span><strong>${fmt(r.rows)}</strong></div>
      <div class="kpi card"><span>Alerts</span><strong>${fmt(r.alerts)}</strong><small>${pct(r.alerts / r.rows)} of flows</small></div>
      <div class="kpi card"><span>Incidents</span><strong>${fmt(r.incidents.length)}</strong></div>
      <div class="kpi card good"><span>Macro F1</span><strong>${ev ? pct(ev.macro.f1) : "—"}</strong><small>${ev ? "vs. the file's labels" : "file has no Label column"}</small></div>
      <div class="kpi card"><span>Benign FPR</span><strong>${ev ? pct(ev.benign_fpr, 2) : "—"}</strong></div></div>
    <div class="result-grid">
      <div class="card"><div class="card-head"><h3>Predicted classes</h3></div><div id="u-classes" class="chart"></div></div>
      <div class="card"><div class="card-head"><h3>Alerts by class</h3><small>most severe of each class first · click to investigate</small></div>
        <div class="scroll"><table class="tbl"><tr><th>Severity</th><th>Class</th><th>Source</th><th>Conf.</th><th>Label</th></tr>
        ${r.top_alerts.slice(0, 150).map((a, i) => `<tr class="click" data-i="${i}"><td><span class="tag sev-${esc(a.severity)}" style="color:#fff;border:0">${esc(a.severity)}</span></td>
          <td>${a.predicted_class === BENIGN ? "Unusual (outlier)" : esc(a.predicted_class)}</td><td class="mono">${esc(a.source)}</td><td>${pct(a.confidence, 0)}</td><td>${a.truth ? verdictTag(a) : "—"}</td></tr>`).join("")}</table></div></div>
      ${ev ? `<div class="card wide"><div class="card-head"><h3>Confusion matrix for your file</h3><small>rows = file label, columns = model prediction</small></div><div id="u-confusion" class="chart tall"></div></div>` : ""}
    </div>`;
  $$("#upload-results tr.click").forEach(tr => (tr.onclick = () => openDrawer(r.top_alerts[+tr.dataset.i])));
  const p = palette(), pc = Object.entries(r.predicted_counts).sort((a, b) => a[1] - b[1]);
  chart("u-classes").dispose?.(); delete charts["u-classes"];
  chart("u-classes").setOption({ ...base(), xAxis: axis({ type: "log", min: 1 }), yAxis: axis({ type: "category", data: pc.map(x => x[0]), axisLabel: { color: p.muted, interval: 0, fontSize: 11 } }),
    series: [{ type: "bar", data: pc.map(([k, v]) => ({ value: v, itemStyle: { color: k === BENIGN ? p.benign : p.attack, borderRadius: 4 } })),
      label: { show: true, position: "right", color: p.muted, formatter: d => fmt(d.value) } }] });
  if (ev) { delete charts["u-confusion"]; drawConfusion("u-confusion", ev.labels, ev.confusion); }
}

/* ---------------- about ---------------- */
function renderAbout() {
  const c = S.card || {};
  $("#about").innerHTML = `<h2>About ExplainIDS</h2>
  <p>Small organisations rarely have a security analyst on call. Machine-learning intrusion detectors can spot attacks in network flows,
  but a bare label such as <code>DoS-Hulk</code> does not tell anyone what happened or what to do. ExplainIDS pairs a detector with
  <b>SHAP explanations</b>, <b>candidate MITRE ATT&amp;CK techniques</b>, plain-language summaries and response steps, and groups alerts into incidents to cut triage noise.</p>
  <h3>How it works</h3>
  <ol><li>Network traffic is summarised into flows (CICFlowMeter features: packet counts, sizes, timings, flags).</li>
  <li>A gradient-boosted or random-forest classifier predicts the flow's class; a benign-only Isolation Forest flags unusual traffic no class explains.</li>
  <li>TreeSHAP lists the features that pushed each alert towards its class, compared with typical benign values.</li>
  <li>Each class maps to a candidate ATT&amp;CK technique with severity and response guidance; an analyst confirms or dismisses it.</li></ol>
  <h3>Data and honesty</h3>
  <p>The live monitor replays <b>real held-out flows</b> from the corrected ${esc(c.dataset || "CIC-IDS2017")} release, in capture order, with their true labels,
  so the scorecard shows real hits, misses and false alarms rather than a scripted demo. Results come from a chronological split; cross-dataset tests on
  CSE-CIC-IDS2018 and traffic from an isolated lab measure how far the model generalises. Lab-trained detectors can degrade on new networks, so alerts are decision support, not verdicts.</p>
  <h3>Sources</h3>
  <ul><li>Sharafaldin, I., Habibi Lashkari, A., &amp; Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. <i>ICISSP 2018</i>. <a href="https://doi.org/10.5220/0006639801080116" target="_blank" rel="noopener">doi:10.5220/0006639801080116</a></li>
  <li>Engelen, G., Rimmer, V., &amp; Joosen, W. (2021). Troubleshooting an intrusion detection dataset: The CICIDS2017 case study. <i>IEEE SPW</i>. <a href="https://doi.org/10.1109/SPW53761.2021.00009" target="_blank" rel="noopener">doi:10.1109/SPW53761.2021.00009</a></li>
  <li>Liu, L., Engelen, G., Lynar, T., Essam, D., &amp; Joosen, W. (2022). Error prevalence in NIDS datasets: A case study on CIC-IDS-2017 and CSE-CIC-IDS-2018. <i>IEEE CNS</i>. <a href="https://doi.org/10.1109/CNS56114.2022.9947235" target="_blank" rel="noopener">doi:10.1109/CNS56114.2022.9947235</a></li>
  <li>Lundberg, S. M., Erion, G., Chen, H., DeGrave, A., Prutkin, J. M., Nair, B., Katz, R., Himmelfarb, J., Bansal, N., &amp; Lee, S.-I. (2020). From local explanations to global understanding with explainable AI for trees. <i>Nature Machine Intelligence, 2</i>(1), 56–67. <a href="https://doi.org/10.1038/s42256-019-0138-9" target="_blank" rel="noopener">doi:10.1038/s42256-019-0138-9</a></li>
  <li>MITRE. (n.d.). <i>MITRE ATT&amp;CK</i>. <a href="https://attack.mitre.org/" target="_blank" rel="noopener">attack.mitre.org</a></li></ul>
  <p class="hint">API documentation: <a href="docs">interactive OpenAPI docs</a>. Source code: <a href="https://github.com/iamnajib71/explainids" target="_blank" rel="noopener">GitHub</a>. Attack traffic is only ever generated inside an isolated lab; no real networks are scanned.</p>`;
}

/* ---------------- boot ---------------- */
async function boot() {
  const pill = $("#model-pill");
  try {
    const [h, c] = await Promise.all([api("health"), api("model")]);
    S.health = h; S.card = c;
    pill.className = "pill ok";
    $("span", pill).textContent = `${h.classifier.toUpperCase()} · ${c.dataset} · ${fmt(h.replay_flows)} real flows`;
    if (!c.models || !Object.keys(c.models).length) $("#replay-hint").textContent = "Demo mode: replaying synthetic flows. Train on real data to replay real traffic.";
  } catch (e) {
    pill.className = "pill err"; $("span", pill).textContent = "API unreachable";
    toast("Cannot reach the API: " + e.message);
  }
  renderAbout(); updateKpis(false); drawTimeline(); drawClasses(); drawGauge(); drawMatrix();
  showView(store.get("view", "live"));
}
boot();
