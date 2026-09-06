"use strict";
/* Red-Team Agent web console — vanilla SPA */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = (p, opt) => fetch(p, opt).then(async r => {
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || r.statusText), { data: j });
  return j;
});
const pct = x => (x == null ? "—" : (x * 100).toFixed(1) + "%");
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtTime = t => t ? new Date(t * 1000).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—";

const STAGES = [
  { key: "write_acceptance", name: "Запись принята", cp: "WRITE_ACCEPTED" },
  { key: "persistence_global", name: "Сохранено в память", cp: "STORED_GLOBAL" },
  { key: "retrieval_candidate", name: "Извлечено при активации", cp: "RETRIEVAL" },
  { key: "behavior_change", name: "Поведение изменено", cp: "BEHAVIOR_CHANGED" },
  { key: "unsafe_output", name: "Небезопасный вывод", cp: "UNSAFE_OUTPUT" },
];
const TRANS = {
  persistence_global: { k: "persistence_given_write", label: "persistence | write" },
  retrieval_candidate: null,
  behavior_change: { k: "activation_given_retrieval", label: "activation | retrieval" },
  unsafe_output: { k: "unsafe_given_behavior", label: "unsafe | behavior" },
};

const state = {
  scenarios: [],
  selected: new Set(),
  filterText: "",
  filterSev: new Set(),
  view: "run",
  monitor: { id: null, offset: 0, poll: null, done: false },
  sort: { key: "unsafe", dir: -1 },
};

/* ── views / router ─────────────────────────────────────────────── */
function show(view) {
  state.view = view;
  $$(".view").forEach(v => v.hidden = v.id !== "view-" + view);
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === view));
  // монитор прогона живёт в табе запуска и продолжает опрашиваться независимо от вкладки
  if (view === "runs") loadRuns();
}

/* ── config summary ─────────────────────────────────────────────── */
async function loadConfig() {
  try {
    const c = await api("/api/config");
    const dot = b => `<span class="dot ${b ? "on" : "off"}"></span>`;
    const keysOk = c.keys.attacker && c.keys.victim && c.keys.secondary;
    $("#target-summary").innerHTML =
      `${dot(true)}цель <b>${esc(c.target_url.replace(/^https?:\/\//, ""))}</b><br>` +
      `attacker <b>${esc(c.attacker_model || "—")}</b> · judge <b>${esc(c.judge_model || "—")}</b><br>` +
      `${dot(keysOk)}ключи стенда ${keysOk ? "заданы" : "не заданы"}`;
    // подставим дефолты параметров
    const d = c.defaults || {};
    setNum("p-loop", d.loop); setNum("p-repeats", d.repeats); setNum("p-seed", d.seed);
    syncRanges(); updateEstimate();
  } catch (e) { $("#target-summary").textContent = "конфиг недоступен"; }
}
function setNum(id, v) { if (v != null && !isNaN(+v)) $("#" + id).value = +v; }

/* ── scenarios ──────────────────────────────────────────────────── */
async function loadScenarios() {
  const r = await api("/api/scenarios");
  state.scenarios = r.scenarios || [];
  // по умолчанию — все включённые core
  state.scenarios.forEach(s => { if (s.enabled) state.selected.add(s.id); });
  renderSevFilters();
  renderScenarios();
}
function renderSevFilters() {
  const sevs = ["critical", "high", "medium", "low"];
  $("#sev-filters").innerHTML = sevs.map(s =>
    `<button class="sevchip" data-sev="${s}">${s}</button>`).join("");
  $$("#sev-filters .sevchip").forEach(b => b.onclick = () => {
    const s = b.dataset.sev;
    state.filterSev.has(s) ? state.filterSev.delete(s) : state.filterSev.add(s);
    b.classList.toggle("active");
    renderScenarios();
  });
}
function matchFilter(s) {
  if (state.filterSev.size && !state.filterSev.has(s.severity)) return false;
  const q = state.filterText.trim().toLowerCase();
  if (!q) return true;
  return (s.id + " " + s.title + " " + s.tags.join(" ") + " " + s.objective).toLowerCase().includes(q);
}
function renderScenarios() {
  const list = $("#scn-list");
  const rows = state.scenarios.filter(matchFilter);
  if (!rows.length) { list.innerHTML = `<div class="empty">ничего не найдено</div>`; }
  else list.innerHTML = rows.map(s => {
    const on = state.selected.has(s.id);
    const tags = s.tags.slice(0, 3).map(t => `<span class="tag">${esc(t)}</span>`).join("");
    const req = (!s.enabled) ? `<div class="req-note">⚠ требует фикстур: ${esc(s.requirements[0] || "внешние требования")}</div>` : "";
    return `<div class="scn ${on ? "on" : ""} ${s.enabled ? "" : "disabled"}" data-id="${esc(s.id)}">
      <div class="cb">${on ? "✓" : ""}</div>
      <div class="sev-tag sev-${s.severity}">${s.severity.slice(0, 4)}</div>
      <div class="scn-main">
        <div class="scn-title" title="${esc(s.objective)}">${esc(s.title)}</div>
        <div class="scn-id">${esc(s.id)}</div>${req}
      </div>
      <div class="scn-tags">${tags}</div>
    </div>`;
  }).join("");
  $$("#scn-list .scn").forEach(el => el.onclick = () => toggle(el.dataset.id));
  updateSelCount();
}
function toggle(id) {
  state.selected.has(id) ? state.selected.delete(id) : state.selected.add(id);
  renderScenarios();
}
function updateSelCount() {
  $("#sel-count").textContent = state.selected.size;
  updateEstimate();
}
function quick(kind) {
  state.selected.clear();
  if (kind === "none") { }
  else if (kind === "core") state.scenarios.forEach(s => { if (s.enabled && s.tags.includes("core")) state.selected.add(s.id); });
  else if (kind === "enabled") state.scenarios.forEach(s => { if (s.enabled) state.selected.add(s.id); });
  else if (kind === "all") state.scenarios.forEach(s => state.selected.add(s.id));
  renderScenarios();
}

/* ── params ─────────────────────────────────────────────────────── */
function syncRanges() {
  $("#p-loop-range").value = Math.min(10, +$("#p-loop").value || 0);
  $("#p-repeats-range").value = Math.min(20, +$("#p-repeats").value || 1);
}
function updateEstimate() {
  const scn = state.selected.size || state.scenarios.filter(s => s.enabled).length;
  const rep = Math.max(1, +$("#p-repeats").value || 1);
  $("#est-scn").textContent = state.selected.size || `${scn} (все)`;
  $("#est-rep").textContent = rep;
  $("#est-total").textContent = scn * rep;
}

/* ── launch ─────────────────────────────────────────────────────── */
async function launch() {
  const btn = $("#btn-launch"); const msg = $("#launch-msg");
  const payload = {
    scenarios: [...state.selected],
    loop: +$("#p-loop").value || 0,
    repeats: +$("#p-repeats").value || 1,
    auth_mode: "vulnerable",
    seed: +$("#p-seed").value || 0,
    fail_fast: $("#p-failfast").checked,
  };
  btn.disabled = true; msg.className = "launch-msg"; msg.textContent = "запуск контейнера…";
  try {
    const r = await api("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    msg.className = "launch-msg ok"; msg.textContent = "запущено: " + r.run_id;
    startMonitor(r.run_id, false);
  } catch (e) {
    msg.className = "launch-msg err"; msg.textContent = "⚠ " + e.message;
  } finally { btn.disabled = false; }
}

async function doctor() {
  const card = $("#doctor-card"), out = $("#doctor-out");
  card.hidden = false; out.textContent = "preflight выполняется (docker compose run … doctor)…";
  try {
    const r = await api("/api/doctor", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ loop: +$("#p-loop").value || 1 }) });
    out.textContent = r.output || "(нет вывода)";
  } catch (e) { out.textContent = "⚠ " + e.message + (e.data && e.data.output ? "\n\n" + e.data.output : ""); }
}

/* ── runs list ──────────────────────────────────────────────────── */
async function loadRuns() {
  const box = $("#runs-list");
  try {
    const r = await api("/api/runs");
    $("#runs-count").textContent = r.runs.length || "";
    if (!r.runs.length) { box.innerHTML = `<div class="empty">пока нет прогонов</div>`; return; }
    box.innerHTML = r.runs.map(runRow).join("");
    $$("#runs-list .run-row").forEach(el => el.onclick = () => startMonitor(el.dataset.id));
  } catch (e) { box.innerHTML = `<div class="empty">ошибка: ${esc(e.message)}</div>`; }
}
function asrClass(x) { return x == null ? "asr-na" : x >= 0.5 ? "asr-hi" : x >= 0.2 ? "asr-mid" : "asr-lo"; }
function runRow(r) {
  const p = r.params || {};
  const scn = p.scenarios && p.scenarios.length ? p.scenarios.length + " сценар." : (p.scenarios_label || "весь набор");
  const meta = [scn, `loop=${p.loop ?? "?"}`, `repeats=${p.repeats ?? "?"}`, p.auth_mode ? `auth=${p.auth_mode}` : null]
    .filter(Boolean).join(" · ");
  const asr = r.has_report
    ? `<div class="val ${asrClass(r.e2e)}">${pct(r.e2e)}</div><div class="lbl">e2e ASR</div>`
    : `<div class="val asr-na">—</div><div class="lbl">${r.status === "running" ? "идёт" : "нет отчёта"}</div>`;
  return `<div class="run-row" data-id="${esc(r.run_id)}" data-status="${r.status}">
    <span class="pill ${r.status}">${r.status}</span>
    <div class="run-info">
      <div class="run-id">${esc(r.run_id)}</div>
      <div class="run-meta">${esc(meta)} · ${fmtTime(r.started_at)}${r.n_runs ? " · n=" + r.n_runs : ""}</div>
    </div>
    <div class="run-asr">${asr}</div>
  </div>`;
}

/* ── монитор прогона (остаётся во вкладке запуска) ───────────────── */
function startMonitor(id, switchTab = true) {
  const m = state.monitor;
  if (m.poll) clearInterval(m.poll);
  state.monitor = { id, offset: 0, poll: null, done: false };
  $("#mon-card").hidden = false;
  $("#mon-id").textContent = id;
  $("#mon-log").textContent = "";
  $("#mon-params").innerHTML = "";
  $("#mon-status").textContent = "";
  $("#mon-status").className = "pill";
  $("#mon-spin").style.display = "";
  $("#btn-stop").style.display = "";
  $("#btn-stop").disabled = false;
  const or = $("#btn-openreport"); or.hidden = true; or.onclick = () => openReport(id);
  if (switchTab) show("run");
  api("/api/runs/" + id).then(d => {
    const p = d.params || {};
    $("#mon-params").innerHTML =
      `<span>сценарии: <b>${p.scenarios && p.scenarios.length ? p.scenarios.join(", ") : "весь enabled-набор"}</b></span>` +
      `<span>LOOP=<b>${p.loop ?? "?"}</b></span><span>REPEATS=<b>${p.repeats ?? "?"}</b></span>` +
      `<span>AUTH=<b>${p.auth_mode ?? "?"}</b></span><span>SEED=<b>${p.seed ?? 0}</b></span>` +
      `<span>FAIL_FAST=<b>${p.fail_fast === false ? "off" : "on"}</b></span>`;
  }).catch(() => { });
  pollMonitor(true);
  state.monitor.poll = setInterval(() => pollMonitor(false), 1400);
}
async function pollMonitor(first) {
  const id = state.monitor.id; if (!id) return;
  try {
    const r = await api(`/api/runs/${id}/log?offset=${state.monitor.offset}`);
    if (r.chunk) {
      const log = $("#mon-log");
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 40;
      log.textContent += r.chunk;
      state.monitor.offset = r.offset;
      if (atBottom || first) log.scrollTop = log.scrollHeight;
    }
    const st = r.status || "running";
    $("#mon-status").textContent = st;
    $("#mon-status").className = "pill " + st;
    $("#mon-spin").style.display = r.done ? "none" : "";
    $("#btn-stop").style.display = r.done ? "none" : "";
    if (r.done && !state.monitor.done) {
      state.monitor.done = true;
      if (state.monitor.poll) { clearInterval(state.monitor.poll); state.monitor.poll = null; }
      loadRuns();
      api("/api/runs/" + id).then(d => { $("#btn-openreport").hidden = !d.has_report; }).catch(() => { });
    }
  } catch (e) { /* transient */ }
}
async function stopMonitor() {
  const id = state.monitor.id; if (!id) return;
  $("#btn-stop").disabled = true;
  try { await api(`/api/runs/${id}/stop`, { method: "POST" }); } catch (e) { }
  $("#btn-stop").disabled = false;
}
function clearMonitor() {
  if (state.monitor.poll) clearInterval(state.monitor.poll);
  state.monitor = { id: null, offset: 0, poll: null, done: false };
  $("#mon-card").hidden = true;
}

/* ── report ─────────────────────────────────────────────────────── */
async function openReport(id) {
  show("report");
  $("#rep-id").textContent = id;
  $("#dl-md").href = `/api/runs/${id}/report.md`;
  $("#dl-json").href = `/api/runs/${id}/report`;
  const body = $("#report-body");
  body.innerHTML = `<div class="empty">загрузка отчёта…</div>`;
  try {
    const d = await api("/api/runs/" + id);
    if (!d.report) { body.innerHTML = `<div class="empty">отчёт не найден. Возможно, прогон завершился ошибкой — посмотрите лог.</div>`; return; }
    renderReport(body, d);
  } catch (e) { body.innerHTML = `<div class="empty">ошибка: ${esc(e.message)}</div>`; }
}

function rate(obj) { return obj ? obj.rate : null; }
function nObs(obj) {
  if (!obj) return 0;
  return obj.observed != null ? obj.observed : (obj.given != null ? obj.given : 0);
}
function ciStr(obj) {
  if (!obj || !obj.ci95 || obj.rate == null) return "";
  return `95% CI ${(obj.ci95[0] * 100).toFixed(0)}–${(obj.ci95[1] * 100).toFixed(0)}%`;
}

function renderReport(root, d) {
  const rep = d.report, rates = rep.rates || {}, cond = rep.conditional || {};
  const p = d.params || (d.campaign || {});
  const e2e = rates.end_to_end || {};
  const asr = e2e.rate;
  const paramLine = [
    p.scenarios && p.scenarios.length ? p.scenarios.length + " сценариев" : "весь enabled-набор",
    `LOOP ${p.loop ?? p.loop_iters ?? "?"}`, `REPEATS ${p.repeats ?? "?"}`,
    p.auth_mode ? `AUTH ${p.auth_mode}` : null, `SEED ${p.seed ?? 0}`,
  ].filter(Boolean).join(" · ");

  const ffc = e2e.first_failed_required_checkpoint || {};
  const ffcTotal = Object.values(ffc).reduce((a, b) => a + b, 0);
  const ffcRows = Object.entries(ffc).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
    `<div class="fstage" style="padding:8px 12px">
      <div class="fstage-top"><span class="fstage-name" style="font-size:12px">${esc(k)}</span>
        <span class="fstage-val" style="font-size:13px">${v}</span></div>
      <div class="fstage-bar"><i style="width:${ffcTotal ? (v / ffcTotal * 100) : 0}%;background:linear-gradient(90deg,#ff8a3d,var(--bad))"></i></div>
    </div>`).join("");

  const kpis = STAGES.map(s => {
    const o = rates[s.key]; const r = rate(o);
    const col = s.key === "unsafe_output" ? "var(--bad)" : s.key === "behavior_change" ? "var(--high)" : "var(--accent2)";
    return `<div class="kpi">
      <div class="k">${s.name} <small style="color:var(--faint)">${s.cp}</small></div>
      <div class="v" style="color:${r == null ? "var(--faint)" : col}">${pct(r)}</div>
      <div class="n">${o ? `${o.reached}/${nObs(o)}` : "нет наблюдений"} ${ciStr(o)}</div>
      <div class="bar"><i style="width:${(r || 0) * 100}%;background:${col}"></i></div>
    </div>`;
  }).join("");

  // funnel with conditional transitions between stages
  let funnel = "";
  STAGES.forEach((s, i) => {
    const o = rates[s.key]; const r = rate(o);
    const t = TRANS[s.key];
    if (t && cond[t.k]) {
      const c = cond[t.k];
      funnel += `<div class="ftrans">↓ переход <b>${t.label}</b> = ${pct(c.rate)} <span style="color:var(--faint)">(n=${nObs(c)})</span></div>`;
    } else if (i > 0) { funnel += `<div class="ftrans">↓</div>`; }
    funnel += `<div class="fstage">
      <div class="fstage-top">
        <span class="fstage-name">${s.name}<small>${s.cp}</small></span>
        <span class="fstage-val" style="color:${r == null ? "var(--faint)" : "var(--ink)"}">${pct(r)}</span>
      </div>
      <div class="fstage-bar"><i style="width:${(r || 0) * 100}%"></i></div>
      <div class="fstage-meta">${o ? `reached ${o.reached} / observed ${nObs(o)}` : "нет наблюдений"}${excStr(o)}</div>
    </div>`;
  });

  // per-scenario table
  const ps = rep.per_scenario || {};
  const scnRows = Object.entries(ps).map(([id, v]) => ({
    id, runs: v.runs,
    stored: rate(v.stored_global), retrieval: rate(v.retrieval),
    behavior: rate(v.behavior), unsafe: rate(v.unsafe), raw: v,
  }));
  const sk = state.sort.key, sd = state.sort.dir;
  scnRows.sort((a, b) => {
    const av = a[sk], bv = b[sk];
    if (av == null) return 1; if (bv == null) return -1;
    return (av > bv ? 1 : av < bv ? -1 : 0) * sd || a.id.localeCompare(b.id);
  });
  const th = (k, label) => `<th data-sort="${k}">${label}${sk === k ? (sd < 0 ? " ▾" : " ▴") : ""}</th>`;
  const rateCell = (o) => {
    const r = rate(o);
    if (r == null) return `<td class="rate-cell dash">—</td>`;
    const cls = asrClass(r);
    return `<td class="rate-cell ${cls}">${pct(r)} <span class="n">n=${nObs(o)}</span></td>`;
  };
  const tbody = scnRows.map(row => {
    const v = row.raw;
    return `<tr>
      <td class="scnid">${esc(row.id)}</td>
      <td>${row.runs}</td>
      ${rateCell(v.stored_global)}${rateCell(v.retrieval)}${rateCell(v.behavior)}${rateCell(v.unsafe)}
    </tr>`;
  }).join("");

  const infra = rep.infrastructure_error_rate, je = rep.judge_error_rate;
  const fp = rep.false_positive_rate || {};

  root.innerHTML = `
    <section class="rep-section hero">
      <div class="verdict">
        <div class="cap">Causal end-to-end ASR</div>
        <div class="big ${asrClass(asr)}">${pct(asr)}</div>
        <div class="sub">${e2e.reached ?? 0} / ${nObs(e2e)} прогонов</div>
        <div class="ci">${ciStr(e2e)}</div>
      </div>
      <div>
        <div class="run-meta" style="margin-bottom:12px;font-family:var(--mono);color:var(--muted)">${esc(paramLine)} · прогонов ${rep.n_runs} (завершено ${rep.n_completed})</div>
        <div class="kpi-grid">${kpis}</div>
      </div>
    </section>

    <section class="rep-section">
      <div class="rep-h">Kill-chain: воронка стадий атаки</div>
      <div class="card"><div class="funnel">${funnel}</div>
      <div class="legend">Безусловная доля = reached среди наблюдавшихся прогонов. Переход «X | Y» — условная вероятность достижения X при достигнутом Y. UNOBSERVED / NOT_APPLICABLE / EVALUATION_ERROR исключены из знаменателя.</div></div>
    </section>

    ${ffcTotal ? `<section class="rep-section">
      <div class="rep-h">Где обрывается обязательный маршрут (${ffcTotal})</div>
      <div class="card"><div class="funnel">${ffcRows}</div></div>
    </section>` : ""}

    <section class="rep-section">
      <div class="rep-h">По сценариям</div>
      <div class="card" style="overflow-x:auto">
        <table class="tbl"><thead><tr>
          ${th("id", "сценарий")}${th("runs", "runs")}
          ${th("stored", "stored")}${th("retrieval", "retrieval")}
          ${th("behavior", "behavior")}${th("unsafe", "unsafe")}
        </tr></thead><tbody>${tbody}</tbody></table>
      </div>
    </section>

    <section class="rep-section">
      <div class="rep-h">Качество и наблюдаемость</div>
      <div class="qgrid">
        ${qcell("false-positive (benign)", pct(fp.rate), `n=${fp.observed ?? 0}, ошибок оценки ${fp.evaluation_errors ?? 0}`)}
        ${qcell("judge error rate", pct(je), `${rep.judge_errors ?? 0}/${rep.judge_evaluations ?? 0} оценок`)}
        ${qcell("infra error rate", pct(infra), `unsupported ${rep.n_unsupported ?? 0}, corrupt ${rep.n_corrupt_results ?? 0}`)}
        ${qcell("avg target queries", (rep.avg_target_queries ?? "—"), "обращений к цели / прогон")}
        ${qcell("avg candidates", (rep.avg_candidate_attempts ?? "—"), "кандидатов / прогон")}
        ${qcell("avg mutations", (rep.avg_accepted_mutations ?? "—"), "принятых мутаций / прогон")}
      </div>
    </section>

    <details class="raw"><summary>Сырой report.json</summary>
      <pre>${esc(JSON.stringify(rep, null, 2))}</pre></details>
  `;

  $$("#report-body .tbl th[data-sort]").forEach(th => th.onclick = () => {
    const k = th.dataset.sort;
    state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : -1 };
    renderReport(root, d);
  });
}
function excStr(o) {
  if (!o || !o.excluded) return "";
  const parts = Object.entries(o.excluded).filter(([, v]) => v > 0).map(([k, v]) => `${k} ${v}`);
  return parts.length ? ` · исключено: ${parts.join(", ")}` : "";
}
function qcell(k, v, n) {
  return `<div class="qcell"><div class="qk">${esc(k)}</div><div class="qv">${esc(v)}</div><div class="qn">${esc(n)}</div></div>`;
}

/* ── wiring ─────────────────────────────────────────────────────── */
function init() {
  $$(".tab").forEach(t => t.onclick = () => show(t.dataset.view));
  $$('[data-view]').forEach(el => { if (!el.classList.contains("tab")) el.onclick = () => show(el.dataset.view); });
  $("#scn-search").oninput = e => { state.filterText = e.target.value; renderScenarios(); };
  $$(".quick .link").forEach(b => b.onclick = () => quick(b.dataset.quick));
  $("#p-loop").oninput = () => { syncRanges(); };
  $("#p-repeats").oninput = () => { syncRanges(); updateEstimate(); };
  $("#p-loop-range").oninput = e => { $("#p-loop").value = e.target.value; };
  $("#p-repeats-range").oninput = e => { $("#p-repeats").value = e.target.value; updateEstimate(); };
  $("#btn-launch").onclick = launch;
  $("#btn-doctor").onclick = doctor;
  $("#doctor-close").onclick = () => $("#doctor-card").hidden = true;
  $("#btn-refresh").onclick = loadRuns;
  $("#btn-stop").onclick = stopMonitor;
  $("#btn-clearmon").onclick = clearMonitor;
  loadConfig();
  loadScenarios().catch(e => $("#scn-list").innerHTML = `<div class="empty">каталог сценариев недоступен: ${esc(e.message)}<br>Запустите сервер через <code>.venv/bin/python</code>.</div>`);
  loadRuns();
  // при перезагрузке страницы восстановить активный прогон в мониторе
  api("/api/runs").then(d => { if (d.active && d.active.length) startMonitor(d.active[0], false); }).catch(() => { });
}
init();
