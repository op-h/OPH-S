/* Shared helpers: DOM, formatting, modal, drawer, toasts, charts, polling. */
(function () {
  "use strict";

  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  function esc(v) { return v === null || v === undefined ? "" : String(v).replace(/[&<>"']/g, c => ESC[c]); }

  /** Tagged template: interpolated values are escaped unless wrapped with raw(). */
  function raw(s) { return { __raw: String(s), toString() { return this.__raw; } }; }
  function html(strings, ...vals) {
    let out = "";
    strings.forEach((s, i) => {
      out += s;
      if (i < vals.length) {
        const v = vals[i];
        if (v && v.__raw !== undefined) out += v.__raw;
        else if (Array.isArray(v)) out += v.map(x => (x && x.__raw !== undefined ? x.__raw : esc(x))).join("");
        else out += esc(v);
      }
    });
    return raw(out);
  }
  function el(markup) { const t = document.createElement("template"); t.innerHTML = (markup && markup.__raw !== undefined ? markup.__raw : markup).trim(); return t.content.firstElementChild; }
  function icon(name, cls) { return raw(`<svg class="i ${cls || ""}" aria-hidden="true"><use href="#i-${name}"/></svg>`); }
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  /* ---------- formatting ---------- */
  const nf = new Intl.NumberFormat("en-US");
  function num(n) { return n === null || n === undefined || isNaN(n) ? "—" : nf.format(n); }
  function compact(n) {
    if (n === null || n === undefined) return "—";
    if (Math.abs(n) < 10000) return nf.format(n);
    return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
  }
  function bytes(b) {
    if (b === null || b === undefined || isNaN(b)) return "—";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0, v = b;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + " " + u[i];
  }
  const pad = n => String(n).padStart(2, "0");
  function absTime(ts) {
    if (!ts) return "—";
    const d = new Date(ts);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }
  function timeOnly(ts) { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`; }
  function dateOnly(ts) { const d = new Date(ts); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }
  function rel(ts) {
    if (!ts) return "never";
    const s = Math.round((Date.now() - ts) / 1000);
    if (s < 0) return "just now";
    if (s < 45) return s + "s ago";
    const m = Math.round(s / 60); if (m < 60) return m + "m ago";
    const h = Math.round(m / 60); if (h < 36) return h + "h ago";
    const d = Math.round(h / 24); if (d < 60) return d + "d ago";
    return dateOnly(ts);
  }
  function relHtml(ts) { return html`<span title="${absTime(ts)}">${rel(ts)}</span>`; }
  const SEVS = ["info", "low", "medium", "high", "critical"];
  function sev(s) { const v = SEVS.includes(s) ? s : "info"; return html`<span class="sev sev-${v}">${v}</span>`; }

  /* ---------- toasts ---------- */
  function toast(msg, kind) {
    const host = $("#toasts");
    const t = el(html`<div class="toast ${kind === "error" ? "error" : ""}" role="status">${icon(kind === "error" ? "alert" : "check", "sm")}<div class="grow">${msg}</div><button class="btn ghost icon sm" aria-label="Dismiss">${icon("x", "sm")}</button></div>`);
    const kill = () => t.remove();
    t.querySelector("button").onclick = kill;
    host.appendChild(t);
    setTimeout(kill, 4000);
  }

  /* ---------- modal ---------- */
  /** confirm({title, body (raw html), confirmLabel, danger}) -> Promise<boolean> */
  function confirmModal(opts) {
    return new Promise(resolve => {
      const prev = document.activeElement;
      const m = el(html`<div class="modal-scrim" role="presentation">
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-t">
          <div class="modal-head"><h2 class="modal-title" id="modal-t">${opts.title}</h2></div>
          <div class="modal-body">${raw(opts.body && opts.body.__raw !== undefined ? opts.body.__raw : esc(opts.body || ""))}</div>
          <div class="modal-foot">
            <button class="btn" data-a="cancel">${opts.cancelLabel || "Cancel"}</button>
            <button class="btn ${opts.danger ? "danger solid" : "primary"}" data-a="ok">${opts.confirmLabel || "Confirm"}</button>
          </div>
        </div></div>`);
      const done = v => { document.removeEventListener("keydown", onKey, true); m.remove(); if (prev && prev.focus) prev.focus(); resolve(v); };
      const onKey = e => {
        if (e.key === "Escape") { e.stopPropagation(); done(false); }
        if (e.key === "Tab") { // focus trap
          const f = $$("button", m); const i = f.indexOf(document.activeElement);
          if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); }
          else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
        }
      };
      m.addEventListener("click", e => {
        if (e.target === m) done(false);
        const a = e.target.closest("[data-a]"); if (a) done(a.dataset.a === "ok");
      });
      document.addEventListener("keydown", onKey, true);
      document.body.appendChild(m);
      m.querySelector('[data-a="ok"]').focus();
    });
  }

  /* ---------- drawer ---------- */
  let drawerEl = null, scrimEl = null, drawerPrev = null;
  function closeDrawer() {
    if (drawerEl) { drawerEl.remove(); scrimEl.remove(); drawerEl = scrimEl = null; document.removeEventListener("keydown", drawerKey); if (drawerPrev && drawerPrev.focus) drawerPrev.focus(); }
  }
  function drawerKey(e) { if (e.key === "Escape" && !$(".modal-scrim")) closeDrawer(); }
  /** openDrawer({title, sub, body(raw), foot(raw)}) -> drawer element */
  function openDrawer(o) {
    closeDrawer();
    drawerPrev = document.activeElement;
    scrimEl = el(`<div class="scrim"></div>`);
    scrimEl.onclick = closeDrawer;
    drawerEl = el(html`<aside class="drawer" role="dialog" aria-modal="true" aria-label="${o.title}">
      <div class="drawer-head"><div class="grow"><h2 class="drawer-title">${o.title}</h2>${o.sub ? o.sub : raw("")}</div>
        <button class="btn ghost icon" data-close aria-label="Close">${icon("x")}</button></div>
      <div class="drawer-body">${o.body || raw("")}</div>
      ${o.foot ? html`<div class="drawer-foot">${o.foot}</div>` : raw("")}
    </aside>`);
    drawerEl.querySelector("[data-close]").onclick = closeDrawer;
    document.body.appendChild(scrimEl);
    document.body.appendChild(drawerEl);
    document.addEventListener("keydown", drawerKey);
    drawerEl.querySelector("[data-close]").focus();
    return drawerEl;
  }


  /* ---------- QR (qrcode-generator, MIT) ---------- */
  function qrSvg(text, px) {
    const q = qrcode(0, "M");
    q.addData(text);
    q.make();
    const n = q.getModuleCount();
    let r = "";
    for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (q.isDark(y, x)) r += `<rect class="m" x="${x}" y="${y}" width="1.02" height="1.02"/>`;
    return raw(`<div class="qr"><svg width="${px}" height="${px}" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges" role="img" aria-label="QR code">${r}</svg></div>`);
  }

  /* ---------- general modal (custom content) ---------- */
  /** openModal({title, body(raw), foot(raw), wide}) -> {el, close}. Escape/scrim closes. */
  function openModal(o) {
    const prev = document.activeElement;
    const m = el(html`<div class="modal-scrim" role="presentation"><div class="modal ${o.wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-labelledby="gm-t">
      <div class="modal-head row"><h2 class="modal-title grow" id="gm-t">${o.title}</h2><button class="btn ghost icon sm" data-close aria-label="Close">${icon("x", "sm")}</button></div>
      <div class="modal-body">${o.body || raw("")}</div>${o.foot ? html`<div class="modal-foot">${o.foot}</div>` : raw("")}</div></div>`);
    const onKey = e => { if (e.key === "Escape" && document.querySelectorAll(".modal-scrim").length === 1) { e.stopPropagation(); close(); } };
    function close() { document.removeEventListener("keydown", onKey, true); m.remove(); if (o.onClose) o.onClose(); if (prev && prev.focus) prev.focus(); }
    m.addEventListener("mousedown", e => { if (e.target === m) close(); });
    m.querySelector("[data-close]").onclick = close;
    document.addEventListener("keydown", onKey, true);
    document.body.appendChild(m);
    const f = m.querySelector("input, button:not([data-close])"); if (f) f.focus();
    return { el: m, close };
  }

  /* ---------- clipboard ---------- */
  async function copy(text, label) {
    try { await navigator.clipboard.writeText(text); toast((label || "Value") + " copied to clipboard"); }
    catch (e) {
      const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); toast((label || "Value") + " copied to clipboard"); } catch (_) { toast("Copy failed", "error"); }
      ta.remove();
    }
  }

  /* ---------- tooltip for charts ---------- */
  let tipEl = null;
  function tip(x, y, markup) {
    if (!tipEl) { tipEl = el(`<div class="chart-tip"></div>`); document.body.appendChild(tipEl); }
    tipEl.innerHTML = markup.__raw !== undefined ? markup.__raw : esc(markup);
    tipEl.style.display = "block";
    const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    let left = x + 12, top = y - h - 8;
    if (left + w > window.innerWidth - 8) left = x - w - 12;
    if (top < 8) top = y + 16;
    tipEl.style.left = left + "px"; tipEl.style.top = top + "px";
  }
  function hideTip() { if (tipEl) tipEl.style.display = "none"; }

  /* ---------- uPlot wrapper (charts read colours from tokens) ---------- */
  function tok(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  /**
   * timeChart(container, {t: ms[], series: [{label, data, color: "--token"}], height, bars, onSelect(fromMs,toMs), label})
   * Returns {destroy()}. Re-renders on container resize.
   */
  function timeChart(container, o) {
    const font = `${tok("--fs-11")} ${tok("--font-sans")}`;
    const axisStroke = tok("--c-text-muted"), grid = tok("--c-chart-grid");
    const xs = o.t.map(v => v / 1000);
    const step = xs.length > 1 ? xs[1] - xs[0] : 60;
    const series = [{}].concat(o.series.map(s => {
      const c = tok(s.color);
      return o.bars
        ? { label: s.label, stroke: c, fill: c, width: 0, paths: uPlot.paths.bars({ size: [0.82, 64], align: 1 }), points: { show: false } }
        : { label: s.label, stroke: c, width: 1.5, fill: c + "1f", points: { show: false } };
    }));
    const opts = {
      width: Math.max(200, container.clientWidth), height: o.height || 200,
      padding: [8, 8, 0, 0],
      legend: { show: false },
      cursor: { drag: { x: !!o.onSelect, y: false, setScale: false }, points: { show: !o.bars, size: 6 }, y: false },
      scales: { x: { time: true, range: o.bars ? (u, min, max) => [min, max + step] : undefined }, y: { range: (u, min, max) => [0, niceMax(Math.max(max, 1))] } },
      axes: [
        { stroke: axisStroke, font, grid: { show: false }, ticks: { stroke: grid, size: 4 }, space: 80 },
        { stroke: axisStroke, font, grid: { stroke: grid, width: 1 }, ticks: { show: false }, size: 44, space: 24, values: (u, v) => v.map(compact) },
      ],
      series,
      hooks: {
        setCursor: [u => {
          const i = u.cursor.idx;
          if (i === null || i === undefined || u.cursor.left < 0) { hideTip(); return; }
          const r = u.over.getBoundingClientRect();
          const t0 = o.t[i];
          const head = o.bars ? `${absTime(t0)} – ${absTime(t0 + step * 1000)}` : absTime(t0);
          tip(r.left + u.cursor.left, r.top + u.cursor.top, html`<div>${head}</div>${o.series.map((s, k) => html`<div>${s.label}: <b class="num">${num(u.data[k + 1][i] || 0)}</b></div>`)}`);
        }],
        setSelect: [u => {
          if (!o.onSelect || u.select.width < 3) return;
          const a = u.posToVal(u.select.left, "x"), b = u.posToVal(u.select.left + u.select.width, "x");
          u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
          hideTip();
          o.onSelect(Math.round(a * 1000), Math.round(b * 1000));
        }],
      },
    };
    container.innerHTML = "";
    const plot = new uPlot(opts, [xs].concat(o.series.map(s => s.data)), container);
    plot.root.setAttribute("role", "img");
    plot.root.setAttribute("aria-label", o.label || "Chart");
    plot.over.addEventListener("mouseleave", hideTip);
    let w = container.clientWidth;
    const ro = new ResizeObserver(() => { const nw = container.clientWidth; if (nw && Math.abs(nw - w) > 2) { w = nw; plot.setSize({ width: nw, height: opts.height }); } });
    ro.observe(container);
    return { destroy() { ro.disconnect(); plot.destroy(); hideTip(); } };
  }
  function niceMax(v) {
    if (v <= 4) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const f = v / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
  }

  /** Horizontal bar list. rows [{key,count}] */
  function barList(rows, opts) {
    opts = opts || {};
    if (!rows || !rows.length) return html`<div class="empty">${opts.empty || "No data in this time range."}</div>`;
    const max = Math.max(...rows.map(r => r.count), 1);
    return html`<div class="bar-list">${rows.map(r => html`<div class="bar-item ${opts.clickable ? "clickable" : ""}" ${raw(opts.clickable ? `tabindex="0" data-key="${esc(r.key)}"` : "")}>
      <span class="ellipsis ${opts.mono ? "mono" : ""}" title="${r.key}">${r.key === "" || r.key === null ? "(empty)" : r.key}</span><span class="num secondary">${num(r.count)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${((r.count / max) * 100).toFixed(1)}%"></div></div></div>`)}</div>`;
  }

  function skeleton(lines) {
    const w = ["w80", "w60", "w40"];
    let s = ""; for (let i = 0; i < (lines || 4); i++) s += `<span class="skel ${w[i % 3]}"></span>`;
    return raw(`<div class="skel-block">${s}</div>`);
  }
  function empty(title, text) { return html`<div class="empty"><strong>${title}</strong>${text || ""}</div>`; }

  /* ---------- JSON highlight ---------- */
  function jsonHtml(obj) {
    const s = esc(JSON.stringify(obj, null, 2));
    return s.replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi, (m0, str, colon, bool) => {
      if (str) return colon ? `<span class="jk">${str}</span>${colon}` : `<span class="js">${str}</span>`;
      if (bool) return `<span class="jb">${m0}</span>`;
      if (m0 === "null") return `<span class="jz">null</span>`;
      return `<span class="jn">${m0}</span>`;
    });
  }

  /* ---------- polling that pauses when hidden ---------- */
  /** poll(fn, ms) -> stop(). Calls fn immediately is caller's job. Skips while document.hidden. */
  function poll(fn, ms) {
    let t = null, stopped = false;
    const tick = async () => {
      if (stopped) return;
      if (!document.hidden) { try { await fn(); } catch (e) { /* surfaced by fn */ } }
      if (!stopped) t = setTimeout(tick, ms);
    };
    t = setTimeout(tick, ms);
    const onVis = () => { if (!document.hidden && !stopped) { clearTimeout(t); tick(); } };
    document.addEventListener("visibilitychange", onVis);
    return () => { stopped = true; clearTimeout(t); document.removeEventListener("visibilitychange", onVis); };
  }

  /* ---------- validation ---------- */
  const reIPv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  function isIPv4(v) { return reIPv4.test(v); }
  function isCIDR(v) { const [a, b] = v.split("/"); return b !== undefined && isIPv4(a) && /^\d+$/.test(b) && +b >= 0 && +b <= 32; }
  function isIPv6(v) { return /^[0-9a-f:]+$/i.test(v) && v.includes(":") && v.split(":").length <= 8; }
  function isDomain(v) { return /^(?=.{1,253}$)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i.test(v); }
  function indicatorKind(v) {
    v = (v || "").trim();
    if (isCIDR(v)) return "cidr";
    if (isIPv4(v) || isIPv6(v)) return "ip";
    if (isDomain(v)) return "domain";
    return null;
  }

  window.U = { esc, raw, html, el, icon, $, $$, num, compact, bytes, absTime, timeOnly, dateOnly, rel, relHtml, sev, SEVS,
    toast, confirmModal, openModal, qrSvg, openDrawer, closeDrawer, copy, tip, hideTip, timeChart, tok, barList, skeleton, empty, jsonHtml, poll, indicatorKind, niceMax };
})();
