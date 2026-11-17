/* Router, app-bar status and lifecycle. Pages register in window.PAGES[name] = { title, mount(root, params) -> cleanup? } */
(function () {
  "use strict";
  const { $, $$ } = U;
  const main = $("#main");
  let cleanup = null;
  let current = null;

  function parseHash() {
    const h = location.hash.replace(/^#\/?/, "");
    const [path, qs] = h.split("?");
    const params = {};
    if (qs) new URLSearchParams(qs).forEach((v, k) => (params[k] = v));
    return { name: path || "search", params };
  }

  function route() {
    const { name, params } = parseHash();
    const alias = { agents: "devices" };
    const want = alias[name] || name;
    const page = window.PAGES[want] ? want : "search";
    if (cleanup) { try { cleanup(); } catch (e) { console.error(e); } cleanup = null; }
    U.closeDrawer(); U.hideTip();
    current = page;
    $$("#nav a").forEach(a => {
      const on = a.dataset.route === page;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    document.title = `${window.PAGES[page].title} · OPH-S`;
    main.innerHTML = "";
    main.scrollTop = 0;
    try { cleanup = window.PAGES[page].mount(main, params) || null; }
    catch (e) { console.error(e); main.innerHTML = `<div class="page"><div class="callout bad">${U.esc(e.message)}</div></div>`; }
  }

  window.APP = {
    go(name, params) {
      const qs = params ? "?" + new URLSearchParams(params).toString() : "";
      const target = "#/" + name + qs;
      if (location.hash === target) route(); else location.hash = target;
    },
    refreshStatus,
    info: null,
    icons: null,
    setIcon,
    loadIcons,
  };

  /** Icon concepts live in icons/index.json + icons/<id>.svg. Missing files fall back to the built-in shield. */
  async function loadIcons() {
    if (APP.icons) return APP.icons;
    try {
      const r = await fetch("icons/index.json", { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      const list = await r.json();
      APP.icons = Array.isArray(list) ? list : [];
    } catch (e) { APP.icons = []; }
    return APP.icons;
  }
  async function setIcon(id) {
    const box = $("#brand-icon");
    const icons = await loadIcons();
    if (id && icons.find(i => i.id === id)) {
      const img = new Image(20, 20);
      img.alt = "";
      img.onload = () => { box.innerHTML = ""; box.appendChild(img); };
      img.onerror = () => { box.innerHTML = '<svg class="i brand-mark" aria-hidden="true"><use href="#i-shield"/></svg>'; };
      img.src = "icons/" + encodeURIComponent(id) + ".svg";
    } else box.innerHTML = '<svg class="i brand-mark" aria-hidden="true"><use href="#i-shield"/></svg>';
  }

  async function refreshStatus() {
    try {
      const o = await API.overview();
      const pill = $("#mode-pill");
      pill.innerHTML = (o.protection_mode === "block" ? "Block" : "Warn") + '<span class="long">&nbsp;mode</span>';
      pill.className = "pill " + (o.protection_mode === "block" ? "block" : "warn");
      pill.title = o.protection_mode === "block" ? "Threats are blocked automatically" : "Threats raise alerts; you decide what to block";
      const dns = $("#dns-status");
      dns.querySelector(".dot").className = "dot " + (o.dns_running ? "ok" : "bad");
      dns.title = o.dns_running ? "DNS resolver running" : "DNS resolver stopped";
      if (typeof o.network_monitoring === "boolean" && !monBusy) renderMon(o.network_monitoring);
      const b = $("#nav-alerts");
      if (o.alerts_open > 0) { b.textContent = o.alerts_open > 99 ? "99+" : String(o.alerts_open); b.classList.remove("hidden"); }
      else b.classList.add("hidden");
    } catch (e) { /* status bar is best effort */ }
    try {
      const lk = await API.leakStatus(), n = lk.leaks.filter(l => l.status === "open" && l.severity !== "info").length, lb = $("#nav-leaks");
      if (n > 0) { lb.textContent = n > 99 ? "99+" : String(n); lb.title = n + " open leaks"; lb.classList.remove("hidden"); } else lb.classList.add("hidden");
    } catch (e) { /* best effort */ }
  }

  /* ---------- network monitoring toggle (top bar) ---------- */
  let monOn = null, monBusy = false, pop = null;
  function renderMon(on) {
    monOn = on;
    const b = $("#mon-pill");
    b.className = "pill mon " + (on ? "on" : "off");
    b.setAttribute("aria-pressed", on ? "true" : "false");
    b.title = on ? "Network monitoring is on. Click to pause." : "Network monitoring is paused. Click to resume.";
    b.innerHTML = on ? '<span class="live" aria-hidden="true"></span>Monitoring<span class="long">&nbsp;on</span>'
      : '<svg class="i" aria-hidden="true"><use href="#i-pause"/></svg>Monitoring<span class="long">&nbsp;paused</span>';
  }
  function closePop() {
    if (!pop) return;
    pop.remove(); pop = null;
    document.removeEventListener("mousedown", outside, true);
    document.removeEventListener("keydown", popKey, true);
  }
  function outside(e) { if (pop && !pop.contains(e.target) && !e.target.closest("#mon-pill")) closePop(); }
  function popKey(e) {
    if (e.key === "Escape") { e.stopPropagation(); closePop(); $("#mon-pill").focus(); return; }
    if (e.key === "Tab" && pop) { // keep focus inside the popover
      const f = Array.from(pop.querySelectorAll("button")); const i = f.indexOf(document.activeElement);
      if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
    }
  }
  async function setMon(on) {
    monBusy = true; renderMon(on);
    try { const r = await API.setMonitoring(on); renderMon(r.network_monitoring); U.toast(r.network_monitoring ? "Network monitoring resumed" : "Network monitoring paused"); }
    catch (e) { renderMon(!on); U.toast("Could not change monitoring: " + e.message, "error"); }
    monBusy = false;
  }
  function onMonClick() {
    if (pop) { closePop(); return; }
    if (monOn === false) { setMon(true); return; }
    pop = U.el(`<div class="mon-pop" role="dialog" aria-modal="false" aria-labelledby="mon-pop-t"><h3 id="mon-pop-t">Pause network monitoring?</h3>
      <p>DNS keeps working for all devices; lookups and connections are not recorded and no alerts are raised until you resume. Manual blocks stay active.</p>
      <div class="row"><button class="btn sm" data-a="cancel">Cancel</button><button class="btn sm primary" data-a="pause">Pause</button></div></div>`);
    $(".mon-wrap").appendChild(pop);
    pop.querySelector('[data-a="cancel"]').onclick = () => { closePop(); $("#mon-pill").focus(); };
    pop.querySelector('[data-a="pause"]').onclick = () => { closePop(); setMon(false); $("#mon-pill").focus(); };
    pop.querySelector('[data-a="pause"]').focus();
    setTimeout(() => { document.addEventListener("mousedown", outside, true); document.addEventListener("keydown", popKey, true); }, 0);
  }

  function tickClock() {
    if (document.hidden) return;
    const d = new Date(), p = n => String(n).padStart(2, "0");
    $("#clock").textContent = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  async function init() {
    try {
      const info = await API.appInfo();
      APP.info = info;
      $("#footer-info").textContent = `v${info.version} · ${info.data_dir}${API.isMock ? " · preview data" : ""}`;
    } catch (e) { $("#footer-info").textContent = "Core unavailable: " + e.message; }
    API.settingsGet().then(s => setIcon(s.icon_style)).catch(() => {});
    $("#mon-pill").addEventListener("click", onMonClick);
    $("#ai-top").addEventListener("click", () => AI.open({ kind: "", data: {}, label: "" }));
    tickClock(); setInterval(tickClock, 1000);
    refreshStatus(); U.poll(refreshStatus, 30000);
    window.addEventListener("hashchange", route);
    route();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
