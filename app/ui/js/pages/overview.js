/* Overview — security posture at a glance. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num } = U;
  const SEV_COLOR = { critical: "--c-sev-critical", high: "--c-sev-high", medium: "--c-sev-medium", low: "--c-sev-low", info: "--c-sev-info" };

  function mount(root) {
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Overview</h1><p class="page-desc">Last 24 hours across this PC, every device that uses OPH DNS, and all connected agents.</p></div>
        <button class="btn" id="o-refresh">${icon("refresh", "sm")} Refresh</button></div>
      <div id="o-body">${U.skeleton(6)}</div></div>`.__raw;
    let chart = null;
    const load = async () => {
      let o, lk = null;
      try { [o, lk] = await Promise.all([API.overview(), PAGES.leaks ? PAGES.leaks.statusSafe() : null]); }
      catch (e) { $("#o-body").innerHTML = html`<div class="callout bad"><strong>Could not load overview.</strong> ${e.message}</div>`.__raw; return; }
      if (!$("#o-body")) return;
      if (chart) { chart.destroy(); chart = null; }
      render(o, lk);
      chart = U.timeChart($("#o-chart"), {
        t: o.series.map(p => p.t), height: 220, label: "Events over time",
        series: [{ label: "All events", data: o.series.map(p => p.total), color: "--c-chart-1" }, { label: "Medium and above", data: o.series.map(p => p.alerts), color: "--c-chart-2" }],
      });
    };
    $("#o-refresh").onclick = load;
    load();
    const stop = U.poll(load, 30000);
    return () => { stop(); if (chart) chart.destroy(); };
  }

  function kpi(label, value, sub, cls) {
    return html`<div class="kpi ${cls || ""}"><div class="kpi-label">${label}</div><div class="kpi-value">${value}</div><div class="kpi-sub">${sub}</div></div>`;
  }

  function coverageKpi(lk) {
    if (!lk || !lk.coverage) return html`<a class="kpi" href="#/leaks"><div class="kpi-label">Protection coverage</div><div class="kpi-value">—</div><div class="kpi-sub">Leak Check unavailable</div></a>`;
    const c = lk.coverage, bad = (c.leaking || 0) + (c.quiet || 0);
    return html`<a class="kpi ${c.leaking ? "alert" : c.quiet ? "warn" : ""}" href="#/leaks" title="Open Leak Check"><div class="kpi-label">Protection coverage</div>
      <div class="kpi-value">${num(c.covered)}<span class="unit"> / ${num(c.total)} devices</span></div>
      <div class="kpi-sub">${bad ? `${num(c.leaking || 0)} leaking · ${num(c.quiet || 0)} quiet` : "Every online device uses OPH-S"}</div></a>`;
  }

  function render(o, lk) {
    const sevOrder = ["critical", "high", "medium", "low", "info"];
    const sevMap = Object.fromEntries((o.severity || []).map(s => [s.key, s.count]));
    const sevTotal = sevOrder.reduce((s, k) => s + (sevMap[k] || 0), 0) || 1;
    $("#o-body").innerHTML = html`
      <div class="kpis k7">
        ${kpi("Events", num(o.events_24h), "Collected in the last 24 hours")}
        ${kpi("Open alerts", num(o.alerts_open), o.alerts_open ? "Waiting for your decision" : "Nothing needs attention", o.alerts_open ? "alert" : "")}
        ${kpi("Blocked", num(o.blocked_24h), o.protection_mode === "block" ? "DNS lookups sinkholed, 24 h" : "Warn mode: only manual blocks apply")}
        ${kpi("Devices", html`${num(o.devices_online)}<span class="unit"> / ${num(o.devices_total)}</span>`, "Online now / seen on the LAN")}
        ${coverageKpi(lk)}
        ${kpi("Agents", num(o.agents_online), "Remote PCs and phones online")}
        ${kpi("Threat indicators", U.compact(o.intel_entries), "Domains, IPs and ranges loaded")}
      </div>
      <div class="grid c-2-1" style="margin-bottom:16px">
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Events over time</h2>
          <div class="chart-legend"><span><span class="sw" style="background:var(--c-chart-1)"></span>All events</span><span><span class="sw" style="background:var(--c-chart-2)"></span>Medium and above</span></div></div>
          <div class="panel-body"><div id="o-chart" style="min-height:220px"></div></div></section>
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Severity</h2><span class="panel-sub">24 h</span></div>
          <div class="panel-body">
            <div class="stack-bar" role="img" aria-label="Severity breakdown">${sevOrder.map(k => sevMap[k] ? raw(`<span style="width:${(sevMap[k] / sevTotal * 100).toFixed(2)}%;background:var(${SEV_COLOR[k]})" title="${k}: ${sevMap[k]}"></span>`) : raw(""))}</div>
            <div class="legend" style="grid-template-columns:1fr">${sevOrder.map(k => html`<a class="legend-item" href="#/search?q=${encodeURIComponent("severity=" + k)}">${U.sev(k)}<span class="num secondary">${num(sevMap[k] || 0)}</span></a>`)}</div>
            <p class="field-help" style="margin-top:12px">Medium and above usually deserve a look. Info is routine activity.</p>
          </div></section>
      </div>
      <div class="grid c3" style="margin-bottom:16px">
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Top domains</h2><a href="#/search?q=${encodeURIComponent("source=dns | stats count by domain")}" class="panel-sub">Open in Search</a></div>
          <div class="panel-body flush" id="o-dom">${U.barList(o.top_domains, { clickable: true, mono: true, empty: "No DNS lookups yet. Point devices at OPH DNS to see them." })}</div></section>
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Top hosts</h2><a href="#/search?q=${encodeURIComponent("| stats count by host")}" class="panel-sub">Open in Search</a></div>
          <div class="panel-body flush" id="o-host">${U.barList(o.top_hosts, { clickable: true, mono: true })}</div></section>
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Protection</h2></div>
          <div class="panel-body"><dl class="kv">
            <dt>Mode</dt><dd>${o.protection_mode === "block" ? html`<span class="pill block">Block</span> threats are blocked automatically` : html`<span class="pill warn">Warn</span> you decide on each alert`}</dd>
            <dt>DNS resolver</dt><dd><span class="status-inline"><span class="dot ${o.dns_running ? "ok" : "bad"}"></span>${o.dns_running ? "Running" : "Stopped"}</span></dd>
            <dt>Threat indicators</dt><dd class="num">${num(o.intel_entries)}</dd>
            <dt>Agents online</dt><dd class="num">${num(o.agents_online)}</dd>
          </dl><p class="field-help" style="margin-top:12px">Change the mode in <a href="#/settings">Settings</a>.</p></div></section>
      </div>
      <section class="panel"><div class="panel-head"><h2 class="panel-title">Open alerts</h2><a href="#/alerts" class="panel-sub">View all alerts</a></div>
        <div class="panel-body flush">${alertTable(o.recent_alerts)}</div></section>`.__raw;

    $$("#o-dom .bar-item").forEach(b => b.addEventListener("click", () => APP.go("search", { q: "domain=" + b.dataset.key })));
    $$("#o-host .bar-item").forEach(b => b.addEventListener("click", () => APP.go("search", { q: "host=" + b.dataset.key })));
    $$("[data-decide]").forEach(b => b.addEventListener("click", async e => {
      e.stopPropagation();
      const a = o.recent_alerts.find(x => x.id === +b.dataset.id);
      if (await PAGES.alerts.decide(a, b.dataset.decide)) { APP.refreshStatus(); APP.go("overview"); }
    }));
    $$("#o-alerts tr[data-id]").forEach(tr => {
      const go = () => APP.go("alerts", { id: tr.dataset.id });
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", e => { if (e.key === "Enter") go(); });
    });
  }

  function alertTable(list) {
    if (!list || !list.length) return U.empty("No open alerts.", "Dangerous lookups and connections will appear here for you to decide on.");
    return html`<div class="table-wrap"><table class="t" id="o-alerts"><thead><tr><th>Severity</th><th>Alert</th><th>Indicator</th><th>Device</th><th>Feed</th><th class="num">Hits</th><th>Last seen</th><th></th></tr></thead><tbody>
      ${list.map(a => html`<tr class="clickable" tabindex="0" data-id="${a.id}">
        <td>${U.sev(a.severity)}</td><td>${a.title}</td><td class="mono ellipsis" style="max-width:260px" title="${a.indicator}">${a.indicator}</td>
        <td class="mono">${a.host}</td><td class="secondary">${a.feed}</td><td class="num">${num(a.count)}</td><td class="nowrap">${U.relHtml(a.last_ts)}</td>
        <td class="right nowrap">${a.indicator_type !== "signature" ? html`<button class="btn sm" data-decide="block" data-id="${a.id}">${icon("ban", "sm")} Block</button> ` : raw("")}<button class="btn sm ghost" data-decide="allow" data-id="${a.id}">Allow</button></td>
      </tr>`)}</tbody></table></div>`;
  }

  window.PAGES.overview = { title: "Overview", mount };
})();
