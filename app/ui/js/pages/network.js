/* Network — every device on the router + live connections of this PC. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num } = U;
  let tab = "devices";
  const NO_NAME_HINT = "No name reported — rename it, or use Router → Set up my Deco automatically to import names from the Deco app.";
  const devId = d => d.mac || d.ip;

  async function firewallSetup() {
    const ok = await U.confirmModal({
      title: "Open firewall ports?", confirmLabel: "Open ports",
      body: html`<p>Windows will ask for administrator approval. OPH then adds inbound allow rules for this PC only:</p><ul>
        <li><span class="mono">53/UDP</span>, so LAN devices can use OPH DNS</li><li>the agent ingest TCP port, so remote agents can connect</li><li>the syslog UDP port, so routers and NAS devices can send logs</li></ul>
        <p>No other ports are opened. You can remove the rules later in Windows Defender Firewall (rule "OPH Sentinel - inbound").</p>`,
    });
    if (!ok) return;
    try { const r = await API.firewallSetup(); U.toast(r.message, r.ok ? "" : "error"); }
    catch (e) { U.toast("Firewall setup failed: " + e.message, "error"); }
  }

  function mount(root, params) {
    if (params.tab) tab = params.tab;
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Network</h1><p class="page-desc">Devices on your router and the live connections of this PC.</p></div>
        <div class="row"><button class="btn" id="n-fw">${icon("lock", "sm")} Open firewall ports</button><button class="btn" id="n-refresh">${icon("refresh", "sm")} Refresh</button></div></div>
      <div id="n-head"></div>
      <div class="tabs" role="tablist">
        <button role="tab" data-t="devices">${icon("router", "sm")} Router devices<span class="count" id="n-c-dev"></span></button>
        <button role="tab" data-t="conns">${icon("monitor", "sm")} This PC connections<span class="count" id="n-c-con"></span></button>
      </div>
      <div id="n-body">${U.skeleton(6)}</div></div>`.__raw;
    let stopConn = null, data = null, conns = [], filter = "", editing = false;

    /* Inline rename editor inside `host`. done(devicesResponse | null) runs after Save or Cancel. */
    function renameEditor(host, d, done) {
      editing = true;
      host.innerHTML = html`<div class="row" style="flex-wrap:nowrap"><input class="input mono" data-rn-inp value="${d.hostname || ""}" maxlength="48" spellcheck="false" autocomplete="off" placeholder="Automatic name" aria-label="New name for ${d.hostname || d.ip}" style="max-width:220px">
        <button type="button" class="btn sm primary" data-rn-save>Save</button><button type="button" class="btn sm ghost" data-rn-cancel>Cancel</button></div>
        <div class="field-help" style="margin-top:2px">Leave empty to go back to the automatic name.</div><div class="field-error" data-rn-err role="alert"></div>`.__raw;
      const inp = host.querySelector("[data-rn-inp]"), err = host.querySelector("[data-rn-err]");
      const stop = e => e.stopPropagation();
      host.addEventListener("click", stop); host.addEventListener("keydown", stop);
      const finish = r => { editing = false; host.removeEventListener("click", stop); host.removeEventListener("keydown", stop); done(r); };
      const save = async () => {
        const b = host.querySelector("[data-rn-save]"); b.disabled = true;
        try { const r = await API.deviceRename(devId(d), inp.value.trim()); U.toast(inp.value.trim() ? `Renamed to ${inp.value.trim()}` : "Name reset to automatic"); finish(r); }
        catch (e) { b.disabled = false; inp.classList.add("invalid"); err.textContent = e.message; inp.focus(); }
      };
      inp.addEventListener("input", () => { inp.classList.remove("invalid"); err.textContent = ""; });
      inp.addEventListener("keydown", e => { e.stopPropagation(); if (e.key === "Enter") { e.preventDefault(); save(); } else if (e.key === "Escape") { e.preventDefault(); finish(null); } });
      host.querySelector("[data-rn-save]").onclick = save;
      host.querySelector("[data-rn-cancel]").onclick = () => finish(null);
      inp.focus(); inp.select();
    }
    function applyRename(r) { if (!r) return; data = Object.assign({}, data, r); if (tab === "devices") renderDevices(); }

    const setTab = t => {
      tab = t;
      $$(".tabs [data-t]").forEach(b => { b.classList.toggle("active", b.dataset.t === t); b.setAttribute("aria-selected", b.dataset.t === t); });
      if (stopConn) { stopConn(); stopConn = null; }
      if (t === "devices") renderDevices();
      else { renderConnsShell(); loadConns(); stopConn = U.poll(loadConns, 5000); }
    };
    $$(".tabs [data-t]").forEach(b => b.onclick = () => setTab(b.dataset.t));

    async function loadDevices() {
      try { data = await API.devices(); } catch (e) { data = { error: e.message, devices: [] }; }
      if (!$("#n-head")) return;
      renderHead();
      $("#n-c-dev").textContent = num(data.devices.length);
      if (tab === "devices" && !editing) renderDevices();
    }
    async function renderHead() {
      let dnsOn = null;
      try { const o = await API.overview(); dnsOn = o.dns_running; } catch (e) { /* ignore */ }
      const ip = (data.devices.find(d => d.is_self) || {}).ip || "this PC's IP";
      if (!$("#n-head")) return;
      $("#n-head").innerHTML = html`<div class="kpis" style="grid-template-columns:repeat(4,minmax(0,1fr))">
          <div class="kpi"><div class="kpi-label">Gateway</div><div class="kpi-value mono" style="font-size:var(--fs-16)">${data.gateway || "—"}</div><div class="kpi-sub">Your router</div></div>
          <div class="kpi"><div class="kpi-label">Subnet</div><div class="kpi-value mono" style="font-size:var(--fs-16)">${data.subnet || "—"}</div><div class="kpi-sub">Scanned for devices every 5 minutes</div></div>
          <div class="kpi"><div class="kpi-label">Devices online</div><div class="kpi-value">${num(data.devices.filter(d => d.online).length)}<span class="unit"> / ${num(data.devices.length)}</span></div><div class="kpi-sub">Seen in the neighbour table</div></div>
          <div class="kpi"><div class="kpi-label">OPH DNS resolver</div><div class="kpi-value" style="font-size:var(--fs-16)"><span class="status-inline" style="font-size:var(--fs-14)"><span class="dot ${dnsOn ? "ok" : "bad"}"></span>${dnsOn === null ? "Unknown" : dnsOn ? "Running" : "Stopped"}</span></div><div class="kpi-sub">Listening on port 53</div></div>
        </div>
        <div class="callout" style="margin-bottom:16px"><strong>Monitor every device on the router.</strong> Open your router's admin page, find <em>DHCP</em> / <em>LAN settings</em>, and set the primary DNS server to <span class="mono">${ip}</span>. Devices pick it up after reconnecting to Wi-Fi.
          Every lookup then appears here per device and dangerous sites can be blocked network-wide. Set the secondary DNS to the same IP, or leave it empty; a public secondary lets devices bypass OPH. Run <b>Open firewall ports</b> once so the router's clients can reach this PC.</div>`.__raw;
    }

    function renderDevices() {
      const box = $("#n-body");
      if (!data) { box.innerHTML = U.skeleton(6).__raw; return; }
      if (data.error) { box.innerHTML = html`<div class="callout bad">${data.error}</div>`.__raw; return; }
      if (!data.devices.length) { box.innerHTML = U.empty("No devices discovered yet.", "Discovery reads the LAN neighbour table. Make sure this PC is connected to your home network.").__raw; return; }
      const list = data.devices.slice().sort((a, b) => (b.online - a.online) || (b.alerts_open - a.alerts_open) || ipNum(a.ip) - ipNum(b.ip));
      box.innerHTML = html`<section class="panel"><div class="table-wrap"><table class="t"><thead><tr>
        <th>Status</th><th>Device</th><th>IP address</th><th>MAC address</th><th>Vendor</th><th>First seen</th><th>Last seen</th><th class="num">Lookups 24h</th><th class="num">Blocked 24h</th><th class="num">Open alerts</th></tr></thead><tbody>
        ${list.map(d => html`<tr class="clickable" tabindex="0" data-ip="${d.ip}">
          <td><span class="status-inline"><span class="dot ${d.online ? "ok" : ""}"></span>${d.online ? "Online" : "Offline"}</span></td>
          <td class="nowrap" data-name-cell><span>${d.hostname || html`<span class="muted" title="${NO_NAME_HINT}">Unknown</span>`}</span>
            <button type="button" class="btn ghost icon sm" data-rename="${d.ip}" aria-label="Rename ${d.hostname || d.ip}" title="Rename">${icon("pencil", "sm")}</button> ${d.is_self ? html`<span class="tag info">This PC</span>` : raw("")} ${d.ip === data.gateway ? html`<span class="tag">Router</span>` : raw("")}</td>
          <td class="mono">${d.ip}</td><td class="mono">${d.mac || "—"}</td>
          <td>${d.vendor || (d.randomized_mac ? "" : raw('<span class="muted">—</span>'))} ${d.randomized_mac ? html`<span class="tag" title="The device uses a private, per-network MAC address, so the vendor can't be identified. Phones do this by default.">Randomized MAC</span>` : raw("")}</td>
          <td class="nowrap">${U.relHtml(d.first_seen)}</td><td class="nowrap">${U.relHtml(d.last_seen)}</td>
          <td class="num">${num(d.queries_24h)}</td><td class="num">${d.blocked_24h ? html`<span class="sev-high">${num(d.blocked_24h)}</span>` : "0"}</td>
          <td class="num">${d.alerts_open ? html`<span class="badge">${d.alerts_open}</span>` : "0"}</td></tr>`)}
        </tbody></table></div></section>
        <p class="field-help" style="margin-top:8px">A device with 0 lookups is not using OPH DNS (it has a hard-coded DNS server, or the router change hasn't reached it yet).</p>`.__raw;
      $$("tr[data-ip]", box).forEach(tr => {
        const go = () => openDevice(data.devices.find(d => d.ip === tr.dataset.ip));
        tr.addEventListener("click", go);
        tr.addEventListener("keydown", e => { if (e.key === "Enter" && e.target === tr) go(); });
      });
      $$("[data-rename]", box).forEach(b => b.addEventListener("click", e => {
        e.stopPropagation();
        const d = data.devices.find(x => x.ip === b.dataset.rename);
        renameEditor(b.closest("[data-name-cell]"), d, r => { if (r) applyRename(r); else renderDevices(); });
      }));
    }

    function nameHtml(d) {
      return html`<span>${d.hostname || html`<span class="muted">Unknown</span>`}</span> <button type="button" class="btn ghost sm" id="dd-rename">${icon("pencil", "sm")} Rename</button>
        ${d.hostname ? raw("") : html`<div class="field-help" style="margin-top:2px">${NO_NAME_HINT}</div>`}`;
    }
    async function openDevice(d) {
      const dr = U.openDrawer({
        title: d.hostname || d.ip, sub: html`<div class="row muted mono" style="margin-top:4px;font-size:var(--fs-12)">${d.ip} · ${d.mac || "no MAC"}</div>`,
        body: html`<dl class="kv"><dt>Name</dt><dd id="dd-name">${nameHtml(d)}</dd><dt>Status</dt><dd>${d.online ? "Online" : "Offline"}</dd><dt>Vendor</dt><dd>${d.vendor || (d.randomized_mac ? "Unknown (randomized MAC)" : "Unknown")}</dd>
          <dt>First seen</dt><dd>${U.absTime(d.first_seen)}</dd><dt>Last seen</dt><dd>${U.absTime(d.last_seen)}</dd>
          <dt>Seen by</dt><dd id="dd-seen"><span class="muted">…</span></dd>
          <dt>Lookups 24h</dt><dd class="num">${num(d.queries_24h)}</dd><dt>Blocked 24h</dt><dd class="num">${num(d.blocked_24h)}</dd><dt>Open alerts</dt><dd class="num">${num(d.alerts_open)}</dd></dl>
          <div id="dd-body">${U.skeleton(5)}</div>`,
        foot: html`<button type="button" class="btn" id="dd-ai">${icon("bot", "sm")} Ask AI about this device</button><a class="btn" href="#/search?q=${encodeURIComponent("src_ip=" + d.ip)}&range=24h">${icon("search", "sm")} Open in Search</a>`,
      });
      const bindName = () => {
        const btn = $("#dd-rename", dr); if (!btn) return;
        btn.onclick = () => renameEditor($("#dd-name", dr), d, r => {
          if (r) { applyRename(r); d = r.devices.find(x => x.ip === d.ip) || d; const t = $(".drawer-title", dr); if (t) t.textContent = d.hostname || d.ip; }
          const n = $("#dd-name", dr); if (n) { n.innerHTML = nameHtml(d).__raw; bindName(); $("#dd-rename", dr).focus(); }
        });
      };
      bindName();
      if (PAGES.leaks) PAGES.leaks.statusSafe().then(lk => {
        const box = $("#dd-seen", dr); if (!box) return;
        const ld = lk && Array.isArray(lk.devices) ? lk.devices.find(x => x.ip === d.ip) : null;
        box.innerHTML = ld ? html`${PAGES.leaks.stateChip(ld.state)} ${PAGES.leaks.seenBy(ld.seen_by)} <a href="#/leaks" class="field-help">Leak Check</a>`.__raw : html`<span class="muted">No Leak Check data for this device yet</span>`.__raw;
      });
      $("#dd-ai", dr).onclick = () => AI.open({ kind: "device", data: { ip: d.ip }, label: `Device: ${d.hostname || "unknown"} (${d.ip})` });
      try {
        const det = await API.deviceDetail(d.ip);
        const b = $("#dd-body", dr); if (!b) return;
        b.innerHTML = html`<div><h3 class="section-title">Top domains</h3><div class="panel">${U.barList(det.top_domains, { mono: true, empty: "No DNS lookups from this device." })}</div></div>
          <div><h3 class="section-title">Recent events</h3>${det.recent.length ? html`<div class="panel"><table class="t"><tbody>${det.recent.map(e => html`<tr><td class="nowrap secondary num" title="${U.absTime(e.ts)}">${U.timeOnly(e.ts).slice(0, 8)}</td><td>${U.sev(e.severity)}</td><td class="mono ellipsis" style="max-width:260px" title="${e.message}">${e.message}</td></tr>`)}</tbody></table></div>` : U.empty("No events yet.")}</div>`.__raw;
      } catch (e) { const b = $("#dd-body", dr); if (b) b.innerHTML = html`<div class="callout bad">${e.message}</div>`.__raw; }
    }

    function renderConnsShell() {
      $("#n-body").innerHTML = html`<section class="panel"><div class="panel-head"><div class="row grow"><input class="input" id="c-filter" placeholder="Filter by process, IP, port, domain or verdict" style="width:360px" aria-label="Filter connections" value="${filter}">
        <span class="panel-sub" id="c-meta"></span></div><span class="panel-sub">Refreshes every 5 s while visible</span></div><div id="c-table">${U.skeleton(8)}</div></section>`.__raw;
      $("#c-filter").addEventListener("input", e => { filter = e.target.value; renderConns(); });
    }
    async function loadConns() {
      try { conns = await API.connections(); } catch (e) { const t = $("#c-table"); if (t) t.innerHTML = html`<div class="callout bad">${e.message}</div>`.__raw; return; }
      $("#n-c-con") && ($("#n-c-con").textContent = num(conns.length));
      renderConns();
    }
    function renderConns() {
      const t = $("#c-table"); if (!t) return;
      const f = filter.trim().toLowerCase();
      const order = { malicious: 0, blocked: 1, allowed: 2, ok: 3 };
      const list = conns.filter(c => !f || [c.process, c.remote_ip, c.remote_port, c.domain, c.verdict, c.state, c.local, c.pid].some(v => v !== null && String(v).toLowerCase().includes(f)))
        .sort((a, b) => (order[a.verdict] - order[b.verdict]) || String(a.process).localeCompare(String(b.process)));
      $("#c-meta").textContent = `${num(list.length)} of ${num(conns.length)} connections`;
      if (!list.length) { t.innerHTML = U.empty(conns.length ? "No connections match the filter." : "No active connections.").__raw; return; }
      t.innerHTML = html`<div class="table-wrap" style="max-height:calc(100vh - 380px)"><table class="t"><thead><tr><th>Verdict</th><th>Process</th><th class="num">PID</th><th>Proto</th><th>Local</th><th>Remote</th><th>Domain</th><th>State</th></tr></thead><tbody>
        ${list.slice(0, 200).map(c => html`<tr><td>${verdict(c.verdict)}</td><td>${c.process || "—"}</td><td class="num">${c.pid}</td><td class="secondary">${c.proto.toUpperCase()}</td>
          <td class="mono">${c.local}</td><td class="mono">${c.remote_ip}:${c.remote_port}</td><td class="mono ellipsis" style="max-width:240px" title="${c.domain || ""}">${c.domain || raw('<span class="muted">—</span>')}</td><td class="secondary">${c.state}</td></tr>`)}
        </tbody></table></div>${list.length > 200 ? html`<div class="t-more">Showing 200 of ${num(list.length)}. Use the filter to narrow down.</div>` : raw("")}`.__raw;
    }
    function verdict(v) {
      return html`<span class="tag ${{ malicious: "bad", blocked: "bad", allowed: "ok", ok: "" }[v] || ""}">${{ malicious: "Malicious", blocked: "Blocked", allowed: "Allowed", ok: "OK" }[v] || v}</span>`;
    }

    $("#n-fw").onclick = firewallSetup;
    $("#n-refresh").onclick = () => { loadDevices(); if (tab === "conns") loadConns(); };
    setTab(tab);
    loadDevices();
    const stopDev = U.poll(loadDevices, 60000);
    return () => { stopDev(); if (stopConn) stopConn(); };
  }
  function ipNum(ip) { return ip.split(".").reduce((s, o) => s * 256 + (+o || 0), 0); }

  window.PAGES.network = { title: "Network", mount, firewallSetup };
})();
