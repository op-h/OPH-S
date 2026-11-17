/* Alerts — review threat matches and decide: block, allow, dismiss. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num } = U;
  const STATUSES = [["open", "Open"], ["blocked", "Blocked"], ["allowed", "Allowed"], ["dismissed", "Dismissed"], ["all", "All"]];
  let status = "open";

  function consequences(a, action) {
    const ind = html`<span class="mono">${a.indicator}</span>`;
    const t = a.indicator_type;
    if (action === "block") {
      if (t === "domain" || t === "url") return {
        title: "Block this domain?", label: "Block domain", danger: true,
        body: html`<p>${ind} will be blocked:</p><ul>
          <li>Every device that uses OPH DNS gets <span class="mono">0.0.0.0</span> for this domain and all its subdomains, so it cannot load.</li>
          <li>The domain is added to your Blocklist (Threat Intel page). This applies in Warn mode too.</li>
          <li>Devices that don't use OPH DNS, or that use encrypted DNS (DoH/Private DNS), are not covered.</li></ul>
          <p>To undo, reopen the alert or remove the domain from the Blocklist.</p>`,
      };
      if (t === "ip") return {
        title: "Block this IP address?", label: "Block IP", danger: true,
        body: html`<p>${ind} will be blocked:</p><ul>
          <li>The IP is added to the Windows Firewall rule <span class="mono">OPH Sentinel - blocked IPs</span>, which blocks all inbound and outbound traffic with it on this PC. Windows may ask for administrator approval.</li>
          <li>The IP is added to your Blocklist and flagged if any agent connects to it.</li></ul>
          <p>To undo, reopen the alert or remove the IP from the Blocklist. OPH deletes its rule.</p>`,
      };
      return { title: "Block", label: "Block", danger: true, body: html`<p>${ind} will be added to the Blocklist.</p>` };
    }
    if (action === "allow") return {
      title: "Allow and trust this indicator?", label: "Allow", danger: false,
      body: html`<p>${ind} will be added to your Allowlist:</p><ul>
        <li>OPH will no longer alert on it or block it, even when a threat feed lists it.</li>
        <li>Lookups and connections are still logged and searchable.</li></ul>
        <p>Only do this if you are sure it is a false positive, for example a site you use for work.</p>`,
    };
    if (action === "dismiss") return {
      title: "Dismiss this alert?", label: "Dismiss", danger: false,
      body: html`<p>The alert closes and nothing is blocked or allowed. If ${ind} is seen again, a new alert opens.</p>`,
    };
    return { title: "Reopen this alert?", label: "Reopen", danger: false,
      body: html`<p>The alert returns to Open.${raw(a.status === "blocked" ? " The block is removed: the indicator leaves the Blocklist and any OPH firewall rule for it is deleted." : a.status === "allowed" ? " The indicator is removed from the Allowlist." : "")}</p>` };
  }

  /** Shared decision flow (used by Overview too). Returns updated alert or null. */
  async function decide(a, action) {
    if (!a) return null;
    const c = consequences(a, action);
    const ok = await U.confirmModal({ title: c.title, body: c.body, confirmLabel: c.label, danger: c.danger });
    if (!ok) return null;
    try {
      const r = await API.alertDecide(a.id, action);
      U.toast({ block: "Blocked ", allow: "Allowed ", dismiss: "Dismissed alert for ", reopen: "Reopened alert for " }[action] + a.indicator);
      return r;
    } catch (e) { U.toast("Decision failed: " + e.message, "error"); return null; }
  }

  function mount(root, params) {
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Alerts</h1><p class="page-desc">Threat-feed matches and IDS detections. In Warn mode nothing is blocked until you decide. Every decision shows exactly what it will change first.</p></div>
        <button class="btn" id="a-refresh">${icon("refresh", "sm")} Refresh</button></div>
      <div class="tabs" role="tablist" id="a-tabs"></div>
      <section class="panel"><div class="panel-body flush" id="a-body">${U.skeleton(6)}</div></section></div>`.__raw;
    let all = [], counts = null;
    const load = async () => {
      try { [all, counts] = await Promise.all([API.alerts("all"), API.alertCounts().catch(() => null)]); }
      catch (e) { $("#a-body").innerHTML = html`<div class="callout bad">${e.message}</div>`.__raw; return; }
      if (!$("#a-body")) return;
      renderTabs(); renderTable();
      if (params.id) { const a = all.find(x => x.id === +params.id); params.id = null; if (a) openAlert(a); }
    };
    function renderTabs() {
      $("#a-tabs").innerHTML = STATUSES.map(([k, l]) => {
        const c = counts ? counts[k] || 0 : k === "all" ? all.length : all.filter(a => a.status === k).length;
        return html`<button role="tab" aria-selected="${status === k}" class="${status === k ? "active" : ""}" data-s="${k}">${l}<span class="count">${num(c)}</span></button>`.__raw;
      }).join("");
      $$("#a-tabs button").forEach(b => b.onclick = () => { status = b.dataset.s; renderTabs(); renderTable(); });
    }
    function renderTable() {
      const list = status === "all" ? all : all.filter(a => a.status === status);
      const box = $("#a-body");
      if (!list.length) { box.innerHTML = U.empty(status === "open" ? "No open alerts." : "Nothing here.", status === "open" ? "When a device touches a dangerous domain or IP, the alert shows up here." : "Alerts move here after you decide on them.").__raw; return; }
      const shown = list.slice(0, 200);
      box.innerHTML = html`<div class="table-wrap"><table class="t"><thead><tr><th>Severity</th><th>Alert</th><th>Indicator</th><th>Type</th><th>Device</th><th>Feed</th><th class="num">Hits</th><th>First seen</th><th>Last seen</th><th>Status</th></tr></thead><tbody>
        ${shown.map(a => html`<tr class="clickable" tabindex="0" data-id="${a.id}"><td>${U.sev(a.severity)}</td><td>${a.title}</td>
          <td class="mono ellipsis" style="max-width:280px" title="${a.indicator}">${a.indicator}</td><td class="secondary">${a.indicator_type}</td>
          <td class="mono">${a.host}</td><td class="secondary">${a.feed}</td><td class="num">${num(a.count)}</td>
          <td class="nowrap">${U.relHtml(a.ts)}</td><td class="nowrap">${U.relHtml(a.last_ts)}</td><td>${statusTag(a.status)}</td></tr>`)}
        </tbody></table></div>${list.length > 200 ? html`<div class="t-more">Showing the newest 200 of ${num(list.length)}.</div>` : raw("")}`.__raw;
      $$("tr[data-id]", box).forEach(tr => {
        const go = () => openAlert(all.find(a => a.id === +tr.dataset.id));
        tr.addEventListener("click", go);
        tr.addEventListener("keydown", e => { if (e.key === "Enter") go(); });
      });
    }
    function openAlert(a) {
      const btns = [];
      if (a.status === "open") {
        if (a.indicator_type !== "signature") btns.push(html`<button class="btn danger" data-act="block">${icon("ban", "sm")} Block</button>`);
        btns.push(html`<button class="btn" data-act="allow">${icon("check", "sm")} Allow</button>`, html`<button class="btn ghost" data-act="dismiss">Dismiss</button>`);
      } else btns.push(html`<button class="btn" data-act="reopen">${icon("undo", "sm")} Reopen</button>`);
      const d = U.openDrawer({
        title: a.title, sub: html`<div class="row" style="margin-top:4px">${U.sev(a.severity)}${statusTag(a.status)}</div>`,
        body: html`<div class="callout ${a.severity === "critical" || a.severity === "high" ? "bad" : "warn"}">${a.explanation}</div>
          <div><h3 class="section-title">Details</h3><dl class="kv">
            <dt>Indicator</dt><dd class="mono">${a.indicator}</dd><dt>Type</dt><dd>${a.indicator_type}</dd>
            <dt>Matched by</dt><dd>${a.feed}</dd><dt>Device</dt><dd class="mono">${a.host}${a.src_ip && a.src_ip !== a.host ? " (" + a.src_ip + ")" : ""}</dd>
            <dt>Hits</dt><dd class="num">${num(a.count)}</dd><dt>First seen</dt><dd>${U.absTime(a.ts)}</dd><dt>Last seen</dt><dd>${U.absTime(a.last_ts)}</dd>
          </dl></div>
          <div><h3 class="section-title">Investigate</h3><div class="row-wrap">
            <a class="btn sm" href="#/search?q=${encodeURIComponent((a.indicator_type === "ip" ? "dst_ip=" : a.indicator_type === "signature" ? "kind=ids.alert " : "domain=") + (a.indicator_type === "signature" ? "" : a.indicator))}&range=7d">${icon("search", "sm")} Related events</a>
            ${a.src_ip ? html`<a class="btn sm" href="#/search?q=${encodeURIComponent("src_ip=" + a.src_ip)}&range=24h">${icon("monitor", "sm")} Device activity</a>` : raw("")}
            <button type="button" class="btn sm" id="al-ai">${icon("bot", "sm")} Ask AI</button>
          </div></div>`,
        foot: html`${btns}`,
      });
      $("#al-ai", d).onclick = () => AI.open({ kind: "alert", data: { id: a.id }, label: `Alert #${a.id}: ${a.title} · ${a.indicator}` });
      $$("[data-act]", d).forEach(b => b.onclick = async () => {
        const r = await decide(a, b.dataset.act);
        if (r) { U.closeDrawer(); APP.refreshStatus(); load(); }
      });
    }
    $("#a-refresh").onclick = load;
    load();
    return U.poll(load, 20000);
  }

  function statusTag(s) {
    const c = { open: "warn", blocked: "bad", allowed: "ok", dismissed: "" }[s] || "";
    return html`<span class="tag ${c}">${s}</span>`;
  }

  window.PAGES.alerts = { title: "Alerts", mount, decide, statusTag };
})();
