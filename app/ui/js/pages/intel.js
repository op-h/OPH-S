/* Threat Intel — feeds, manual blocklist and allowlist. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num } = U;
  const KIND_LABEL = { domains: "Domains", hosts: "Hosts file", urls: "URLs", ips: "IP addresses", cidr: "IP ranges", oui: "MAC vendors", popular: "Top sites" };
  const FEED_NOTE = { tranco: "False-positive guard: entries on the 20,000 most-used sites are ignored unless the site hosts many listed pages (a hosting platform)." };

  function mount(root) {
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Threat Intel</h1><p class="page-desc">Open threat-intelligence lists that OPH checks every DNS lookup and connection against, plus your own block and allow decisions. Your Allowlist always wins.</p></div>
        <button class="btn primary" id="i-update">${icon("refresh", "sm")} Update now</button></div>
      <div id="i-body">${U.skeleton(6)}</div></div>`.__raw;
    let st = null, pollStop = null;

    const load = async () => {
      try { st = await API.intelStatus(); } catch (e) { $("#i-body").innerHTML = html`<div class="callout bad">${e.message}</div>`.__raw; return; }
      if ($("#i-body")) render();
    };
    function render() {
      $("#i-body").innerHTML = html`
        <section class="panel" style="margin-bottom:16px"><div class="panel-head"><h2 class="panel-title">Feeds</h2>
          <span class="panel-sub">${st.updating ? html`<span class="status-inline"><span class="dot warn"></span>Updating…</span>` : html`${num(st.total)} indicators loaded`}</span></div>
          <div class="table-wrap"><table class="t"><thead><tr><th style="width:56px">On</th><th>Feed</th><th>Type</th><th class="num">Entries</th><th>Last update</th><th>Status</th></tr></thead><tbody>
          ${st.feeds.filter(f => !["adult", "vpn"].includes(f.category)).map(f => html`<tr><td><label class="toggle" title="${f.enabled ? "Disable" : "Enable"} ${f.name}"><input type="checkbox" data-feed="${f.id}" ${raw(f.enabled ? "checked" : "")} aria-label="Enable ${f.name}"><span class="track"></span></label></td>
            <td><div>${f.name}</div><div class="mono muted ellipsis" style="max-width:520px;font-size:var(--fs-11)" title="${f.url}">${f.url}</div>${FEED_NOTE[f.id] ? html`<div class="secondary" style="font-size:var(--fs-11)">${FEED_NOTE[f.id]}</div>` : raw("")}</td>
            <td class="secondary">${KIND_LABEL[f.kind] || f.kind}</td><td class="num">${num(f.entries)}</td><td class="nowrap">${U.relHtml(f.last_update)}</td>
            <td>${f.last_error ? html`<span class="tag bad" title="${f.last_error}">Error</span> <span class="secondary" style="font-size:var(--fs-11)">${f.last_error}</span>` : f.enabled ? html`<span class="tag ok">OK</span>` : html`<span class="tag">Off</span>`}</td></tr>`)}
          ${st.feeds.some(f => ["adult", "vpn"].includes(f.category)) ? html`<tr class="subhead"><td colspan="6"><b>Content categories</b> <span class="muted">· Used only for the PD and VPN search filters; never raise threat alerts.</span></td></tr>
          ${st.feeds.filter(f => ["adult", "vpn"].includes(f.category)).map(f => html`<tr><td><label class="toggle" title="${f.enabled ? "Disable" : "Enable"} ${f.name}"><input type="checkbox" data-feed="${f.id}" ${raw(f.enabled ? "checked" : "")} aria-label="Enable ${f.name}"><span class="track"></span></label></td>
            <td><div>${f.name} <span class="tag">${f.id === "pd" ? "PD" : f.category}</span></div><div class="mono muted ellipsis" style="max-width:520px;font-size:var(--fs-11)" title="${f.url}">${f.url}</div></td>
            <td class="secondary">${f.category === "adult" ? "Adult sites" : f.category === "vpn" ? "VPN / proxy services" : f.category}</td><td class="num">${num(f.entries)}</td><td class="nowrap">${U.relHtml(f.last_update)}</td>
            <td>${f.last_error ? html`<span class="tag bad" title="${f.last_error}">Error</span>` : f.enabled ? html`<span class="tag ok">OK</span>` : html`<span class="tag">Off</span>`}</td></tr>`)}` : raw("")}
          </tbody></table></div>
          <div class="t-more">${icon("info", "sm")} URLhaus needs a free abuse.ch Auth-Key. Add it in <a href="#/settings">Settings &rsaquo; Threat intel</a>. Feeds refresh automatically on the interval set there.</div></section>
        <div class="grid c2">${listPanel("block", "Blocklist", "Always treated as dangerous: blocked by OPH DNS and, for IPs, by Windows Firewall.", st.manual_block)}${listPanel("allow", "Allowlist", "Never alerted on or blocked, even if a feed lists it. Use it for false positives.", st.manual_allow)}</div>`.__raw;

      $$("[data-feed]").forEach(c => c.addEventListener("change", async () => {
        try { st = await API.feedToggle(c.dataset.feed, c.checked); render(); U.toast(`${c.checked ? "Enabled" : "Disabled"} feed`); }
        catch (e) { c.checked = !c.checked; U.toast(e.message, "error"); }
      }));
      $$("form[data-list]").forEach(form => {
        const list = form.dataset.list, inp = form.querySelector("[name=value]"), err = form.querySelector(".field-error");
        inp.addEventListener("input", () => { inp.classList.remove("invalid"); err.textContent = ""; });
        form.addEventListener("submit", async e => {
          e.preventDefault();
          const v = inp.value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
          if (!U.indicatorKind(v)) { inp.classList.add("invalid"); err.textContent = "Enter a domain (example.com), an IP (203.0.113.5) or a CIDR range (203.0.113.0/24)."; inp.focus(); return; }
          try { st = await API.listAdd(list, v, form.querySelector("[name=note]").value.trim()); render(); U.toast(`Added ${v} to the ${list === "block" ? "Blocklist" : "Allowlist"}`); }
          catch (er) { inp.classList.add("invalid"); err.textContent = er.message; }
        });
      });
      $$("[data-remove]").forEach(b => b.addEventListener("click", async () => {
        const [list, value] = [b.dataset.list, b.dataset.remove];
        const ok = await U.confirmModal({ title: `Remove from ${list === "block" ? "Blocklist" : "Allowlist"}?`, confirmLabel: "Remove", danger: list === "allow",
          body: list === "block" ? html`<p><span class="mono">${value}</span> will no longer be blocked unless a threat feed lists it. Any OPH firewall rule for it is deleted.</p>`
            : html`<p><span class="mono">${value}</span> will be checked against threat feeds again and may raise alerts or be blocked.</p>` });
        if (!ok) return;
        try { st = await API.listRemove(list, value); render(); U.toast("Removed " + value); } catch (e) { U.toast(e.message, "error"); }
      }));
    }
    function listPanel(id, title, desc, rows) {
      return html`<section class="panel"><div class="panel-head"><div><h2 class="panel-title">${title}</h2><div class="panel-sub">${desc}</div></div><span class="badge neutral">${num(rows.length)}</span></div>
        <form class="panel-body" data-list="${id}" novalidate style="border-bottom:1px solid var(--c-border)"><div class="row" style="align-items:flex-start">
          <input class="input mono grow" name="value" placeholder="domain, IP or CIDR" aria-label="${title} value" spellcheck="false">
          <input class="input grow" name="note" placeholder="Note (optional)" aria-label="Note">
          <button class="btn ${id === "block" ? "danger" : ""}" type="submit">${icon("plus", "sm")} Add</button></div><div class="field-error" style="margin-top:4px"></div></form>
        ${rows.length ? html`<div class="table-wrap" style="max-height:420px"><table class="t"><thead><tr><th>Value</th><th>Type</th><th>Note</th><th>Added</th><th></th></tr></thead><tbody>
          ${rows.map(r => html`<tr><td class="mono">${r.value}</td><td class="secondary">${r.kind}</td><td class="secondary ellipsis" style="max-width:200px" title="${r.note}">${r.note || "—"}</td><td class="nowrap">${U.relHtml(r.added)}</td>
            <td class="right"><button class="btn ghost icon sm" data-list="${id}" data-remove="${r.value}" aria-label="Remove ${r.value}" title="Remove">${icon("trash", "sm")}</button></td></tr>`)}</tbody></table></div>`
          : U.empty(`${title} is empty.`, id === "block" ? "Add a domain or IP to always block it." : "Add trusted domains here to silence false positives.")}</section>`;
    }

    $("#i-update").onclick = async () => {
      const b = $("#i-update"); b.disabled = true;
      try {
        st = await API.intelUpdate(); render(); U.toast("Feed update started");
        if (pollStop) pollStop();
        let n = 0;
        pollStop = U.poll(async () => { await load(); if ((st && !st.updating) || ++n > 40) { pollStop(); pollStop = null; b.disabled = false; } }, 3000);
        if (!st.updating) b.disabled = false;
      } catch (e) { U.toast(e.message, "error"); b.disabled = false; }
    };
    load();
    return () => { if (pollStop) pollStop(); };
  }

  window.PAGES.intel = { title: "Threat Intel", mount };
})();
