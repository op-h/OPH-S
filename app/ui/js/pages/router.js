/* Router — detect the router and guide the user to point its DHCP DNS at OPH-S. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num } = U;

  const FAMILIES = [
    ["tplink-deco", "TP-Link Deco (Deco app)"], ["tplink", "TP-Link Archer (web UI)"], ["asus", "ASUS"], ["netgear", "NETGEAR"],
    ["huawei", "Huawei"], ["zte", "ZTE"], ["mikrotik", "MikroTik"], ["generic", "Other / generic"],
  ];
  let chosen = null;

  const P = (...parts) => html`<span class="path">${parts.map((p, i) => html`${i ? raw('<span class="sep">›</span>') : raw("")}${p}`)}</span>`;
  const ip = v => html`<span class="mono">${v}</span>`;

  function inSubnet(a, gw) {
    if (!a || !gw) return true;
    const x = a.split("."), g = gw.split(".");
    return x.length === 4 && x[0] === g[0] && x[1] === g[1] && x[2] === g[2];
  }

  /** Router-side steps for each family. */
  function routerSteps(f, r) {
    const pc = ip(r.pc_ip);
    const dnsStep = (where) => html`<li><div><h4>Set this PC as the DNS server</h4><p>${where}</p>
      <p>Primary DNS = ${pc}. Leave <strong>Secondary DNS empty</strong> (or set it to ${pc} too). If you put a public server like 8.8.8.8 there, devices quietly use it whenever they like and bypass OPH-S. Save.</p></div></li>`;
    const reserve = (where) => html`<li><div><h4>Reserve this PC's IP address</h4><p>${where}</p><p>Add this PC so it always gets ${pc}. If the address ever changed, every device would lose DNS.${r.reserved_hint ? html` <span class="muted">${r.reserved_hint}</span>` : raw("")}</p></div></li>`;
    switch (f) {
      case "tplink-deco": return [
        reserve(html`Open the Deco app: ${P("More", "Advanced", "Address Reservation")}, then tap <strong>+</strong> and pick this PC.`),
        dnsStep(html`In the Deco app: ${P("More", "Advanced", "DHCP Server")}. Set <strong>Primary DNS</strong> = ${pc} and leave <strong>Secondary DNS</strong> empty.`),
      ];
      case "tplink": return [
        reserve(html`Open ${adminLink(r)} and go to ${P("Advanced", "Network", "DHCP Server", "Address Reservation")}.`),
        dnsStep(html`${P("Advanced", "Network", "DHCP Server")}: set <strong>Primary DNS</strong> = ${pc}, clear <strong>Secondary DNS</strong>.`),
      ];
      case "asus": return [
        reserve(html`Open ${adminLink(r)} and go to ${P("LAN", "DHCP Server", "Manually Assigned IP around the DHCP list")}.`),
        dnsStep(html`${P("LAN", "DHCP Server")}: set <strong>DNS Server 1</strong> = ${pc}, leave DNS Server 2 empty. Turn off <em>Advertise router's IP in addition to user-specified DNS</em> if your firmware has it.`),
      ];
      case "netgear": return [
        reserve(html`Open ${adminLink(r)} and go to ${P("Advanced", "Setup", "LAN Setup", "Address Reservation")}.`),
        dnsStep(html`NETGEAR has no LAN DNS field (LAN Setup only sets the router's own IP). Use ${P("Internet", "Domain Name Server (DNS) Address", "Use These DNS Servers")} with Primary = ${pc}. The router then forwards every device's lookups to OPH-S. In OPH-S, per-device names then show as the router's IP.`),
      ];
      case "huawei": case "zte": return [
        reserve(html`Open ${adminLink(r)}. Look under ${P("LAN", "DHCP", "Static IP / Address Reservation")} (the exact names vary by ISP firmware).`),
        dnsStep(html`${P("LAN", "DHCP Server")} (sometimes ${P("Network", "LAN", "DHCP")}): set <strong>Primary DNS</strong> = ${pc}, clear Secondary DNS. Some ISP-locked units hide this field. If yours does, use the per-device method on the Help page.`),
      ];
      case "mikrotik": return [
        reserve(html`In WinBox or WebFig: ${P("IP", "DHCP Server", "Leases")}, select this PC, then <strong>Make Static</strong>.`),
        dnsStep(html`${P("IP", "DHCP Server", "Networks")}: open your LAN network and set <strong>DNS Servers</strong> = ${pc} (only that entry).`),
      ];
      default: return [
        reserve(html`Open ${adminLink(r)} and look for <em>DHCP reservation</em>, <em>Static lease</em> or <em>Address reservation</em>.`),
        dnsStep(html`Find <em>DHCP server</em> / <em>LAN settings</em> and the fields named <em>DNS server</em>, <em>Primary DNS</em> or <em>DNS 1</em>.`),
      ];
    }
  }
  function adminLink(r) { return r.admin_url ? html`<a href="${r.admin_url}" target="_blank" rel="noopener">${r.admin_url}</a>` : html`the router admin page`; }

  /* ---------- automatic Deco setup state (module-level: survives page changes) ---------- */
  const auto = { pw: "", show: false, remember: true, mode: "safe", busy: null, check: null, result: null, error: null, manualOpen: null };

  function mount(root) {
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Router</h1><p class="page-desc">Point your router's DNS at this PC once, and OPH-S sees and protects every phone, TV and laptop on the network with nothing installed on them.</p></div>
        <div class="row"><button class="btn" id="r-fw">${icon("lock", "sm")} Open firewall ports</button><button class="btn primary" id="r-test">${icon("refresh", "sm")} Test now</button></div></div>
      <div id="r-body">${U.skeleton(8)}</div></div>`;
    let info = null, busy = false, built = false, burst = null;

    async function load(manual) {
      if (busy) return; busy = true;
      const b = $("#r-test"); if (b && manual) b.disabled = true;
      try {
        info = await API.routerInfo();
        if ($("#r-body")) { if (!built) build(); else { renderTop(); renderUndo(); } }
        if (manual) U.toast(info.lan_clients_10m ? `${num(info.lan_clients_10m)} devices are using OPH DNS` : "No LAN devices have used OPH DNS in the last 10 minutes");
      } catch (e) { if ($("#r-body") && !built) $("#r-body").innerHTML = html`<div class="callout bad"><strong>Could not detect the router.</strong> ${e.message}</div>`; }
      busy = false; if (b) b.disabled = false;
    }

    /* Layout: top (polled), auto card (stateful, never wiped by polling), manual guide. */
    function build() {
      built = true;
      if (auto.manualOpen === null) auto.manualOpen = !info.auto_supported;
      $("#r-body").innerHTML = html`<div id="r-top"></div>${info.auto_supported ? html`<section class="panel" id="r-auto" style="margin-bottom:16px"></section>` : raw("")}
        <details class="panel guide" id="r-guide" ${raw(auto.manualOpen ? "open" : "")}><summary class="panel-head"><h2 class="panel-title">${icon("chev-r", "sm")} ${info.auto_supported ? "Manual setup guide" : "Setup guide"}</h2><span class="panel-sub">${info.auto_supported ? "Do it by hand in the router's app or web page" : ""}</span></summary><div id="r-guide-body"></div></details>`;
      $("#r-guide").addEventListener("toggle", e => { auto.manualOpen = e.target.open; });
      renderTop(); renderGuide();
      if (info.auto_supported) renderAuto();
    }

    function renderTop() {
      const r = info, n = r.lan_clients_10m || 0;
      const stale = (r.pc_dns_servers || []).filter(d => !inSubnet(d, r.gateway) && d !== "127.0.0.1" && d !== "::1");
      const state = !r.dns_running ? { cls: "bad", t: "OPH DNS is not running", d: html`Turn on the DNS resolver in <a href="#/settings">Settings</a>. Port 53 may be in use by another program (see the system events in Search).` }
        : n > 0 ? { cls: "ok", t: "Working", d: html`Devices on your network are resolving names through OPH-S. Newly connected devices join automatically.` }
        : { cls: "warn", t: "Not configured yet", d: html`No device other than this PC has used OPH DNS in the last 10 minutes. ${info.auto_supported ? "Use the automatic setup below, or follow the manual guide" : "Follow the steps below"}, reconnect a phone to Wi-Fi, then press Test now.` };
      $("#r-top").innerHTML = html`
        <div class="grid c2" style="margin-bottom:16px">
          <section class="panel"><div class="panel-head"><h2 class="panel-title">${icon("router", "sm")} Detected router</h2>${r.admin_url ? html`<a class="btn sm" href="${r.admin_url}" target="_blank" rel="noopener">${icon("external", "sm")} Open admin page</a>` : raw("")}</div>
            <div class="panel-body"><dl class="kv">
              <dt>Router</dt><dd>${r.vendor || "Unknown vendor"}</dd>
              <dt>Gateway</dt><dd class="mono">${r.gateway || "—"}${r.gateway_mac ? html` <span class="muted">(${r.gateway_mac})</span>` : raw("")}</dd>
              <dt>This PC</dt><dd class="mono">${r.pc_ip || "—"}</dd>
              <dt>This PC's DNS servers</dt><dd class="mono">${(r.pc_dns_servers || []).join(", ") || "—"}</dd>
              <dt>OPH DNS listens on</dt><dd class="mono">${r.dns_bind || "—"}</dd>
            </dl></div></section>
          <section class="panel"><div class="panel-head"><h2 class="panel-title">${icon("activity", "sm")} Live check</h2><span class="panel-sub">${burst ? "Watching every 15 s for 2 min" : "Re-checked every 15 s"}</span></div>
            <div class="panel-body stack">
              <div class="check-card"><span class="dot ${state.cls}" style="width:12px;height:12px"></span>
                <div class="grow"><div class="big">${num(n)} <span class="secondary" style="font-size:var(--fs-13);font-weight:var(--fw-regular)">devices using OPH DNS in the last 10 min</span></div>
                <div><span class="tag ${state.cls === "ok" ? "ok" : state.cls === "bad" ? "bad" : "warn"}">${state.t}</span></div></div></div>
              <p class="field-help">${state.d}${burst ? " Reconnect a phone to Wi-Fi to see it immediately." : ""}</p>
            </div></section>
        </div>
        ${stale.length ? html`<div class="callout bad" style="margin-bottom:16px"><strong>This PC has a stale manual DNS entry:</strong> ${stale.map((d, i) => html`${i ? ", " : ""}<span class="mono">${d}</span>`)} is outside your router's network (${r.gateway}). Windows may wait on it before every lookup. Fix it with the "Fix this PC's own DNS" step in the guide below.</div>` : raw("")}`;
    }

    function renderGuide() {
      const r = info, fam = chosen || r.family || "generic";
      const stale = (r.pc_dns_servers || []).filter(d => !inSubnet(d, r.gateway) && d !== "127.0.0.1" && d !== "::1");
      $("#r-guide-body").innerHTML = html`<div class="panel-body">
        <label class="row" style="gap:8px;margin-bottom:8px"><span class="panel-sub">Steps for</span><select class="select" id="r-fam" aria-label="Router family">${FAMILIES.map(([k, l]) => html`<option value="${k}" ${raw(k === fam ? "selected" : "")}>${l}${k === r.family ? " (detected)" : ""}</option>`)}</select></label>
        <ol class="steps">
          ${routerSteps(fam, r)}
          <li><div><h4>Reconnect your devices</h4><p>Turn Wi-Fi off and on, on phones and laptops, or simply wait. Devices pick up the new DNS when their DHCP lease renews (usually within a few hours). Then press <strong>Test now</strong> above.</p></div></li>
          <li><div><h4>Fix this PC's own DNS</h4><p>Windows ${P("Settings", "Network & internet", "Ethernet (or Wi-Fi)", "DNS server assignment", "Edit")} → <strong>Automatic (DHCP)</strong>. This PC then uses the router, which points to OPH-S. Do not enter this PC's own IP manually.</p>
            ${stale.length ? html`<p class="sev-high">Currently listed: ${(r.pc_dns_servers || []).join(", ")}. Remove ${stale.join(", ")}.</p>` : html`<p class="muted">Current DNS servers look fine: ${(r.pc_dns_servers || []).join(", ") || "none"}.</p>`}</div></li>
          <li><div><h4>Turn off encrypted DNS that bypasses OPH-S</h4>
            <p>Brave: ${P("Settings", "Privacy and security", "Security", "Use secure DNS")} → off. Chrome and Edge have the same switch under Privacy / Security.</p>
            <p>Android: ${P("Settings", "Network & internet", "Private DNS")} → <strong>Off</strong>. iPhone: remove any DNS or VPN profile under ${P("Settings", "General", "VPN & Device Management")}.</p></div></li>
          <li><div><h4>Allow devices to reach this PC</h4><p>Windows Firewall blocks incoming DNS by default. Click <strong>Open firewall ports</strong> and approve the administrator prompt.</p>
            <button class="btn sm" id="r-fw2">${icon("lock", "sm")} Open firewall ports</button></div></li>
        </ol></div>`;
      $("#r-fam").onchange = e => { chosen = e.target.value; renderGuide(); };
      $("#r-fw2").onclick = () => PAGES.network.firewallSetup();
    }

    /* ---------- automatic setup card ---------- */
    const dnsVal = v => v ? html`<span class="mono">${v}</span>` : html`<span class="muted">none</span>`;
    const resVal = r => r ? html`<span class="mono">${r.ip}</span> <span class="muted">for</span> <span class="mono">${r.mac}</span>` : html`<span class="muted">none</span>`;

    function stepsList(steps) {
      if (!steps || !steps.length) return raw("");
      return html`<ul class="auto-steps">${steps.map(s => html`<li><span class="${s.ok ? "ok" : "bad"}" aria-label="${s.ok ? "Succeeded" : "Failed"}">${icon(s.ok ? "circle-check" : "circle-x", "sm")}</span><span><b>${s.name}</b>${s.detail ? html` <span class="secondary">${s.detail}</span>` : raw("")}</span></li>`)}</ul>`;
    }
    function planTable(c, heads) {
      heads = heads || ["Current", "Planned"];
      if (!c || !c.planned) return raw("");
      const cur = c.current || {}, pl = c.planned;
      const row = (label, a, b, same) => html`<tr><td class="secondary">${label}</td><td>${a}</td><td>${b}${same && heads[0] === "Current" ? html` <span class="tag">unchanged</span>` : raw("")}</td></tr>`;
      const sameRes = !!cur.reservation && !!pl.reservation && cur.reservation.ip === pl.reservation.ip && cur.reservation.mac === pl.reservation.mac;
      return html`<table class="t" style="max-width:720px"><thead><tr><th>Setting</th><th>${heads[0]}</th><th>${heads[1]}</th></tr></thead><tbody>
        ${row("Primary DNS", dnsVal(cur.primaryDns), dnsVal(pl.primaryDns), (cur.primaryDns || "") === (pl.primaryDns || ""))}
        ${row("Secondary DNS", dnsVal(cur.secondaryDns), dnsVal(pl.secondaryDns), (cur.secondaryDns || "") === (pl.secondaryDns || ""))}
        ${row("IP reservation for this PC", resVal(cur.reservation), resVal(pl.reservation), sameRes)}
      </tbody></table>`;
    }
    function isUnsupported(err) { return /does not allow/i.test(err || ""); }

    function renderAuto() {
      const box = $("#r-auto"); if (!box) return;
      const saved = info.credential_saved, b = auto.busy;
      const checkOk = !!(auto.check && auto.check.ok && !auto.check.error && auto.check.planned);
      const err = auto.error;
      const applied = !!(auto.result && auto.result.applied);
      const shown = applied ? { current: auto.check && auto.check.current, planned: auto.result.current || auto.result.planned } : auto.check;
      const steps = (auto.result && auto.result.steps) || (auto.check && auto.check.steps);
      box.innerHTML = html`<div class="panel-head"><div><h2 class="panel-title">${icon("router", "sm")} Set up my Deco automatically</h2><div class="panel-sub">OPH-S signs in to your Deco on the local network, reserves this PC's address and sets it as the DNS server. Nothing changes until you press Apply.</div></div>
          <a href="#" id="ra-manual" class="panel-sub nowrap">Do it by hand instead</a></div>
        <div class="panel-body stack">
          ${auto.result && auto.result.ok && auto.result.applied ? html`<div class="callout ok"><strong>Your Deco now uses OPH-S for DNS.</strong> Devices switch over as they renew their address. Reconnect a phone to Wi-Fi to see it immediately. The live check above updates every 15 s for the next 2 minutes.</div>` : raw("")}
          ${err ? html`<div class="callout bad"><strong>${isUnsupported(err) ? "Your Deco firmware doesn't allow this locally. Use the steps below in the Deco app." : "The router setup did not complete."}</strong> <span class="mono" style="font-size:var(--fs-12)">${err}</span></div>` : raw("")}
          <div class="grid c2" style="gap:24px">
            <div class="stack">
              <div class="form-field"><label class="field-label" for="ra-pw">Deco owner password</label>
                <div class="row"><input class="input grow" id="ra-pw" type="${auto.show ? "text" : "password"}" autocomplete="off" spellcheck="false" placeholder="${saved ? "Saved password will be used" : "Password of the owner TP-Link ID"}" ${raw(b ? "disabled" : "")}>
                  <button class="btn icon" type="button" id="ra-show" aria-label="${auto.show ? "Hide" : "Show"} password" aria-pressed="${auto.show}" ${raw(b ? "disabled" : "")}>${icon(auto.show ? "eye-off" : "eye", "sm")}</button></div>
                <p class="field-help">The password of the TP-Link ID that owns the Deco (the one you use in the Deco app). Manager accounts can't sign in locally.${saved ? raw(' <a href="#" id="ra-forget">Forget saved password</a>') : raw("")}</p></div>
              <div class="form-field inline"><input type="checkbox" class="checkbox" id="ra-rem" ${raw(auto.remember ? "checked" : "")} ${raw(b ? "disabled" : "")} style="margin-top:2px">
                <div><label class="field-label" for="ra-rem">Remember on this PC</label><p class="field-help">Encrypted with Windows (DPAPI) for your account only.</p></div></div>
            </div>
            <fieldset class="stack" style="border:none;margin:0;padding:0;min-width:0" ${raw(b ? "disabled" : "")}><legend class="field-label" style="margin-bottom:4px">Mode</legend>
              <label class="drive ${auto.mode === "safe" ? "selected" : ""}" style="grid-template-columns:20px minmax(0,1fr)"><input type="radio" name="ra-mode" value="safe" ${raw(auto.mode === "safe" ? "checked" : "")}>
                <span><b>Safe (recommended)</b><span class="meta" style="display:block">Your Deco stays as backup DNS, so the internet keeps working if this PC is off. A few lookups may skip OPH-S.</span></span></label>
              <label class="drive ${auto.mode === "strict" ? "selected" : ""}" style="grid-template-columns:20px minmax(0,1fr)"><input type="radio" name="ra-mode" value="strict" ${raw(auto.mode === "strict" ? "checked" : "")}>
                <span><b>Strict</b><span class="meta" style="display:block">Every lookup goes through OPH-S. If this PC is off or OPH-S stops, devices lose internet until you undo.</span></span></label>
            </fieldset>
          </div>
          <div class="row-wrap">
            <button class="btn" id="ra-check" ${raw(b ? "disabled" : "")}>${icon("search", "sm")} ${b === "check" ? "Checking…" : "Check first"}</button>
            <button class="btn primary" id="ra-apply" ${raw(!checkOk || b ? "disabled" : "")} title="${checkOk ? "Apply the planned changes" : "Run Check first"}">${icon("check", "sm")} ${b === "apply" ? "Applying…" : "Apply to router"}</button>
            <span id="ra-undo-slot"></span>
            ${b ? html`<span class="status-inline" role="status"><span class="dot warn"></span>Talking to your Deco… about 10 s</span>` : raw("")}
          </div>
          ${shown || steps ? html`<div class="stack"><h3 class="section-title" style="margin:0">${auto.result && auto.result.applied ? "Result" : "Check result"}</h3>${planTable(shown, applied ? ["Before", "Now"] : null)}${stepsList(steps)}</div>` : raw("")}
        </div>`;
      renderUndo();
      const pw = $("#ra-pw");
      pw.value = auto.pw;
      pw.addEventListener("input", () => { auto.pw = pw.value; });
      $("#ra-show").onclick = () => { auto.show = !auto.show; pw.type = auto.show ? "text" : "password"; const s = $("#ra-show"); s.innerHTML = icon(auto.show ? "eye-off" : "eye", "sm"); s.setAttribute("aria-pressed", auto.show); s.setAttribute("aria-label", (auto.show ? "Hide" : "Show") + " password"); };
      $("#ra-rem").onchange = e => { auto.remember = e.target.checked; };
      $$('input[name="ra-mode"]').forEach(r => r.onchange = () => { auto.mode = r.value; auto.check = null; auto.result = null; renderAuto(); });
      $("#ra-manual").onclick = e => { e.preventDefault(); openManual(); };
      const fg = $("#ra-forget"); if (fg) fg.onclick = forget;
      $("#ra-check").onclick = () => configure(false);
      $("#ra-apply").onclick = confirmApply;
    }
    function renderUndo() {
      const slot = $("#ra-undo-slot"); if (!slot) return;
      slot.innerHTML = info.backup ? html`<button class="btn danger" id="ra-undo" ${raw(auto.busy ? "disabled" : "")}>${icon("undo", "sm")} Undo router changes</button>` : "";
      const u = $("#ra-undo"); if (u) u.onclick = undo;
    }
    function openManual() { const g = $("#r-guide"); g.open = true; auto.manualOpen = true; g.scrollIntoView({ block: "start", behavior: "smooth" }); }

    async function configure(apply) {
      auto.busy = apply ? "apply" : "check"; auto.error = null; auto.result = null;
      renderAuto();
      try {
        const r = await API.routerConfigure(auto.pw || null, auto.remember, auto.mode, apply);
        if (apply) auto.result = r; else auto.check = r;
        auto.error = r.error || (r.ok ? null : "The router reported a problem. See the steps below.");
        if (r.ok && auto.remember) auto.pw = "";
      } catch (e) { auto.error = e.message; }
      auto.busy = null;
      try { info = await API.routerInfo(); } catch (e) { /* keep old */ }
      if (!$("#r-auto")) return;
      renderTop(); renderAuto();
      if (isUnsupported(auto.error)) openManual();
      if (apply && auto.result && auto.result.ok && auto.result.applied) { U.toast("Router updated"); startBurst(); }
    }
    async function confirmApply() {
      const pl = auto.check.planned;
      const res = pl.reservation || { ip: info.pc_ip, mac: "this PC" };
      const ok = await U.confirmModal({ title: "Apply these changes to your Deco?", confirmLabel: "Apply to router",
        body: html`<ul>
          <li>Reserve <span class="mono">${res.ip}</span> for <span class="mono">${res.mac}</span> (this PC).</li>
          <li>Set Primary DNS to <span class="mono">${pl.primaryDns}</span>.</li>
          <li>Set Secondary DNS to ${pl.secondaryDns ? html`<span class="mono">${pl.secondaryDns}</span>` : html`<strong>none</strong>`}.</li>
          <li>The Deco app on your phone will be signed out (normal).</li>
          <li>A backup of the current settings is kept, so you can undo.</li></ul>` });
      if (ok) configure(true);
    }
    async function undo() {
      const bk = info.backup;
      const ok = await U.confirmModal({ title: "Undo the router changes?", confirmLabel: "Restore backup", danger: true,
        body: html`<p>OPH-S signs in to your Deco and restores the DNS settings saved ${bk && bk.ts ? U.rel(bk.ts) : "earlier"}:</p><ul>
          <li>Primary DNS: ${bk && bk.primaryDns ? html`<span class="mono">${bk.primaryDns}</span>` : html`automatic`}</li><li>Secondary DNS: ${bk && bk.secondaryDns ? html`<span class="mono">${bk.secondaryDns}</span>` : html`automatic`}</li></ul>
          <p>Devices stop using OPH-S for DNS as they renew their address. The Deco app on your phone will be signed out (normal).</p>` });
      if (!ok) return;
      auto.busy = "undo"; auto.error = null; renderAuto();
      try {
        const r = await API.routerUndo(auto.pw || null);
        auto.result = { ok: r.ok, applied: false, steps: r.steps };
        auto.error = r.error || null;
        if (r.ok) U.toast("Router settings restored");
      } catch (e) { auto.error = e.message; }
      auto.busy = null;
      try { info = await API.routerInfo(); } catch (e) { /* keep */ }
      if ($("#r-auto")) { renderTop(); renderAuto(); }
    }
    async function forget(e) {
      e.preventDefault();
      const ok = await U.confirmModal({ title: "Forget the saved Deco password?", confirmLabel: "Forget", body: html`<p>The encrypted password is deleted from this PC. You'll need to type it again for the next check, apply or undo.</p>` });
      if (!ok) return;
      try { await API.routerForget(); info.credential_saved = false; renderAuto(); U.toast("Saved password removed"); } catch (er) { U.toast(er.message, "error"); }
    }
    function startBurst() {
      if (burst) burst();
      const t0 = Date.now();
      burst = U.poll(async () => {
        await load(false);
        if (Date.now() - t0 > 120000 && burst) { burst(); burst = null; if ($("#r-top")) renderTop(); }
      }, 15000);
      renderTop();
    }

    $("#r-fw").onclick = () => PAGES.network.firewallSetup();
    $("#r-test").onclick = () => load(true);
    load(false);
    const stop = U.poll(() => (auto.busy || burst ? null : load(false)), 15000);
    return () => { stop(); if (burst) burst(); burst = null; };
  }

  window.PAGES.router = { title: "Router", mount };
})();
