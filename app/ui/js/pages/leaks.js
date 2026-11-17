/* Leak Check — which devices get around OPH-S protection, and why. Counts by default; sample domains only on expand. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num } = U;

  const STATE = {
    covered: { label: "Covered", cls: "ok", tip: "Uses OPH-S DNS for its lookups." },
    leaking: { label: "Leaking", cls: "bad", tip: "Some lookups go around OPH-S. See the open leaks above." },
    quiet: { label: "Quiet", cls: "warn", tip: "Online, but stopped asking OPH-S. It is probably using Private DNS, a VPN, Private Relay or a manual DNS server." },
    too_new: { label: "Too new", cls: "", tip: "Seen only recently. OPH-S needs a little longer before it can judge this device." },
  };

  const CLASS = {
    A: {
      title: () => "Hidden lookup on this PC",
      why: l => html`<span class="mono">${l.actor}</span> resolved names without going through Windows' DNS client. It has its own DNS code, so its lookups skip OPH-S and are not filtered.`,
      guide: null,
    },
    B: {
      title: l => /^secure dns in /i.test(l.actor) ? "Secure DNS in " + l.actor.replace(/^secure dns in /i, "") : "This PC asks another DNS server",
      why: l => /^secure dns in /i.test(l.actor)
        ? html`The browser's built-in <em>Secure DNS</em> sends lookups encrypted to its own provider, so OPH-S never sees them and cannot block anything for that browser.`
        : html`<span class="mono">${l.actor}</span>: lookups go straight to a different DNS server instead of OPH-S, so they are not filtered.`,
      guide: html`<ul><li><strong>Browser:</strong> Settings → Privacy &amp; security → Use secure DNS → Off.</li>
        <li><strong>Network adapter DNS:</strong> Settings → Network → Ethernet/Wi-Fi → DNS → Automatic (DHCP).</li></ul>`,
    },
    C: {
      title: () => "Went quiet",
      why: l => html`The device is online but stopped using OPH-S DNS${l.actor ? html` (likely <strong>${l.actor}</strong>)` : raw("")}. Usual causes: Android Private DNS, a VPN, iCloud Private Relay or a manually set DNS server.`,
      guide: html`<ul><li><strong>Android:</strong> Settings → Network &amp; internet → Private DNS → Off or Automatic.</li>
        <li><strong>iPhone / iPad:</strong> Settings → [your name] → iCloud → Private Relay → Off for this network, or Wi-Fi → (i) → Limit IP Address Tracking → Off.</li>
        <li><strong>VPN:</strong> disconnect it while at home, or set its DNS to this PC.</li></ul>`,
    },
    D: {
      title: () => "Encrypted-DNS attempt",
      why: l => html`The device looked up <span class="mono">${l.actor}</span>, a name that browsers and phones use to find or test encrypted DNS. On its own this is informational; if the device then goes quiet, the quiet leak is raised.`,
      guide: null,
    },
  };

  const FIX = {
    canaries: {
      name: "Answer the canary names", short: "Canary answers", scope: "House-wide",
      desc: "Tells Firefox and iCloud Private Relay to use house DNS.",
      body: () => html`<p>OPH-S will answer these names with <span class="mono">NXDOMAIN</span> (does not exist) for every device that uses OPH-S DNS:</p><ul>
        <li><span class="mono">use-application-dns.net</span>: Firefox then turns off its built-in encrypted DNS.</li>
        <li><span class="mono">mask.icloud.com</span> and <span class="mono">mask-h2.icloud.com</span>: iPhones, iPads and Macs then turn off iCloud Private Relay on this network.</li></ul>
        <p>Nothing else changes. Undo it any time from Leak Check → Fixes.</p>`,
    },
    doh_names: {
      name: "Block encrypted-DNS names", short: "Encrypted-DNS names blocked", scope: "House-wide",
      desc: "Devices can no longer find well-known encrypted-DNS providers and fall back to house DNS.",
      body: () => html`<p>OPH-S will answer the names of well-known encrypted-DNS providers (for example <span class="mono">dns.google</span>, <span class="mono">cloudflare-dns.com</span>, <span class="mono">dns.quad9.net</span>) with <span class="mono">NXDOMAIN</span> for every device that uses OPH-S DNS. Browsers and phones then fall back to house DNS.</p>
        <div class="callout warn"><strong>Heads-up:</strong> A phone with Android Private DNS set to a specific provider will show 'No internet' until Private DNS is set to Off or Automatic.</div>
        <p>Undo it any time from Leak Check → Fixes.</p>`,
    },
    firewall_doh: {
      name: "Block encrypted DNS on this PC", short: "Encrypted DNS blocked on this PC", scope: "This PC only",
      desc: "A Windows Firewall rule stops programs on this PC from using DNS-over-TLS or DNS-over-HTTPS servers.",
      body: () => html`<p>OPH-S adds the Windows Firewall rule <span class="mono">OPH Sentinel - block encrypted DNS</span> on this PC:</p><ul>
        <li>Blocks outbound DNS-over-TLS (port <span class="mono">853</span>).</li>
        <li>Blocks HTTPS to the IP addresses of known DNS-over-HTTPS servers.</li></ul>
        <p>Programs then fall back to Windows' DNS client, which uses OPH-S. Other devices are not affected. Windows may ask for administrator approval.</p>
        <p>Undo it any time from Leak Check → Fixes. OPH-S deletes its rule.</p>`,
    },
  };
  const FIX_ORDER = ["canaries", "doh_names", "firewall_doh"];

  /** Fixes that address a leak, by class. */
  function fixesFor(l, st) {
    if (l.class === "A") { const d = st.devices.find(x => x.ip === l.dev); return d && d.seen_by && d.seen_by.encrypted_dns ? ["firewall_doh"] : []; }
    if (l.class === "B") return ["firewall_doh"];
    if (l.class === "C") return ["canaries", "doh_names"];
    if (l.class === "D") return ["canaries"];
    return [];
  }

  /** Confirm and apply/undo a house fix. Returns the new status or null. */
  async function runFix(k, undo) {
    const f = FIX[k];
    const ok = await U.confirmModal(undo
      ? { title: `Undo "${f.name}"?`, confirmLabel: "Undo fix", body: html`<p>OPH-S removes this change and everything goes back to how it was before:</p><div class="callout">${f.desc}</div><p>You can apply it again later.</p>` }
      : { title: f.name + "?", confirmLabel: "Apply fix", body: f.body() });
    if (!ok) return null;
    try { const r = await API.leakFix(undo ? "undo_" + k : k); if (r.message) U.toast(r.message); return r; }
    catch (e) { U.toast(e.message, "error"); return null; }
  }

  function stateChip(s) { const m = STATE[s] || { label: s, cls: "" }; return html`<span class="tag ${m.cls}" title="${m.tip || ""}">${m.label}</span>`; }
  function seenBy(sb) {
    if (!sb) return html`<span class="muted">—</span>`;
    const yes = (l, t) => html`<span class="lk-seen ok" title="${t}">${icon("circle-check", "sm")}${l}</span>`;
    const no = (l, t) => html`<span class="lk-seen" title="${t}">${l} –</span>`;
    return html`<span class="lk-seen-row">
      ${sb.resolver ? yes("Resolver", "OPH-S DNS answered lookups from this device") : no("Resolver", "No recent lookups through OPH-S DNS")}
      ${sb.windows ? yes("Windows", "Seen in this PC's Windows DNS client") : no("Windows", "Not a monitored Windows PC")}
      ${sb.app === "online" ? yes("App online", "The OPH-S app or agent on this device is connected") : no("App", "No OPH-S app or agent online on this device")}
      ${sb.encrypted_dns ? html`<span class="lk-seen warn" title="This device looked up an encrypted-DNS (DoH) or canary name">${icon("alert", "sm")}Encrypted DNS seen</span>` : raw("")}</span>`;
  }

  function mount(root) {
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Leak Check</h1><p class="page-desc">Which devices get around your protection, and why.</p>
        <p class="lk-pitch">Every other filter shows what it blocked. OPH-S shows what got around it.</p></div>
        <button class="btn" id="lk-refresh">${icon("refresh", "sm")} Refresh</button></div>
      <div id="lk-body">${U.skeleton(8)}</div></div>`.__raw;
    let st = null, busy = false;
    const openSamples = new Set();
    let showDone = false;

    const load = async () => {
      if (busy) return;
      try { st = await API.leakStatus(); }
      catch (e) { const b = $("#lk-body"); if (b) b.innerHTML = html`<div class="callout bad"><strong>Could not load Leak Check.</strong> ${e.message}</div>`.__raw; return; }
      if (!$("#lk-body")) return;
      render();
    };
    const apply = r => { if (r) { st = r; render(); } };

    function render() {
      const c = st.coverage || {};
      const open = st.leaks.filter(l => l.status === "open").sort((a, b) => U.SEVS.indexOf(b.severity) - U.SEVS.indexOf(a.severity) || b.last_ts - a.last_ts);
      const done = st.leaks.filter(l => l.status !== "open").sort((a, b) => b.last_ts - a.last_ts);
      const devs = st.devices.slice().sort((a, b) => ["leaking", "quiet", "too_new", "covered"].indexOf(a.state) - ["leaking", "quiet", "too_new", "covered"].indexOf(b.state) || ipNum(a.ip) - ipNum(b.ip));
      const y = $("#main").scrollTop;
      $("#lk-body").innerHTML = html`
        <section class="panel lk-cov"><div class="lk-cov-main"><span class="kpi-label row" style="gap:4px">${icon("shield-alert", "sm")} Protection coverage</span>
            <span class="lk-cov-val"><span class="num">${num(c.covered)}</span><span class="unit"> of ${num(c.total)} devices</span></span></div>
          <div class="lk-cov-bar" role="img" aria-label="${num(c.covered)} covered, ${num(c.leaking)} leaking, ${num(c.quiet)} quiet, ${num(c.too_new)} too new">
            ${["covered", "leaking", "quiet", "too_new"].map(k => c[k] ? raw(`<span class="s-${k}" style="width:${(c[k] / (c.total || 1) * 100).toFixed(2)}%"></span>`) : raw(""))}</div>
          <div class="lk-chips">${["covered", "leaking", "quiet", "too_new"].map(k => html`<span class="lk-chip s-${k}" title="${STATE[k].tip}"><span class="sw"></span>${STATE[k].label}<b class="num">${num(c[k] || 0)}</b></span>`)}</div></section>

        <div class="lk-sec-head"><h2 class="section-title">Open leaks <span class="badge ${open.length ? "" : "neutral"}">${open.length}</span></h2></div>
        ${open.length ? html`<div class="lk-grid">${open.map(card)}</div>`
          : html`<section class="panel">${U.empty("No leaks found. Every online device is using OPH-S.", "Devices that bypass OPH-S DNS show up here with the reason and a fix.")}</section>`}

        ${done.length ? html`<details class="panel guide lk-done" id="lk-done" ${raw(showDone ? "open" : "")}><summary class="panel-head"><h2 class="panel-title">${icon("chev-r", "sm")} Fixed / ignored <span class="count muted num">${done.length}</span></h2><span class="panel-sub">Reopen a leak to watch it again</span></summary>
          <div class="table-wrap"><table class="t"><thead><tr><th>Status</th><th>Leak</th><th>Device</th><th>What</th><th class="num">Count</th><th>Last seen</th><th></th></tr></thead><tbody>
            ${done.map(l => html`<tr><td>${l.status === "fixed" ? html`<span class="tag ok">fixed</span>` : html`<span class="tag">ignored</span>`}</td><td>${CLASS[l.class] ? CLASS[l.class].title(l) : l.class}</td>
              <td>${l.dev_name || html`<span class="mono">${l.dev}</span>`}</td><td class="mono ellipsis" style="max-width:260px" title="${l.actor}">${l.actor}</td><td class="num">${num(l.count)}</td>
              <td class="nowrap">${U.relHtml(l.last_ts)}</td><td class="right"><button class="btn sm" data-act="reopen" data-id="${l.id}">${icon("undo", "sm")} Reopen</button></td></tr>`)}
          </tbody></table></div></details>` : raw("")}

        <div class="grid c-2-1" style="margin-top:16px">
          <section class="panel"><div class="panel-head"><h2 class="panel-title">Devices</h2><span class="panel-sub">${num(devs.length)} seen on the network</span></div>
            <div class="table-wrap"><table class="t"><thead><tr><th>State</th><th>Device</th><th>IP address</th><th>Vendor</th><th>Seen by</th></tr></thead><tbody>
              ${devs.map(d => html`<tr><td>${stateChip(d.state)}</td><td class="nowrap">${d.name || html`<span class="muted">Unknown</span>`}</td><td class="mono">${d.ip}</td>
                <td class="secondary">${d.vendor || "—"}</td><td>${seenBy(d.seen_by)}</td></tr>`)}
            </tbody></table></div></section>
          <section class="panel"><div class="panel-head"><h2 class="panel-title">Fixes</h2><span class="panel-sub">Each one can be undone</span></div>
            <div class="lk-fixes">${FIX_ORDER.map(k => { const on = !!(st.fixes && st.fixes[k]); return html`<div class="lk-fix">
              <div class="grow"><div class="row" style="gap:6px"><strong>${FIX[k].name}</strong><span class="tag">${FIX[k].scope}</span></div><p class="field-help">${FIX[k].desc}</p></div>
              <div class="lk-fix-act">${on ? html`<span class="status-inline"><span class="dot ok"></span>Applied</span><button class="btn sm" data-fix="${k}" data-undo="1">${icon("undo", "sm")} Undo</button>`
                : html`<span class="status-inline muted"><span class="dot"></span>Off</span><button class="btn sm" data-fix="${k}">Apply…</button>`}</div></div>`; })}</div></section>
        </div>
        <p class="field-help" style="margin-top:12px">An online device counts as quiet after <strong class="num">${num(st.quiet_minutes)}</strong> minutes without any lookup through OPH-S. Change it in <a href="#/settings?section=leak">Settings</a>. Refreshes every 15 s while visible.${st.tap_dropped ? html` The capture tap dropped ${num(st.tap_dropped)} packets, so a few hidden lookups may have been missed.` : raw("")}</p>`.__raw;
      $("#main").scrollTop = y;
      bind();
    }

    function card(l) {
      const C = CLASS[l.class] || { title: () => "Leak", why: () => "", guide: null };
      const fx = fixesFor(l, st), sOpen = openSamples.has(l.id);
      return html`<section class="panel lk-card sev-edge-${U.SEVS.includes(l.severity) ? l.severity : "info"}" data-leak="${l.id}">
        <div class="panel-head"><div class="row" style="gap:8px;min-width:0">${U.sev(l.severity)}<h3 class="panel-title ellipsis">${C.title(l)}</h3></div><span class="tag">Class ${l.class}</span></div>
        <div class="panel-body stack" style="gap:8px">
          <dl class="kv lk-kv"><dt>Device</dt><dd>${l.dev_name || "Unknown"} <span class="mono muted">${l.dev}</span></dd>
            <dt>What</dt><dd class="mono">${l.actor}</dd>
            <dt>Seen</dt><dd><span class="num">${num(l.count)}</span> ${l.count === 1 ? "time" : "times"} · first ${U.relHtml(l.first_ts)} · last ${U.relHtml(l.last_ts)}</dd></dl>
          <p class="lk-why">${C.why(l)}</p>
          ${C.guide ? html`<details class="more"><summary>How to fix it on the device</summary><div class="lk-guide">${C.guide}</div></details>` : raw("")}
          ${l.samples && l.samples.length ? html`<div><button type="button" class="btn ghost sm" data-samples="${l.id}" aria-expanded="${sOpen}">${icon(sOpen ? "chev-d" : "chev-r", "sm")} ${sOpen ? "Hide" : "Show"} sample domains (${l.samples.length})</button>
            ${sOpen ? html`<ul class="lk-samples">${l.samples.map(s => html`<li class="mono">${s}</li>`)}</ul>` : raw("")}</div>` : raw("")}
        </div>
        <div class="lk-card-foot">
          ${fx.map(k => st.fixes && st.fixes[k]
            ? html`<span class="tag ok" title="${FIX[k].desc}">${icon("check", "sm")} ${FIX[k].short}</span><button class="btn sm ghost" data-fix="${k}" data-undo="1">Undo</button>`
            : html`<button class="btn sm primary" data-fix="${k}">${FIX[k].name}…</button>`)}
          <button class="btn sm" data-act="recheck" data-id="${l.id}">${icon("refresh", "sm")} Recheck</button>
          <button class="btn sm ghost" data-act="ignore" data-id="${l.id}">${l.class === "A" ? "Ignore this program" : "Ignore"}</button>
          ${window.AI && AI.open ? html`<button class="btn sm ghost" data-ai="${l.id}">${icon("bot", "sm")} Ask AI</button>` : raw("")}
        </div></section>`;
    }

    function bind() {
      const box = $("#lk-body");
      $$("[data-samples]", box).forEach(b => b.onclick = () => { const id = +b.dataset.samples; if (openSamples.has(id)) openSamples.delete(id); else openSamples.add(id); render(); });
      const det = $("#lk-done", box); if (det) det.addEventListener("toggle", () => { showDone = det.open; });
      $$("[data-fix]", box).forEach(b => b.onclick = async () => { busy = true; try { apply(await runFix(b.dataset.fix, !!b.dataset.undo)); } finally { busy = false; } });
      $$("[data-act]", box).forEach(b => b.onclick = async () => {
        const l = st.leaks.find(x => x.id === +b.dataset.id); if (!l) return;
        const act = b.dataset.act;
        if (act === "ignore") {
          const ok = await U.confirmModal({ title: l.class === "A" ? "Ignore this program?" : "Ignore this leak?", confirmLabel: "Ignore",
            body: html`<p>The leak for <span class="mono">${l.actor}</span> on ${l.dev_name || l.dev} moves to Fixed / ignored and no longer counts against coverage. Nothing on the device changes, and its lookups still bypass OPH-S.</p><p>You can reopen it any time.</p>` });
          if (!ok) return;
        }
        b.disabled = true; busy = true;
        try { const r = await API.leakAction(l.id, act); if (r.message) U.toast(r.message); st = r; }
        catch (e) { U.toast(e.message, "error"); }
        finally { busy = false; }
        render();
      });
      $$("[data-ai]", box).forEach(b => b.onclick = () => {
        const l = st.leaks.find(x => x.id === +b.dataset.ai); if (!l) return;
        AI.open({ kind: "device", data: { ip: l.dev }, label: `Leak: ${(CLASS[l.class] || { title: () => "" }).title(l)} · ${l.dev_name || l.dev} (${l.dev})` });
      });
    }

    $("#lk-refresh").onclick = load;
    load();
    return U.poll(load, 15000);
  }
  function ipNum(ip) { return String(ip).split(".").reduce((s, o) => s * 256 + (+o || 0), 0); }

  /** Shared with Overview and Network: status fetch that never throws. */
  async function statusSafe() { try { return await API.leakStatus(); } catch (e) { return null; } }

  window.PAGES.leaks = { title: "Leak Check", mount, seenBy, stateChip, statusSafe };
})();
