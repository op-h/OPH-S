/* Devices — enroll PCs and phones (each with its own revocable key) and manage them. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num } = U;
  const PLAT = { windows: ["monitor", "Windows"], android: ["phone", "Android"], iphone: ["tablet", "iPhone"], linux: ["terminal", "Linux"] };

  function codeLine(text, label, id) {
    return html`<div class="code-line"><code ${raw(id ? `id="${id}"` : "")}>${text}</code><button class="btn ghost icon sm" data-copytext="${text}" data-label="${label}" aria-label="Copy ${label}" title="Copy">${icon("copy", "sm")}</button></div>`;
  }
  function bindCopy(root) { $$("[data-copytext]", root).forEach(b => b.onclick = () => U.copy(b.dataset.copytext, b.dataset.label)); }

  /* ---------- Add device flow ---------- */
  function addDevice(onDone) {
    let platform = "windows", result = null, apkTimer = null;
    const m = U.openModal({ title: "Add a device", wide: true, body: html`<div id="ad-root"></div>`, onClose: () => { clearInterval(apkTimer); onDone(); } });
    const rootEl = $("#ad-root", m.el);

    function render() {
      clearInterval(apkTimer);
      rootEl.innerHTML = html`<div class="stack">
        <div class="seg" role="tablist" aria-label="Platform">${Object.entries(PLAT).map(([k, [ic, l]]) => html`<button role="tab" aria-selected="${k === platform}" class="${k === platform ? "active" : ""}" data-p="${k}">${icon(ic, "sm")} ${l}</button>`)}</div>
        ${platform === "iphone" ? iphoneCard() : result && result.platform === platform ? enrolled() : nameForm()}
      </div>`;
      $$("[data-p]", rootEl).forEach(b => b.onclick = () => { platform = b.dataset.p; if (result && result.platform !== platform) result = null; render(); });
      const f = $("#ad-form", rootEl);
      if (f) {
        const inp = $("#ad-name", rootEl); inp.focus();
        f.onsubmit = async e => {
          e.preventDefault();
          const name = inp.value.trim().replace(/[^A-Za-z0-9._ -]/g, "").slice(0, 40);
          if (!name) { inp.classList.add("invalid"); $("#ad-err", rootEl).textContent = "Give the device a name you will recognise, such as Galaxy-S23."; return; }
          const btn = $("#ad-go", rootEl); btn.disabled = true;
          try { result = await API.deviceEnroll(name, platform); render(); }
          catch (er) { $("#ad-err", rootEl).textContent = er.message; btn.disabled = false; }
        };
      }
      const share = $("#ad-apk", rootEl);
      if (share) share.onclick = async () => {
        share.disabled = true;
        try { const r = await API.apkShare(true); result.apk_url = r.url; result.apk_expires = r.expires; render(); }
        catch (e) { U.toast("Could not share the APK: " + e.message, "error"); share.disabled = false; }
      };
      const stop = $("#ad-apk-stop", rootEl);
      if (stop) stop.onclick = async () => { try { await API.apkShare(false); } catch (e) { /* ignore */ } result.apk_url = null; result.apk_expires = null; render(); };
      if (result && result.share_expires && result.platform === "windows") {
        const tick2 = () => {
          const left = Math.max(0, result.share_expires - Date.now()), c = $("#ad-share", rootEl);
          if (!c) return clearInterval(apkTimer);
          c.textContent = `${Math.floor(left / 60000)}:${String(Math.floor(left / 1000) % 60).padStart(2, "0")}`;
          if (!left) { clearInterval(apkTimer); c.textContent = "0:00 (stopped)"; }
        };
        tick2(); apkTimer = setInterval(tick2, 1000);
      }
      if (result && result.apk_expires) {
        const tick = () => {
          const left = Math.max(0, result.apk_expires - Date.now()), c = $("#ad-count", rootEl);
          if (!c) return clearInterval(apkTimer);
          c.textContent = `${Math.floor(left / 60000)}:${String(Math.floor(left / 1000) % 60).padStart(2, "0")}`;
          if (!left) { clearInterval(apkTimer); result.apk_url = null; result.apk_expires = null; render(); }
        };
        tick(); apkTimer = setInterval(tick, 1000);
      }
      bindCopy(rootEl);
    }

    function nameForm() {
      return html`<form id="ad-form" class="stack" novalidate>
        <div class="form-field"><label class="field-label" for="ad-name">Device name</label>
          <input class="input" id="ad-name" placeholder="${platform === "android" ? "Galaxy-S23" : platform === "linux" ? "home-server" : "work-laptop"}" style="max-width:320px" spellcheck="false">
          <p class="field-help">Shown as <span class="mono">host</span> in every event from it. Each device gets its own key, which you can revoke on its own later.</p><div class="field-error" id="ad-err"></div></div>
        ${platform === "windows" ? html`<div class="callout">${icon("info", "sm")} <strong>Not needed on this PC.</strong> The PC running OPH-S is already monitored directly. Use this only for your <em>other</em> Windows PCs.</div>` : raw("")}
        <div><button class="btn primary" id="ad-go" type="submit">${icon("key", "sm")} Create key for ${PLAT[platform][1]}</button></div></form>`;
    }

    function enrolled() {
      const r = result;
      if (r.platform === "windows") return html`<div class="stack">
        ${r.this_pc_note ? html`<div class="callout">${icon("info", "sm")} ${r.this_pc_note}</div>` : raw("")}
        <div class="callout ok"><strong>Key created for ${r.name}.</strong> On that PC, open PowerShell as administrator and run the command below. It downloads the agent from this PC, installs it, and registers a background task that starts at logon.</div>
        <div class="form-field"><span class="field-label">Install (recommended)</span>${codeLine(r.windows_install_cmd, "Install command")}</div>
        <div class="form-field"><span class="field-label">Run once, in the foreground</span>${codeLine(r.windows_cmd, "Command")}</div>
        ${r.share_expires ? html`<p class="field-help">${icon("wifi", "sm")} The download server on this PC is running for <b id="ad-share" class="num"></b> more. After that, add the device again to restart it.</p>` : raw("")}
        <p class="field-help"><span class="mono">oph-agent.exe</span> also ships with OPH-S in <span class="mono">C:\\Program Files\\OPH-S\\oph-agent.exe</span> if you prefer to copy it by hand.</p></div>`;
      if (r.platform === "android") return html`<div class="stack">
        <div class="callout ok"><strong>Key created for ${r.name}.</strong> Install the OPH-S app on the phone, then scan the first code with the phone's camera. It opens the app and enrolls automatically.</div>
        <div class="qr-row">
          <div>${U.qrSvg(r.android_uri, 220)}<div class="qr-cap"><strong>1. Enroll.</strong> Scan with the camera. It opens OPH-S and connects to ${r.host}:${r.port}.</div></div>
          <div>${r.apk_url ? html`${U.qrSvg(r.apk_url, 220)}<div class="qr-cap"><strong>2. Get the app.</strong> Scan to download <span class="mono">OPH-S.apk</span> over Wi-Fi. Link expires in <b id="ad-count" class="num"></b>.
              <div style="margin-top:8px"><button class="btn sm" id="ad-apk-stop">Stop sharing</button></div></div>`
            : html`<div class="stack" style="max-width:260px"><p class="field-help" style="margin:0">Don't have the app on the phone yet? Share the APK on your Wi-Fi for 15 minutes and scan its code.</p>
              <button class="btn" id="ad-apk">${icon("wifi", "sm")} Share APK on Wi-Fi</button>
              <p class="field-help" style="margin:0">Android will ask to allow installs from your browser. That is expected for apps outside the Play Store.</p></div>`}</div>
        </div>
        <details class="more"><summary>Alternative: Termux command line</summary><div class="stack">
          <p class="field-help" style="margin:0">Install Termux from F-Droid, copy <span class="mono">oph-agent</span> (aarch64) to the phone, run <span class="mono">termux-wake-lock</span>, then:</p>${codeLine(r.termux_cmd, "Termux command")}</div></details></div>`;
      return html`<div class="stack">
        <div class="callout ok"><strong>Key created for ${r.name}.</strong> Copy the Linux build of <span class="mono">oph-agent</span> to the machine, make it executable (<span class="mono">chmod +x oph-agent</span>) and run:</div>
        ${codeLine(r.termux_cmd.replace(/\s--logcat\b/, " --tail /var/log/syslog"), "Linux command")}
        <p class="field-help">Use <span class="mono">--tail &lt;file&gt;</span> for any log file. To run it at boot, add it as a systemd service.</p></div>`;
    }

    function iphoneCard() {
      return html`<div class="stack">
        <div class="callout warn"><strong>iOS does not allow background log agents.</strong> Apple blocks apps from reading system logs or other apps' traffic, so there is no OPH-S agent for iPhone. iPhones are still protected through DNS, and their lookups appear on the Network page.</div>
        <ol class="steps">
          <li><div><h4>Easiest: the router setup</h4><p>If you completed the <a href="#/router">Router</a> guide, every iPhone on your Wi-Fi is already covered. Nothing else to do.</p></div></li>
          <li><div><h4>Or set it on the iPhone only</h4><p><span class="path">Settings<span class="sep">›</span>Wi-Fi<span class="sep">›</span>(i) next to your network<span class="sep">›</span>Configure DNS<span class="sep">›</span>Manual</span></p>
            <p>Remove the existing servers, tap <strong>Add Server</strong>, enter <span class="mono" id="ad-pcip">${(PAGES.devices._lan || "this PC's IP")}</span>, then <strong>Save</strong>.</p></div></li>
          <li><div><h4>Remove anything that bypasses DNS</h4><p>Under <span class="path">Settings<span class="sep">›</span>General<span class="sep">›</span>VPN &amp; Device Management</span>, remove DNS profiles you don't need. iCloud Private Relay (Settings › your name › iCloud) also bypasses OPH-S for Safari.</p></div></li>
        </ol></div>`;
    }
    render();
  }

  /* ---------- page ---------- */
  function mount(root) {
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Devices</h1><p class="page-desc">PCs and phones that send their logs to OPH-S over an encrypted channel (TLS 1.3, pinned certificate). Each device has its own key, so you can revoke a lost phone without touching the others.</p></div>
        <div class="row"><button class="btn" id="g-fw">${icon("lock", "sm")} Open firewall ports</button><button class="btn primary" id="g-add">${icon("plus", "sm")} Add device</button></div></div>
      <div id="g-body">${U.skeleton(6)}</div></div>`;
    let st = null;
    const load = async () => {
      try { st = await API.agents(); } catch (e) { $("#g-body").innerHTML = html`<div class="callout bad">${e.message}</div>`; return; }
      PAGES.devices._lan = st.server.lan_ip;
      if ($("#g-body")) render();
    };
    function render() {
      const s = st.server;
      const list = st.agents.filter(a => !a.revoked);
      $("#g-body").innerHTML = html`
        <div class="kpis" style="grid-template-columns:repeat(4,minmax(0,1fr))">
          <div class="kpi"><div class="kpi-label">Ingest server</div><div class="kpi-value" style="font-size:var(--fs-16)"><span class="status-inline" style="font-size:var(--fs-14)"><span class="dot ${s.running ? "ok" : "bad"}"></span>${s.running ? "Listening" : "Stopped"}</span></div><div class="kpi-sub mono">${s.lan_ip}:${s.port}</div></div>
          <div class="kpi"><div class="kpi-label">Devices online</div><div class="kpi-value">${num(list.filter(a => a.online).length)}<span class="unit"> / ${num(list.length)}</span></div><div class="kpi-sub">Enrolled devices</div></div>
          <div class="kpi"><div class="kpi-label">Syslog receiver</div><div class="kpi-value" style="font-size:var(--fs-16)"><span class="status-inline" style="font-size:var(--fs-14)"><span class="dot ${s.syslog_running ? "ok" : ""}"></span>${s.syslog_running ? "Listening" : "Off"}</span></div><div class="kpi-sub">${s.syslog_running ? html`UDP port ${s.syslog_port}` : html`Enable in Settings`}</div></div>
          <div class="kpi"><div class="kpi-label">Certificate fingerprint</div><div class="kpi-value mono ellipsis" style="font-size:var(--fs-12);font-weight:var(--fw-regular)" title="${s.fingerprint}">${s.fingerprint.slice(0, 23)}…</div><div class="kpi-sub"><a href="#" id="g-fp">Copy full SHA-256</a></div></div>
        </div>
        ${s.error ? html`<div class="callout bad" style="margin-bottom:16px"><strong>Ingest server problem:</strong> ${s.error}</div>` : raw("")}
        ${s.syslog_error ? html`<div class="callout bad" style="margin-bottom:16px"><strong>Syslog receiver problem:</strong> ${s.syslog_error}</div>` : raw("")}
        <div class="callout ok" style="margin-bottom:16px">${icon("monitor", "sm")} <strong>This PC is protected directly.</strong> OPH-S runs here, so this PC needs no agent. Add devices only for your other PCs and phones.</div>
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Enrolled devices</h2><span class="panel-sub">${num(list.filter(a => a.online).length)} online</span></div>
          ${list.length ? html`<div class="table-wrap"><table class="t"><thead><tr><th>Status</th><th>Name</th><th>Platform</th><th>Added</th><th>Last seen</th><th class="num">Events received</th><th></th></tr></thead><tbody>
            ${list.map(a => html`<tr><td><span class="status-inline"><span class="dot ${a.online ? "ok" : ""}"></span>${a.online ? "Online" : a.last_seen ? "Offline" : "Waiting"}</span></td>
              <td>${a.name}</td><td class="secondary"><span class="row" style="gap:6px">${icon((PLAT[a.platform] || ["monitor"])[0], "sm")}${(PLAT[a.platform] || [0, a.platform])[1]}</span></td>
              <td class="nowrap">${U.relHtml(a.created)}</td><td class="nowrap">${a.last_seen ? U.relHtml(a.last_seen) : html`<span class="muted">never</span>`}</td><td class="num">${num(a.events)}</td>
              <td class="right nowrap"><a class="btn sm ghost" href="#/search?q=${encodeURIComponent("host=" + a.name)}">${icon("search", "sm")} Events</a> <button class="btn sm danger" data-revoke="${a.id}">Revoke</button></td></tr>`)}</tbody></table></div>`
            : U.empty("No devices yet.", "Click Add device to enroll a PC or phone. It appears here within seconds of connecting.")}</section>`;
      $("#g-fp").onclick = e => { e.preventDefault(); U.copy(s.fingerprint, "Fingerprint"); };
      $$("[data-revoke]").forEach(b => b.onclick = async () => {
        const a = st.agents.find(x => x.id === b.dataset.revoke);
        const ok = await U.confirmModal({ title: `Revoke ${a.name}?`, confirmLabel: "Revoke key", danger: true,
          body: html`<p>The key for <strong>${a.name}</strong> stops working immediately:</p><ul><li>The device is disconnected and can't send logs any more.</li><li>Events it already sent stay searchable.</li><li>Other devices are not affected.</li></ul><p>To reconnect it later, add it again to get a new key.</p>` });
        if (!ok) return;
        try { st = await API.deviceRevoke(a.id); render(); U.toast(`Revoked ${a.name}`); } catch (e) { U.toast(e.message, "error"); }
      });
    }
    $("#g-add").onclick = () => addDevice(load);
    $("#g-fw").onclick = () => PAGES.network.firewallSetup();
    load();
    return U.poll(() => ($(".modal-scrim") ? null : load()), 15000);
  }

  window.PAGES.devices = { title: "Devices", mount };
})();
