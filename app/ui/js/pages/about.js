/* About. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, icon } = U;

  function mount(root) {
    const i = APP.info || { version: "—", data_dir: "—", admin: false, platform: "—" };
    root.innerHTML = html`<div class="page"><div class="about">
      <section class="panel">
        <div class="about-sig"><span id="about-icon">${icon("shield", "mark")}</span><div><div class="name">OPH-S <span class="secondary" style="font-weight:var(--fw-regular)">· OPH-Sentinel</span></div><div class="by">Done by <b>OPH</b></div></div></div>
        <div class="panel-body"><dl class="kv">
          <dt>Version</dt><dd class="mono">${i.version}</dd><dt>Platform</dt><dd>${i.platform}</dd>
          <dt>Privileges</dt><dd>${i.admin ? "Administrator" : "Standard user (firewall changes request approval)"}</dd>
          <dt>Data folder</dt><dd class="mono">${i.data_dir}</dd>
          <dt>Built with</dt><dd>Rust core, Tauri 2 shell with the system WebView, SQLite storage, rustls TLS</dd>
        </dl></div>
        <div class="panel-body" style="border-top:1px solid var(--c-border)">
          <h3 class="section-title">Design goals</h3>
          <p class="secondary" style="margin:0 0 12px">A personal SIEM and network protection console for home networks. The core keeps running in the tray. The interface only exists while its window is open, so idle RAM use stays low.</p>
          <h3 class="section-title">Open-source components</h3>
          <p class="secondary" style="margin:0">uPlot (MIT) · Lucide icons (ISC) · IBM Plex Sans and Mono (SIL OFL 1.1) · threat data from OpenPhish, Phishing.Database, abuse.ch and Spamhaus under their own terms.</p>
        </div>
      </section></div></div>`;
    API.settingsGet().then(st => {
      const id = st.icon_style, box = document.getElementById("about-icon");
      if (box && id && (APP.icons || []).find(i => i.id === id)) box.innerHTML = `<img src="icons/${encodeURIComponent(id)}.svg" alt="" width="40" height="40" style="display:block">`;
    }).catch(() => {});
  }

  window.PAGES.about = { title: "About", mount };
})();
