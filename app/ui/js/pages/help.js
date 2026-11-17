/* Help — searchable explanation of every log type, field and feature. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, $, $$ } = U;

  const GUIDES = [
    { id: "query", title: "Query language", body: html`
      <p>The Search bar works like Splunk's: write filters separated by spaces, then optionally pipe the results into a command.</p>
      <h3>Filters</h3><ul>
        <li><code class="inline">field=value</code> exact match: <code class="inline">kind=dns.blocked</code></li>
        <li><code class="inline">field!=value</code> excludes: <code class="inline">process!=svchost.exe</code></li>
        <li><code class="inline">*</code> is a wildcard: <code class="inline">domain=*.google.com</code></li>
        <li><code class="inline">severity&gt;=medium</code> compares severities (info &lt; low &lt; medium &lt; high &lt; critical)</li>
        <li>Bare words and <code class="inline">"quoted phrases"</code> search the message, domain, process and host</li></ul>
      <h3>Commands (after a pipe)</h3><ul>
        <li><code class="inline">| stats count by domain</code> counts events per value and shows a table</li>
        <li><code class="inline">| head 50</code> keeps only the first 50 results</li>
        <li><code class="inline">| sort ts</code> shows oldest first (<code class="inline">sort -ts</code> is newest first, the default)</li></ul>
      <h3>Useful searches</h3><ul>
        <li><code class="inline">severity&gt;=high</code> shows everything that matters</li>
        <li><code class="inline">source=dns src_ip=192.168.1.23 | stats count by domain</code> shows what one device talks to</li>
        <li><code class="inline">kind=conn.open dst_port!=443 dst_port!=80</code> finds connections on unusual ports</li>
        <li><code class="inline">source=agent severity&gt;=medium | stats count by host</code> shows which machines log errors</li></ul>
      <p>Click any <span class="mono">field=value</span> token under an event, or any value in the Fields sidebar, to add it as a filter. Drag across the timeline to zoom in.</p>` },
    { id: "protection", title: "How protection works", body: html`
      <h3>DNS sinkhole (network-wide)</h3><p>Every device needs DNS to turn names into addresses. When devices use OPH as their DNS server, OPH checks each name against the threat lists and your Blocklist. A blocked name gets <span class="mono">0.0.0.0</span>, a dead end, so the site never loads. This works for phones, TVs and IoT devices with nothing installed on them.</p>
      <h3>Windows Firewall (this PC)</h3><p>Some malware connects straight to an IP without DNS. For blocked IPs, OPH-S adds them to the Windows Firewall rule <span class="mono">OPH Sentinel - blocked IPs</span>. Windows enforces it in the kernel, so it costs no RAM.</p>
      <h3>Warn vs Block mode</h3><p><strong>Warn</strong> (default) raises an alert and shows a notification, and nothing is blocked until you choose. <strong>Block</strong> applies feed matches automatically. Your manual Blocklist is always enforced, and your Allowlist always wins, in both modes.</p>
      <h3>Suricata IDS (optional)</h3><p>For deep packet inspection, install Suricata for Windows (with Npcap) and set its <span class="mono">eve.json</span> path in Settings. OPH then shows its signature alerts here. Suricata uses a few hundred MB of RAM with full rule sets, which is why it is optional.</p>
      <h3>Limits</h3><ul><li>Devices that use encrypted DNS (DoH, or Android Private DNS) bypass the sinkhole. Turn those features off, or block their providers.</li><li>Threat lists only know about threats that have already been reported. They complement, and don't replace, updates and antivirus.</li></ul>` },
    { id: "leaks", title: "Leak Check", body: html`
      <p>Every other filter shows what it blocked. <strong>Leak Check shows what got around it</strong>: which devices or programs resolve names without OPH-S, and why. Cards show counts; sample domains appear only when you expand a card.</p>
      <h3>The four detectors</h3><ul>
        <li><strong>A · Hidden lookup on this PC</strong>: a program resolved names without Windows' DNS client because it has its own DNS code.</li>
        <li><strong>B · Another DNS server</strong>: this PC (or a browser's Secure DNS) sends lookups to a different server, for example <span class="mono">chrome.exe → 1.1.1.1</span>.</li>
        <li><strong>C · Went quiet</strong>: a device is online but stopped asking OPH-S for longer than the quiet time (Settings → Leak Check). Usual causes are Android Private DNS, a VPN, iCloud Private Relay or a manual DNS server.</li>
        <li><strong>D · Encrypted-DNS attempt</strong>: a device looked up a DoH provider or canary name. This is informational, and it escalates a later quiet leak.</li></ul>
      <h3>House fixes (each can be undone)</h3><ul>
        <li><strong>Answer the canary names</strong>: when this fix is on, OPH-S answers the Firefox canary <span class="mono">use-application-dns.net</span> and the iCloud Private Relay names <span class="mono">mask.icloud.com</span> / <span class="mono">mask-h2.icloud.com</span> with <span class="mono">NXDOMAIN</span>. Firefox then keeps its encrypted DNS off, and Apple devices turn Private Relay off on this network.</li>
        <li><strong>Block encrypted-DNS names</strong>: well-known DoH providers get <span class="mono">NXDOMAIN</span> house-wide. A phone with Android Private DNS set to a specific provider will show 'No internet' until Private DNS is set to Off or Automatic.</li>
        <li><strong>Block encrypted DNS on this PC</strong>: a Windows Firewall rule blocks DNS-over-TLS and known DoH servers for programs on this PC only.</li></ul>
      <p>Recheck asks OPH-S to test a leak again right away. Ignore moves it to Fixed / ignored without changing anything on the device.</p>` },
    { id: "router", title: "Monitoring all router devices", body: html`
      <p>OPH sees every device on your network through DNS, without replacing the router or intercepting traffic.</p>
      <ol><li>Give this PC a fixed IP. In the router, reserve its current address (DHCP reservation), or set a static IP in Windows.</li>
        <li>In the router admin page (often <span class="mono">192.168.1.1</span>), open the DHCP / LAN settings and set <strong>DNS server 1</strong> to this PC's IP. Set DNS 2 to the same IP, or leave it empty.</li>
        <li>On the Network page, click <strong>Open firewall ports</strong> so devices can reach port 53.</li>
        <li>Reconnect devices to Wi-Fi, or wait for their DHCP lease to renew. They appear on the Network page with lookup counts.</li></ol>
      <p>Device discovery reads the LAN neighbour (ARP) table and sends a harmless probe across your subnet every 5 minutes, so devices show up even before they use OPH DNS.</p>
      <p>Optional: if your router can send <strong>syslog</strong>, point it at this PC on the syslog port from Settings to see router logins, DHCP leases and firewall drops.</p>
      <p>When this PC is off, devices lose DNS. Either keep the PC running, or set DNS 2 to a public resolver and accept that devices can then bypass OPH.</p>` },
    { id: "android", title: "Android setup", body: html`
      <p>There are two complementary options.</p>
      <h3>1. Network coverage (no install)</h3><p>On your home Wi-Fi the phone uses the router's DNS, so it is covered by the router setup. In Android Settings &rsaquo; Network &rsaquo; Private DNS, choose <strong>Off</strong> or <strong>Automatic</strong>. A custom Private DNS provider bypasses OPH.</p>
      <h3>2. The OPH agent in Termux (logs)</h3><ol>
        <li>Install <strong>Termux</strong> from F-Droid. The Play Store build is outdated.</li>
        <li>Copy the <span class="mono">oph-agent</span> binary for <span class="mono">aarch64-linux-android</span> to the phone and run <span class="mono">chmod +x oph-agent</span>.</li>
        <li>Run <span class="mono">termux-wake-lock</span> so Android doesn't stop it.</li>
        <li>On the Devices page, click Add device, choose Android and use the Termux command.</li>
        <li>Optional, for full system logs: from a PC with USB debugging, run <span class="mono">adb shell pm grant com.termux android.permission.READ_LOGS</span>.</li></ol>
      <p>Android 10 and later stop normal apps from reading other apps' connections, so the agent focuses on logs. Per-app traffic needs a local VPN-based app such as RethinkDNS or PCAPdroid, which can export to syslog.</p>` },
  ];

  function mount(root) {
    root.innerHTML = html`<div class="page"><div class="page-head"><div><h1 class="page-title">Help</h1><p class="page-desc">What every log means, why it matters and what to do about it.</p></div>
      <input class="input" id="h-q" placeholder="Search help (for example: blocked, port, android)" style="width:340px" aria-label="Search help"></div>
      <div class="help-layout"><nav class="help-nav" id="h-nav" aria-label="Help sections"></nav><div id="h-body"></div></div></div>`.__raw;
    const render = q => {
      q = (q || "").trim().toLowerCase();
      const hit = (...s) => !q || s.join(" ").toLowerCase().includes(q);
      const mark = s => { if (!q) return U.esc(s); const re = new RegExp("(" + q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig"); return U.esc(s).replace(re, "<mark>$1</mark>"); };
      const kinds = Object.entries(HELP.KINDS).filter(([k, v]) => hit(k, v.title, v.what, v.why, v.todo, v.source));
      const fields = Object.entries(HELP.FIELDS).filter(([k, v]) => hit(k, v));
      const guides = GUIDES.filter(g => hit(g.title, g.body.__raw.replace(/<[^>]+>/g, " ")));
      const sections = [];
      if (kinds.length) sections.push({ id: "kinds", title: "Log types", html: kinds.map(([k, v]) => html`<article class="help-entry" id="kind-${k}"><h3><span class="mono">${raw(mark(k))}</span><span class="secondary">· ${raw(mark(v.title))}</span><span class="tag">${v.source}</span>
          <a class="btn sm ghost" style="margin-left:auto" href="#/search?q=${encodeURIComponent("kind=" + k)}&range=7d">Show events</a></h3>
          <div class="grid3"><p><span class="lbl">What it is</span>${raw(mark(v.what))}</p><p><span class="lbl">Why it matters</span>${raw(mark(v.why))}</p><p><span class="lbl">What to do</span>${raw(mark(v.todo))}</p></div>
          <p class="field-help" style="margin-top:8px">Key fields: ${v.fields.map((f, i) => html`${i ? ", " : ""}<span class="mono">${f}</span>`)}</p></article>`).map(x => x.__raw).join("") });
      if (fields.length) sections.push({ id: "fields", title: "Fields", html: html`<section class="panel"><table class="t"><thead><tr><th style="width:140px">Field</th><th>Meaning</th></tr></thead><tbody>${fields.map(([k, v]) => html`<tr><td class="mono">${raw(mark(k))}</td><td class="wrap">${raw(mark(v))}</td></tr>`)}</tbody></table></section>
          <p class="field-help" style="margin-top:8px">Sources: ${Object.entries(HELP.SOURCES).map(([k, v], i) => html`${i ? " · " : ""}<span class="mono">${k}</span> ${v}`)}</p>`.__raw });
      guides.forEach(g => sections.push({ id: g.id, title: g.title, html: `<div class="prose">${g.body.__raw}</div>` }));
      $("#h-nav").innerHTML = sections.map(s => `<a href="#" data-to="${s.id}">${U.esc(s.title)}</a>`).join("");
      $("#h-body").innerHTML = sections.length ? sections.map(s => `<section class="help-section" id="help-${s.id}"><h2>${U.esc(s.title)}</h2>${s.html}</section>`).join("") : U.empty("No help topics match.", "Try a shorter word.").__raw;
      $$("#h-nav a").forEach(a => a.onclick = e => { e.preventDefault(); $$("#h-nav a").forEach(x => x.classList.remove("active")); a.classList.add("active"); const t = $("#help-" + a.dataset.to); if (t) t.scrollIntoView({ block: "start" }); });
    };
    $("#h-q").addEventListener("input", e => render(e.target.value));
    render("");
  }

  window.PAGES.help = { title: "Help", mount };
})();
