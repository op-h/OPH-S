/* Settings — every core option, grouped, with help text. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num, bytes } = U;
  /* IPv4:port with each octet 0-255 and port 1-65535 (the core silently resets anything else). */
  const ipv4Port = (v, eg) => {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$/.exec(v.trim());
    return (m && m.slice(1, 5).every(o => +o <= 255) && +m[5] >= 1 && +m[5] <= 65535) || `Use IPv4:port with port 1-65535, for example ${eg}`;
  };

  const GROUPS = [
    { title: "Appearance", desc: "The icon shown in the top bar, the tray and the window.", fields: [
      { k: "icon_style", type: "icons", label: "App icon", help: "Applies immediately to the top bar, tray and taskbar." },
    ]},
    { title: "Protection", desc: "How OPH-S reacts when something dangerous is found.", fields: [
      { k: "mode", type: "select", label: "Protection mode", opts: [["warn", "Warn: alert me and let me decide"], ["block", "Block: sinkhole and firewall threats automatically"]],
        help: "Warn is recommended at first so you can spot false positives. Your manual Blocklist is enforced in both modes." },
      { k: "watch_local_dns", type: "bool", label: "Watch this PC's DNS cache", help: "Watch this PC's DNS cache for dangerous sites. Works without changing the router." },
      { k: "notifications", type: "bool", label: "Desktop notifications", help: "Show a Windows notification for new high and critical alerts, at most once per indicator per hour." },
      { k: "suricata_eve_path", type: "text", label: "Suricata eve.json path", mono: true, placeholder: "C:\\Program Files\\Suricata\\log\\eve.json",
        help: "Optional. If Suricata IDS is installed, OPH-S tails its eve.json and turns signature hits into alerts. Leave empty to disable." },
      { k: "_unblock", type: "unblock", label: "Remove all blocks", help: "Clears the Blocklist, reopens blocked alerts, removes OPH-S entries from the hosts file and deletes every OPH-S firewall rule. Use it if something important stopped working." },
    ]},
    { title: "DNS resolver", desc: "The network-wide filter. Point your router's DHCP DNS at this PC to cover every device (see the Router page).", fields: [
      { k: "dns_enabled", type: "bool", label: "Run the DNS resolver", help: "Answers DNS for devices that use this PC, logs each lookup and sinkholes blocked domains." },
      { k: "dns_bind", type: "text", label: "Listen address", mono: true, placeholder: "0.0.0.0:53", help: "0.0.0.0:53 serves the whole LAN. Use 127.0.0.1:53 to protect only this PC.", validate: v => ipv4Port(v, "0.0.0.0:53") },
      { k: "dns_upstream", type: "text", label: "Upstream resolver", mono: true, placeholder: "1.1.1.1:53", help: "Where allowed lookups are forwarded. 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9, also filters malware) or your ISP.", validate: v => ipv4Port(v, "9.9.9.9:53") },
    ]},
    { id: "leak", title: "Leak Check", desc: "How OPH-S decides that a device has gone around your protection.", fields: [
      { k: "leak_quiet_minutes", type: "number", int: true, label: "Quiet after (minutes)", min: 2, max: 1440, help: "Minutes without any lookup before an online device counts as quiet. 60 is normal; 2 is for a quick demo." },
    ]},
    { title: "File monitoring", desc: "Watch important folders on this PC for new, changed, renamed or deleted files.", fields: [
      { k: "fim_enabled", type: "bool", label: "Watch folders for file changes", help: "Flags new executables and scripts, anything added to Startup folders or scheduled tasks, and hosts-file changes. OPH-S never watches its own log folders." },
      { k: "fim_paths", type: "paths", label: "Watched folders", help: "Leave the list empty to use the defaults shown. Adding a folder replaces the defaults, so add them back if you still want them. OPH-S never watches its own log folders." },
    ]},
    { title: "Device ingest", desc: "Receiving logs from other PCs, phones and network gear.", fields: [
      { k: "ingest_enabled", type: "bool", label: "Accept device connections", help: "Runs the TLS server that OPH-S agents and the Android app connect to." },
      { k: "ingest_port", type: "number", int: true, label: "Device TCP port", min: 1024, max: 65535, help: "Default 8443. Changing it means re-adding your devices." },
      { k: "syslog_enabled", type: "bool", label: "Syslog receiver", help: "Receive syslog (UDP) from routers, NAS, Fluent Bit, rsyslog." },
      { k: "syslog_port", type: "number", int: true, label: "Syslog UDP port", min: 1, max: 65535, help: "514 is standard but often taken; 5514 avoids conflicts. Set the same port in your router's remote-log setting." },
    ]},
    { title: "Threat intel", desc: "Open threat lists used for matching.", fields: [
      { k: "intel_interval_hours", type: "number", int: true, label: "Refresh interval (hours)", min: 1, max: 168, help: "How often feeds are downloaded. 6 hours balances freshness against load on the free feed providers." },
      { k: "abuse_ch_key", type: "secret", label: "abuse.ch Auth-Key", mono: true, placeholder: "Paste your Auth-Key", help: "Free key from auth.abuse.ch. Enables the URLhaus feed." },
    ]},
    { title: "Storage & retention", desc: "Where logs are kept, for how long, and how much space they may use.", fields: [
      { k: "_status", type: "storage-status", label: "Current storage" },
      { k: "retention_days", type: "number", int: true, label: "Keep events for (days)", min: 1, max: 365, help: "Older events are deleted daily. Default 7." },
      { k: "max_store_mb", type: "gb", label: "Capacity cap (GB)", min: 1, max: 1953, help: "When logs reach this size the oldest events are removed first, even if they are younger than the retention period." },
      { k: "storage_primary", type: "drive-primary", label: "Primary location", help: "OPH-S recognises the drive by its volume serial, so it still finds a USB disk after Windows gives it a different letter." },
      { k: "storage_fallback", type: "drive-fallback", label: "Fallback location", help: "Used while the primary drive is unplugged. Events are merged back into the primary when it returns." },
      { k: "cleaner_schedule", type: "select", label: "Scheduled cleanup", opts: [["off", "Off"], ["daily", "Daily"], ["weekly", "Weekly"]], help: "Runs only the Safe cleaner categories, at low priority, and always to quarantine (undoable)." },
    ]},
    { id: "ai", title: "Ask AI", desc: "Let an AI model explain logs, alerts and devices in plain language.", fields: [
      { k: "_ai_info", type: "ai-info" },
      { k: "ai_provider", type: "ai-provider", label: "Provider" },
      { k: "_ai_key", type: "ai-key", label: "API key" },
      { k: "ai_base_url", type: "text", mono: true, label: "Base URL", placeholder: "https://api.openai.com/v1", showIf: d => d.ai_provider === "openai",
        help: "Any OpenAI-compatible endpoint. OpenAI: https://api.openai.com/v1 · OpenRouter: https://openrouter.ai/api/v1 · Groq: https://api.groq.com/openai/v1 · local Ollama: http://localhost:11434/v1 (no key needed).",
        validate: v => /^https?:\/\/\S+$/.test(v) || "Enter a URL starting with http:// or https://" },
      { k: "ai_model", type: "text", mono: true, label: "Model", placeholder: "claude-opus-5-5",
        help: "Claude: Opus 5.5 is the most capable default; claude-sonnet-5-5 or claude-haiku-5-5 are cheaper. Other providers: the provider's model name, for example llama3.1 on Ollama.",
        validate: v => !!v.trim() || "Enter a model name" },
      { k: "ai_redact", type: "bool", label: "Hide local IPs and MAC addresses before sending", help: "Masks private addresses (192.168.x.x, 10.x.x.x and so on) and MAC addresses in the logs sent to the AI. Domains and process names are still sent." },
    ]},
    { title: "Startup", desc: "Background behaviour.", fields: [
      { k: "autostart", type: "bool", label: "Start with Windows", help: "Starts OPH-S minimized to the tray when you sign in. The window is closed until you open it, which keeps RAM use low." },
    ]},
  ];
  const FIELDS = GROUPS.flatMap(g => g.fields);
  const folderOn = l => `${l}:\\OPH-S\\logs`;

  function mount(root, params) {
    root.innerHTML = html`<div class="page"><div class="page-head"><div><h1 class="page-title">Settings</h1><p class="page-desc">Changes apply as soon as you save. Services restart automatically if needed.</p></div></div>
      <div id="st-body">${U.skeleton(8)}</div></div>`;
    let saved = null, draft = null, showSecret = false, drives = [], storage = null, icons = [], aiSt = null, aiKeyShow = false;
    const isDirty = () => JSON.stringify(saved) !== JSON.stringify(draft);

    async function load() {
      try {
        const [s, d, st, ic] = await Promise.all([API.settingsGet(), API.drivesList().catch(() => []), API.storageStatus().catch(() => null), APP.loadIcons()]);
        saved = s; draft = Object.assign({}, s); drives = d || []; storage = st; icons = ic || [];
        try { aiSt = await API.aiStatus(); } catch (e) { aiSt = null; }
        if (!draft.icon_style) draft.icon_style = saved.icon_style = "op-shield";
        render();
        if (params && params.section) { const g = $(`[data-group="${params.section}"]`); if (g) g.scrollIntoView({ block: "start" }); }
      } catch (e) { $("#st-body").innerHTML = html`<div class="callout bad">${e.message}</div>`; }
    }

    /* ---------- custom controls ---------- */
    function iconPicker() {
      if (!icons.length) return html`<p class="field-help">Icon files were not found in <span class="mono">icons/</span>. The built-in shield is used.</p>`;
      return html`<div class="icon-grid" role="radiogroup" aria-label="App icon">${icons.map(ic => html`<button type="button" role="radio" aria-checked="${draft.icon_style === ic.id}" class="icon-card ${draft.icon_style === ic.id ? "selected" : ""}" data-icon="${ic.id}">
        <div class="previews"><img class="p64" src="icons/${ic.id}.svg" alt=""><img class="p16" src="icons/${ic.id}.svg" alt=""></div>
        <div class="nm">${ic.name}${draft.icon_style === ic.id ? html`<span class="chk">${icon("check", "sm")}</span>` : raw("")}</div><div class="ds">${ic.description}</div></button>`)}</div>`;
    }
    function driveRow(d, name, checked) {
      const usedPct = d.size ? (1 - d.free / d.size) * 100 : 0;
      const big = d.bus === "USB" && d.size >= 1e12;
      return html`<label class="drive ${checked ? "selected" : ""}"><input type="radio" name="${name}" value="${d.letter}" ${raw(checked ? "checked" : "")}>
        <span class="letter">${d.letter}:</span>
        <span><span class="row" style="gap:6px">${d.label || "Local disk"} <span class="tag">${d.bus}</span>${d.removable ? html`<span class="tag">Removable</span>` : raw("")}${big ? html`<span class="tag ok">Recommended for logs</span>` : raw("")}</span>
          <span class="meta num">${bytes(d.free)} free of ${bytes(d.size)} · serial ${d.serial}</span><span class="bar" style="display:block"><span style="width:${usedPct.toFixed(1)}%"></span></span></span>
        <span class="meta mono">${folderOn(d.letter)}</span></label>`;
    }
    function primaryPicker() {
      const cur = (draft.storage_primary || "").slice(0, 1).toUpperCase();
      const appData = !draft.storage_primary;
      return html`<div class="drive-list">
        <label class="drive ${appData ? "selected" : ""}"><input type="radio" name="prim" value="" ${raw(appData ? "checked" : "")}><span class="letter">—</span><span>This PC (app data)<span class="meta" style="display:block">Default. Stored next to the program data on the system drive.</span></span><span></span></label>
        ${drives.map(d => driveRow(d, "prim", !appData && d.letter === cur))}</div>`;
    }
    function fallbackPicker() {
      const prim = (draft.storage_primary || "").slice(0, 1).toUpperCase();
      const cur = (draft.storage_fallback || "").slice(0, 1).toUpperCase();
      const appData = !draft.storage_fallback;
      return html`<div class="drive-list">
        <label class="drive ${appData ? "selected" : ""}"><input type="radio" name="fb" value="" ${raw(appData ? "checked" : "")}><span class="letter">—</span><span>This PC (app data)<span class="meta" style="display:block">Recommended: always available.</span></span><span></span></label>
        ${drives.filter(d => d.letter !== prim).map(d => driveRow(d, "fb", !appData && d.letter === cur))}</div>`;
    }
    function statusCard() {
      if (!storage) return html`<p class="field-help">Storage status is not available.</p>`;
      const s = storage, pct = s.max_bytes ? Math.min(100, s.events_bytes / s.max_bytes * 100) : 0;
      return html`<div class="panel"><div class="panel-body stack">
        <div class="row" style="justify-content:space-between"><span class="status-inline"><span class="dot ${s.active === "primary" ? "ok" : "warn"}"></span>Writing to ${s.active === "primary" ? "primary" : "fallback"} location</span><span class="mono secondary ellipsis" title="${s.path}">${s.path}</span></div>
        ${s.primary_path && !s.primary_online ? html`<div class="callout warn">The primary drive (<span class="mono">${s.primary_path}</span>) is not connected. Events go to the fallback and are merged back when it returns.</div>` : raw("")}
        <div><div class="gauge" role="img" aria-label="Log storage ${pct.toFixed(0)} percent of cap"><span class="g-used" style="width:${pct.toFixed(2)}%"></span></div>
          <div class="row" style="justify-content:space-between;margin-top:4px"><span class="field-help num">${bytes(s.events_bytes)} used of ${bytes(s.max_bytes)} cap (${pct.toFixed(0)}%)</span><span class="field-help num">${bytes(s.free_bytes)} free on drive</span></div></div>
        <dl class="kv"><dt>Oldest event</dt><dd>${s.oldest_ts ? html`${U.absTime(s.oldest_ts)} <span class="muted">(${U.rel(s.oldest_ts)})</span>` : "—"}</dd><dt>Retention</dt><dd>${num(s.retention_days)} days</dd></dl>
      </div></div>`;
    }

    function input(f) {
      const v = draft[f.k];
      const id = "st-" + f.k;
      if (f.type === "icons") return html`<div class="form-field"><span class="field-label">${f.label}</span>${iconPicker()}<p class="field-help">${f.help}</p></div>`;
      if (f.type === "storage-status") return html`<div class="form-field"><span class="field-label">${f.label}</span>${statusCard()}</div>`;
      if (f.type === "drive-primary") return html`<div class="form-field"><span class="field-label">${f.label}</span>${primaryPicker()}<p class="field-help">${f.help}</p></div>`;
      if (f.type === "drive-fallback") return html`<div class="form-field"><span class="field-label">${f.label}</span>${fallbackPicker()}<p class="field-help">${f.help}</p></div>`;
      if (f.type === "paths") {
        const list = Array.isArray(v) ? v : [];
        const DEF = ["Desktop", "Downloads", "Documents", "Startup (you)", "Startup (all users)", "C:\\Windows\\System32\\Tasks", "hosts file folder (C:\\Windows\\System32\\drivers\\etc)"];
        return html`<div class="form-field"><span class="field-label">${f.label}</span>
          <div class="path-list" aria-label="Watched folders">${list.length ? list.map((p, i) => html`<div class="item"><span class="grow ellipsis" title="${p}">${p}</span><button type="button" class="btn ghost icon sm" data-path-rm="${i}" aria-label="Remove ${p}" title="Remove">${icon("x", "sm")}</button></div>`)
            : DEF.map(p => html`<div class="item default"><span class="grow">${p}</span><span class="tag">default</span></div>`)}</div>
          <form class="row" id="st-path-form" novalidate style="margin-top:4px"><input class="input mono grow" id="st-path-new" placeholder="C:\\Users\\you\\Projects" spellcheck="false" aria-label="Folder to watch"><button class="btn" type="submit">${icon("plus", "sm")} Add folder</button></form>
          <p class="field-help">${f.help}</p><div class="field-error" data-err="${f.k}"></div></div>`;
      }
      if (f.showIf && !f.showIf(draft)) return raw("");
      if (f.type === "ai-info") return html`<div class="callout">${icon("info", "sm")} Claude.ai Pro/Max subscriptions can't be used by other apps — Anthropic only allows API keys for that. Create a key at <span class="mono">console.anthropic.com</span> → API Keys. Questions are billed to that key (typically a few cents each). <strong>Log data you ask about is sent to the provider you choose.</strong></div>`;
      if (f.type === "ai-provider") return html`<fieldset class="stack" style="border:none;margin:0;padding:0;gap:4px"><legend class="field-label" style="margin-bottom:4px">${f.label}</legend>
        <label class="drive ${draft.ai_provider !== "openai" ? "selected" : ""}" style="grid-template-columns:20px minmax(0,1fr)"><input type="radio" name="ai-prov" value="anthropic" ${raw(draft.ai_provider !== "openai" ? "checked" : "")}><span><b>Claude</b> (Anthropic API key)<span class="meta" style="display:block">Recommended. Best at reading security logs.</span></span></label>
        <label class="drive ${draft.ai_provider === "openai" ? "selected" : ""}" style="grid-template-columns:20px minmax(0,1fr)"><input type="radio" name="ai-prov" value="openai" ${raw(draft.ai_provider === "openai" ? "checked" : "")}><span><b>Other AI</b> (OpenAI-compatible)<span class="meta" style="display:block">OpenAI, OpenRouter, Groq, or a local Ollama model that keeps everything on your network.</span></span></label></fieldset>`;
      if (f.type === "ai-key") {
        const claude = draft.ai_provider !== "openai", have = aiSt && aiSt.key_saved;
        return html`<div class="form-field"><label class="field-label" for="st-ai-key">${claude ? "Anthropic API key" : "API key (optional)"}</label>
          <div class="row"><input class="input mono grow" id="st-ai-key" type="${aiKeyShow ? "text" : "password"}" autocomplete="off" spellcheck="false" placeholder="${have ? "A key is saved. Paste a new one to replace it." : claude ? "sk-ant-…" : "Leave empty for local Ollama"}">
            <button class="btn icon" type="button" id="st-ai-show" aria-label="${aiKeyShow ? "Hide" : "Show"} key" aria-pressed="${aiKeyShow}">${icon(aiKeyShow ? "eye-off" : "eye", "sm")}</button>
            <button class="btn" type="button" id="st-ai-save">${icon("key", "sm")} Save key</button>
            ${have ? html`<button class="btn danger" type="button" id="st-ai-rm">Remove key</button>` : raw("")}</div>
          <p class="field-help">${have ? html`<span class="status-inline"><span class="dot ok"></span>Key saved</span> · ` : raw("")}Stored encrypted with Windows (DPAPI) for your account only. It is never shown again, and is saved separately from the Save button above.</p>
          <div class="field-error" id="st-ai-err"></div></div>`;
      }
      if (f.type === "unblock") return html`<div class="form-field"><span class="field-label">${f.label}</span><div><button type="button" class="btn danger" id="st-unblock">${icon("ban", "sm")} Remove all blocks…</button></div><p class="field-help">${f.help}</p></div>`;
      if (f.type === "bool") return html`<div class="form-field inline"><label class="toggle"><input type="checkbox" id="${id}" data-k="${f.k}" ${raw(v ? "checked" : "")}><span class="track"></span></label>
        <div><label class="field-label" for="${id}">${f.label}</label><p class="field-help">${f.help}</p></div></div>`;
      let ctl;
      if (f.type === "select") ctl = html`<select class="select" id="${id}" data-k="${f.k}" style="max-width:420px">${f.opts.map(([ov, ol]) => html`<option value="${ov}" ${raw(ov === v ? "selected" : "")}>${ol}</option>`)}</select>`;
      else if (f.type === "secret") ctl = html`<div class="row"><input class="input mono grow" type="${showSecret ? "text" : "password"}" id="${id}" data-k="${f.k}" value="${v || ""}" placeholder="${f.placeholder || ""}" autocomplete="off" spellcheck="false">
        <button class="btn icon" type="button" id="st-secret" aria-label="${showSecret ? "Hide" : "Show"} key">${icon(showSecret ? "eye-off" : "eye", "sm")}</button></div>`;
      else if (f.type === "gb") ctl = html`<input class="input" type="number" id="${id}" data-k="${f.k}" value="${v ? Math.round(v / 1024) : ""}" min="${f.min}" max="${f.max}" style="max-width:160px">`;
      else ctl = html`<input class="input ${f.mono ? "mono" : ""}" type="${f.type === "number" ? "number" : "text"}" id="${id}" data-k="${f.k}" value="${v === null || v === undefined ? "" : v}" placeholder="${f.placeholder || ""}" ${raw(f.min !== undefined ? `min="${f.min}" max="${f.max}"${f.int ? ' step="1" inputmode="numeric"' : ""}` : "")} spellcheck="false" style="${f.type === "number" ? "max-width:160px" : ""}">`;
      return html`<div class="form-field"><label class="field-label" for="${id}">${f.label}</label>${ctl}<p class="field-help">${f.help}</p><div class="field-error" data-err="${f.k}"></div></div>`;
    }

    function render() {
      const y = $("#main").scrollTop;
      $("#st-body").innerHTML = html`<div class="sticky-bar"><span class="secondary" id="st-state"></span><div class="row"><button class="btn" id="st-reset" disabled>Discard changes</button><button class="btn primary" id="st-save" disabled>${icon("check", "sm")} Save</button></div></div>
        <section class="panel">${GROUPS.map(g => html`<div class="form-section" data-group="${g.id || g.title}"><div><h3>${g.title}</h3><p>${g.desc}</p></div><div class="form-fields" ${raw(g.title === "Appearance" || g.title === "Storage & retention" ? 'style="max-width:760px"' : "")}>${g.fields.map(input)}</div></div>`)}</section>`;
      $("#main").scrollTop = y;
      $$("[data-k]").forEach(el => el.addEventListener(el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input", () => {
        const f = FIELDS.find(x => x.k === el.dataset.k);
        draft[f.k] = f.type === "bool" ? el.checked : f.type === "gb" ? (el.value === "" ? null : Math.round(+el.value * 1024)) : f.type === "number" ? (el.value === "" ? null : +el.value) : el.value;
        validateOne(f); updateState();
      }));
      // Icon picks save immediately (only icon_style), so the top bar and tray update at once.
      $$("[data-icon]").forEach(b => b.onclick = async () => {
        const id = b.dataset.icon; if (id === saved.icon_style) return;
        try {
          const res = await API.settingsSet(Object.assign({}, saved, { icon_style: id }));
          saved = res; draft.icon_style = res.icon_style; APP.setIcon(res.icon_style); render();
          U.toast("Icon changed to " + (icons.find(i => i.id === id) || {}).name);
        } catch (e) { U.toast("Could not change the icon: " + e.message, "error"); }
      });
      $$('input[name="prim"]').forEach(r => r.onchange = () => {
        const d = drives.find(x => x.letter === r.value);
        draft.storage_primary = d ? folderOn(d.letter) : ""; draft.storage_primary_serial = d ? d.serial : "";
        if (d && (draft.storage_fallback || "").slice(0, 1).toUpperCase() === d.letter) draft.storage_fallback = "";
        render();
      });
      $$('input[name="fb"]').forEach(r => r.onchange = () => { draft.storage_fallback = r.value ? folderOn(r.value) : ""; render(); });
      const sec = $("#st-secret"); if (sec) sec.onclick = () => { showSecret = !showSecret; const el = $("#st-abuse_ch_key"); el.type = showSecret ? "text" : "password"; sec.innerHTML = icon(showSecret ? "eye-off" : "eye", "sm"); };
      $("#st-unblock").onclick = unblockAll;
      $$('input[name="ai-prov"]').forEach(r => r.onchange = () => {
        draft.ai_provider = r.value;
        if (r.value === "anthropic" && !/^claude-/.test(draft.ai_model || "")) draft.ai_model = "claude-opus-5-5";
        if (r.value === "openai" && /^claude-/.test(draft.ai_model || "")) draft.ai_model = "";
        if (r.value === "openai" && !draft.ai_base_url) draft.ai_base_url = "https://api.openai.com/v1";
        render();
      });
      const mdl = $("#st-ai_model"); if (mdl) mdl.placeholder = draft.ai_provider === "openai" ? "llama3.1 (Ollama) or your provider's model name" : "claude-opus-5-5";
      const aiShow = $("#st-ai-show");
      if (aiShow) aiShow.onclick = () => { aiKeyShow = !aiKeyShow; const k = $("#st-ai-key"); k.type = aiKeyShow ? "text" : "password"; aiShow.innerHTML = icon(aiKeyShow ? "eye-off" : "eye", "sm"); aiShow.setAttribute("aria-pressed", aiKeyShow); };
      const aiSave = $("#st-ai-save");
      if (aiSave) aiSave.onclick = async () => {
        const k = $("#st-ai-key"), v = k.value.trim(), err = $("#st-ai-err");
        if (!v) { err.textContent = "Paste a key first."; k.focus(); return; }
        if (draft.ai_provider !== "openai" && !/^sk-ant-/.test(v)) { err.textContent = "Anthropic keys start with sk-ant-. Check that you copied the whole key."; k.focus(); return; }
        aiSave.disabled = true;
        try { await API.aiSetKey(v); k.value = ""; aiSt = await API.aiStatus(); render(); U.toast("API key saved"); }
        catch (e) { err.textContent = e.message; aiSave.disabled = false; }
      };
      const aiRm = $("#st-ai-rm");
      if (aiRm) aiRm.onclick = async () => {
        const ok = await U.confirmModal({ title: "Remove the saved API key?", confirmLabel: "Remove key", danger: true, body: html`<p>The encrypted key is deleted from this PC and Ask AI stops working until you add a key again. The key itself stays valid in your provider's console; revoke it there if it may have leaked.</p>` });
        if (!ok) return;
        try { await API.aiSetKey(""); aiSt = await API.aiStatus(); render(); U.toast("API key removed"); } catch (e) { U.toast(e.message, "error"); }
      };
      const pf = $("#st-path-form");
      if (pf) pf.onsubmit = e => {
        e.preventDefault();
        const inp = $("#st-path-new"), v = inp.value.trim().replace(/[\\/]+$/, "");
        const err = $('[data-err="fim_paths"]');
        if (!/^([a-zA-Z]:\\|\\\\)/.test(v)) { err.textContent = "Enter a full folder path, for example C:\\Users\\you\\Projects"; inp.classList.add("invalid"); inp.focus(); return; }
        const cur = Array.isArray(draft.fim_paths) ? draft.fim_paths.slice() : [];
        if (cur.some(p => p.toLowerCase() === v.toLowerCase())) { err.textContent = "That folder is already in the list."; inp.focus(); return; }
        cur.push(v); draft.fim_paths = cur; render(); const n = $("#st-path-new"); if (n) n.focus();
      };
      $$("[data-path-rm]").forEach(b => b.onclick = () => { const cur = draft.fim_paths.slice(); cur.splice(+b.dataset.pathRm, 1); draft.fim_paths = cur; render(); });
      $("#st-reset").onclick = () => { draft = Object.assign({}, saved); render(); };
      $("#st-save").onclick = save;
      updateState();
    }
    function validateOne(f) {
      const err = $(`[data-err="${f.k}"]`), el = $("#st-" + f.k); if (!err || !el) return true;
      let msg = "";
      let v = draft[f.k];
      if (f.type === "gb") v = v === null ? null : v / 1024;
      if (f.type === "number" || f.type === "gb") { if (v === null || isNaN(v)) msg = "Enter a number"; else if (f.int && !Number.isInteger(v)) msg = "Enter a whole number"; else if (v < f.min || v > f.max) msg = `Must be between ${f.min} and ${f.max}`; }
      if (!msg && f.validate) { const r = f.validate(String(v || "")); if (r !== true) msg = r; }
      err.textContent = msg; el.classList.toggle("invalid", !!msg);
      return !msg;
    }
    function updateState() {
      const d = isDirty();
      $("#st-state").innerHTML = d ? html`<span class="status-inline"><span class="dot warn"></span>Unsaved changes</span>` : html`<span class="status-inline"><span class="dot ok"></span>All changes saved</span>`;
      $("#st-save").disabled = !d; $("#st-reset").disabled = !d;
    }
    async function unblockAll() {
      const ok = await U.confirmModal({ title: "Remove every block?", confirmLabel: "Remove all blocks", danger: true,
        body: html`<p>This undoes all blocking done by OPH-S:</p><ul><li>The manual Blocklist is emptied.</li><li>Blocked alerts return to Open, so you can decide again.</li><li>OPH-S entries are removed from the Windows hosts file.</li><li>The <span class="mono">OPH Sentinel - blocked IPs</span> firewall rules are deleted (administrator approval may be requested).</li></ul>
          <p>Threat feeds stay enabled. In Block mode, feed matches are blocked again as they happen.</p>` });
      if (!ok) return;
      try { const r = await API.unblockAll(); U.toast(r.message, r.ok ? "" : "error"); APP.refreshStatus(); } catch (e) { U.toast(e.message, "error"); }
    }
    async function save() {
      const ok = FIELDS.map(validateOne).every(Boolean);
      if (!ok) { U.toast("Fix the highlighted fields first", "error"); return; }
      if (draft.mode === "block" && saved.mode !== "block") {
        const c = await U.confirmModal({ title: "Switch to Block mode?", confirmLabel: "Enable Block mode",
          body: html`<p>From now on, OPH-S will block automatically without asking:</p><ul><li>Domains on any enabled feed get 0.0.0.0 from OPH DNS.</li><li>IPs on feeds get a Windows Firewall rule (admin approval may be requested).</li></ul><p>False positives can break sites until you add them to the Allowlist.</p>` });
        if (!c) return;
      }
      if (draft.storage_primary !== saved.storage_primary) {
        const c = await U.confirmModal({ title: "Change the log location?", confirmLabel: "Move logs",
          body: html`<p>New events will be written to <span class="mono">${draft.storage_primary || "this PC (app data)"}</span>. Existing events are moved there in the background. Searching keeps working during the move.</p>` });
        if (!c) return;
      }
      FIELDS.forEach(f => { if (f.int && typeof draft[f.k] === "number") draft[f.k] = Math.round(draft[f.k]); });
      try {
        saved = await API.settingsSet(draft); draft = Object.assign({}, saved);
        storage = await API.storageStatus().catch(() => storage);
        try { aiSt = await API.aiStatus(); } catch (e) { /* keep */ }
        render(); APP.refreshStatus(); APP.setIcon(saved.icon_style); U.toast("Settings saved");
      } catch (e) { U.toast("Save failed: " + e.message, "error"); }
    }
    const beforeUnload = e => { if (draft && isDirty()) { e.preventDefault(); e.returnValue = ""; } };
    window.addEventListener("beforeunload", beforeUnload);
    load();
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }

  window.PAGES.settings = { title: "Settings", mount };
})();
