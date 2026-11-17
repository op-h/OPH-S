/* Search & Reporting — Splunk-style event search, keyboard-first, with guidance for new users. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, esc, $, $$, num } = U;

  const RANGES = [
    { id: "15m", label: "Last 15 minutes", ms: 15 * 60e3, words: "in the last 15 minutes" },
    { id: "60m", label: "Last 60 minutes", ms: 60 * 60e3, words: "in the last hour" },
    { id: "4h", label: "Last 4 hours", ms: 4 * 3600e3, words: "in the last 4 hours" },
    { id: "24h", label: "Last 24 hours", ms: 24 * 3600e3, words: "in the last 24 hours" },
    { id: "7d", label: "Last 7 days", ms: 7 * 24 * 3600e3, words: "in the last 7 days" },
    { id: "all", label: "All time", ms: 0, words: "across all time" },
  ];
  const PAGE = 100, LIMIT = 1000;
  const FIELDS = ["source", "kind", "severity", "host", "src_ip", "dst_ip", "dst_port", "domain", "process", "pd", "vpn"];
  const SELECTED = ["host", "source", "kind"];
  const INTERESTING = ["severity", "domain", "process"];
  const SEVS = ["info", "low", "medium", "high", "critical"];
  const COMMANDS = [
    { insert: "stats count by ", hint: "Count events per value of a field" },
    { insert: "top ", hint: "The 10 most common values of a field" },
    { insert: "head ", hint: "Keep only the first N results" },
    { insert: "sort ts", hint: "Oldest first" },
    { insert: "sort -ts", hint: "Newest first (default)" },
  ];
  const CHIPS = [
    { label: "Threats", clause: "kind=threat.match OR kind=ids.alert" },
    { label: "Blocked", clause: "kind=dns.blocked" },
    { label: "DNS lookups", clause: "kind=dns.query" },
    { label: "Connections", clause: "kind=conn.open" },
    { label: "Files", clause: "source=file" },
    { label: "This PC", clause: "host=this-pc" },
    { label: "Phones & agents", clause: "source=agent" },
    { label: "Errors & warnings", clause: "severity>=medium" },
    { label: "Leaks", clause: "source=leak", tip: "Leak Check events: devices and programs that went around OPH-S DNS, and leaks that were fixed." },
    { label: "VPN", clause: "vpn=yes", tip: "VPN connections: lookups of VPN / proxy / encrypted-DNS services (hagezi list), VPN apps (OpenVPN, WireGuard, NordVPN, Tailscale, WARP, Android VPN apps) and VPN-only ports. Detection only." },
    { label: "PD", clause: "pd=yes", tip: "PD — porn detector: shows visits to adult websites (OISD NSFW list). Detection only, nothing is blocked." },
  ];
  const EXAMPLES = [
    { title: "What did my phone look up today?", q: "kind=dns.query NOT host=this-pc | stats count by domain", range: "24h", why: "Lookups from other devices on your network. Add host=<your phone's IP> to narrow it down." },
    { title: "Which programs connect to the internet?", q: "kind=conn.open | stats count by process", range: "24h", why: "Every program on this PC that opened a connection, busiest first." },
    { title: "Top domains", q: "source=dns | top domain", range: "24h", why: "The 10 names your network looks up most." },
    { title: "New devices", q: "kind=device.new", range: "7d", why: "Devices that joined your network for the first time this week." },
    { title: "Files created in Downloads", q: "kind=file.created Downloads", range: "7d", why: "New files in your Downloads folder. Executables and scripts are marked medium." },
    { title: "Threats this week", q: "kind=threat.match OR kind=ids.alert", range: "7d", why: "Threat-feed matches and IDS signature hits." },
    { title: "Which devices use a VPN or proxy?", q: "vpn=yes | stats count by host", range: "7d", why: "A VPN on a device hides what it does from OPH-S DNS. Combines the hagezi VPN/proxy list, VPN apps and VPN-only ports." },
    { title: "Which devices visited adult sites?", q: "pd=yes | stats count by host", range: "7d", why: "PD (porn detector) uses the OISD NSFW list. Detection only, nothing is blocked." },
  ];
  const KIND_NOUN = {
    "dns.query": "DNS lookups", "dns.blocked": "blocked lookups", "conn.open": "connections", "threat.match": "threat matches", "ids.alert": "IDS alerts",
    "agent.log": "agent log lines", "agent.connect": "agent connections", "agent.disconnect": "agent disconnects", "device.new": "new devices",
    "firewall.block": "firewall blocks", "firewall.unblock": "firewall unblocks", "intel.update": "feed updates", "cleaner.run": "cleanup runs",
    "cleaner.undo": "cleanup undos", "system.start": "service starts", "system.error": "service problems", "syslog.message": "syslog messages",
    "file.created": "created files", "file.modified": "modified files", "file.deleted": "deleted files", "file.renamed": "renamed files",
  };
  const SOURCE_NOUN = { dns: "DNS events", conn: "connections", ids: "IDS alerts", agent: "agent logs", system: "system events", intel: "threat-intel events", cleaner: "cleaner events", firewall: "firewall events", syslog: "syslog messages", file: "file changes" };
  const RECENT_KEY = "ophs.search.recent";

  const state = { q: "", range: "24h", from: null, to: null, zoomStack: [], page: 0, result: null, window: null, open: new Set() };
  let devNames = {}, settingsCache = null;

  /* ---------- query text helpers ---------- */
  const needsQuote = v => /[\s"|=()]/.test(v);
  const term = (f, v) => `${f}=${needsQuote(String(v)) ? '"' + String(v).replace(/"/g, "") + '"' : v}`;
  const splitQ = q => { const i = q.indexOf("|"); return i < 0 ? [q.trim(), ""] : [q.slice(0, i).trim(), q.slice(i)]; };
  const joinQ = (base, pipes) => (base.trim() + (pipes ? " " + pipes.trim() : "")).trim();
  function hasClause(base, clause) { return (" " + base.replace(/\s+/g, " ") + " ").includes(" " + clause + " "); }
  function removeClause(base, clause) { return (" " + base.replace(/\s+/g, " ") + " ").replace(" " + clause + " ", " ").trim(); }
  function isIp(v) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(v || ""); }
  function devLabel(v) { if (v === "this-pc") return "this PC"; return devNames[v] ? `${devNames[v]} (${v})` : v; }
  function ipTitle(f, v) { return (f === "host" || f === "src_ip" || f === "dst_ip") && devNames[v] ? devNames[v] : ""; }

  /** Tokenise the main part of a query like the core does (implicit AND, OR, NOT). */
  function parseTerms(base) {
    const re = /"([^"]*)"|(\w+)\s*(!=|>=|<=|=|>|<)\s*("[^"]*"|[^\s()]+)|(\S+)/g;
    const groups = []; let neg = false, orNext = false, m;
    while ((m = re.exec(base))) {
      let t;
      if (m[1] !== undefined) t = { free: m[1] };
      else if (m[2]) t = { f: m[2], op: m[3], v: m[4].replace(/^"|"$/g, "") };
      else { const w = m[5].replace(/^\(+|\)+$/g, ""); if (w === "NOT") { neg = true; continue; } if (w === "OR") { orNext = true; continue; } if (!w || w === "*" || w === "AND") continue; t = { free: w }; }
      t.neg = neg; neg = false;
      if (orNext && groups.length) groups[groups.length - 1].push(t); else groups.push([t]);
      orNext = false;
    }
    return groups;
  }

  /* ---------- plain-language summary ---------- */
  function summary(res) {
    const [base, pipes] = splitQ(state.q);
    const groups = parseTerms(base);
    let subject = null; const conds = [];
    const sevWords = (op, v) => op === ">=" ? `severity ${v} or higher` : op === ">" ? `severity above ${v}` : op === "<=" ? `severity ${v} or lower` : op === "<" ? `severity below ${v}` : `severity ${v}`;
    const phrase = t => {
      const v = t.v, wild = /\*/.test(v || "");
      if (t.free !== undefined) return (t.neg ? "not containing " : "containing ") + `"${t.free}"`;
      const neg = t.neg || t.op === "!=";
      switch (t.f) {
        case "host": case "src_ip": return (neg ? "not from " : "from ") + devLabel(v);
        case "dst_ip": return (neg ? "not to " : "to ") + devLabel(v);
        case "domain": return (neg ? "excluding " : wild ? "matching " : "for ") + v;
        case "process": return (neg ? "not by " : "by ") + v;
        case "dst_port": return (neg ? "not on port " : "on port ") + v;
        case "severity": return (neg ? "without " : "with ") + sevWords(t.op === "!=" ? "=" : t.op, v);
        case "kind": return (neg ? "excluding " : "") + (KIND_NOUN[v] || v);
        case "pd": return ((/^(yes|true|1)$/i.test(v)) !== neg) ? "to adult sites (PD)" : "excluding adult sites (PD)";
        case "vpn": return ((/^(yes|true|1)$/i.test(v)) !== neg) ? "involving VPNs or proxies" : "excluding VPN / proxy activity";
        case "source": return (neg ? "excluding " : "") + (SOURCE_NOUN[v] || v);
        default: return `${neg ? "where not " : "where "}${t.f} is ${v}`;
      }
    };
    for (const g of groups) {
      const subj = g.every(t => !t.neg && t.op === "=" && (t.f === "kind" || t.f === "source"));
      if (subj && !subject) subject = g.map(phrase).join(" or ");
      else conds.push(g.map(phrase).join(" or "));
    }
    const r = RANGES.find(x => x.id === state.range);
    const when = state.from ? `between ${U.absTime(state.from)} and ${U.absTime(state.to)}` : r ? r.words : "";
    let s = `Showing ${subject || "all events"}${conds.length ? " " + conds.join(", ") : ""} ${when}`;
    const st = /\|\s*stats\s+count\s+by\s+(\w+)/i.exec(pipes), tp = /\|\s*top\s+(\w+)/i.exec(pipes);
    if (st) s += `, counted by ${st[1]}`;
    if (tp) s += `, top 10 values of ${tp[1]}`;
    return s + ` — ${num(res.total)} event${res.total === 1 ? "" : "s"}`;
  }

  /* ---------- recent searches (per viewer, best effort) ---------- */
  function recentGet() { try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); } catch (e) { return []; } }
  function recentPush(q, range) {
    if (!q.trim()) return;
    try { const list = recentGet().filter(x => x.q !== q); list.unshift({ q, range, ts: Date.now() }); localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 10))); } catch (e) { /* storage unavailable */ }
  }

  /* ---------- small dropdown menus ---------- */
  let menuEl = null;
  function closeMenu() { if (menuEl) { menuEl.remove(); menuEl = null; document.removeEventListener("mousedown", menuOutside, true); document.removeEventListener("keydown", menuKey, true); } }
  function menuOutside(e) { if (menuEl && !menuEl.contains(e.target) && !e.target.closest("[data-menu-anchor]")) closeMenu(); }
  function menuKey(e) {
    if (!menuEl) return;
    if (e.key === "Escape") { e.stopPropagation(); const a = menuEl._anchor; closeMenu(); if (a) a.focus(); return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const items = $$(".menu-item", menuEl); if (!items.length) return;
      e.preventDefault();
      const i = items.indexOf(document.activeElement);
      items[(i + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length].focus();
    }
  }
  function openMenu(anchor, markup, width) {
    const again = menuEl && menuEl._anchor === anchor;
    closeMenu(); if (again) return null;
    menuEl = U.el(html`<div class="popover menu" role="menu" style="width:${width || 360}px">${markup}</div>`);
    menuEl._anchor = anchor;
    document.body.appendChild(menuEl);
    const r = anchor.getBoundingClientRect();
    menuEl.style.left = Math.max(8, Math.min(r.left, window.innerWidth - menuEl.offsetWidth - 8)) + "px";
    menuEl.style.top = Math.min(r.bottom + 4, window.innerHeight - menuEl.offsetHeight - 8) + "px";
    setTimeout(() => { document.addEventListener("mousedown", menuOutside, true); document.addEventListener("keydown", menuKey, true); }, 0);
    const f = menuEl.querySelector(".menu-item, input, select"); if (f) f.focus();
    return menuEl;
  }

  /* ====================================================================== */
  function mount(root, params) {
    if (params.q !== undefined) { state.q = params.q; state.zoomStack = []; state.from = state.to = null; state.result = null; }
    if (params.range && RANGES.find(r => r.id === params.range)) { state.range = params.range; state.result = null; }
    state.open = new Set(); state.page = 0;

    root.innerHTML = html`<div class="page-full">
      <div class="search-top">
        <form class="search-bar" id="s-form" autocomplete="off">
          <div class="q-wrap">
            <input class="q" id="s-q" spellcheck="false" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="s-ac" aria-label="Search query"
              placeholder='Type a field name, e.g. kind=dns.query severity>=medium   ·   press / to focus'>
            <div class="ac hidden" id="s-ac" role="listbox" aria-label="Suggestions"></div>
          </div>
          <select class="select" id="s-range" aria-label="Time range">
            ${RANGES.map(r => html`<option value="${r.id}">${r.label}</option>`)}
            <option value="custom" disabled>Custom range</option>
          </select>
          <button class="btn primary" type="submit" aria-label="Run search" title="Search (Enter)">${icon("search")}</button>
        </form>
        <div class="s-tools">
          <div class="chips" id="s-chips" role="group" aria-label="Quick filters"></div>
          <div class="row s-actions">
            <button type="button" class="btn sm ghost" id="s-build" data-menu-anchor>${icon("list-filter", "sm")} Build a filter</button>
            <button type="button" class="btn sm ghost" id="s-examples" data-menu-anchor>${icon("book", "sm")} Examples</button>
            <button type="button" class="btn sm ghost" id="s-saved" data-menu-anchor>${icon("star", "sm")} Saved</button>
            <button type="button" class="btn sm ghost" id="s-recent" data-menu-anchor>${icon("history", "sm")} Recent</button>
            <span class="vsep" aria-hidden="true"></span>
            <button type="button" class="btn sm ghost icon" id="s-star" title="Save this search" aria-label="Save this search">${icon("star", "sm")}</button>
            <button type="button" class="btn sm" id="s-ai">${icon("bot", "sm")} Ask AI</button>
            <button type="button" class="btn sm ghost" id="s-export">${icon("file-down", "sm")} Export CSV</button>
            <button type="button" class="btn sm ghost icon" id="s-keys" data-menu-anchor title="Keyboard shortcuts" aria-label="Keyboard shortcuts">?</button>
          </div>
        </div>
        <div class="s-summary" id="s-summary" aria-live="polite"></div>
        <div class="search-meta"><span id="s-meta" class="num"></span><span class="row" id="s-zoom"></span></div>
      </div>
      <div class="histo-wrap" id="s-histo-wrap"><div class="histo" id="s-histo"></div>
        <div class="histo-foot"><span id="s-h-from"></span><span class="muted">Drag across the timeline to zoom into a time range</span><span id="s-h-to"></span></div></div>
      <div class="search-body">
        <aside class="fields" id="s-fields" aria-label="Fields"></aside>
        <section class="events" id="s-events" aria-label="Results"></section>
      </div>
    </div>`;

    const q = $("#s-q"), rangeSel = $("#s-range");
    q.value = state.q;
    rangeSel.value = state.from ? "custom" : state.range;
    renderChips();

    $("#s-form").addEventListener("submit", e => { e.preventDefault(); acClose(); state.q = q.value.trim(); state.page = 0; run(); });
    rangeSel.addEventListener("change", () => { state.range = rangeSel.value; state.from = state.to = null; state.zoomStack = []; state.page = 0; run(); });
    q.addEventListener("input", () => { renderChips(q.value); acUpdate(false); });
    q.addEventListener("keydown", acKeydown);
    q.addEventListener("blur", () => setTimeout(() => { if (document.activeElement !== q) acClose(); }, 120));
    q.addEventListener("focus", () => { if (!q.value.trim()) acUpdate(true); });

    $("#s-build").onclick = e => openBuilder(e.currentTarget);
    $("#s-examples").onclick = e => openExamples(e.currentTarget);
    $("#s-saved").onclick = e => openSaved(e.currentTarget);
    $("#s-recent").onclick = e => openRecent(e.currentTarget);
    $("#s-star").onclick = saveCurrent;
    $("#s-export").onclick = exportCsv;
    $("#s-ai").onclick = () => {
      const [from, to] = timeWindow(), res = state.result;
      const n = res && !res.error ? res.total : null;
      AI.open({ kind: "search", data: { query: state.q, fromTs: from, toTs: to },
        label: `Search: ${state.q || "(all events)"} · ${state.from ? "custom range" : (RANGES.find(r => r.id === state.range) || {}).label}${n !== null ? ` (${num(n)} events, newest ${Math.min(n, 60)} sent)` : ""}` });
    };
    $("#s-keys").onclick = e => openMenu(e.currentTarget, html`<div class="panel-head"><h3 class="panel-title">${icon("keyboard", "sm")} Keyboard shortcuts</h3></div>
      <dl class="kv keys" style="padding:12px"><dt><kbd>/</kbd></dt><dd>Focus the search bar</dd><dt><kbd>Enter</kbd></dt><dd>Run the search (or accept a highlighted suggestion)</dd>
      <dt><kbd>Ctrl</kbd>+<kbd>Enter</kbd></dt><dd>Run the search, even while suggestions are open</dd><dt><kbd>Tab</kbd></dt><dd>Accept the suggestion</dd>
      <dt><kbd>↑</kbd> <kbd>↓</kbd></dt><dd>Move through suggestions (↓ also opens them)</dd><dt><kbd>Esc</kbd></dt><dd>Close suggestions and menus</dd></dl>`, 380);

    const slash = e => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target; if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
      if ($(".modal-scrim")) return;
      e.preventDefault(); q.focus(); q.setSelectionRange(q.value.length, q.value.length);
    };
    document.addEventListener("keydown", slash);

    API.devices().then(d => { devNames = {}; (d.devices || []).forEach(x => { if (x.hostname) devNames[x.ip] = x.hostname; }); if (state.result) renderSummary(); }).catch(() => {});
    API.settingsGet().then(s => { settingsCache = s; }).catch(() => {});

    if (state.result && params.q === undefined && state.window) {
      const [f, t] = state.window;
      renderAll(state.result, f, t);
    } else run();
    q.focus();

    return () => {
      if (chart) { chart.destroy(); chart = null; }
      closeMenu(); acClose();
      const p = $(".popover"); if (p) p.remove();
      document.removeEventListener("keydown", slash);
      document.removeEventListener("mousedown", closePopoverOutside, true);
    };
  }

  function timeWindow() {
    if (state.from) return [state.from, state.to];
    const r = RANGES.find(x => x.id === state.range) || RANGES[3];
    const now = Date.now();
    return [r.ms ? now - r.ms : 0, now];
  }

  let reqSeq = 0;
  async function run() {
    const seq = ++reqSeq;
    const [from, to] = timeWindow();
    $("#s-meta").innerHTML = '<span class="muted">Searching…</span>';
    $("#s-events").innerHTML = U.skeleton(8);
    renderChips(state.q);
    let res;
    try { res = await API.search(state.q, from, to, LIMIT); }
    catch (e) { res = { events: [], total: 0, histogram: [], fields: {}, stats: null, took_ms: 0, error: e.message }; }
    if (seq !== reqSeq || !$("#s-events")) return;
    state.result = res; state.window = [from, to];
    if (!res.error) recentPush(state.q, state.from ? "custom" : state.range);
    renderAll(res, from, to);
  }
  function renderAll(res, from, to) {
    renderMeta(res, from, to); renderSummary(); renderHisto(res.histogram || [], from, to); renderFields(res.fields || {}); renderEvents();
  }
  function renderSummary() {
    const el = $("#s-summary"); if (!el || !state.result) return;
    el.textContent = state.result.error ? "" : summary(state.result);
  }

  function renderMeta(res, from, to) {
    const m = $("#s-meta");
    if (res.error) {
      const dm = /Did you mean "([^"]+)"/.exec(res.error), uf = /Unknown field "([^"]+)"/.exec(res.error);
      m.innerHTML = html`<span class="err">${icon("alert", "sm")} ${res.error}</span>${dm && uf ? html` <button type="button" class="btn sm" id="s-fix">Use ${dm[1]}</button>` : raw("")}`;
      const fx = $("#s-fix");
      if (fx) fx.onclick = () => {
        const bad = uf[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        let nq = state.q.replace(new RegExp(`\\b${bad}(?=\\s*(!=|>=|<=|=|>|<))`, "g"), dm[1]);
        nq = nq.replace(new RegExp(`\\b(by|top)\\s+${bad}\\b`, "g"), `$1 ${dm[1]}`);
        setQuery(nq);
      };
    } else {
      const shown = Math.min(res.total, LIMIT);
      m.innerHTML = html`<b>${num(res.total)}</b> events${raw(res.total > LIMIT ? ` <span class="muted">(newest ${num(shown)} loaded)</span>` : "")} <span class="muted">· ${U.absTime(from || (res.histogram[0] && res.histogram[0].t))} to ${U.absTime(to)} · ${num(res.took_ms)} ms</span>`;
    }
    const z = $("#s-zoom");
    z.innerHTML = state.from ? html`<button class="btn sm" id="s-zoomout">${icon("zoom-out", "sm")} Zoom out</button><button class="btn sm ghost" id="s-reset">Reset to ${(RANGES.find(r => r.id === state.range) || {}).label || "range"}</button>` : "";
    if (state.from) {
      $("#s-zoomout").onclick = () => { const prev = state.zoomStack.pop(); if (prev) { state.from = prev[0]; state.to = prev[1]; } else { state.from = state.to = null; } $("#s-range").value = state.from ? "custom" : state.range; run(); };
      $("#s-reset").onclick = () => { state.from = state.to = null; state.zoomStack = []; $("#s-range").value = state.range; run(); };
    }
  }

  /* ---------- quick filter chips ---------- */
  function renderChips(text) {
    const box = $("#s-chips"); if (!box) return;
    const [base] = splitQ(text === undefined ? state.q : text);
    box.innerHTML = html`<span class="muted chips-lbl">Quick filters</span>${CHIPS.map((c, i) => {
      const on = hasClause(base, c.clause);
      return html`<button type="button" class="chip ${on ? "active" : ""}" aria-pressed="${on}" data-chip="${i}" title="${c.tip || (on ? "Remove " : "Add ") + c.clause}">${on ? icon("check", "sm") : raw("")}${c.label}</button>`;
    })}`;
    $$("[data-chip]", box).forEach(b => b.onclick = () => {
      const c = CHIPS[+b.dataset.chip];
      const cur = $("#s-q").value;
      const [base, pipes] = splitQ(cur);
      const nb = hasClause(base, c.clause) ? removeClause(base, c.clause) : (base + " " + c.clause).trim();
      setQuery(joinQ(nb, pipes));
    });
  }

  /* ---------- autocomplete ---------- */
  let ac = { items: [], active: -1, start: 0, end: 0, seq: 0 }, acTimer = null;
  function acClose() { const box = $("#s-ac"); if (box) { box.classList.add("hidden"); box.innerHTML = ""; } const q = $("#s-q"); if (q) { q.setAttribute("aria-expanded", "false"); q.removeAttribute("aria-activedescendant"); } ac.items = []; ac.active = -1; clearTimeout(acTimer); }
  function acRender() {
    const box = $("#s-ac"), q = $("#s-q"); if (!box) return;
    if (!ac.items.length) { acClose(); return; }
    box.innerHTML = ac.items.map((it, i) => html`<div class="ac-item ${i === ac.active ? "active" : ""}" role="option" id="ac-${i}" aria-selected="${i === ac.active}" data-i="${i}">
      <span class="ac-label">${it.label}</span>${it.count !== undefined ? html`<span class="ac-count num">${num(it.count)}</span>` : raw("")}<span class="ac-hint">${it.hint || ""}</span></div>`).join("")
      + `<div class="ac-foot">Tab or Enter to accept · Esc to close · Ctrl+Enter to run</div>`;
    box.classList.remove("hidden");
    q.setAttribute("aria-expanded", "true");
    if (ac.active >= 0) q.setAttribute("aria-activedescendant", "ac-" + ac.active); else q.removeAttribute("aria-activedescendant");
    $$(".ac-item", box).forEach(el => {
      el.addEventListener("mousedown", e => { e.preventDefault(); acAccept(+el.dataset.i); });
    });
    const a = box.querySelector(".ac-item.active"); if (a) a.scrollIntoView({ block: "nearest" });
  }
  function acAccept(i) {
    const it = ac.items[i]; if (!it) return;
    const q = $("#s-q"), v = q.value;
    const nv = v.slice(0, ac.start) + it.insert + v.slice(ac.end);
    q.value = nv;
    const caret = ac.start + it.insert.length;
    q.setSelectionRange(caret, caret);
    renderChips(nv);
    if (it.reopen) acUpdate(true); else acClose();
  }
  function acKeydown(e) {
    const open = ac.items.length > 0;
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); acClose(); state.q = e.target.value.trim(); state.page = 0; run(); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); if (!open) { acUpdate(true); return; } ac.active = (ac.active + 1) % ac.items.length; acRender(); return; }
    if (e.key === "ArrowUp" && open) { e.preventDefault(); ac.active = ac.active <= 0 ? ac.items.length - 1 : ac.active - 1; acRender(); return; }
    if (e.key === "Tab" && open) { e.preventDefault(); acAccept(Math.max(0, ac.active)); return; }
    if (e.key === "Enter" && open && ac.active >= 0) { e.preventDefault(); acAccept(ac.active); return; }
    if (e.key === "Escape" && open) { e.preventDefault(); e.stopPropagation(); acClose(); }
  }
  function fieldItems(prefix, start, end) {
    const p = prefix.toLowerCase();
    const items = [];
    FIELDS.filter(f => f.startsWith(p)).forEach(f => {
      const hint = (HELP.FIELDS[f] || "").split(". ")[0];
      if (f === "severity") {
        items.push({ label: "severity=", insert: "severity=", hint: "Exactly this severity", reopen: true });
        items.push({ label: "severity>=", insert: "severity>=", hint: "This severity or higher", reopen: true });
      } else items.push({ label: f + "=", insert: f + "=", hint, reopen: true });
    });
    if ("not".startsWith(p) && p) items.push({ label: "NOT", insert: "NOT ", hint: "Exclude the next filter", reopen: true });
    if ("or".startsWith(p) && p) items.push({ label: "OR", insert: "OR ", hint: "Match either the filter before or after", reopen: true });
    ac.start = start; ac.end = end;
    return items;
  }
  function acUpdate(force) {
    clearTimeout(acTimer);
    const q = $("#s-q"); if (!q) return;
    const v = q.value, caret = q.selectionStart || 0;
    const before = v.slice(0, caret);
    let end = caret; const after = /^\S*/.exec(v.slice(caret)); if (after) end = caret + after[0].length;
    const pi = before.lastIndexOf("|");
    const seq = ++ac.seq;
    let items = [];
    if (pi >= 0) {
      const seg = before.slice(pi + 1).replace(/^\s+/, "");
      const mf = /^(stats\s+count\s+by|top)\s+(\w*)$/i.exec(seg);
      if (mf) {
        items = FIELDS.filter(f => f.startsWith(mf[2].toLowerCase())).map(f => ({ label: f, insert: f + " ", hint: (HELP.FIELDS[f] || "").split(". ")[0] }));
        ac.start = caret - mf[2].length; ac.end = end;
      } else if (/^\w*$/.test(seg)) {
        items = COMMANDS.filter(c => c.insert.startsWith(seg.toLowerCase())).map(c => ({ label: c.insert.trim(), insert: c.insert, hint: c.hint, reopen: /\s$/.test(c.insert) && c.insert !== "head " }));
        ac.start = caret - seg.length; ac.end = end;
        if (!seg && !force && !/\|\s*$/.test(before)) items = [];
      }
      ac.items = items; ac.active = items.length && (force || seg) ? 0 : -1; acRender();
      return;
    }
    const token = /(\S*)$/.exec(before)[1];
    const start = caret - token.length;
    const mv = /^(\w+)(!=|>=|<=|=|>|<)("?)([^"]*)$/.exec(token);
    if (mv && FIELDS.includes(mv[1])) {
      const [, f, op, , pre] = mv;
      const make = (key, count) => ({ label: `${f}${op}${key}`, insert: `${f}${op}${needsQuote(key) ? '"' + key + '"' : key} `, count, hint: ipTitle(f, key) });
      ac.start = start; ac.end = end;
      if (f === "severity") { ac.items = SEVS.filter(s => s.startsWith(pre.toLowerCase())).map(s => make(s)); ac.active = 0; acRender(); return; }
      if (f === "vpn") { ac.items = [["yes", "VPN / proxy use (service domains, VPN apps, VPN ports)"], ["no", "Everything except VPN activity"]].filter(([k]) => k.startsWith(pre.toLowerCase())).map(([k, h]) => Object.assign(make(k), { hint: h })); ac.active = 0; acRender(); return; }
      if (f === "pd") { ac.items = [["yes", "Visits to adult sites"], ["no", "Everything except adult sites"]].filter(([k]) => k.startsWith(pre.toLowerCase())).map(([k, h]) => Object.assign(make(k), { hint: h })); ac.active = 0; acRender(); return; }
      acTimer = setTimeout(async () => {
        let vals = [];
        try { vals = (await API.searchSuggest(f, pre)).values || []; } catch (e) { vals = []; }
        if (seq !== ac.seq) return;
        ac.items = vals.map(x => make(x.key, x.count));
        if (!ac.items.length) ac.items = [{ label: pre ? `No ${f} values in the last 7 days start with "${pre}"` : `No ${f} values in the last 7 days`, insert: "", hint: "" }];
        ac.active = vals.length ? 0 : -1; acRender();
      }, 150);
      return;
    }
    if (/^\w*$/.test(token) && (token || force)) {
      ac.items = fieldItems(token, start, end);
      ac.active = token ? 0 : -1;
      acRender();
      return;
    }
    acClose();
  }

  /* ---------- builder ---------- */
  function openBuilder(anchor) {
    const m = openMenu(anchor, html`<form class="builder" id="b-form" novalidate>
      <div class="panel-head"><h3 class="panel-title">${icon("list-filter", "sm")} Build a filter</h3></div>
      <div class="stack" style="padding:12px">
        <label class="form-field"><span class="field-label">Field</span><select class="select" id="b-field">${FIELDS.map(f => html`<option value="${f}">${f}</option>`)}</select></label>
        <p class="field-help" id="b-fhelp" style="margin-top:-8px"></p>
        <label class="form-field"><span class="field-label">Condition</span><select class="select" id="b-op"></select></label>
        <label class="form-field"><span class="field-label">Value</span><span id="b-val-slot"></span></label>
        <div class="row" style="justify-content:flex-end"><button type="button" class="btn sm" id="b-cancel">Cancel</button><button type="submit" class="btn sm primary">${icon("plus", "sm")} Add to search</button></div>
      </div></form>`, 340);
    if (!m) return;
    const fSel = $("#b-field", m), opSel = $("#b-op", m), slot = $("#b-val-slot", m);
    let t = null;
    const sync = () => {
      const f = fSel.value;
      $("#b-fhelp", m).textContent = HELP.FIELDS[f] || "";
      opSel.innerHTML = (f === "severity" ? [["is", "is"], ["not", "is not"], ["ge", "is at least (≥)"]] : [["is", "is"], ["not", "is not"], ["contains", "contains"]]).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join("");
      if (f === "severity") slot.innerHTML = `<select class="select" id="b-val">${SEVS.map(s => `<option>${s}</option>`).join("")}</select>`;
      else {
        slot.innerHTML = `<input class="input mono" id="b-val" list="b-dl" spellcheck="false" placeholder="Start typing for suggestions" style="width:100%"><datalist id="b-dl"></datalist>`;
        const inp = $("#b-val", m);
        const load = () => { clearTimeout(t); t = setTimeout(async () => { try { const r = await API.searchSuggest(f, inp.value); const dl = $("#b-dl", m); if (dl) dl.innerHTML = (r.values || []).map(x => `<option value="${esc(x.key)}">${esc(String(x.count))} events</option>`).join(""); } catch (e) { /* ignore */ } }, 150); };
        inp.addEventListener("input", load); load();
      }
    };
    fSel.onchange = sync; sync();
    $("#b-cancel", m).onclick = () => { closeMenu(); anchor.focus(); };
    $("#b-form", m).onsubmit = e => {
      e.preventDefault();
      const f = fSel.value, op = opSel.value, v = ($("#b-val", m).value || "").trim();
      if (!v) { $("#b-val", m).classList.add("invalid"); $("#b-val", m).focus(); return; }
      const clause = op === "ge" ? `severity>=${v}` : op === "contains" ? term(f, `*${v}*`) : (op === "not" ? "NOT " : "") + term(f, v);
      closeMenu();
      const [base, pipes] = splitQ($("#s-q").value);
      setQuery(joinQ((base + " " + clause).trim(), pipes));
    };
  }

  /* ---------- examples / saved / recent ---------- */
  function openExamples(anchor) {
    const m = openMenu(anchor, html`<div class="panel-head"><h3 class="panel-title">${icon("book", "sm")} Example searches</h3></div>
      ${EXAMPLES.map((x, i) => html`<button type="button" class="menu-item" role="menuitem" data-ex="${i}"><span class="mi-title">${x.title}</span><span class="mi-sub">${x.why}</span><span class="mi-q mono">${x.q}</span></button>`)}`, 420);
    if (!m) return;
    $$("[data-ex]", m).forEach(b => b.onclick = () => { const x = EXAMPLES[+b.dataset.ex]; closeMenu(); applySearch(x.q, x.range); });
  }
  function rangeLabel(id) { const r = RANGES.find(x => x.id === id); return r ? r.label : "Custom range"; }
  async function openSaved(anchor) {
    try { settingsCache = await API.settingsGet(); } catch (e) { /* use cache */ }
    const list = (settingsCache && settingsCache.saved_searches) || [];
    const m = openMenu(anchor, html`<div class="panel-head"><h3 class="panel-title">${icon("star", "sm")} Saved searches</h3><button type="button" class="btn sm" id="sv-add">${icon("plus", "sm")} Save current</button></div>
      ${list.length ? list.map((x, i) => html`<div class="menu-row"><button type="button" class="menu-item" role="menuitem" data-run="${i}"><span class="mi-title">${x.name}</span><span class="mi-q mono">${x.query}</span><span class="mi-sub">${rangeLabel(x.range)}</span></button>
          <button type="button" class="btn ghost icon sm" data-ren="${i}" aria-label="Rename ${x.name}" title="Rename">${icon("pencil", "sm")}</button><button type="button" class="btn ghost icon sm" data-del="${i}" aria-label="Delete ${x.name}" title="Delete">${icon("trash", "sm")}</button></div>`)
        : html`<div class="empty" style="padding:16px">No saved searches yet. Click the star next to Export to save the current search.</div>`}`, 420);
    if (!m) return;
    $("#sv-add", m).onclick = () => { closeMenu(); saveCurrent(); };
    $$("[data-run]", m).forEach(b => b.onclick = () => { const x = list[+b.dataset.run]; closeMenu(); applySearch(x.query, x.range); });
    $$("[data-ren]", m).forEach(b => b.onclick = () => { const i = +b.dataset.ren; closeMenu(); nameDialog("Rename saved search", list[i].name, async name => { const l = list.slice(); l[i] = Object.assign({}, l[i], { name }); await storeSaved(l, "Renamed"); }); });
    $$("[data-del]", m).forEach(b => b.onclick = async () => {
      const i = +b.dataset.del; closeMenu();
      const ok = await U.confirmModal({ title: "Delete saved search?", confirmLabel: "Delete", danger: true, body: html`<p><strong>${list[i].name}</strong> (<span class="mono">${list[i].query}</span>) will be removed from your saved searches.</p>` });
      if (ok) { const l = list.slice(); l.splice(i, 1); await storeSaved(l, "Deleted"); }
    });
  }
  async function storeSaved(list, verb) {
    try {
      const cur = await API.settingsGet();
      settingsCache = await API.settingsSet(Object.assign({}, cur, { saved_searches: list }));
      U.toast(`${verb} saved search`);
    } catch (e) { U.toast("Could not save: " + e.message, "error"); }
  }
  function nameDialog(title, value, onSave) {
    const md = U.openModal({ title, body: html`<form id="nd-form" class="stack" novalidate><label class="form-field"><span class="field-label">Name</span><input class="input" id="nd-name" value="${value}" maxlength="60"></label><div class="field-error" id="nd-err"></div></form>`,
      foot: html`<button class="btn" data-a="cancel">Cancel</button><button class="btn primary" data-a="save">Save</button>` });
    const inp = $("#nd-name", md.el); inp.focus(); inp.select();
    const go = async () => { const n = inp.value.trim(); if (!n) { $("#nd-err", md.el).textContent = "Enter a name."; inp.focus(); return; } md.close(); await onSave(n); };
    $("#nd-form", md.el).onsubmit = e => { e.preventDefault(); go(); };
    md.el.querySelector('[data-a="save"]').onclick = go;
    md.el.querySelector('[data-a="cancel"]').onclick = () => md.close();
  }
  function saveCurrent() {
    const qv = $("#s-q").value.trim();
    if (!qv) { U.toast("Type a search first, then save it", "error"); return; }
    const def = state.result && !state.result.error ? summary(state.result).replace(/^Showing /, "").replace(/ — .*$/, "") : qv;
    nameDialog("Save this search", def.charAt(0).toUpperCase() + def.slice(1, 60), async name => {
      const cur = (settingsCache && settingsCache.saved_searches) || [];
      await storeSaved(cur.concat([{ name, query: qv, range: state.from ? "24h" : state.range }]), "Added");
    });
  }
  function openRecent(anchor) {
    const list = recentGet();
    const m = openMenu(anchor, html`<div class="panel-head"><h3 class="panel-title">${icon("history", "sm")} Recent searches</h3>${list.length ? html`<button type="button" class="btn sm ghost" id="rc-clear">Clear</button>` : raw("")}</div>
      ${list.length ? list.map((x, i) => html`<button type="button" class="menu-item" role="menuitem" data-rc="${i}"><span class="mi-q mono">${x.q}</span><span class="mi-sub">${rangeLabel(x.range)} · ${U.rel(x.ts)}</span></button>`)
        : html`<div class="empty" style="padding:16px">Searches you run appear here (on this PC only).</div>`}`, 420);
    if (!m) return;
    $$("[data-rc]", m).forEach(b => b.onclick = () => { const x = list[+b.dataset.rc]; closeMenu(); applySearch(x.q, x.range === "custom" ? state.range : x.range); });
    const c = $("#rc-clear", m); if (c) c.onclick = () => { try { localStorage.removeItem(RECENT_KEY); } catch (e) { /* ignore */ } closeMenu(); U.toast("Recent searches cleared"); };
  }
  function applySearch(qv, range) {
    if (range && RANGES.find(r => r.id === range)) { state.range = range; $("#s-range").value = range; }
    state.from = state.to = null; state.zoomStack = [];
    setQuery(qv);
  }
  async function exportCsv() {
    const b = $("#s-export"); b.disabled = true;
    const [from, to] = timeWindow();
    try { const r = await API.exportSearch(state.q, from, to); U.toast(`Exported ${num(r.rows)} rows to ${r.path}`); }
    catch (e) { U.toast("Export failed: " + e.message, "error"); }
    b.disabled = false;
  }

  /* ---------- histogram (uPlot bars, drag to zoom) ---------- */
  let chart = null;
  function renderHisto(h, from, to) {
    if (chart) { chart.destroy(); chart = null; }
    const box = $("#s-histo");
    $("#s-h-from").textContent = h.length ? U.absTime(h[0].t) : "";
    $("#s-h-to").textContent = U.absTime(to);
    if (!h.length) { box.innerHTML = '<div class="empty">No timeline for this search.</div>'; return; }
    chart = U.timeChart(box, {
      t: h.map(b => b.t), series: [{ label: "Events", data: h.map(b => b.count), color: "--c-chart-1" }],
      height: 96, bars: true, label: "Event timeline",
      onSelect(a, b) {
        if (state.from) state.zoomStack.push([state.from, state.to]);
        state.from = Math.max(a, h[0].t); state.to = b; state.page = 0;
        $("#s-range").value = "custom";
        run();
      },
    });
  }

  /* ---------- fields sidebar ---------- */
  function renderFields(fields) {
    const box = $("#s-fields");
    const item = f => {
      const vals = fields[f] || [];
      return html`<button class="field-btn" data-f="${f}" ${raw(vals.length ? "" : "disabled")}><span class="ft">a</span><span>${f}</span><span class="fc">${vals.length}${vals.length >= 10 ? "+" : ""}</span></button>`;
    };
    box.innerHTML = html`<h4>Selected fields</h4>${SELECTED.map(item)}<h4>Interesting fields</h4>${INTERESTING.map(item)}
      <h4>Query help</h4><div class="muted" style="padding:0 16px">Click a field to see its values, then <b>+</b> to include or <b>−</b> to exclude one. Press <kbd>/</kbd> to type a search. See Help &rsaquo; Query language.</div>`;
    $$(".field-btn", box).forEach(b => b.addEventListener("click", e => { e.stopPropagation(); openPopover(b, b.dataset.f, fields[b.dataset.f] || []); }));
  }
  function closePopoverOutside(e) { const p = $(".popover.fieldpop"); if (p && !p.contains(e.target)) { p.remove(); document.removeEventListener("mousedown", closePopoverOutside, true); } }
  function openPopover(anchor, f, vals) {
    const old = $(".popover.fieldpop"); if (old) old.remove();
    const max = Math.max(1, ...vals.map(v => v.count));
    const p = U.el(html`<div class="popover fieldpop" role="dialog" aria-label="${f} values">
      <div class="panel-head"><div><div class="panel-title mono">${f}</div><div class="panel-sub">Top ${vals.length} values in these results${HELP.FIELDS[f] ? " · " + HELP.FIELDS[f] : ""}</div></div>
        <button class="btn ghost icon sm" data-close aria-label="Close">${icon("x", "sm")}</button></div>
      <div class="row" style="padding:8px 12px;gap:8px"><button class="btn sm" data-stats>${icon("activity", "sm")} stats count by ${f}</button><button class="btn sm" data-top>top ${f}</button></div>
      <div class="bar-list">${vals.map(v => html`<div class="bar-item vrow"><span class="ellipsis ${f === "severity" || f === "source" || f === "kind" ? "" : "mono"}" title="${ipTitle(f, v.key) || v.key}">${v.key}</span>
        <span class="row" style="gap:4px"><span class="num secondary">${num(v.count)}</span>${vbtns(f, v.key)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(v.count / max * 100).toFixed(1)}%"></div></div></div>`)}</div>
    </div>`);
    document.body.appendChild(p);
    const r = anchor.getBoundingClientRect();
    p.style.left = Math.min(r.right + 4, window.innerWidth - p.offsetWidth - 8) + "px";
    p.style.top = Math.max(8, Math.min(r.top, window.innerHeight - p.offsetHeight - 8)) + "px";
    p.querySelector("[data-close]").onclick = () => p.remove();
    p.querySelector("[data-stats]").onclick = () => { p.remove(); setQuery(splitQ(state.q)[0] + ` | stats count by ${f}`); };
    p.querySelector("[data-top]").onclick = () => { p.remove(); setQuery(splitQ(state.q)[0] + ` | top ${f}`); };
    bindVbtns(p, () => p.remove());
    setTimeout(() => document.addEventListener("mousedown", closePopoverOutside, true), 0);
    const first = p.querySelector("[data-vadd]"); if (first) first.focus();
  }
  function vbtns(f, v) {
    return html`<button type="button" class="vbtn" data-vadd data-f="${f}" data-v="${v}" title="Include ${f}=${v}" aria-label="Include ${f}=${v}">+</button><button type="button" class="vbtn" data-vnot data-f="${f}" data-v="${v}" title="Exclude ${f}=${v}" aria-label="Exclude ${f}=${v}">−</button>`;
  }
  function bindVbtns(rootEl, after) {
    $$("[data-ai-ev]", rootEl).forEach(b => b.onclick = e => {
      e.stopPropagation();
      const ev = state.result.events.find(x => x.id === +b.dataset.aiEv);
      AI.open({ kind: "event", data: { id: ev.id }, label: `Event #${ev.id}: ${ev.kind} · ${ev.message.slice(0, 80)}` });
    });
    $$("[data-vadd],[data-vnot]", rootEl).forEach(b => b.onclick = e => { e.stopPropagation(); if (after) after(); addTerm(b.dataset.f, b.dataset.v, b.hasAttribute("data-vnot")); });
  }
  const isEmptyKey = v => v === "" || v === "(empty)";
  function addTerm(f, v, neg) {
    const [base, pipes] = splitQ($("#s-q").value);
    if (isEmptyKey(v)) { addMissing(f, neg, base, pipes); return; }
    const pos = term(f, v), negc = "NOT " + pos;
    let nb = base;
    if (neg) { if (hasClause(nb, negc)) return; if (hasClause(nb, pos)) nb = removeClause(nb, pos); nb = (nb + " " + negc).trim(); }
    else { if (hasClause(nb, pos) && !hasClause(nb, negc)) return; if (hasClause(nb, negc)) nb = removeClause(nb, negc); nb = (nb + " " + pos).trim(); }
    setQuery(joinQ(nb, pipes));
  }
  /* "(empty)" stats row = field missing (NULL). Include -> NOT f=*, exclude -> f=*. */
  function addMissing(f, neg, base, pipes) {
    const missing = `NOT ${f}=*`, present = `${f}=*`;
    let nb = hasClause(base, missing) ? removeClause(base, missing) : base;
    if (hasClause(nb, present)) nb = removeClause(nb, present);
    setQuery(joinQ((nb + " " + (neg ? present : missing)).trim(), pipes));
  }
  function setQuery(qv) { state.q = qv; state.page = 0; const q = $("#s-q"); if (q) q.value = qv; acClose(); run(); }

  /* ---------- events ---------- */
  const TOKENS = ["host", "source", "kind", "severity", "src_ip", "dst_ip", "dst_port", "domain", "process"];
  function renderEvents() {
    const box = $("#s-events");
    const res = state.result;
    if (!res) return;
    if (res.error) { box.innerHTML = html`<div class="page"><div class="callout bad"><strong>Search failed.</strong> ${res.error}</div></div>`; return; }
    let statsHtml = "";
    if (res.stats) {
      const rows = res.stats.rows || [];
      const max = Math.max(1, ...rows.map(r => r.count));
      statsHtml = html`<div class="stats-wrap"><div class="panel">
        <div class="panel-head"><h3 class="panel-title">Statistics <span class="muted">· count by <span class="mono">${res.stats.by}</span></span></h3><span class="panel-sub">${num(rows.length)} rows · click a row to filter</span></div>
        <div class="table-wrap" style="max-height:420px"><table class="t"><thead><tr><th>${res.stats.by}</th><th class="num">count</th><th style="width:40%"></th><th></th></tr></thead><tbody>
        ${rows.length ? rows.map(r => html`<tr class="clickable" tabindex="0" data-k="${r.key}"><td class="mono" title="${ipTitle(res.stats.by, r.key)}">${isEmptyKey(r.key) ? raw('<span class="muted">(empty)</span>') : r.key}</td><td class="num">${num(r.count)}</td><td><div class="bar-track" style="height:6px"><div class="bar-fill" style="width:${(r.count / max * 100).toFixed(1)}%"></div></div></td><td class="right nowrap">${vbtns(res.stats.by, r.key)}</td></tr>`) : raw('<tr><td colspan="4" class="muted">No rows</td></tr>')}
        </tbody></table></div></div></div>`.__raw;
    }
    const evs = res.events || [];
    if (!evs.length) {
      const r = RANGES.find(x => x.id === state.range);
      box.innerHTML = statsHtml + html`<div class="empty"><strong>No events match.</strong>
        <div class="row-wrap" style="justify-content:center;margin-top:8px">
          ${state.from ? html`<button class="btn sm" data-widen="reset">${icon("zoom-out", "sm")} Show the whole ${r ? r.label.toLowerCase() : "range"}</button>` : raw("")}
          ${!state.from && r && r.ms && r.ms < 7 * 24 * 3600e3 ? html`<button class="btn sm" data-widen="7d">Search the last 7 days</button>` : raw("")}
          ${!state.from && state.range !== "all" ? html`<button class="btn sm" data-widen="all">Search all time</button>` : raw("")}
        </div><div class="chips" id="s-dym" style="justify-content:center;margin-top:12px"></div></div>`;
      bindStats(box);
      $$("[data-widen]", box).forEach(b => b.onclick = () => { const w = b.dataset.widen; state.from = state.to = null; state.zoomStack = []; if (w !== "reset") { state.range = w; } $("#s-range").value = state.range; run(); });
      didYouMean();
      return;
    }
    const pages = Math.ceil(evs.length / PAGE);
    state.page = Math.min(state.page, pages - 1);
    const slice = evs.slice(state.page * PAGE, (state.page + 1) * PAGE);
    box.innerHTML = statsHtml + html`<div class="events-head"><span>Events <span class="muted">(${num(evs.length)} loaded, newest first)</span></span>
      <span class="row"><button class="btn sm ghost" id="s-expand">Expand all</button><button class="btn sm ghost" id="s-collapse">Collapse all</button></span></div>
      <div id="s-list">${slice.map(evRow)}</div>
      ${pages > 1 ? html`<div class="pager"><button class="btn sm" id="s-prev" ${raw(state.page === 0 ? "disabled" : "")}>Previous</button><span class="num">Page ${state.page + 1} of ${pages}</span><button class="btn sm" id="s-next" ${raw(state.page >= pages - 1 ? "disabled" : "")}>Next</button></div>` : raw("")}`;
    bindStats(box);
    const list = $("#s-list");
    list.addEventListener("click", e => {
      if (e.target.closest("[data-vadd],[data-vnot]")) return;
      const tok = e.target.closest(".tok");
      if (tok) { addTerm(tok.dataset.f, tok.dataset.v, false); return; }
      const row = e.target.closest(".ev");
      if (row && (e.target.closest(".ev-toggle") || e.target.closest(".ev-msg") || e.target.closest(".ev-time"))) toggle(row);
    });
    list.addEventListener("keydown", e => { if (e.key === "Enter" && e.target.classList.contains("ev-toggle")) { e.preventDefault(); toggle(e.target.closest(".ev")); } });
    bindVbtns(list);
    $("#s-expand").onclick = () => { slice.forEach(ev => state.open.add(ev.id)); renderEvents(); };
    $("#s-collapse").onclick = () => { state.open.clear(); renderEvents(); };
    const prev = $("#s-prev"), next = $("#s-next");
    if (prev) prev.onclick = () => { state.page--; renderEvents(); $("#main").scrollTop = 0; };
    if (next) next.onclick = () => { state.page++; renderEvents(); $("#main").scrollTop = 0; };
  }
  async function didYouMean() {
    const box = $("#s-dym"); if (!box) return;
    const [base] = splitQ(state.q);
    const cands = [];
    for (const g of parseTerms(base)) for (const t of g) {
      if (t.neg || t.op !== "=" || !t.f || /\*/.test(t.v) || !FIELDS.includes(t.f) || t.f === "severity") continue;
      try {
        const r = await API.searchSuggest(t.f, t.v.slice(0, 2));
        const close = (r.values || []).map(x => [x.key, dist(x.key.toLowerCase(), t.v.toLowerCase())]).filter(([k, d]) => k !== t.v && d <= Math.max(2, Math.floor(t.v.length / 3))).sort((a, b) => a[1] - b[1]).slice(0, 3);
        close.forEach(([k]) => cands.push({ f: t.f, from: t.v, to: k }));
      } catch (e) { /* ignore */ }
    }
    if (!cands.length || !$("#s-dym")) return;
    box.innerHTML = html`<span class="muted chips-lbl">Did you mean</span>${cands.map((c, i) => html`<button type="button" class="chip" data-dym="${i}">${c.f}=${c.to}</button>`)}`;
    $$("[data-dym]", box).forEach(b => b.onclick = () => {
      const c = cands[+b.dataset.dym];
      setQuery(state.q.replace(term(c.f, c.from), term(c.f, c.to)));
    });
  }
  function dist(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return d[a.length][b.length];
  }
  function bindStats(box) {
    $$("tr[data-k]", box).forEach(tr => {
      const go = () => { const by = state.result.stats.by; state.q = splitQ(state.q)[0]; $("#s-q").value = state.q; addTerm(by, tr.dataset.k, false); };
      tr.addEventListener("click", e => { if (!e.target.closest(".vbtn")) go(); });
      tr.addEventListener("keydown", e => { if (e.key === "Enter" && e.target === tr) go(); });
    });
    $$(".stats-wrap", box).forEach(w => $$("[data-vadd],[data-vnot]", w).forEach(b => b.onclick = e => {
      e.stopPropagation(); state.q = splitQ(state.q)[0]; $("#s-q").value = state.q; addTerm(b.dataset.f, b.dataset.v, b.hasAttribute("data-vnot"));
    }));
  }
  function toggle(row) {
    const id = +row.dataset.id;
    if (state.open.has(id)) state.open.delete(id); else state.open.add(id);
    const ev = state.result.events.find(e => e.id === id);
    const fresh = U.el(evRow(ev));
    row.replaceWith(fresh);
    bindVbtns(fresh);
    fresh.querySelector(".ev-toggle").focus();
  }
  function evRow(ev) {
    const open = state.open.has(ev.id);
    const present = TOKENS.filter(f => ev[f] !== null && ev[f] !== undefined && ev[f] !== "");
    const toks = present.map(f =>
      html`<span class="tok" data-f="${f}" data-v="${ev[f]}" title="${ipTitle(f, ev[f]) ? ipTitle(f, ev[f]) + " · " : ""}Add ${f}=${ev[f]} to search"><span class="k">${f}</span>=<span class="v">${ev[f]}</span></span>`);
    let detail = raw("");
    if (open) {
      const hs = HELP.snippet(ev.kind);
      const full = Object.assign({ id: ev.id, ts: ev.ts, time: U.absTime(ev.ts) }, ev);
      detail = html`<div class="ev-detail">
        <div class="stack" style="gap:8px;min-width:0">
          <table class="t ev-fields"><thead><tr><th>Field</th><th>Value</th><th class="right">Filter</th></tr></thead><tbody>
            ${present.map(f => html`<tr><td class="mono secondary">${f}</td><td class="mono"><span title="${ipTitle(f, ev[f])}">${ev[f]}</span>${ipTitle(f, ev[f]) ? html` <span class="muted">${ipTitle(f, ev[f])}</span>` : raw("")}</td><td class="right nowrap">${vbtns(f, String(ev[f]))}</td></tr>`)}
          </tbody></table>
          <pre class="json">${raw(U.jsonHtml(full))}</pre>
          <div><button type="button" class="btn sm" data-ai-ev="${ev.id}">${icon("bot", "sm")} Ask AI about this event</button></div></div>
        <div class="help-snip">${hs ? html`<h5>What is this? · ${hs.title}</h5>
          <p><span class="lbl">What it is</span>${hs.what}</p><p><span class="lbl">Why it matters</span>${hs.why}</p><p><span class="lbl">What to do</span>${hs.todo}</p>`
          : html`<h5>What is this?</h5><p>No description for <span class="mono">${ev.kind}</span> yet. The raw record on the left contains all collected fields.</p>`}</div>
      </div>`;
    }
    return html`<div class="ev ${open ? "open" : ""}" data-id="${ev.id}">
      <button class="ev-toggle" aria-expanded="${open}" aria-label="Toggle event details">${icon("chev-r", "sm")}</button>
      <div class="ev-time" title="${U.absTime(ev.ts)}">${U.timeOnly(ev.ts)}<span class="d">${U.dateOnly(ev.ts)}</span></div>
      <div class="ev-body"><div class="row" style="gap:8px;align-items:baseline">${U.sev(ev.severity)}<span class="ev-msg">${ev.message}</span></div>
        <div class="ev-tokens">${toks}</div></div>
      ${detail}
    </div>`;
  }

  window.PAGES.search = { title: "Search", mount };
})();
