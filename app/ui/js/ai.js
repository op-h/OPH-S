/* "Ask AI" side panel — reusable from Search, events, alerts, devices and the top bar.
   Answers are rendered from escaped text with a tiny safe formatter (no raw HTML from the model). */
(function () {
  "use strict";
  const { html, raw, icon, esc, $, $$, num } = U;

  const SUGGEST = {
    search: ["Summarise this", "Anything suspicious?", "Which device is most active and why?"],
    event: ["What is this?", "Is it dangerous?", "What should I do?"],
    alert: ["What is this?", "Is it dangerous?", "What should I do?"],
    device: ["What is this device doing?", "Anything unusual about it?", "Which services does it talk to most?"],
    "": ["How do I protect my phone?", "What does DNS sinkholing do?", "Is Warn or Block mode better for me?"],
  };

  /** Safe mini-markdown: paragraphs, headings, bullet/numbered lists, **bold**, `code`, ``` fences. */
  function render(text) {
    const inline = s => esc(s)
      .replace(/`([^`]+)`/g, '<code class="inline">$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    const lines = String(text || "").replace(/\r/g, "").split("\n");
    let out = "", list = null, para = [], fence = null;
    const flushPara = () => { if (para.length) { out += `<p>${inline(para.join(" "))}</p>`; para = []; } };
    const flushList = () => { if (list) { out += `<${list.t}>${list.items.map(i => `<li>${inline(i)}</li>`).join("")}</${list.t}>`; list = null; } };
    for (const line of lines) {
      if (fence !== null) {
        if (/^```/.test(line)) { out += `<pre class="json">${esc(fence.join("\n"))}</pre>`; fence = null; } else fence.push(line);
        continue;
      }
      if (/^```/.test(line)) { flushPara(); flushList(); fence = []; continue; }
      let m;
      if ((m = /^\s*#{1,4}\s+(.*)$/.exec(line))) { flushPara(); flushList(); out += `<h4>${inline(m[1])}</h4>`; continue; }
      if ((m = /^\s*[-*•]\s+(.*)$/.exec(line))) { flushPara(); if (!list || list.t !== "ul") { flushList(); list = { t: "ul", items: [] }; } list.items.push(m[1]); continue; }
      if ((m = /^\s*\d+[.)]\s+(.*)$/.exec(line))) { flushPara(); if (!list || list.t !== "ol") { flushList(); list = { t: "ol", items: [] }; } list.items.push(m[1]); continue; }
      if (!line.trim()) { flushPara(); flushList(); continue; }
      if (list && /^\s{2,}\S/.test(line)) { list.items[list.items.length - 1] += " " + line.trim(); continue; }
      flushList(); para.push(line.trim());
    }
    if (fence !== null) out += `<pre class="json">${esc(fence.join("\n"))}</pre>`;
    flushPara(); flushList();
    return out;
  }

  let panel = null, ctx = null, history = [], busy = false, status = null, prevFocus = null;

  function close() {
    if (!panel) return;
    panel.remove(); panel = null; busy = false;
    document.removeEventListener("keydown", onKey, true);
    if (prevFocus && prevFocus.focus) prevFocus.focus();
  }
  function onKey(e) {
    if (e.key === "Escape" && panel && !$(".modal-scrim") && panel.contains(document.activeElement)) { e.stopPropagation(); close(); }
  }

  /** open({kind: "search"|"event"|"alert"|"device"|"", data: {...}, label: "Search: kind=dns.query …"}) */
  async function open(c) {
    const same = ctx && panel && ctx.kind === c.kind && JSON.stringify(ctx.data) === JSON.stringify(c.data);
    ctx = c;
    if (!same) history = [];
    if (!panel) {
      prevFocus = document.activeElement;
      panel = U.el(`<aside class="ai-panel" role="dialog" aria-label="Ask AI" aria-modal="false"></aside>`);
      document.body.appendChild(panel);
      document.addEventListener("keydown", onKey, true);
    }
    panel.innerHTML = html`<div class="drawer-head"><div class="grow"><h2 class="drawer-title row" style="gap:8px">${icon("bot")} Ask AI</h2><div class="panel-sub" id="ai-model"></div></div>
      <button class="btn ghost icon" data-close aria-label="Close Ask AI">${icon("x")}</button></div>
      <div class="drawer-body" id="ai-body">${U.skeleton(4)}</div>`;
    panel.querySelector("[data-close]").onclick = close;
    try { status = await API.aiStatus(); } catch (e) { status = { ready: false, error: e.message }; }
    if (!panel) return;
    renderBody();
  }

  function ctxLabel() {
    if (!ctx || !ctx.kind) return "General question · no logs attached";
    return ctx.label || ctx.kind;
  }

  function renderBody() {
    const body = $("#ai-body", panel);
    $("#ai-model", panel).textContent = status && status.ready ? `${status.provider === "openai" ? "OpenAI-compatible" : "Claude"} · ${status.model}` : "";
    if (!status || !status.ready) {
      body.innerHTML = html`<div class="callout warn"><strong>Ask AI isn't set up yet.</strong> Add a Claude API key (or another OpenAI-compatible provider) in Settings first. Questions are billed to your key, and the logs you ask about are sent to that provider.</div>
        ${status && status.error ? html`<p class="field-help">${status.error}</p>` : raw("")}
        <div><a class="btn primary" href="#/settings?section=ai" id="ai-setup">${icon("key", "sm")} Set up Ask AI</a></div>`;
      $("#ai-setup", body).onclick = () => close();
      return;
    }
    const sugg = SUGGEST[ctx && ctx.kind ? ctx.kind : ""] || SUGGEST[""];
    body.innerHTML = html`
      <div class="ai-ctx"><span class="tag info">${ctx && ctx.kind ? ctx.kind : "general"}</span><span class="ellipsis" title="${ctxLabel()}">${ctxLabel()}</span></div>
      ${ctx && ctx.kind ? html`<details class="more" id="ai-prev"><summary>Preview what will be sent${status.redact ? " (local IPs and MACs hidden)" : ""}</summary><div><pre class="json ai-preview" id="ai-prev-text">Loading…</pre><p class="field-help" id="ai-prev-meta"></p></div></details>` : raw("")}
      <div id="ai-hist" class="ai-hist" aria-live="polite"></div>
      <div class="chips" id="ai-sugg">${sugg.map(s => html`<button type="button" class="chip" data-q="${s}">${s}</button>`)}</div>
      <form id="ai-form" class="stack" style="gap:8px" novalidate>
        <label class="field-label" for="ai-q">Your question</label>
        <textarea class="textarea" id="ai-q" rows="3" placeholder="Ask about ${ctx && ctx.kind ? "these logs" : "your network or security"}…"></textarea>
        <div class="row" style="justify-content:space-between"><span class="field-help">Ctrl+Enter to ask · each question resends the attached logs</span>
          <button class="btn primary" type="submit" id="ai-go">${icon("send", "sm")} Ask</button></div>
      </form>`;
    renderHistory();
    const prev = $("#ai-prev", body);
    if (prev) prev.addEventListener("toggle", async () => {
      if (!prev.open || prev.dataset.loaded) return;
      prev.dataset.loaded = "1";
      try {
        const r = await API.aiPreview(ctx.kind, ctx.data);
        const t = $("#ai-prev-text", body); if (!t) return;
        if (!r.ok) { t.textContent = r.error || "Preview unavailable"; return; }
        t.textContent = r.text;
        $("#ai-prev-meta", body).textContent = `${r.context} · ${num(r.chars)} characters`;
      } catch (e) { const t = $("#ai-prev-text", body); if (t) t.textContent = e.message; }
    });
    $$("[data-q]", body).forEach(b => b.onclick = () => ask(b.dataset.q));
    const q = $("#ai-q", body);
    q.addEventListener("keydown", e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); ask(q.value); } });
    $("#ai-form", body).onsubmit = e => { e.preventDefault(); ask(q.value); };
    q.focus();
  }

  function renderHistory() {
    const box = panel && $("#ai-hist", panel); if (!box) return;
    box.innerHTML = history.map((h, i) => html`<div class="ai-turn">
      <div class="ai-q">${icon("ask", "sm")}<span>${h.q}</span></div>
      ${h.pending ? html`<div class="ai-a ai-wait" role="status"><span class="dot warn"></span>${status.provider === "openai" ? "The model" : "Claude"} is analysing… can take up to a minute</div>`
        : h.error ? html`<div class="callout bad">${h.error}</div>`
        : html`<div class="ai-a">${raw(render(h.answer))}</div>
          <div class="ai-foot"><span class="muted">${h.model || ""}${h.usage ? ` · ${num((h.usage.input_tokens || 0) + (h.usage.output_tokens || 0))} tokens` : ""}${h.seconds !== undefined ? ` · ${Number(h.seconds).toFixed(1)} s` : ""}</span>
            <button type="button" class="btn ghost sm" data-copy="${i}">${icon("copy", "sm")} Copy</button></div>`}
    </div>`).join("");
    $$("[data-copy]", box).forEach(b => b.onclick = () => U.copy(history[+b.dataset.copy].answer, "Answer"));
    const last = box.lastElementChild; if (last) last.scrollIntoView({ block: "nearest" });
  }

  async function ask(question) {
    question = String(question || "").trim();
    if (!question || busy || !panel) return;
    busy = true;
    const go = $("#ai-go", panel), q = $("#ai-q", panel);
    go.disabled = true; q.value = "";
    $$("#ai-sugg .chip", panel).forEach(c => c.disabled = true);
    const turn = { q: question, pending: true };
    history.push(turn); renderHistory();
    try {
      const r = await API.aiAsk(question, ctx ? ctx.kind : "", ctx ? ctx.data : {});
      Object.assign(turn, r.ok ? { answer: r.answer, model: r.model, usage: r.usage, seconds: r.seconds } : { error: r.error || "The AI provider returned an error." });
    } catch (e) { turn.error = e.message; }
    turn.pending = false; busy = false;
    if (!panel) return;
    renderHistory();
    go.disabled = false; $$("#ai-sugg .chip", panel).forEach(c => c.disabled = false);
    q.focus();
  }

  window.AI = { open, close, render };
})();
