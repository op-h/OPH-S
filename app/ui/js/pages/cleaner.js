/* Cleaner — storage cleanup with preview + quarantine/undo, and memory trim. */
(function () {
  "use strict";
  window.PAGES = window.PAGES || {};
  const { html, raw, icon, $, $$, num, bytes } = U;
  // Module-level store: survives leaving and re-entering the page. Seeded from the core's last scan.
  const store = { scan: null, sel: new Set(), openCat: new Set(), seeded: false };

  function mount(root) {
    root.innerHTML = html`<div class="page">
      <div class="page-head"><div><h1 class="page-title">Cleaner</h1><p class="page-desc">Removes data that apps and Windows can rebuild: temporary files, caches, crash dumps and old OPH data. Nothing is deleted straight away. Files go to a quarantine folder that you can undo for 7 days. The scan runs at low priority.</p></div></div>
      <section class="panel" style="margin-bottom:16px" id="mem">${U.skeleton(3)}</section>
      <section class="panel" style="margin-bottom:16px"><div class="panel-head"><div><h2 class="panel-title">${icon("drive", "sm")} Storage</h2><div class="panel-sub">Review each category before cleaning. "Review" items are safe but cost something, such as re-downloads.</div></div>
        <div class="row"><button class="btn" id="c-scan">${icon("search", "sm")} Scan</button><button class="btn primary" id="c-run" disabled>Move selected to quarantine</button></div></div>
        <div id="c-cats">${U.empty("Not scanned yet.", "Click Scan to measure what can be cleaned. Nothing is changed until you confirm.")}</div></section>
      <section class="panel" id="c-q"></section></div>`.__raw;

    let scan = store.scan; const sel = store.sel; const openCat = store.openCat;

    async function loadMem() {
      let m; try { m = await API.memoryStatus(); } catch (e) { $("#mem").innerHTML = html`<div class="panel-body"><div class="callout bad">${e.message}</div></div>`.__raw; return; }
      if (!$("#mem")) return;
      const usedPct = m.used / m.total * 100, appPct = Math.max(0.3, m.app_bytes / m.total * 100);
      $("#mem").innerHTML = html`<div class="panel-head"><div><h2 class="panel-title">${icon("cpu", "sm")} Memory</h2><div class="panel-sub">Physical RAM on this PC</div></div><button class="btn" id="m-trim">Trim working sets</button></div>
        <div class="panel-body stack">
          <div class="gauge" role="img" aria-label="Memory usage ${usedPct.toFixed(0)} percent"><span class="g-app" style="width:${appPct.toFixed(2)}%"></span><span class="g-used" style="width:${Math.max(0, usedPct - appPct).toFixed(2)}%"></span></div>
          <div class="legend" style="grid-template-columns:repeat(5,minmax(0,1fr))">
            <div><div class="field-label">Used</div><div class="num">${bytes(m.used)} <span class="muted">(${usedPct.toFixed(0)}%)</span></div></div>
            <div><div class="field-label">Available</div><div class="num">${bytes(m.available)}</div></div>
            <div><div class="field-label">Total</div><div class="num">${bytes(m.total)}</div></div>
            <div><div class="field-label"><span class="sw" style="display:inline-block;width:8px;height:8px;background:var(--c-accent);margin-right:6px"></span>OPH Sentinel</div><div class="num">${bytes(m.app_bytes)}</div></div>
            <div><div class="field-label">Page file</div><div class="num">${bytes(m.swap_used)} / ${bytes(m.swap_total)}</div></div>
          </div>
          <p class="field-help">Trimming asks Windows to move idle memory pages of your programs to standby. Available RAM goes up immediately, but programs may briefly slow down as they page data back in. Windows already does this under memory pressure, so this is a one-off convenience, not a speed-up. It cannot touch protected or other users' processes.</p>
        </div>`.__raw;
      $("#m-trim").onclick = async () => {
        const b = $("#m-trim"); b.disabled = true;
        try { const r = await API.memoryTrim(); U.toast(`Trimmed ${num(r.processes)} processes · available RAM ${bytes(r.before_available)} → ${bytes(r.after_available)}`); loadMem(); }
        catch (e) { U.toast(e.message, "error"); b.disabled = false; }
      };
    }

    function renderCats() {
      const box = $("#c-cats");
      if (!scan) return;
      if (!scan.categories.length) { box.innerHTML = U.empty("Nothing to clean.").__raw; return; }
      const selBytes = scan.categories.filter(c => sel.has(c.id)).reduce((s, c) => s + c.bytes, 0);
      box.innerHTML = html`<table class="t"><thead><tr><th style="width:36px"><input type="checkbox" class="checkbox" id="c-all" aria-label="Select all safe categories"></th><th style="width:24px"></th><th>Category</th><th>Risk</th><th class="num">Files</th><th class="num">Size</th></tr></thead><tbody>
        ${scan.categories.map(c => html`<tr data-cat="${c.id}"><td><input type="checkbox" class="checkbox" data-sel="${c.id}" ${raw(sel.has(c.id) ? "checked" : "")} ${raw(c.files ? "" : "disabled")} aria-label="Select ${c.name}"></td>
          <td><button class="btn ghost icon sm" data-exp="${c.id}" aria-expanded="${openCat.has(c.id)}" aria-label="Preview ${c.name}" ${raw(c.items.length ? "" : "disabled")}>${icon(openCat.has(c.id) ? "chev-d" : "chev-r", "sm")}</button></td>
          <td class="wrap"><div>${c.name}</div><div class="muted" style="font-size:var(--fs-11)">${c.description}</div></td>
          <td>${c.risk === "safe" ? html`<span class="tag ok">Safe</span>` : html`<span class="tag warn">Review</span>`}</td>
          <td class="num">${num(c.files)}</td><td class="num">${bytes(c.bytes)}</td></tr>
          ${openCat.has(c.id) ? html`<tr><td></td><td colspan="5" style="padding:0 12px 12px"><table class="t" style="border:1px solid var(--c-border)"><thead><tr><th>Largest items</th><th class="num">Size</th><th>Modified</th></tr></thead><tbody>
            ${c.items.map(i => html`<tr><td class="mono ellipsis" style="max-width:780px" title="${i.path}">${i.path}</td><td class="num">${bytes(i.bytes)}</td><td class="nowrap">${U.relHtml(i.modified)}</td></tr>`)}
            </tbody></table>${c.files > c.items.length ? html`<div class="t-more">Showing the ${num(c.items.length)} largest of ${num(c.files)} files.</div>` : raw("")}</td></tr>` : raw("")}`)}
        </tbody><tfoot><tr><td colspan="4" style="padding:8px 12px" class="secondary">Total reclaimable <b class="num">${bytes(scan.total_bytes)}</b></td><td colspan="2" class="num" style="padding:8px 12px">Selected <b>${bytes(selBytes)}</b></td></tr></tfoot></table>`.__raw;
      const all = $("#c-all");
      const safe = scan.categories.filter(c => c.risk === "safe" && c.files);
      all.checked = safe.length > 0 && safe.every(c => sel.has(c.id));
      all.onchange = () => { safe.forEach(c => all.checked ? sel.add(c.id) : sel.delete(c.id)); renderCats(); };
      $$("[data-sel]", box).forEach(c => c.onchange = () => { c.checked ? sel.add(c.dataset.sel) : sel.delete(c.dataset.sel); renderCats(); });
      $$("[data-exp]", box).forEach(b => b.onclick = () => { const id = b.dataset.exp; openCat.has(id) ? openCat.delete(id) : openCat.add(id); renderCats(); });
      const run = $("#c-run"); run.disabled = sel.size === 0;
      run.textContent = sel.size ? `Move ${bytes(selBytes)} to quarantine` : "Move selected to quarantine";
    }

    function renderQ() {
      const q = scan ? scan.quarantine : null, box = $("#c-q");
      if (!q) { box.innerHTML = ""; return; }
      box.innerHTML = html`<div class="panel-head"><div><h2 class="panel-title">${icon("undo", "sm")} Quarantine</h2><div class="panel-sub">Cleaned files are kept here for 7 days, then purged automatically. Disk space is released when they are purged.</div></div>
        <button class="btn danger" id="q-purge" ${raw(q.runs.length ? "" : "disabled")}>${icon("trash", "sm")} Purge ${bytes(q.bytes)} now</button></div>
        ${q.runs.length ? html`<table class="t"><thead><tr><th>Run</th><th>Cleaned</th><th class="num">Files</th><th class="num">Size</th><th></th></tr></thead><tbody>
          ${q.runs.map(r => html`<tr><td class="mono secondary">${r.id}</td><td>${U.relHtml(r.ts)} <span class="muted">${U.absTime(r.ts)}</span></td><td class="num">${num(r.files)}</td><td class="num">${bytes(r.bytes)}</td>
            <td class="right"><button class="btn sm" data-undo="${r.id}">${icon("undo", "sm")} Undo</button></td></tr>`)}</tbody></table>`
          : U.empty("Quarantine is empty.")}`.__raw;
      $$("[data-undo]", box).forEach(b => b.onclick = async () => {
        const ok = await U.confirmModal({ title: "Restore this cleanup run?", confirmLabel: "Restore files", body: html`<p>All files from run <span class="mono">${b.dataset.undo}</span> are moved back to their original locations. Files that have been re-created since are kept, and the quarantined copy is skipped.</p>` });
        if (!ok) return;
        try { const r = await API.cleanerUndo(b.dataset.undo); U.toast(`Restored ${num(r.restored)} files${r.errors.length ? `, ${r.errors.length} errors` : ""}`, r.errors.length ? "error" : ""); doScan(); }
        catch (e) { U.toast(e.message, "error"); }
      });
      const p = $("#q-purge");
      p.onclick = async () => {
        const ok = await U.confirmModal({ title: "Permanently delete quarantined files?", confirmLabel: "Purge permanently", danger: true,
          body: html`<p>${num(q.runs.reduce((s, r) => s + r.files, 0))} files (${bytes(q.bytes)}) are deleted for good. <strong>This cannot be undone</strong>, and they do not go to the Recycle Bin.</p>` });
        if (!ok) return;
        try { const r = await API.cleanerPurge(); U.toast(r.pending_reboot ? `Freed ${bytes(r.freed_bytes)}. ${r.pending_reboot} protected files will be removed at the next restart.` : `Freed ${bytes(r.freed_bytes)}`, r.failed ? "error" : undefined); doScan(); } catch (e) { U.toast(e.message, "error"); }
      };
    }

    async function doScan() {
      const b = $("#c-scan"); b.disabled = true; b.innerHTML = html`${icon("clock", "sm")} Scanning…`.__raw;
      $("#c-cats").innerHTML = U.skeleton(6).__raw;
      try {
        scan = store.scan = await API.cleanerScan();
        if (!$("#c-cats")) return;
        if (!sel.size) scan.categories.filter(c => c.risk === "safe" && c.files).forEach(c => sel.add(c.id));
        for (const id of Array.from(sel)) if (!scan.categories.find(c => c.id === id && c.files)) sel.delete(id);
        renderCats(); renderQ();
      } catch (e) { $("#c-cats").innerHTML = html`<div class="panel-body"><div class="callout bad">${e.message}</div></div>`.__raw; }
      b.disabled = false; b.innerHTML = html`${icon("refresh", "sm")} Rescan`.__raw;
    }

    $("#c-scan").onclick = doScan;
    async function restore() {
      if (!scan && !store.seeded) {
        store.seeded = true;
        try { const last = await API.cleanerLast(); if (last && !store.scan) { scan = store.scan = last; if (!sel.size) last.categories.filter(c => c.risk === "safe" && c.files).forEach(c => sel.add(c.id)); } } catch (e) { /* no previous scan */ }
      }
      if (scan && $("#c-cats")) { renderCats(); renderQ(); $("#c-scan").innerHTML = html`${icon("refresh", "sm")} Rescan`; }
    }
    restore();
    $("#c-run").onclick = async () => {
      const cats = scan.categories.filter(c => sel.has(c.id));
      const ok = await U.confirmModal({ title: "Move files to quarantine?", confirmLabel: "Clean now",
        body: html`<p>${num(cats.reduce((s, c) => s + c.files, 0))} files (${bytes(cats.reduce((s, c) => s + c.bytes, 0))}) from:</p><ul>${cats.map(c => html`<li>${c.name}</li>`)}</ul>
          <p>Files in use are skipped. You can undo this run from the Quarantine section for 7 days.${raw(cats.some(c => c.id === "browser_cache") ? " Close your browsers first for the best result." : "")}</p>` });
      if (!ok) return;
      const b = $("#c-run"); b.disabled = true; b.textContent = "Cleaning…";
      try {
        const r = await API.cleanerRun(cats.map(c => c.id));
        U.toast(`Moved ${num(r.moved_files)} files (${bytes(r.moved_bytes)}) to quarantine${r.skipped ? ` · ${num(r.skipped)} skipped` : ""}`);
        if (r.errors && r.errors.length) U.toast(`${r.errors.length} items could not be moved: ${r.errors[0]}`, "error");
        sel.clear(); doScan();
      } catch (e) { U.toast(e.message, "error"); b.disabled = false; }
    };
    loadMem();
    return U.poll(loadMem, 10000);
  }

  window.PAGES.cleaner = { title: "Cleaner", mount };
})();
