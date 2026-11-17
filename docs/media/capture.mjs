// Reproducible README media for OPH-S.
// Serves app/ui in its built-in demo mode (no Tauri → realistic mock data, no personal data),
// drives Microsoft Edge with puppeteer-core and writes:
//   docs/media/*.png        page screenshots (1440x900)
//   docs/media/*.gif|*.mp4  short interaction clips (frames → ffmpeg)
// Usage: npm install && npm run capture   (needs Edge or Chrome + ffmpeg on PATH)
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";

const here = path.dirname(fileURLToPath(import.meta.url));
const UI = path.resolve(here, "../../app/ui");
const OUT = here;
const FRAMES = path.join(OUT, ".frames");
const W = 1440, H = 900;
const BROWSER = [
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/usr/bin/chromium", "/usr/bin/google-chrome",
].find((p) => fs.existsSync(p));

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".png": "image/png" };
const server = http.createServer((req, res) => {
  const p = path.join(UI, decodeURIComponent(req.url.split("?")[0]).replace(/\/$/, "/index.html"));
  if (!p.startsWith(UI) || !fs.existsSync(p)) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { "content-type": TYPES[path.extname(p)] || "application/octet-stream" });
  fs.createReadStream(p).pipe(res);
}).listen(0);
const BASE = `http://127.0.0.1:${server.address().port}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: BROWSER, headless: "new", args: ["--hide-scrollbars", "--force-color-profile=srgb"], defaultViewport: { width: W, height: H, deviceScaleFactor: 1 } });
const page = await browser.newPage();
await page.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "no-preference" }]);

async function go(route, wait = 1200) {
  // full reload for every capture: a hash change alone would keep panels/state from the previous shot
  await page.goto("about:blank");
  await page.goto(`${BASE}/index.html#/${route}`, { waitUntil: "networkidle0" });
  await sleep(wait);
}
async function shot(name) {
  await page.screenshot({ path: path.join(OUT, `${name}.png`) });
  console.log("png", name);
}
const click = (sel) => page.$eval(sel, (el) => el.click()).catch(() => {});

// ---------- clips: capture frames at ~15 fps while an async scenario runs
async function clip(name, scenario, { fps = 15, gifWidth = 960 } = {}) {
  fs.rmSync(FRAMES, { recursive: true, force: true });
  fs.mkdirSync(FRAMES, { recursive: true });
  let n = 0, recording = true;
  const rec = (async () => {
    while (recording) {
      const t = Date.now();
      await page.screenshot({ path: path.join(FRAMES, `f${String(n++).padStart(4, "0")}.png`) });
      await sleep(Math.max(0, 1000 / fps - (Date.now() - t)));
    }
  })();
  await scenario();
  recording = false;
  await rec;
  const input = ["-y", "-hide_banner", "-loglevel", "error", "-framerate", String(fps), "-i", path.join(FRAMES, "f%04d.png")];
  execFileSync("ffmpeg", [...input, "-vf", "format=yuv420p", "-c:v", "libx264", "-crf", "22", "-preset", "slow", "-movflags", "+faststart", path.join(OUT, `${name}.mp4`)]);
  execFileSync("ffmpeg", [...input, "-vf", `fps=${Math.min(fps, 12)},scale=${gifWidth}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle`, path.join(OUT, `${name}.gif`)]);
  fs.rmSync(FRAMES, { recursive: true, force: true });
  console.log("clip", name, `${n} frames`);
}

async function typeSlow(sel, text, delay = 55) {
  await page.focus(sel);
  await page.$eval(sel, (el) => { el.value = ""; el.dispatchEvent(new Event("input", { bubbles: true })); });
  await page.type(sel, text, { delay });
}

// ---------- screenshots
await go("overview", 1800);  await shot("overview");
await go("search", 1500);
await typeSlow("#s-q", "kind=dns.query", 0);
await page.keyboard.press("Escape"); await page.keyboard.press("Enter"); await sleep(1800);
await shot("search");
await go("leaks", 1500);     await shot("leak-check");
await go("network", 1500);   await shot("network");
await go("router", 1500);    await shot("router");
await go("intel", 1500);     await shot("threat-intel");
await go("alerts", 1500);    await shot("alerts");
await go("cleaner", 800);    await click("#c-scan"); await sleep(2500); await shot("cleaner");
await go("devices", 1500);   await shot("devices");
await go("settings", 1500);  await shot("settings");

// Ask AI panel (demo key so the mock answers)
await go("search", 1500);
await page.evaluate(() => window.API && window.API.aiSetKey && window.API.aiSetKey("demo-key"));
await click("#s-ai"); await sleep(1200);
await page.$eval("#ai-q", (el) => { el.value = "Anything suspicious in this search?"; el.dispatchEvent(new Event("input", { bubbles: true })); }).catch(() => {});
await click("#ai-go"); await sleep(3500);
await shot("ask-ai");

// ---------- clips
await go("overview", 1500);
await clip("brand-hover", async () => {
  await sleep(500);
  const b = await page.$(".brand");
  const box = await b.boundingBox();
  await page.mouse.move(box.x + 30, box.y + box.height / 2, { steps: 8 });
  await sleep(1400);
  await page.mouse.move(box.x + 30, box.y + 260, { steps: 8 });
  await sleep(900);
}, { fps: 20, gifWidth: 720 });

await go("search", 1500);
await clip("search-flow", async () => {
  await sleep(600);
  await typeSlow("#s-q", "kind=dns.query severity>=low ");
  await sleep(500);
  await page.$$eval("#s-chips .chip", (els) => { const vpn = els.find((e) => e.textContent.trim() === "VPN"); vpn && vpn.click(); });
  await sleep(900);
  await page.keyboard.press("Escape");
  await page.keyboard.press("Enter");
  await sleep(1600);
  await typeSlow("#s-q", "vpn=yes | stats count by host");
  await page.keyboard.press("Escape");  // close suggestions, then run
  await page.keyboard.press("Enter");
  await sleep(2400);
});

await go("leaks", 1500);
await clip("leak-check", async () => {
  await sleep(800);
  await page.mouse.wheel({ deltaY: 380 }); await sleep(1000);
  await page.$$eval("button", (els) => { const b = els.find((e) => /samples|details|show/i.test(e.textContent)); b && b.click(); });
  await sleep(1400);
  await page.mouse.wheel({ deltaY: 520 }); await sleep(1400);
  await page.mouse.wheel({ deltaY: -900 }); await sleep(1200);
});

await browser.close();
server.close();
console.log("done →", OUT);
