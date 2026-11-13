// The Web Components in Chromium against the live fixture: pair through the dialog, see the host
// connect with its services, survive a reload from IndexedDB, and capture each state.
import { createServer } from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(path.join(process.cwd(), "package.json"));
const { chromium } = require("@playwright/test");
const fixture = JSON.parse(readFileSync(process.env.TETHER_WEB_FIXTURE, "utf8"));
const dist = process.env.TETHER_WEB_DIST;
const shots = process.env.TETHER_WEB_SHOTS;
mkdirSync(shots, { recursive: true });
const nextCode = () => execFileSync(fixture.binary, ["host", "pair-code", "--config", fixture.hostConfig], { encoding: "utf8" }).trim();

const page = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tether web fixture</title>
<style>:root{color-scheme:light dark}body{margin:0;padding:32px 16px;background:Canvas;color:CanvasText;font-family:system-ui}main{max-width:640px;margin:0 auto}</style>
<main><tether-workspace id="workspace" device="browser"></tether-workspace></main>
<script type="module">
  import { createTestClient } from "./dist/testing.js";
  import "./dist/elements.js";
  const client = await createTestClient({ appId: ${JSON.stringify(fixture.appID)} });
  document.getElementById("workspace").client = client;
  window.tetherReady = true;
</script>`;
const types = { ".js": "text/javascript", ".wasm": "application/wasm", ".html": "text/html" };
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/") return res.writeHead(200, { "content-type": "text/html" }).end(url.search === "?plain" ? page.replace(":root{color-scheme:light dark}", "") : page);
  const file = path.join(dist, url.pathname.replace(/^\/dist\//, "/"));
  if (!url.pathname.startsWith("/dist/") || !file.startsWith(dist)) return res.writeHead(404).end();
  try {
    res.writeHead(200, { "content-type": types[path.extname(file)] ?? "application/octet-stream" }).end(readFileSync(file));
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

// WCAG contrast of every visible text node inside the components, against the first opaque
// background behind it (crossing shadow roots). Disabled controls are exempt.
const contrast = (tab, label) => tab.evaluate((label) => {
  const parse = (c) => {
    const m = c.match(/rgba?\(([^)]+)\)/) ?? c.match(/color\(srgb ([^)]+)\)/);
    if (!m) return null;
    const parts = m[1].split(/[ ,/]+/).filter(Boolean).map(Number);
    const scale = c.startsWith("color(") ? 255 : 1;
    return { r: parts[0] * scale, g: parts[1] * scale, b: parts[2] * scale, a: parts[3] ?? 1 };
  };
  const lum = ({ r, g, b }) => [r, g, b].map((v) => (v /= 255) <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4).reduce((s, v, i) => s + v * [0.2126, 0.7152, 0.0722][i], 0);
  const parent = (el) => el.parentElement ?? el.getRootNode().host ?? null;
  const backdrop = (el) => {
    for (let at = el; at; at = parent(at)) {
      const bg = parse(getComputedStyle(at).backgroundColor);
      if (bg && bg.a > 0.9) return bg;
      if (at.tagName === "DIALOG" && at.open) break;
    }
    return parse(getComputedStyle(document.body).backgroundColor) ?? { r: 255, g: 255, b: 255 };
  };
  const failures = [];
  const visit = (root) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) visit(el.shadowRoot);
      const text = [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent.trim()).join("");
      if (!text || el.closest("[disabled]") || el.matches(":disabled")) continue;
      const box = el.getBoundingClientRect();
      if (!box.width || !box.height || getComputedStyle(el).visibility === "hidden") continue;
      const style = getComputedStyle(el);
      const fg = parse(style.color);
      if (!fg) continue;
      const [a, b] = [lum(fg), lum(backdrop(el))].sort((x, y) => y - x);
      const ratio = (a + 0.05) / (b + 0.05);
      const size = parseFloat(style.fontSize), weight = Number(style.fontWeight);
      const need = size >= 24 || (size >= 18.66 && weight >= 700) ? 3 : 4.5;
      if (ratio < need) failures.push(`${label}: "${text.slice(0, 30)}" ${ratio.toFixed(2)}:1 (needs ${need})`);
    }
  };
  for (const host of document.querySelectorAll("tether-workspace,tether-pair")) visit(host.shadowRoot);
  return failures;
}, label);

const browser = await chromium.launch();
const problems = [];
let step = 0;
const shoot = async (target, name) => {
  await target.screenshot({ path: path.join(shots, `${String(++step).padStart(2, "0")}-${name}.png`), fullPage: true });
};
try {
  const context = await browser.newContext({ viewport: { width: 1180, height: 820 }, deviceScaleFactor: 2 });
  const tab = await context.newPage();
  tab.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  tab.on("console", (m) => m.type() === "error" && problems.push(`console: ${m.text()}`));
  await tab.goto(origin);
  await tab.waitForFunction(() => window.tetherReady);
  const workspace = tab.locator("tether-workspace");
  await workspace.getByText("Add a Mac or PC").waitFor();
  await shoot(tab, "empty");
  problems.push(...(await contrast(tab, "empty")));

  await workspace.getByRole("button", { name: "Add a computer" }).click();
  const sheet = workspace.locator("tether-pair");
  await sheet.getByRole("heading", { name: "Pair with a code" }).waitFor();
  const pair = sheet.getByRole("button", { name: "Pair", exact: true });
  if (!(await pair.isDisabled())) throw new Error("Pair enabled with nothing entered");
  await shoot(tab, "pair-sheet");

  await sheet.getByLabel("Invitation link").fill("tether://pair?data=bm90LWFuLWludml0YXRpb24");
  await sheet.getByText("expired or is for another app").waitFor();
  await sheet.getByLabel("Invitation link").fill("");
  await sheet.locator("summary").click();
  await sheet.getByLabel("Relay URL").fill(fixture.relayURL);
  await sheet.getByLabel("Host ID").fill(fixture.hostID);
  const first = nextCode();
  await sheet.getByLabel("Pairing code").fill(first.slice(0, 7) + (first[7] === "A" ? "B" : "A"));
  // ws:// relays are refused unless the client allows loopback, which the fixture's client does.
  await sheet.getByLabel("Pairing code").press("Enter");
  await sheet.getByText("Couldn't pair").waitFor({ timeout: 20_000 });
  await shoot(tab, "pair-failed");
  problems.push(...(await contrast(tab, "failed")));

  await sheet.getByLabel("Pairing code").fill(nextCode().toLowerCase().replace(/^(.{4})/, "$1-"));
  await sheet.getByRole("button", { name: "Try again" }).click();
  await sheet.getByRole("heading", { name: /^Connected to/ }).waitFor({ timeout: 20_000 });
  await shoot(tab, "pair-connected");
  const modal = await tab.evaluate(() => document.querySelector("tether-workspace").shadowRoot.querySelector("dialog").matches(":modal"));
  if (!modal) problems.push("the pairing dialog stopped being modal after the list refreshed");
  await sheet.getByRole("button", { name: "Done" }).click();

  const host = workspace.locator("li.host").first();
  await host.getByText("Connected", { exact: true }).waitFor({ timeout: 20_000 });
  await host.locator(".services code", { hasText: "tcp" }).waitFor();
  await shoot(tab, "workspace-connected");
  problems.push(...(await contrast(tab, "connected")));

  await tab.reload();
  await tab.waitForFunction(() => window.tetherReady);
  await workspace.locator("li.host").first().getByText("Connected", { exact: true }).waitFor({ timeout: 20_000 });

  await tab.emulateMedia({ colorScheme: "dark" });
  await shoot(tab, "workspace-dark");
  problems.push(...(await contrast(tab, "dark")));
  await tab.setViewportSize({ width: 390, height: 844 });
  await shoot(tab, "workspace-phone-dark");
  await tab.emulateMedia({ colorScheme: "light" });
  await workspace.getByRole("button", { name: "Add a computer" }).click();
  await shoot(tab, "pair-sheet-phone");
  await tab.emulateMedia({ colorScheme: "dark" });
  await shoot(tab, "pair-sheet-phone-dark");
  problems.push(...(await contrast(tab, "pair dark")));
  await tab.emulateMedia({ colorScheme: "light" });
  await sheet.getByRole("button", { name: "Cancel" }).click();

  await host.getByRole("button", { name: "Forget on this device" }).click();
  await workspace.getByRole("dialog").getByText("Only this device forgets").waitFor();
  await shoot(tab, "forget-confirm-phone");
  problems.push(...(await contrast(tab, "confirm")));
  await workspace.getByRole("dialog").getByRole("button", { name: "Forget on this device" }).click();
  await workspace.getByText("Add a Mac or PC").waitFor();

  const plain = await context.newPage();
  await plain.emulateMedia({ colorScheme: "dark" });
  await plain.goto(origin + "/?plain");
  await plain.waitForFunction(() => window.tetherReady);
  const heading = await plain.evaluate(() => getComputedStyle(document.querySelector("tether-workspace").shadowRoot.querySelector("h2")).color);
  if (heading !== "rgb(31, 32, 34)") problems.push(`light page in dark OS: heading ${heading}`);
  // The contrast check has to be able to fail: a faint secondary colour must be caught.
  await plain.evaluate(() => document.querySelector("tether-workspace").style.setProperty("--tether-secondary", "#d4d4d4"));
  if ((await contrast(plain, "control")).length === 0) problems.push("contrast check missed a 1.5:1 message");
  await plain.close();

  const focusless = await tab.evaluate(() => {
    const root = document.querySelector("tether-workspace").shadowRoot;
    return [...root.querySelectorAll("button")].filter((b) => getComputedStyle(b).minHeight === "0px").length;
  });
  if (focusless) problems.push(`${focusless} buttons without a minimum height`);
  if (problems.length) throw new Error(problems.join("\n"));
  console.log(`ok - browser pairing, reconnect after reload, forget; ${step} captures in ${shots}`);
} finally {
  await browser.close();
  server.close();
}
