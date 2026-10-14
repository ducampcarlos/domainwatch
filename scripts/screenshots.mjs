// Renders the README screenshots from the real dashboard, served by the real API, over DEMO data
// seeded straight into the database (no network checks run). Needs `npm run build` first.
//
//   CHROME_PATH=/path/to/chromium node scripts/screenshots.mjs

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright-core";

import { buildApp } from "../dist/app.js";
import { loadConfig } from "../dist/config.js";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const TOKEN = "demo-token-0123456789abcdef";
const NOW = Math.floor(Date.now() / 1000);
const clock = { now: () => NOW };

const app = buildApp(loadConfig({ DOMAINWATCH_TOKEN: TOKEN }), { clock, dbPath: ":memory:", log: () => undefined });
const { db } = app;

// A tiny deterministic generator so the sparklines are the same on every run.
let seed = 7;
const rand = () => ((seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32);

function seedMonitor(input, history, summary, state, extra = {}) {
  const m = db.addMonitor(input, NOW - 86_400 * 9);
  for (let i = history.length - 1; i >= 0; i--) {
    const [status, latency, text] = history[i];
    db.insertResult(m.id, NOW - (history.length - 1 - i) * input.intervalS - 20, { status, summary: text ?? summary, latencyMs: latency, metrics: {}, detail: {} });
  }
  db.saveState({ monitorId: m.id, status: state.status, failures: state.failures ?? 0, since: NOW - state.sinceAgo, lastAlertTs: state.alerted ? NOW - state.sinceAgo : 0, baseline: null });
  return { ...m, ...extra };
}
const healthy = (n, base) => Array.from({ length: n }, () => ["ok", Math.round(base * (0.7 + rand() * 0.7))]);

const shop = seedMonitor({ name: "Shop", kind: "http", target: "https://shop.example.com/", intervalS: 60, config: {} }, healthy(60, 180), "HTTP 200", { status: "ok", sinceAgo: 86_400 * 3 }, {});
seedMonitor({ name: "API", kind: "http", target: "https://api.example.com/health", intervalS: 60, config: {} },
  [...healthy(48, 90), ["warn", 3400, "HTTP 200 but slow: 3400 ms (warns above 3000 ms)"], ["warn", 3900, "HTTP 200 but slow: 3900 ms (warns above 3000 ms)"], ...healthy(10, 95)], "HTTP 200", { status: "ok", sinceAgo: 600 });
const checkout = seedMonitor({ name: "Checkout", kind: "http", target: "https://pay.example.com/status", intervalS: 60, config: {} },
  [...healthy(50, 140), ...Array.from({ length: 10 }, () => ["fail", 30, "HTTP 503, expected 2xx or 3xx"])], "HTTP 503, expected 2xx or 3xx", { status: "fail", failures: 10, sinceAgo: 540, alerted: true });
seedMonitor({ name: "example.com certificate", kind: "tls", target: "example.com", intervalS: 21_600, config: {} }, Array.from({ length: 20 }, () => ["ok", Math.round(60 + rand() * 20), "Valid for 63 days (until 2026-12-16), issued by R11"]), "", { status: "ok", sinceAgo: 86_400 * 8 });
seedMonitor({ name: "shop.example.com certificate", kind: "tls", target: "shop.example.com:443", intervalS: 21_600, config: {} }, Array.from({ length: 20 }, (_, i) => [i > 15 ? "warn" : "ok", 70, i > 15 ? "Certificate expires in 12 days (2026-10-26)" : "Valid for 30 days"]), "", { status: "warn", sinceAgo: 3600 * 20, alerted: true });
seedMonitor({ name: "example.com records", kind: "dns", target: "example.com", intervalS: 900, config: {} }, Array.from({ length: 30 }, () => ["ok", 25, "No changes (9 records)"]), "", { status: "ok", sinceAgo: 86_400 * 9 });
seedMonitor({ name: "example.com mail", kind: "mail", target: "example.com", intervalS: 3600, config: {} }, Array.from({ length: 12 }, () => ["ok", 40, "SPF and DMARC (p=reject) are published"]), "", { status: "ok", sinceAgo: 86_400 * 9 });

db.insertAlert(checkout.id, NOW - 540, "down", "[DOWN] Checkout (http https://pay.example.com/status): HTTP 503, expected 2xx or 3xx");
db.markDelivered(1);
db.insertAlert(shop.id, NOW - 86_400 * 2, "recovered", "[RECOVERED] Shop (http https://shop.example.com/) after 4m: HTTP 200 in 171 ms");
db.markDelivered(2);
db.insertAlert(6 - 1, NOW - 3600 * 20, "warning", "[WARNING] shop.example.com certificate (tls shop.example.com:443): Certificate expires in 12 days (2026-10-26)");
db.markDelivered(3);

await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${app.server.address().port}`;
mkdirSync(join(root, "assets"), { recursive: true });

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined, args: ["--no-sandbox"] });
try {
  for (const [name, viewport] of [["dashboard", { width: 1180, height: 940 }], ["dashboard-mobile", { width: 390, height: 1100 }]]) {
    const context = await browser.newContext({ viewport, colorScheme: "dark", deviceScaleFactor: 2 });
    const page = await context.newPage();
    await page.addInitScript((token) => sessionStorage.setItem("domainwatch.token", token), TOKEN);
    await page.goto(base);
    await page.locator(".monitor").first().waitFor();
    await page.waitForFunction(() => document.querySelectorAll(".monitor .spark").length >= 6);
    await page.screenshot({ path: join(root, "assets", `${name}.png`), fullPage: true });
    await context.close();
    console.log(`wrote assets/${name}.png`);
  }
} finally {
  await browser.close();
  await app.close();
}
