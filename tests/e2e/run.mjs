// End-to-end: the REAL built server (dist/) as a child process, a real Chromium driving the dashboard,
// a flip-able target site and a webhook receiver.
//
//   npm run build && npm run test:e2e
//
// Set CHROME_PATH to use a specific browser binary.

import assert from "node:assert/strict";
import { execFile, spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright-core";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..");
const cli = join(root, "dist", "index.js");
const TOKEN = "e2e-token-0123456789abcdef";

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (error) {
    failures.push(name);
    console.log(`  FAIL ${name}\n       ${String(error.stack ?? error.message).split("\n").slice(0, 8).join("\n       ")}`);
  }
}
const listen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));

console.log("domainwatch end-to-end");

// --- CLI ----------------------------------------------------------------------------------------
const run = (args, env = {}) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", env: { PATH: process.env.PATH, ...env } });

await test("cli: --version, --help and usage errors", () => {
  assert.match(run(["--version"]).stdout, /^\d+\.\d+\.\d+\n$/);
  assert.match(run(["--help"]).stdout, /domainwatch serve/);
  const bad = run(["frobnicate"]);
  assert.equal(bad.status, 64);
  assert.match(bad.stderr, /Unknown command/);
});

await test("cli: serve refuses to start without a token", () => {
  const r = run(["serve"]);
  assert.equal(r.status, 64);
  assert.match(r.stderr, /DOMAINWATCH_TOKEN/);
  assert.equal(r.stdout, "");
});

await test("cli: check refuses private targets by default and allows them with --allow-private", async () => {
  const site = createServer((_req, res) => void res.writeHead(200).end("hi"));
  const port = await listen(site);
  try {
    const refused = run(["check", "http", `http://127.0.0.1:${port}/`]);
    assert.equal(refused.status, 2);
    assert.match(refused.stdout, /FAIL.*127\.0\.0\.1.*private/);
    // Asynchronous on purpose: spawnSync would block this process, and the test site lives in it.
    const allowed = await new Promise((resolve) => execFile(process.execPath, [cli, "check", "http", `http://127.0.0.1:${port}/`, "--allow-private", "--json"], (error, stdout) => resolve({ status: error ? error.code : 0, stdout })));
    assert.equal(allowed.status, 0);
    assert.equal(JSON.parse(allowed.stdout).status, "ok");
  } finally {
    site.close();
  }
});

// --- server + browser ---------------------------------------------------------------------------
let healthy = true;
const site = createServer((_req, res) => void res.writeHead(healthy ? 200 : 503).end());
const sitePort = await listen(site);
const hooks = [];
const hook = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    hooks.push(JSON.parse(body));
    res.writeHead(204).end();
  });
});
const hookPort = await listen(hook);

const dataDir = mkdtempSync(join(tmpdir(), "dw-e2e-"));
const port = 20000 + Math.floor(Math.random() * 20000);
const child = spawn(process.execPath, [cli, "serve"], {
  env: { PATH: process.env.PATH, PORT: String(port), DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_DATA: dataDir, DOMAINWATCH_ALLOW_PRIVATE: "1", DOMAINWATCH_WEBHOOKS: `http://127.0.0.1:${hookPort}/hook` },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverOutput = "";
child.stdout.on("data", (c) => (serverOutput += c));
child.stderr.on("data", (c) => (serverOutput += c));
const base = `http://127.0.0.1:${port}`;
for (let i = 0; i < 100 && !(await fetch(`${base}/healthz`).then((r) => r.ok, () => false)); i++) await new Promise((r) => setTimeout(r, 50));

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined, args: ["--no-sandbox"] });
const problems = [];
const context = await browser.newContext({ viewport: { width: 1280, height: 860 } });
const page = await context.newPage();
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
page.on("console", (m) => m.type() === "error" && !/401|Failed to load resource/.test(m.text()) && problems.push(`console.error: ${m.text()}`));
page.on("dialog", (d) => void d.accept());

try {
  await test("shows the sign-in form, rejects a wrong token and accepts the right one", async () => {
    await page.goto(base);
    await page.locator("#login").waitFor();
    assert.equal(await page.locator("#app").isVisible(), false);
    await page.locator("#token").fill("definitely-not-the-token");
    await page.locator("#login-form button").click();
    await page.locator("#login-error").waitFor();
    assert.match(await page.locator("#login-error").innerText(), /invalid bearer token/i);
    await page.locator("#token").fill(TOKEN);
    await page.locator("#login-form button").click();
    await page.locator("#app").waitFor();
    assert.equal(await page.locator("#login").isVisible(), false);
    assert.match(await page.locator("#version").innerText(), /^v\d/);
  });

  await test("adds monitors and shows their first result", async () => {
    await page.locator("#toggle-add").click();
    await page.locator("#f-kind").selectOption("http");
    await page.locator("#f-target").fill(`http://127.0.0.1:${sitePort}/`);
    await page.locator("#f-name").fill("Shop");
    await page.locator("#add-form button[type=submit]").click();
    await page.locator(".monitor", { hasText: "Shop" }).waitFor();
    await page.locator(".monitor", { hasText: /HTTP 200/ }).waitFor();
    assert.equal(await page.locator("#n-ok").innerText(), "1");

    await page.locator("#toggle-add").click();
    await page.locator("#f-kind").selectOption("dns");
    await page.locator("#f-target").fill("localhost");
    await page.locator("#add-form button[type=submit]").click();
    await page.locator(".monitor .kind", { hasText: "dns" }).waitFor(); // whatever the resolver answers, a DNS monitor is created and checked

    // A port nobody listens on: one failed check is not yet an outage, so the dot must say neither "ok" nor "failing".
    await page.locator("#toggle-add").click();
    await page.locator("#f-kind").selectOption("http");
    await page.locator("#f-target").fill("http://127.0.0.1:1/");
    await page.locator("#f-name").fill("Closed");
    await page.locator("#add-form button[type=submit]").click();
    const closed = page.locator(".monitor", { hasText: "Closed" });
    await closed.locator(".summary", { hasText: /connection refused/ }).waitFor();
    assert.equal(await closed.locator(".dot.unconfirmed").count(), 1);
    assert.match(await closed.innerText(), /alert follows if the next one fails too/);
    assert.doesNotMatch(await closed.innerText(), /ok since/);
  });

  await test("validation errors from the API are shown and nothing is created", async () => {
    await page.locator("#toggle-add").click();
    await page.locator("#f-kind").selectOption("http");
    await page.locator("#f-target").fill("ftp://example.test/");
    await page.locator("#add-form button[type=submit]").click();
    await page.locator("#add-error").filter({ hasText: /http:\/\/ or https:\/\//i }).waitFor();
    await page.locator("#cancel-add").click();
    assert.equal(await page.locator(".monitor").count(), 3);
  });

  await test("an outage raises one alert (after two failures), a webhook, and a recovery", async () => {
    healthy = false;
    const shop = () => page.locator(".monitor", { hasText: "Shop" });
    await shop().getByRole("button", { name: "Check now" }).click();
    await shop().locator(".summary", { hasText: /HTTP 503/ }).waitFor();
    assert.equal(hooks.length, 0, "a single failure must not page");
    await shop().getByRole("button", { name: "Check now" }).click();
    await page.locator("#alerts li.down").waitFor();
    assert.equal(await page.locator("#n-fail").innerText(), "1");
    assert.equal(hooks.length, 1);
    assert.equal(hooks[0].event.kind, "down");
    assert.match(hooks[0].text, /^\[DOWN\] Shop \(http http:\/\/127\.0\.0\.1:\d+\/\): HTTP 503/);

    healthy = true;
    await shop().getByRole("button", { name: "Check now" }).click();
    await page.locator("#alerts li.recovered").waitFor();
    assert.deepEqual(hooks.map((h) => h.event.kind), ["down", "recovered"]);
    assert.equal(await page.locator("#n-fail").innerText(), "0");
  });

  await test("pause and delete work, and a reload keeps the session but not after sign-out", async () => {
    const shop = page.locator(".monitor", { hasText: "Shop" });
    await shop.getByRole("button", { name: "Pause" }).click();
    await page.locator(".monitor.paused", { hasText: "Shop" }).waitFor();
    await page.locator(".monitor.paused").getByRole("button", { name: "Resume" }).click();
    await page.locator(".monitor:not(.paused)", { hasText: "Shop" }).waitFor();

    await page.reload();
    await page.locator("#app").waitFor();

    await page.locator(".monitor", { hasText: "Shop" }).getByRole("button", { name: "Delete" }).click();
    await page.waitForFunction(() => ![...document.querySelectorAll(".monitor .name")].some((n) => n.textContent === "Shop"));
    await page.locator("#logout").click();
    await page.locator("#login").waitFor();
    await page.reload();
    await page.locator("#login").waitFor();
  });

  await test("hostile monitor names are rendered as text, not HTML", async () => {
    const res = await fetch(`${base}/api/monitors`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ kind: "dns", target: "xss.localhost", name: `<img src=x onerror="window.__pwned=1"><b>bold</b>` }),
    });
    assert.equal(res.status, 201);
    await page.reload();
    await page.locator("#token").fill(TOKEN);
    await page.locator("#login-form button").click();
    await page.locator(".monitor .name", { hasText: "<img" }).waitFor();
    assert.equal(await page.evaluate(() => window.__pwned), undefined);
    assert.equal(await page.locator(".monitor .name b").count(), 0);
  });

  await test("the API behaves over real HTTP: auth, metrics, headers, restart persistence", async () => {
    const auth = { authorization: `Bearer ${TOKEN}` };
    assert.equal((await fetch(`${base}/api/monitors`)).status, 401);
    const metrics = await (await fetch(`${base}/metrics`, { headers: auth })).text();
    assert.match(metrics, /^domainwatch_monitors 3$/m);
    const page0 = await fetch(`${base}/`);
    assert.match(page0.headers.get("content-security-policy"), /default-src 'none'/);
    assert.equal(page0.headers.get("access-control-allow-origin"), null);
  });

  await test("graceful shutdown on SIGTERM, and the data survives a restart", async () => {
    const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
    child.kill("SIGTERM");
    const result = await Promise.race([exited, new Promise((r) => setTimeout(() => r("timeout"), 8000))]);
    assert.deepEqual(result, { code: 0, signal: null });
    assert.match(serverOutput, /Shutting down/);
    const again = spawn(process.execPath, [cli, "serve"], { env: { PATH: process.env.PATH, PORT: String(port), DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_DATA: dataDir, DOMAINWATCH_ALLOW_PRIVATE: "1" }, stdio: "ignore" });
    try {
      for (let i = 0; i < 100 && !(await fetch(`${base}/healthz`).then((r) => r.ok, () => false)); i++) await new Promise((r) => setTimeout(r, 50));
      const list = await (await fetch(`${base}/api/monitors`, { headers: { authorization: `Bearer ${TOKEN}` } })).json();
      assert.equal(list.length, 3);
    } finally {
      again.kill("SIGKILL");
    }
  });

  await test("no console errors or uncaught exceptions in the browser", () => {
    assert.deepEqual(problems, []);
  });
} finally {
  await browser.close();
  child.kill("SIGKILL");
  site.close();
  hook.close();
  rmSync(dataDir, { recursive: true, force: true });
}

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`Server output:\n${serverOutput}`);
  process.exit(1);
}
