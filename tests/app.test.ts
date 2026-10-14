import { mkdtempSync, rmSync, statSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { PUBLIC_DIR, VERSION, buildApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { FakeDns, deps, startServer } from "./helpers.js";

const TOKEN = "k".repeat(32);
const cleanup: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) await fn();
});

describe("app wiring", () => {
  it("monitors a target end to end: failure, webhook, recovery, persistence across restart", async () => {
    // A target that we can flip between healthy and broken, and a webhook receiver.
    let healthy = true;
    const target = await startServer((_req, res) => void res.writeHead(healthy ? 200 : 500).end());
    const received: Array<{ text: string; event: { kind: string } }> = [];
    const hook = await startServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received.push(JSON.parse(body));
        res.writeHead(204).end();
      });
    });
    cleanup.push(target.close, hook.close);

    const dataDir = mkdtempSync(join(tmpdir(), "dw-data-"));
    cleanup.push(() => rmSync(dataDir, { recursive: true, force: true }));
    const config = loadConfig({ DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_DATA: dataDir, DOMAINWATCH_WEBHOOKS: `http://127.0.0.1:${hook.port}/h`, PORT: "9" });
    const clock = { t: 1_000_000, now() { return this.t; } };
    const open = () => buildApp(config, { clock, checkDeps: deps({ dns: new FakeDns() }), log: () => undefined });

    let app = open();
    expect((statSync(dataDir).mode & 0o777).toString(8)).toBe("700");
    await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
    const api = (path: string, init: RequestInit = {}) => fetch(`http://127.0.0.1:${(app.server.address() as AddressInfo).port}${path}`, { ...init, headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" } });

    const created = (await (await api("/api/monitors", { method: "POST", body: JSON.stringify({ kind: "http", target: `http://public.test:${target.port}/`, name: "App", intervalS: 30 }) })).json()) as { id: number };
    expect(await app.scheduler.tick()).toBe(1);
    expect((await (await api("/api/summary")).json()).counts).toMatchObject({ ok: 1, fail: 0 });

    healthy = false;
    clock.t += 30;
    await app.scheduler.tick(); // first failure: silent
    expect(received).toHaveLength(0);
    clock.t += 30;
    await app.scheduler.tick(); // second: alert
    expect(received).toHaveLength(1);
    expect(received[0]!.event.kind).toBe("down");
    expect(received[0]!.text).toMatch(/^\[DOWN\] App \(http http:\/\/public\.test:\d+\/\): HTTP 500/);

    // Restart on the same data: the outage is remembered, so there is no second "down" alert.
    await app.close();
    app = open();
    await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
    cleanup.push(() => app.close());
    expect(app.db.getState(created.id)).toMatchObject({ status: "fail" });
    clock.t += 30;
    await app.scheduler.tick();
    expect(received).toHaveLength(1);

    healthy = true;
    clock.t += 30;
    await app.scheduler.tick();
    expect(received.map((r) => r.event.kind)).toEqual(["down", "recovered"]);
    const alerts = (await (await api("/api/alerts")).json()) as Array<{ delivered: boolean }>;
    expect(alerts).toHaveLength(2);
    expect(alerts.every((a) => a.delivered)).toBe(true);
    expect(await (await fetch(`http://127.0.0.1:${(app.server.address() as AddressInfo).port}/healthz`)).json()).toMatchObject({ version: VERSION, monitors: 1 });
  });

  it("keeps alerts as undelivered when the webhook is unreachable, without breaking monitoring", async () => {
    const config = loadConfig({ DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_WEBHOOKS: "http://127.0.0.1:1/h" });
    const clock = { t: 5000, now() { return this.t; } };
    const app = buildApp(config, { clock, dbPath: ":memory:", checkDeps: deps(), log: () => undefined });
    cleanup.push(() => app.close());
    app.db.addMonitor({ name: "Dead", kind: "http", target: "http://nowhere.test/", intervalS: 30, config: {} }, clock.t);
    await app.scheduler.tick();
    clock.t += 30;
    await app.scheduler.tick();
    expect(app.db.recentAlerts(5)).toMatchObject([{ kind: "down", delivered: false }]);
  }, 15_000);

  it("ships its dashboard files", async () => {
    const { readdirSync } = await import("node:fs");
    expect(readdirSync(PUBLIC_DIR)).toEqual(expect.arrayContaining(["index.html", "app.js", "style.css"]));
  });
});

describe("config", () => {
  it("requires a strong token and validates the rest", () => {
    expect(() => loadConfig({})).toThrow(/DOMAINWATCH_TOKEN/);
    expect(() => loadConfig({ DOMAINWATCH_TOKEN: "short" })).toThrow(/16 characters/);
    expect(loadConfig({}, { requireToken: false }).token).toBe("");
    expect(() => loadConfig({ DOMAINWATCH_TOKEN: TOKEN, PORT: "70000" })).toThrow(/PORT/);
    expect(() => loadConfig({ DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_CONCURRENCY: "0" })).toThrow(/CONCURRENCY/);
    expect(() => loadConfig({ DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_WEBHOOKS: "ftp://x" })).toThrow(/invalid URL/);
    expect(() => loadConfig({ DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_WEBHOOKS: "not a url" })).toThrow(/invalid URL/);
  });
  it("has safe defaults", () => {
    expect(loadConfig({ DOMAINWATCH_TOKEN: TOKEN })).toMatchObject({ host: "127.0.0.1", port: 8787, allowPrivate: false, retentionDays: 30, concurrency: 4, maxMonitors: 200, webhooks: [] });
    expect(loadConfig({ DOMAINWATCH_TOKEN: TOKEN, DOMAINWATCH_ALLOW_PRIVATE: "YES", DOMAINWATCH_WEBHOOKS: " http://a.test/x , https://b.test/y " })).toMatchObject({ allowPrivate: true, webhooks: ["http://a.test/x", "https://b.test/y"] });
  });
});
