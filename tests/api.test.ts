import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createApi } from "../src/api/server.js";
import { renderMetrics } from "../src/api/metrics.js";
import { validateNewMonitor, validatePatch } from "../src/api/validate.js";
import { Db } from "../src/db.js";
import { Scheduler } from "../src/engine/scheduler.js";
import type { Observation } from "../src/types.js";

const TOKEN = "t".repeat(32);
let db: Db;
let server: Server;
let base: string;
let dir: string;
let observe: () => Promise<Observation> | Observation;
const clock = { t: 100_000, now() { return this.t; } };

beforeEach(async () => {
  clock.t = 100_000;
  db = new Db(":memory:");
  dir = mkdtempSync(join(tmpdir(), "dw-pub-"));
  writeFileSync(join(dir, "index.html"), "<!doctype html><title>dashboard</title>");
  writeFileSync(join(dir, "app.js"), "console.log(1)");
  writeFileSync(join(dir, "notes.txt"), "not served");
  observe = () => ({ latencyMs: 12, metrics: { status_code: 200, redirects: 0 }, detail: { statusCode: 200 } });
  const scheduler = new Scheduler({ db, clock, runCheck: async () => observe(), notify: async () => true });
  server = createApi({ db, scheduler, clock, token: TOKEN, maxMonitors: 3, publicDir: dir, version: "9.9.9" });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const call = (path: string, init: RequestInit & { token?: string | null } = {}) => {
  const { token = TOKEN, headers, ...rest } = init;
  return fetch(`${base}${path}`, { ...rest, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(rest.body ? { "content-type": "application/json" } : {}), ...(headers as Record<string, string>) } });
};
const post = (path: string, body: unknown) => call(path, { method: "POST", body: JSON.stringify(body) });
const create = async (overrides: Record<string, unknown> = {}) => {
  const res = await post("/api/monitors", { kind: "http", target: "https://example.test/", name: "Example", ...overrides });
  return (await res.json()) as { id: number; [k: string]: unknown };
};

describe("authentication", () => {
  it("lets /healthz and the dashboard through without a token, and nothing else", async () => {
    expect((await call("/healthz", { token: null })).status).toBe(200);
    expect(await (await call("/healthz", { token: null })).json()).toEqual({ status: "ok", version: "9.9.9", monitors: 0 });
    expect((await call("/", { token: null })).status).toBe(200);
    for (const path of ["/api/monitors", "/api/summary", "/api/alerts", "/metrics", "/api/monitors/1"]) {
      const res = await call(path, { token: null });
      expect(res.status, path).toBe(401);
      expect(res.headers.get("www-authenticate")).toMatch(/Bearer/);
    }
  });

  it("rejects wrong, truncated and malformed tokens", async () => {
    for (const token of ["wrong", TOKEN.slice(0, -1), `${TOKEN}x`, "", " "]) expect((await call("/api/monitors", { token })).status).toBe(401);
    const res = await fetch(`${base}/api/monitors`, { headers: { authorization: `Basic ${TOKEN}` } });
    expect(res.status).toBe(401);
  });

  it("throttles repeated failures, then recovers after the window", async () => {
    for (let i = 0; i < 10; i++) expect((await call("/api/monitors", { token: "nope" })).status).toBe(401);
    const blocked = await call("/api/monitors", { token: TOKEN }); // even the right token is refused while throttled
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    clock.t += 61;
    expect((await call("/api/monitors")).status).toBe(200);
  });
});

describe("monitors", () => {
  it("creates, lists, reads, updates and deletes", async () => {
    const created = await post("/api/monitors", { kind: "tls", target: "Example.COM", name: "Cert", intervalS: 3600, config: { warnDays: 30 } });
    expect(created.status).toBe(201);
    const m = (await created.json()) as { id: number };
    expect(created.headers.get("location")).toBe(`/api/monitors/${m.id}`);
    expect(m).toMatchObject({ kind: "tls", target: "example.com", intervalS: 3600, enabled: true, config: { warnDays: 30 } });

    expect(await (await call("/api/monitors")).json()).toHaveLength(1);
    const patched = await call(`/api/monitors/${m.id}`, { method: "PATCH", body: JSON.stringify({ name: "Renamed", enabled: false }) });
    expect(await patched.json()).toMatchObject({ name: "Renamed", enabled: false });
    expect((await call(`/api/monitors/${m.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await call(`/api/monitors/${m.id}`)).status).toBe(404);
  });

  it("applies defaults per kind", async () => {
    expect(await create({ kind: "dns", target: "example.test", name: undefined })).toMatchObject({ intervalS: 900, name: "example.test" });
    expect(await create({ kind: "mail", target: "example.test" })).toMatchObject({ intervalS: 3600 });
  });

  it("rejects bad input with a 400 and a reason", async () => {
    const cases: Array<[unknown, RegExp]> = [
      [{ kind: "ping", target: "x.test" }, /kind must be/],
      [{ kind: "http", target: "ftp://x.test" }, /http:\/\/ or https:\/\//],
      [{ kind: "http", target: "https://user:pw@x.test/" }, /credentials/],
      [{ kind: "http", target: "nope" }, /valid URL/],
      [{ kind: "tls", target: "x.test:99999" }, /port/i],
      [{ kind: "dns", target: "host:80" }, /port/i],
      [{ kind: "dns", target: "a b" }, /valid host/],
      [{ kind: "http", target: "https://x.test/", intervalS: 5 }, /intervalS/],
      [{ kind: "http", target: "https://x.test/", extra: 1 }, /Unknown field "extra"/],
      [{ kind: "http", target: "https://x.test/", config: { warnDays: 5 } }, /Unknown field "warnDays"/],
      [{ kind: "tls", target: "x.test", config: { warnDays: 5, failDays: 9 } }, /smaller than/],
      [{ kind: "http", target: "https://x.test/", config: { expectStatus: [] } }, /expectStatus/],
      [{ kind: "http", target: "https://x.test/", name: "bad\nname" }, /name/],
      [[], /JSON object/],
    ];
    for (const [body, pattern] of cases) {
      const res = await post("/api/monitors", body);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(((await res.json()) as { error: string }).error).toMatch(pattern);
    }
  });

  it("returns 409 for a duplicate and when the monitor limit is reached", async () => {
    await create();
    expect((await post("/api/monitors", { kind: "http", target: "https://example.test/" })).status).toBe(409);
    await create({ target: "https://b.test/" });
    await create({ target: "https://c.test/" });
    const over = await post("/api/monitors", { kind: "http", target: "https://d.test/" });
    expect(over.status).toBe(409);
    expect(((await over.json()) as { error: string }).error).toMatch(/limit/);
  });

  it("will not change kind or target on PATCH", async () => {
    const m = await create();
    const res = await call(`/api/monitors/${m.id}`, { method: "PATCH", body: JSON.stringify({ target: "https://evil.test/" }) });
    expect(res.status).toBe(400);
    expect((await call(`/api/monitors/${m.id}`, { method: "PATCH", body: "{}" })).status).toBe(400);
  });

  it("404s for unknown ids and odd ids", async () => {
    for (const id of ["99", "0", "-1", "abc", "1.5", "1e3"]) expect((await call(`/api/monitors/${id}`)).status, id).toBe(404);
  });

  it("answers 405 with an Allow header", async () => {
    const m = await create();
    const res = await call(`/api/monitors/${m.id}`, { method: "PUT", body: "{}" });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET, PATCH, DELETE");
    expect((await call("/api/summary", { method: "POST", body: "{}" })).status).toBe(405);
  });
});

describe("request hygiene", () => {
  it("requires JSON, caps the body and rejects malformed JSON", async () => {
    const wrongType = await fetch(`${base}/api/monitors`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "text/plain" }, body: "{}" });
    expect(wrongType.status).toBe(415);
    const big = await call("/api/monitors", { method: "POST", body: JSON.stringify({ kind: "http", target: "https://x.test/", name: "x".repeat(20_000) }) });
    expect(big.status).toBe(413);
    const broken = await call("/api/monitors", { method: "POST", body: "{nope" });
    expect(broken.status).toBe(400);
  });

  it("sends hardening headers and no CORS", async () => {
    const res = await call("/api/monitors");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    const page = await call("/", { token: null });
    expect(page.headers.get("content-security-policy")).toMatch(/default-src 'none'.*script-src 'self'/);
    expect(page.headers.get("x-frame-options")).toBe("DENY");
  });

  it("serves only known static types and never escapes the public directory", async () => {
    expect((await call("/app.js", { token: null })).headers.get("content-type")).toMatch(/javascript/);
    expect((await call("/notes.txt", { token: null })).status).toBe(404);
    for (const path of ["/../package.json", "/%2e%2e/package.json", "/..%2f..%2fetc/passwd", "/%00", "//etc/passwd"]) {
      const res = await fetch(`${base}${path}`);
      expect([400, 404], path).toContain(res.status);
    }
    expect((await fetch(`${base}/`, { method: "POST" })).status).toBe(405);
  });
});

describe("results, summary, run and metrics", () => {
  it("runs a check on demand and records it", async () => {
    const m = await create();
    const run = await post(`/api/monitors/${m.id}/run`, {});
    expect(run.status).toBe(200);
    expect(await run.json()).toMatchObject({ status: "ok", monitorId: m.id });
    const results = (await (await call(`/api/monitors/${m.id}/results?limit=5`)).json()) as unknown[];
    expect(results).toHaveLength(1);
    expect((await call(`/api/monitors/${m.id}/results?limit=0`)).status).toBe(400);
    expect((await call(`/api/monitors/${m.id}/results?limit=abc`)).status).toBe(400);
    expect((await call(`/api/monitors/${m.id}/run`)).status).toBe(405);
  });

  it("refuses to start a second check while one is running", async () => {
    let release!: () => void;
    observe = () => new Promise((resolve) => (release = () => resolve({ metrics: { status_code: 200 }, detail: {} })));
    const m = await create();
    const first = post(`/api/monitors/${m.id}/run`, {});
    await new Promise((r) => setTimeout(r, 30));
    expect((await post(`/api/monitors/${m.id}/run`, {})).status).toBe(409);
    release();
    expect((await first).status).toBe(200);
  });

  it("summarises counts and recent alerts", async () => {
    const a = await create({ target: "https://a.test/", name: "A" });
    const b = await create({ target: "https://b.test/", name: "B" });
    await create({ target: "https://c.test/", name: "C" });
    await call(`/api/monitors/${b.id}`, { method: "PATCH", body: JSON.stringify({ enabled: false }) });
    await post(`/api/monitors/${a.id}/run`, {});
    const summary = (await (await call("/api/summary")).json()) as { counts: Record<string, number>; monitors: unknown[]; alerts: unknown[] };
    expect(summary.counts).toEqual({ total: 3, ok: 1, warn: 0, fail: 0, paused: 1, pending: 1 });
    expect(summary.monitors).toHaveLength(3);
    expect(summary.alerts).toEqual([]);
  });

  it("raises an alert after two failing runs and lists it", async () => {
    observe = () => ({ error: "connection refused", metrics: {}, detail: {} });
    const m = await create();
    await post(`/api/monitors/${m.id}/run`, {});
    await post(`/api/monitors/${m.id}/run`, {});
    const alerts = (await (await call("/api/alerts")).json()) as Array<{ kind: string; monitorName: string; delivered: boolean }>;
    expect(alerts).toMatchObject([{ kind: "down", monitorName: "Example", delivered: true }]);
  });

  it("exposes Prometheus metrics with escaped labels", async () => {
    const m = await create({ name: 'Quote " and \\ slash' });
    await post(`/api/monitors/${m.id}/run`, {});
    const res = await call("/metrics");
    expect(res.headers.get("content-type")).toMatch(/text\/plain; version=0\.0\.4/);
    const text = await res.text();
    expect(text).toContain('domainwatch_up{monitor="Quote \\" and \\\\ slash",kind="http",target="https://example.test/"} 1');
    expect(text).toMatch(/^domainwatch_status\{.*\} 0$/m);
    expect(text).toMatch(/^domainwatch_status_code\{.*\} 200$/m);
    expect(text).toMatch(/^domainwatch_monitors 1$/m);
    expect(text).toMatch(/^# TYPE domainwatch_up gauge$/m);
  });

  it("renders valid, empty-safe output with no monitors", () => {
    const text = renderMetrics([], { alertsStored: 0, startedAt: 0, now: 5 });
    expect(text).toContain("domainwatch_monitors 0");
    expect(text).toContain("domainwatch_uptime_seconds 5");
    expect(text).not.toContain("domainwatch_up{");
  });
});

describe("validation helpers", () => {
  it("normalises targets", () => {
    expect(validateNewMonitor({ kind: "tls", target: " Example.com:8443 " }).target).toBe("example.com:8443");
    expect(validateNewMonitor({ kind: "tls", target: "example.com:443" }).target).toBe("example.com");
    expect(validateNewMonitor({ kind: "tls", target: "[2001:db8::1]:8443" }).target).toBe("[2001:db8::1]:8443");
    expect(validateNewMonitor({ kind: "mail", target: "Example.COM." }).target).toBe("example.com");
    expect(validateNewMonitor({ kind: "http", target: "https://Example.com" }).target).toBe("https://example.com/");
    expect(validateNewMonitor({ kind: "http", target: "https://x.test/", config: { expectStatus: [200, 200, 204] } }).config.expectStatus).toEqual([200, 204]);
  });
  it("patches only known fields", () => {
    expect(validatePatch("http", { name: " New ", config: { warnMs: 500 } })).toEqual({ name: "New", config: { warnMs: 500 } });
    expect(() => validatePatch("http", { config: { warnDays: 3 } })).toThrow(/Unknown field/);
    expect(() => validatePatch("http", { enabled: "yes" })).toThrow(/true or false/);
    expect(() => validatePatch("http", { warnMs: 5 })).toThrow(/Unknown field "warnMs"/);
  });
});
