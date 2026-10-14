import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { Db, UniqueViolation } from "../src/db.js";
import { verdict } from "./helpers.js";

const open: Db[] = [];
const fresh = () => {
  const db = new Db(":memory:");
  open.push(db);
  return db;
};
afterEach(() => open.splice(0).forEach((d) => d.close()));

const add = (db: Db, overrides: Partial<Parameters<Db["addMonitor"]>[0]> = {}, now = 1000) =>
  db.addMonitor({ name: "Site", kind: "http", target: "https://x.test/", intervalS: 60, config: {}, ...overrides }, now);

describe("monitors", () => {
  it("adds, reads, lists and counts", () => {
    const db = fresh();
    const a = add(db, { name: "Beta", target: "https://b.test/" });
    add(db, { name: "alpha", target: "https://a.test/", config: { warnMs: 500 } });
    expect(a).toMatchObject({ id: 1, name: "Beta", kind: "http", intervalS: 60, enabled: true, createdAt: 1000 });
    expect(db.getMonitor(2)!.config).toEqual({ warnMs: 500 });
    expect(db.listMonitors().map((m) => m.name)).toEqual(["alpha", "Beta"]); // case-insensitive order
    expect(db.countMonitors()).toBe(2);
    expect(db.getMonitor(99)).toBeUndefined();
  });

  it("refuses the same target twice for the same kind, but allows other kinds", () => {
    const db = fresh();
    add(db, { kind: "dns", target: "x.test" });
    expect(() => add(db, { kind: "dns", target: "x.test", name: "again" })).toThrow(UniqueViolation);
    expect(() => add(db, { kind: "mail", target: "x.test" })).not.toThrow();
  });

  it("rejects values the schema forbids", () => {
    const db = fresh();
    expect(() => add(db, { intervalS: 5 })).toThrow();
    expect(() => add(db, { intervalS: 100_000, target: "https://y.test/" })).toThrow();
  });

  it("updates selected fields and makes the monitor due again", () => {
    const db = fresh();
    const m = add(db);
    db.setNextRun(m.id, 9999);
    const updated = db.updateMonitor(m.id, { name: "Renamed", enabled: false, intervalS: 120, config: { warnMs: 1 } })!;
    expect(updated).toMatchObject({ name: "Renamed", enabled: false, intervalS: 120, config: { warnMs: 1 }, target: "https://x.test/" });
    expect(db.dueMonitors(0, 10)).toEqual([]); // disabled monitors are never due
    db.updateMonitor(m.id, { enabled: true });
    expect(db.dueMonitors(0, 10).map((x) => x.id)).toEqual([m.id]); // next_run was reset
    expect(db.updateMonitor(404, { name: "x" })).toBeUndefined();
  });

  it("deletes a monitor together with its results, state and alerts", () => {
    const db = fresh();
    const m = add(db);
    db.insertResult(m.id, 1, verdict("ok"));
    db.saveState({ monitorId: m.id, status: "ok", failures: 0, since: 1, lastAlertTs: 0, baseline: null });
    db.insertAlert(m.id, 1, "down", "x");
    expect(db.deleteMonitor(m.id)).toBe(true);
    expect(db.recentResults(m.id, 10)).toEqual([]);
    expect(db.getState(m.id)).toBeNull();
    expect(db.recentAlerts(10)).toEqual([]);
    expect(db.deleteMonitor(m.id)).toBe(false);
  });
});

describe("scheduling queries", () => {
  it("returns due monitors oldest first and respects the limit", () => {
    const db = fresh();
    const [a, b, c] = ["a", "b", "c"].map((n) => add(db, { name: n, target: `https://${n}.test/` }));
    db.setNextRun(a!.id, 300);
    db.setNextRun(b!.id, 100);
    db.setNextRun(c!.id, 200);
    expect(db.dueMonitors(250, 10).map((m) => m.name)).toEqual(["b", "c"]);
    expect(db.dueMonitors(500, 2).map((m) => m.name)).toEqual(["b", "c"]);
  });

  it("staggers monitors that never ran across the spread, leaving others alone", () => {
    const db = fresh();
    const ms = Array.from({ length: 4 }, (_, i) => add(db, { name: `m${i}`, target: `https://m${i}.test/` }));
    db.setNextRun(ms[3]!.id, 5000);
    db.staggerNeverRun(1000, 30);
    expect(db.dueMonitors(1000, 10).map((m) => m.name)).toEqual(["m0"]);
    expect(db.dueMonitors(1010, 10).map((m) => m.name)).toEqual(["m0", "m1"]);
    expect(db.dueMonitors(1029, 10).map((m) => m.name)).toEqual(["m0", "m1", "m2"]);
    expect(db.listMonitors().find((m) => m.name === "m3")).toBeDefined();
    expect(db.dueMonitors(4999, 10).some((m) => m.name === "m3")).toBe(false); // untouched
    expect(db.dueMonitors(5000, 10).some((m) => m.name === "m3")).toBe(true);
  });
});

describe("results, state and alerts", () => {
  it("stores results with metrics and detail, newest first", () => {
    const db = fresh();
    const m = add(db);
    db.insertResult(m.id, 10, { status: "ok", summary: "first", latencyMs: 12.5, metrics: { up: 1 }, detail: { a: 1 } });
    db.insertResult(m.id, 20, { status: "fail", summary: "second", metrics: { up: 0 }, detail: {} });
    const results = db.recentResults(m.id, 10);
    expect(results.map((r) => r.summary)).toEqual(["second", "first"]);
    expect(results[1]).toMatchObject({ latencyMs: 12.5, metrics: { up: 1 }, detail: { a: 1 }, monitorId: m.id });
    expect(results[0]!.latencyMs).toBeUndefined();
    expect(db.lastResult(m.id)!.summary).toBe("second");
    expect(db.recentResults(m.id, 1)).toHaveLength(1);
  });

  it("round-trips and updates state", () => {
    const db = fresh();
    const m = add(db);
    expect(db.getState(m.id)).toBeNull();
    const state = { monitorId: m.id, status: "warn" as const, failures: 0, since: 5, lastAlertTs: 6, baseline: '{"A":["1.1.1.1"]}' };
    db.saveState(state);
    expect(db.getState(m.id)).toEqual(state);
    db.saveState({ ...state, status: "fail", failures: 3, baseline: null });
    expect(db.getState(m.id)).toMatchObject({ status: "fail", failures: 3, baseline: null });
  });

  it("prunes old results and alerts, keeping recent ones", () => {
    const db = fresh();
    const m = add(db);
    for (const ts of [100, 200, 300]) db.insertResult(m.id, ts, verdict("ok"));
    db.insertAlert(m.id, 100, "down", "old");
    db.insertAlert(m.id, 300, "recovered", "new");
    expect(db.prune(250)).toBe(3);
    expect(db.recentResults(m.id, 10).map((r) => r.ts)).toEqual([300]);
    expect(db.recentAlerts(10).map((a) => a.message)).toEqual(["new"]);
  });

  it("tracks alert delivery", () => {
    const db = fresh();
    const m = add(db);
    const alert = db.insertAlert(m.id, 1, "down", "x");
    expect(db.recentAlerts(5)[0]).toMatchObject({ delivered: false, monitorName: "Site" });
    db.markDelivered(alert.id);
    expect(db.recentAlerts(5)[0]!.delivered).toBe(true);
  });

  it("computes uptime, counting warnings as up", () => {
    const db = fresh();
    const m = add(db);
    expect(db.uptime(m.id, 0)).toBeNull();
    for (const [ts, status] of [[1, "ok"], [2, "warn"], [3, "fail"], [4, "ok"]] as const) db.insertResult(m.id, ts, verdict(status));
    expect(db.uptime(m.id, 0)).toBe(75);
    expect(db.uptime(m.id, 3)).toBe(50);
    expect(db.uptime(m.id, 100)).toBeNull();
  });

  it("builds the overview for the dashboard", () => {
    const db = fresh();
    const m = add(db);
    db.insertResult(m.id, 90_000, verdict("ok"));
    db.saveState({ monitorId: m.id, status: "ok", failures: 0, since: 90_000, lastAlertTs: 0, baseline: null });
    const [row] = db.overview(100_000);
    expect(row).toMatchObject({ monitor: { id: m.id }, state: { status: "ok" }, last: { summary: "ok" }, uptime24h: 100 });
    expect(db.overview(10_000_000)[0]!.uptime24h).toBeNull();
  });
});

describe("persistence", () => {
  it("survives a reopen and refuses a database from the future", () => {
    const dir = mkdtempSync(join(tmpdir(), "dw-db-"));
    try {
      const path = join(dir, "nested", "dw.sqlite");
      const first = new Db(path);
      add(first);
      first.close();
      const second = new Db(path);
      expect(second.listMonitors()).toHaveLength(1);
      second.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
