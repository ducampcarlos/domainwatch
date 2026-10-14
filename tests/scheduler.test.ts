import { afterEach, describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { Scheduler } from "../src/engine/scheduler.js";
import type { Alert, Monitor, Observation } from "../src/types.js";

const open: Db[] = [];
afterEach(() => open.splice(0).forEach((d) => d.close()));

function setup(options: { observe?: (m: Monitor, call: number) => Promise<Observation> | Observation; notify?: (a: Alert) => Promise<boolean>; concurrency?: number } = {}) {
  const db = new Db(":memory:");
  open.push(db);
  const clock = { t: 10_000, now() { return this.t; } };
  const calls: number[] = [];
  const delivered: Alert[] = [];
  const scheduler = new Scheduler({
    db,
    clock,
    concurrency: options.concurrency,
    runCheck: async (m) => {
      calls.push(m.id);
      return options.observe ? options.observe(m, calls.length) : { metrics: { status_code: 200 }, detail: { statusCode: 200 } };
    },
    notify: async (a) => {
      delivered.push(a);
      return options.notify ? options.notify(a) : true;
    },
  });
  const add = (name: string, intervalS = 60) => db.addMonitor({ name, kind: "http", target: `https://${name}.test/`, intervalS, config: {} }, clock.t);
  return { db, clock, scheduler, calls, delivered, add };
}

describe("scheduler", () => {
  it("runs due monitors once and respects the interval", async () => {
    const { scheduler, clock, calls, add } = setup();
    add("a");
    expect(await scheduler.tick()).toBe(1);
    expect(await scheduler.tick()).toBe(0);
    clock.t += 59;
    expect(await scheduler.tick()).toBe(0);
    clock.t += 1;
    expect(await scheduler.tick()).toBe(1);
    expect(calls).toHaveLength(2);
  });

  it("stores results and state", async () => {
    const { scheduler, db, add } = setup();
    const m = add("a");
    await scheduler.tick();
    expect(db.lastResult(m.id)).toMatchObject({ status: "ok", summary: expect.stringContaining("HTTP 200") });
    expect(db.getState(m.id)).toMatchObject({ status: "ok", failures: 0 });
  });

  it("alerts on the second consecutive failure and delivers it", async () => {
    const { scheduler, clock, db, delivered, add } = setup({ observe: () => ({ error: "connection refused", metrics: {}, detail: {} }) });
    const m = add("a");
    await scheduler.tick();
    expect(delivered).toEqual([]);
    clock.t += 60;
    await scheduler.tick();
    expect(delivered).toHaveLength(1);
    expect(delivered[0]).toMatchObject({ kind: "down", monitorId: m.id });
    expect(db.recentAlerts(10)[0]).toMatchObject({ kind: "down", delivered: true, monitorName: "a" });
  });

  it("keeps an alert as undelivered when every receiver failed, and when notify throws", async () => {
    const { scheduler, clock, db, add } = setup({ observe: () => ({ error: "boom", metrics: {}, detail: {} }), notify: async () => { throw new Error("hook down"); } });
    add("a");
    await scheduler.tick();
    clock.t += 60;
    await scheduler.tick();
    expect(db.recentAlerts(10)[0]).toMatchObject({ kind: "down", delivered: false });
  });

  it("turns a crashing check into a failed result instead of stopping the scheduler", async () => {
    const { scheduler, db, add } = setup({ observe: () => { throw new Error("kaboom"); } });
    const m = add("a");
    await scheduler.tick();
    expect(db.lastResult(m.id)).toMatchObject({ status: "fail" });
    expect(db.lastResult(m.id)!.summary).toContain("kaboom");
  });

  it("never exceeds the concurrency limit and never starts a slow monitor twice", async () => {
    let active = 0;
    let peak = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { scheduler, calls, add } = setup({
      concurrency: 2,
      observe: async () => {
        active++;
        peak = Math.max(peak, active);
        await gate;
        active--;
        return { metrics: {}, detail: { statusCode: 200 } };
      },
    });
    for (const n of ["a", "b", "c", "d"]) add(n);
    const first = scheduler.tick();
    await new Promise((r) => setTimeout(r, 10));
    expect(await scheduler.tick()).toBe(0); // both slots are busy
    release();
    expect(await first).toBe(2);
    expect(peak).toBe(2);
    expect(await scheduler.tick()).toBe(2); // the other two
    expect(new Set(calls).size).toBe(4);
  });

  it("skips disabled monitors", async () => {
    const { scheduler, db, calls, add } = setup();
    const m = add("a");
    db.updateMonitor(m.id, { enabled: false });
    expect(await scheduler.tick()).toBe(0);
    expect(calls).toEqual([]);
  });

  it("prunes old results about once an hour", async () => {
    const { scheduler, clock, db, add } = setup();
    const m = add("a", 60);
    db.insertResult(m.id, clock.t - 40 * 86_400, { status: "ok", summary: "ancient", metrics: {}, detail: {} });
    await scheduler.tick();
    expect(db.recentResults(m.id, 10).map((r) => r.summary)).not.toContain("ancient");
  });

  it("start() staggers monitors that never ran, and stop() is idempotent", async () => {
    const { scheduler, db, add } = setup();
    for (const n of ["a", "b", "c"]) add(n);
    scheduler.start(20);
    scheduler.start(20);
    await new Promise((r) => setTimeout(r, 80));
    scheduler.stop();
    scheduler.stop();
    expect(db.dueMonitors(10_000, 10).length).toBeLessThanOrEqual(3);
  });
});
