/**
 * The scheduler: runs the checks that are due, records the results, applies the alert rules and
 * sends the notifications. `tick()` does one pass and awaits it, so tests drive it with a fake clock.
 */

import type { Db } from "../db.js";
import { type AlertRules, DEFAULT_RULES, advance } from "./alerts.js";
import { evaluate } from "./evaluate.js";
import type { Alert, CheckResult, Clock, Monitor, Observation } from "../types.js";

export interface SchedulerDeps {
  db: Db;
  clock: Clock;
  runCheck: (monitor: Monitor) => Promise<Observation>;
  /** Deliver an alert. Resolves true when at least one receiver accepted it. */
  notify: (alert: Alert, monitor: Monitor) => Promise<boolean>;
  concurrency?: number;
  retentionDays?: number;
  rules?: AlertRules;
  log?: (message: string) => void;
}

const PRUNE_EVERY_S = 3600;
const STARTUP_SPREAD_S = 30;

export class Scheduler {
  private readonly running = new Set<number>();
  private timer: NodeJS.Timeout | undefined;
  private lastPrune = 0;
  private readonly concurrency: number;
  private readonly rules: AlertRules;

  constructor(private readonly deps: SchedulerDeps) {
    this.concurrency = deps.concurrency ?? 4;
    this.rules = deps.rules ?? DEFAULT_RULES;
  }

  /** Check one monitor now: observe, judge, store, alert. Used by the schedule and by "run now". */
  async runMonitor(monitor: Monitor): Promise<CheckResult> {
    const { db, clock } = this.deps;
    this.running.add(monitor.id);
    try {
      const observation = await this.deps.runCheck(monitor).catch(
        (error): Observation => ({ error: `Unexpected error: ${error instanceof Error ? error.message.slice(0, 150) : String(error)}`, metrics: {}, detail: {} }),
      );
      const now = clock.now();
      const previous = db.getState(monitor.id);
      const { verdict, baseline } = evaluate(monitor, observation, previous?.baseline ?? null);
      const result = db.insertResult(monitor.id, now, verdict);
      const transition = advance(previous, monitor, verdict, now, baseline, this.rules);
      db.saveState(transition.state);

      for (const pending of transition.alerts) {
        const alert = db.insertAlert(monitor.id, now, pending.kind, pending.message);
        this.deps.log?.(pending.message);
        const delivered = await this.deps.notify(alert, monitor).catch(() => false);
        if (delivered) db.markDelivered(alert.id);
      }
      return result;
    } finally {
      this.running.delete(monitor.id);
      db.setNextRun(monitor.id, clock.now() + monitor.intervalS);
    }
  }

  /** One pass: run every due monitor (up to the concurrency limit) and wait for them. Returns how many ran. */
  async tick(): Promise<number> {
    const { db, clock } = this.deps;
    const now = clock.now();
    if (now - this.lastPrune >= PRUNE_EVERY_S) {
      this.lastPrune = now;
      db.prune(now - (this.deps.retentionDays ?? 30) * 86_400);
    }
    const slots = this.concurrency - this.running.size;
    if (slots <= 0) return 0;
    const due = db.dueMonitors(now, slots + this.running.size).filter((m) => !this.running.has(m.id)).slice(0, slots);
    for (const monitor of due) db.setNextRun(monitor.id, now + monitor.intervalS); // claim it before running, so a slow check is not started twice
    await Promise.all(due.map((monitor) => this.runMonitor(monitor)));
    return due.length;
  }

  isRunning(id: number): boolean {
    return this.running.has(id);
  }

  start(everyMs = 1000): void {
    if (this.timer) return;
    this.deps.db.staggerNeverRun(this.deps.clock.now(), STARTUP_SPREAD_S);
    let busy = false;
    this.timer = setInterval(() => {
      if (busy) return; // never overlap passes
      busy = true;
      this.tick()
        .catch((error) => this.deps.log?.(`scheduler error: ${error instanceof Error ? error.message : String(error)}`))
        .finally(() => (busy = false));
    }, everyMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }
}
