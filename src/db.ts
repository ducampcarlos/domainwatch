/** SQLite storage (the `node:sqlite` built-in, so there is no native module to compile). */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { Alert, AlertKind, CheckResult, Kind, Monitor, MonitorConfig, MonitorState, Status, Verdict } from "./types.js";

// node:sqlite prints an ExperimentalWarning on import in current Node versions. It is stable enough
// for this use, and a warning on every start is noise, so that one message is silenced.
const originalEmitWarning = process.emitWarning;
process.emitWarning = ((warning: string | Error, ...args: unknown[]) => {
  const text = typeof warning === "string" ? warning : warning.message;
  if (/sqlite/i.test(text)) return;
  return (originalEmitWarning as (...a: unknown[]) => void).call(process, warning, ...args);
}) as typeof process.emitWarning;
const { DatabaseSync } = await import("node:sqlite");
process.emitWarning = originalEmitWarning;

type Row = Record<string, unknown>;

const SCHEMA_VERSION = 1;

const MIGRATIONS: Record<number, string> = {
  1: `
    CREATE TABLE monitors (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('tls','http','dns','mail')),
      target TEXT NOT NULL,
      interval_s INTEGER NOT NULL CHECK (interval_s BETWEEN 30 AND 86400),
      enabled INTEGER NOT NULL DEFAULT 1,
      config TEXT NOT NULL DEFAULT '{}',
      created_at INTEGER NOT NULL,
      next_run INTEGER NOT NULL DEFAULT 0,
      UNIQUE (kind, target)
    );
    CREATE TABLE results (
      id INTEGER PRIMARY KEY,
      monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
      ts INTEGER NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('ok','warn','fail')),
      summary TEXT NOT NULL,
      latency_ms REAL,
      metrics TEXT NOT NULL,
      detail TEXT NOT NULL
    );
    CREATE INDEX results_monitor_ts ON results (monitor_id, ts DESC);
    CREATE INDEX results_ts ON results (ts);
    CREATE TABLE state (
      monitor_id INTEGER PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,
      status TEXT NOT NULL,
      failures INTEGER NOT NULL,
      since INTEGER NOT NULL,
      last_alert_ts INTEGER NOT NULL,
      baseline TEXT
    );
    CREATE TABLE alerts (
      id INTEGER PRIMARY KEY,
      monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
      ts INTEGER NOT NULL,
      kind TEXT NOT NULL,
      message TEXT NOT NULL,
      delivered INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX alerts_ts ON alerts (ts DESC);
  `,
};

const json = <T>(text: unknown, fallback: T): T => {
  try {
    return JSON.parse(String(text)) as T;
  } catch {
    return fallback;
  }
};

const toMonitor = (row: Row): Monitor => ({
  id: Number(row.id),
  name: String(row.name),
  kind: row.kind as Kind,
  target: String(row.target),
  intervalS: Number(row.interval_s),
  enabled: Number(row.enabled) === 1,
  config: json<MonitorConfig>(row.config, {}),
  createdAt: Number(row.created_at),
});

const toResult = (row: Row): CheckResult => ({
  id: Number(row.id),
  monitorId: Number(row.monitor_id),
  ts: Number(row.ts),
  status: row.status as Status,
  summary: String(row.summary),
  latencyMs: row.latency_ms === null || row.latency_ms === undefined ? undefined : Number(row.latency_ms),
  metrics: json<Record<string, number>>(row.metrics, {}),
  detail: json<Record<string, unknown>>(row.detail, {}),
});

export interface NewMonitor {
  name: string;
  kind: Kind;
  target: string;
  intervalS: number;
  config: MonitorConfig;
  enabled?: boolean;
}

export interface MonitorOverview {
  monitor: Monitor;
  state: MonitorState | null;
  last: CheckResult | null;
  /** Share of the last 24 hours' checks that were not failing, 0-100, or null with no data. */
  uptime24h: number | null;
}

export class UniqueViolation extends Error {
  constructor() {
    super("A monitor of this kind already watches that target");
    this.name = "UniqueViolation";
  }
}

export class Db {
  private readonly db: InstanceType<typeof DatabaseSync>;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;");
    this.migrate();
  }

  private migrate(): void {
    const current = Number((this.db.prepare("PRAGMA user_version").get() as Row).user_version);
    if (current > SCHEMA_VERSION) throw new Error(`The database was written by a newer version of domainwatch (schema ${current}, this build understands ${SCHEMA_VERSION})`);
    for (let version = current + 1; version <= SCHEMA_VERSION; version++) {
      this.db.exec("BEGIN");
      try {
        this.db.exec(MIGRATIONS[version]!);
        this.db.exec(`PRAGMA user_version = ${version}`);
        this.db.exec("COMMIT");
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw error;
      }
    }
  }

  close(): void {
    this.db.close();
  }

  // ---- monitors ------------------------------------------------------------------------------

  addMonitor(input: NewMonitor, now: number): Monitor {
    try {
      const result = this.db
        .prepare("INSERT INTO monitors (name, kind, target, interval_s, enabled, config, created_at, next_run) VALUES (?, ?, ?, ?, ?, ?, ?, 0)")
        .run(input.name, input.kind, input.target, input.intervalS, input.enabled === false ? 0 : 1, JSON.stringify(input.config), now);
      return this.getMonitor(Number(result.lastInsertRowid))!;
    } catch (error) {
      if (/UNIQUE constraint failed/i.test((error as Error).message)) throw new UniqueViolation();
      throw error;
    }
  }

  getMonitor(id: number): Monitor | undefined {
    const row = this.db.prepare("SELECT * FROM monitors WHERE id = ?").get(id) as Row | undefined;
    return row ? toMonitor(row) : undefined;
  }

  listMonitors(): Monitor[] {
    return (this.db.prepare("SELECT * FROM monitors ORDER BY name COLLATE NOCASE, id").all() as Row[]).map(toMonitor);
  }

  countMonitors(): number {
    return Number((this.db.prepare("SELECT COUNT(*) AS n FROM monitors").get() as Row).n);
  }

  updateMonitor(id: number, patch: Partial<Pick<Monitor, "name" | "intervalS" | "enabled" | "config">>): Monitor | undefined {
    const current = this.getMonitor(id);
    if (!current) return undefined;
    const next = { ...current, ...patch };
    this.db
      .prepare("UPDATE monitors SET name = ?, interval_s = ?, enabled = ?, config = ?, next_run = 0 WHERE id = ?")
      .run(next.name, next.intervalS, next.enabled ? 1 : 0, JSON.stringify(next.config), id);
    return this.getMonitor(id);
  }

  deleteMonitor(id: number): boolean {
    return Number(this.db.prepare("DELETE FROM monitors WHERE id = ?").run(id).changes) > 0;
  }

  /** Enabled monitors whose next run is due, oldest due first. */
  dueMonitors(now: number, limit: number): Monitor[] {
    return (this.db.prepare("SELECT * FROM monitors WHERE enabled = 1 AND next_run <= ? ORDER BY next_run, id LIMIT ?").all(now, limit) as Row[]).map(toMonitor);
  }

  setNextRun(id: number, ts: number): void {
    this.db.prepare("UPDATE monitors SET next_run = ? WHERE id = ?").run(ts, id);
  }

  /** Spread the first runs of monitors that have never run, so a restart does not fire everything at once. */
  staggerNeverRun(now: number, spreadS: number): void {
    const rows = this.db.prepare("SELECT id FROM monitors WHERE next_run = 0 ORDER BY id").all() as Row[];
    const update = this.db.prepare("UPDATE monitors SET next_run = ? WHERE id = ?");
    rows.forEach((row, index) => update.run(now + Math.floor((index * spreadS) / Math.max(1, rows.length)), Number(row.id)));
  }

  // ---- results -------------------------------------------------------------------------------

  insertResult(monitorId: number, ts: number, verdict: Verdict): CheckResult {
    const result = this.db
      .prepare("INSERT INTO results (monitor_id, ts, status, summary, latency_ms, metrics, detail) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(monitorId, ts, verdict.status, verdict.summary, verdict.latencyMs ?? null, JSON.stringify(verdict.metrics), JSON.stringify(verdict.detail));
    return { ...verdict, id: Number(result.lastInsertRowid), monitorId, ts };
  }

  recentResults(monitorId: number, limit: number): CheckResult[] {
    return (this.db.prepare("SELECT * FROM results WHERE monitor_id = ? ORDER BY ts DESC, id DESC LIMIT ?").all(monitorId, limit) as Row[]).map(toResult);
  }

  lastResult(monitorId: number): CheckResult | undefined {
    return this.recentResults(monitorId, 1)[0];
  }

  /** Delete results older than `olderThan` (epoch seconds). Returns how many were removed. */
  prune(olderThan: number): number {
    const results = Number(this.db.prepare("DELETE FROM results WHERE ts < ?").run(olderThan).changes);
    const alerts = Number(this.db.prepare("DELETE FROM alerts WHERE ts < ?").run(olderThan).changes);
    return results + alerts;
  }

  uptime(monitorId: number, since: number): number | null {
    const row = this.db
      .prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'fail' THEN 0 ELSE 1 END) AS up FROM results WHERE monitor_id = ? AND ts >= ?")
      .get(monitorId, since) as Row;
    const total = Number(row.total);
    return total === 0 ? null : Math.round((Number(row.up) / total) * 1000) / 10;
  }

  // ---- state ---------------------------------------------------------------------------------

  getState(monitorId: number): MonitorState | null {
    const row = this.db.prepare("SELECT * FROM state WHERE monitor_id = ?").get(monitorId) as Row | undefined;
    if (!row) return null;
    return {
      monitorId,
      status: row.status as Status,
      failures: Number(row.failures),
      since: Number(row.since),
      lastAlertTs: Number(row.last_alert_ts),
      baseline: row.baseline === null ? null : String(row.baseline),
    };
  }

  saveState(state: MonitorState): void {
    this.db
      .prepare(
        `INSERT INTO state (monitor_id, status, failures, since, last_alert_ts, baseline) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(monitor_id) DO UPDATE SET status = excluded.status, failures = excluded.failures, since = excluded.since,
           last_alert_ts = excluded.last_alert_ts, baseline = excluded.baseline`,
      )
      .run(state.monitorId, state.status, state.failures, state.since, state.lastAlertTs, state.baseline);
  }

  // ---- alerts --------------------------------------------------------------------------------

  insertAlert(monitorId: number, ts: number, kind: AlertKind, message: string): Alert {
    const result = this.db.prepare("INSERT INTO alerts (monitor_id, ts, kind, message) VALUES (?, ?, ?, ?)").run(monitorId, ts, kind, message);
    return { id: Number(result.lastInsertRowid), monitorId, ts, kind, message, delivered: false };
  }

  markDelivered(id: number): void {
    this.db.prepare("UPDATE alerts SET delivered = 1 WHERE id = ?").run(id);
  }

  countAlerts(): number {
    return Number((this.db.prepare("SELECT COUNT(*) AS n FROM alerts").get() as Row).n);
  }

  recentAlerts(limit: number): Array<Alert & { monitorName: string }> {
    const rows = this.db
      .prepare("SELECT a.*, m.name AS monitor_name FROM alerts a JOIN monitors m ON m.id = a.monitor_id ORDER BY a.ts DESC, a.id DESC LIMIT ?")
      .all(limit) as Row[];
    return rows.map((row) => ({
      id: Number(row.id),
      monitorId: Number(row.monitor_id),
      ts: Number(row.ts),
      kind: row.kind as AlertKind,
      message: String(row.message),
      delivered: Number(row.delivered) === 1,
      monitorName: String(row.monitor_name),
    }));
  }

  // ---- overview ------------------------------------------------------------------------------

  overview(now: number): MonitorOverview[] {
    return this.listMonitors().map((monitor) => ({
      monitor,
      state: this.getState(monitor.id),
      last: this.lastResult(monitor.id) ?? null,
      uptime24h: this.uptime(monitor.id, now - 86_400),
    }));
  }
}
