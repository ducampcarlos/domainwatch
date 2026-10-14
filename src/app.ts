/** Wiring: builds the database, scheduler and API from a Config. Used by the CLI and by tests. */

import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import { join } from "node:path";

import { createApi } from "./api/server.js";
import { runCheck } from "./checks/index.js";
import type { CheckDeps } from "./checks/deps.js";
import type { Config } from "./config.js";
import { Db } from "./db.js";
import { Scheduler } from "./engine/scheduler.js";
import { SystemDnsClient } from "./net/dns.js";
import { TargetPolicy } from "./net/policy.js";
import { buildPayload, sendWebhook } from "./notify/webhook.js";
import { type Clock, systemClock } from "./types.js";

export const VERSION: string = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;
export const PUBLIC_DIR = new URL("../public", import.meta.url).pathname;

export interface App {
  server: Server;
  scheduler: Scheduler;
  db: Db;
  close(): Promise<void>;
}

export interface AppOptions {
  clock?: Clock;
  checkDeps?: CheckDeps;
  log?: (message: string) => void;
  dbPath?: string;
  publicDir?: string;
}

export function productionDeps(config: Pick<Config, "allowPrivate">): CheckDeps {
  return { policy: new TargetPolicy(config.allowPrivate), dns: new SystemDnsClient() };
}

export function buildApp(config: Config, options: AppOptions = {}): App {
  const clock = options.clock ?? systemClock;
  const log = options.log ?? ((message: string) => console.log(`${new Date().toISOString()} ${message}`));
  let dbPath = options.dbPath;
  if (!dbPath) {
    mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
    try {
      chmodSync(config.dataDir, 0o700);
    } catch {
      /* not ours to change (a mounted volume): carry on */
    }
    dbPath = join(config.dataDir, "domainwatch.db");
  }
  const db = new Db(dbPath);
  const checkDeps = options.checkDeps ?? productionDeps(config);

  const scheduler = new Scheduler({
    db,
    clock,
    concurrency: config.concurrency,
    retentionDays: config.retentionDays,
    log,
    runCheck: (monitor) => runCheck(checkDeps, monitor),
    notify: async (alert, monitor) => {
      if (config.webhooks.length === 0) return false;
      const payload = buildPayload(alert, monitor);
      const outcomes = await Promise.all(config.webhooks.map((url) => sendWebhook(url, payload)));
      return outcomes.some(Boolean);
    },
  });
  const server = createApi({ db, scheduler, clock, token: config.token, maxMonitors: config.maxMonitors, publicDir: options.publicDir ?? PUBLIC_DIR, version: VERSION, log });

  return {
    server,
    scheduler,
    db,
    close: async () => {
      scheduler.stop();
      server.closeIdleConnections();
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          server.closeAllConnections();
          resolve();
        }, 3000);
        server.close(() => {
          clearTimeout(timer);
          resolve();
        });
      });
      db.close();
    },
  };
}
