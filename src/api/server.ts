/**
 * HTTP API and dashboard. Plain node:http, no framework.
 *
 *  - Everything except /healthz and the static dashboard files needs `Authorization: Bearer <token>`.
 *  - The token is compared in constant time, and repeated failures from one address are throttled.
 *  - Bodies are capped, JSON only, unknown fields rejected. No CORS headers are sent, and the
 *    dashboard is served with a strict Content-Security-Policy.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { type IncomingMessage, type Server, type ServerResponse, createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";

import type { Db } from "../db.js";
import type { Scheduler } from "../engine/scheduler.js";
import type { Clock } from "../types.js";
import { renderMetrics } from "./metrics.js";
import { ValidationError, validateNewMonitor, validatePatch } from "./validate.js";
import { UniqueViolation } from "../db.js";

export interface ApiDeps {
  db: Db;
  scheduler: Scheduler;
  clock: Clock;
  token: string;
  maxMonitors: number;
  publicDir: string;
  version: string;
  log?: (message: string) => void;
}

const MAX_BODY = 16 * 1024;
const FAIL_LIMIT = 10;
const FAIL_WINDOW_S = 60;

const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cross-origin-resource-policy": "same-origin",
  "cache-control": "no-store",
};
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const MIME: Record<string, string> = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

const digest = (value: string) => createHash("sha256").update(value).digest();

export function createApi(deps: ApiDeps): Server {
  const expected = digest(deps.token);
  const failures = new Map<string, { count: number; resetAt: number }>();
  const startedAt = deps.clock.now();
  const root = resolve(deps.publicDir);

  const authorize = (req: IncomingMessage): void => {
    const address = req.socket.remoteAddress ?? "unknown";
    const now = deps.clock.now();
    const record = failures.get(address);
    if (record && record.resetAt <= now) failures.delete(address);
    const current = failures.get(address);
    if (current && current.count >= FAIL_LIMIT) throw new HttpError(429, "Too many failed attempts; try again in a minute", { "retry-after": String(Math.max(1, current.resetAt - now)) });

    const header = req.headers.authorization ?? "";
    const match = /^Bearer (\S{1,512})$/.exec(header);
    if (match && timingSafeEqual(digest(match[1]!), expected)) return;

    const entry = current ?? { count: 0, resetAt: now + FAIL_WINDOW_S };
    entry.count++;
    failures.set(address, entry);
    if (failures.size > 10_000) failures.clear(); // bound memory under a spray of addresses
    throw new HttpError(401, "Missing or invalid bearer token", { "www-authenticate": 'Bearer realm="domainwatch"' });
  };

  const send = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
    const text = typeof body === "string" ? body : JSON.stringify(body);
    res.writeHead(status, { ...SECURITY_HEADERS, "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8", ...headers });
    res.end(text);
  };

  const readJson = async (req: IncomingMessage): Promise<unknown> => {
    if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) throw new HttpError(415, "Content-Type must be application/json");
    const declared = Number(req.headers["content-length"] ?? 0);
    if (declared > MAX_BODY) throw new HttpError(413, "Body too large");
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > MAX_BODY) throw new HttpError(413, "Body too large");
      chunks.push(chunk as Buffer);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      throw new HttpError(400, "Body is not valid JSON");
    }
  };

  const monitorOr404 = (raw: string | undefined) => {
    const id = Number(raw);
    const monitor = Number.isInteger(id) && id > 0 ? deps.db.getMonitor(id) : undefined;
    if (!monitor) throw new HttpError(404, "No such monitor");
    return monitor;
  };

  const limitParam = (url: URL, fallback: number, max: number) => {
    const raw = url.searchParams.get("limit");
    if (raw === null) return fallback;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > max) throw new HttpError(400, `limit must be an integer between 1 and ${max}`);
    return n;
  };

  async function serveStatic(pathname: string, res: ServerResponse): Promise<boolean> {
    const name = pathname === "/" ? "index.html" : pathname.slice(1);
    const file = normalize(join(root, name));
    if (!file.startsWith(root + sep) || !MIME[extname(file)]) return false;
    try {
      const body = await readFile(file);
      res.writeHead(200, { ...SECURITY_HEADERS, "content-type": MIME[extname(file)]!, "content-security-policy": CSP, "cache-control": "no-cache" });
      res.end(body);
      return true;
    } catch {
      return false;
    }
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const method = req.method ?? "GET";
    const path = url.pathname;

    if (path === "/healthz") {
      if (method !== "GET" && method !== "HEAD") throw new HttpError(405, "Method not allowed", { allow: "GET, HEAD" });
      return send(res, 200, { status: "ok", version: deps.version, monitors: deps.db.countMonitors() });
    }
    if (!path.startsWith("/api/") && path !== "/metrics") {
      if (method !== "GET" && method !== "HEAD") throw new HttpError(405, "Method not allowed", { allow: "GET, HEAD" });
      if (await serveStatic(path, res)) return;
      throw new HttpError(404, "Not found");
    }

    authorize(req);
    const now = deps.clock.now();

    if (path === "/metrics") {
      if (method !== "GET") throw new HttpError(405, "Method not allowed", { allow: "GET" });
      return send(res, 200, renderMetrics(deps.db.overview(now), { alertsStored: deps.db.countAlerts(), startedAt, now }), { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
    }

    const parts = path.split("/").filter(Boolean); // ["api", "monitors", "3", "run"]
    if (parts[1] === "summary" && parts.length === 2) {
      if (method !== "GET") throw new HttpError(405, "Method not allowed", { allow: "GET" });
      const overview = deps.db.overview(now);
      const count = (status: string) => overview.filter((o) => o.monitor.enabled && o.state?.status === status).length;
      return send(res, 200, {
        now,
        counts: { total: overview.length, ok: count("ok"), warn: count("warn"), fail: count("fail"), paused: overview.filter((o) => !o.monitor.enabled).length, pending: overview.filter((o) => o.monitor.enabled && !o.state).length },
        monitors: overview,
        alerts: deps.db.recentAlerts(20),
      });
    }
    if (parts[1] === "alerts" && parts.length === 2) {
      if (method !== "GET") throw new HttpError(405, "Method not allowed", { allow: "GET" });
      return send(res, 200, deps.db.recentAlerts(limitParam(url, 50, 200)));
    }
    if (parts[1] !== "monitors") throw new HttpError(404, "Not found");

    if (parts.length === 2) {
      if (method === "GET") return send(res, 200, deps.db.listMonitors());
      if (method === "POST") {
        const input = validateNewMonitor(await readJson(req));
        if (deps.db.countMonitors() >= deps.maxMonitors) throw new HttpError(409, `Monitor limit reached (${deps.maxMonitors})`);
        const monitor = deps.db.addMonitor(input, now);
        return send(res, 201, monitor, { location: `/api/monitors/${monitor.id}` });
      }
      throw new HttpError(405, "Method not allowed", { allow: "GET, POST" });
    }

    const monitor = monitorOr404(parts[2]);
    if (parts.length === 3) {
      if (method === "GET") return send(res, 200, { monitor, state: deps.db.getState(monitor.id), last: deps.db.lastResult(monitor.id) ?? null, uptime24h: deps.db.uptime(monitor.id, now - 86_400) });
      if (method === "PATCH") {
        const patch = validatePatch(monitor.kind, await readJson(req));
        return send(res, 200, deps.db.updateMonitor(monitor.id, patch));
      }
      if (method === "DELETE") {
        deps.db.deleteMonitor(monitor.id);
        res.writeHead(204, SECURITY_HEADERS);
        return void res.end();
      }
      throw new HttpError(405, "Method not allowed", { allow: "GET, PATCH, DELETE" });
    }
    if (parts.length === 4 && parts[3] === "results") {
      if (method !== "GET") throw new HttpError(405, "Method not allowed", { allow: "GET" });
      return send(res, 200, deps.db.recentResults(monitor.id, limitParam(url, 100, 1000)));
    }
    if (parts.length === 4 && parts[3] === "run") {
      if (method !== "POST") throw new HttpError(405, "Method not allowed", { allow: "POST" });
      if (deps.scheduler.isRunning(monitor.id)) throw new HttpError(409, "A check for this monitor is already running");
      return send(res, 200, await deps.scheduler.runMonitor(monitor));
    }
    throw new HttpError(404, "Not found");
  }

  const server = createServer((req, res) => {
    route(req, res).catch((error: unknown) => {
      if (res.headersSent) return void res.destroy();
      if (error instanceof HttpError) return send(res, error.status, { error: error.message }, error.headers);
      if (error instanceof ValidationError) return send(res, 400, { error: error.message });
      if (error instanceof UniqueViolation) return send(res, 409, { error: error.message });
      deps.log?.(`api error: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
      send(res, 500, { error: "Internal error" }); // details stay out of the response
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.on("clientError", (_error, socket) => socket.destroy());
  return server;
}
