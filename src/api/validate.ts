/**
 * Input validation for the API. Everything that arrives as JSON is `unknown` until it passes here;
 * unknown fields are rejected rather than ignored so a typo in a setting cannot silently do nothing.
 */

import { parseHostPort } from "../checks/deps.js";
import { PolicyError, normalizeHost } from "../net/policy.js";
import { KINDS, type Kind, type MonitorConfig } from "../types.js";

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export interface MonitorInput {
  name: string;
  kind: Kind;
  target: string;
  intervalS: number;
  config: MonitorConfig;
}

export const MIN_INTERVAL_S = 30;
export const MAX_INTERVAL_S = 86_400;
export const DEFAULT_INTERVALS: Record<Kind, number> = { tls: 21_600, http: 60, dns: 900, mail: 3600 };

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

function onlyKeys(value: Record<string, unknown>, allowed: string[], where: string): void {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new ValidationError(`Unknown field "${key.slice(0, 40)}" in ${where}`);
}

function integer(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) throw new ValidationError(`${name} must be an integer between ${min} and ${max}`);
  return value;
}

export function validateConfig(kind: Kind, raw: unknown): MonitorConfig {
  if (raw === undefined) return {};
  if (!isObject(raw)) throw new ValidationError("config must be an object");
  const allowed: Record<Kind, string[]> = {
    tls: ["warnDays", "failDays", "timeoutMs"],
    http: ["expectStatus", "warnMs", "timeoutMs"],
    dns: [],
    mail: [],
  };
  onlyKeys(raw, allowed[kind], `config for a ${kind} monitor`);
  const config: MonitorConfig = {};
  if (raw.warnDays !== undefined) config.warnDays = integer(raw.warnDays, "config.warnDays", 1, 365);
  if (raw.failDays !== undefined) config.failDays = integer(raw.failDays, "config.failDays", 0, 365);
  if (config.warnDays !== undefined && config.failDays !== undefined && config.failDays >= config.warnDays) throw new ValidationError("config.failDays must be smaller than config.warnDays");
  if (raw.warnMs !== undefined) config.warnMs = integer(raw.warnMs, "config.warnMs", 50, 60_000);
  if (raw.timeoutMs !== undefined) config.timeoutMs = integer(raw.timeoutMs, "config.timeoutMs", 1000, 30_000);
  if (raw.expectStatus !== undefined) {
    if (!Array.isArray(raw.expectStatus) || raw.expectStatus.length === 0 || raw.expectStatus.length > 20) throw new ValidationError("config.expectStatus must be a list of 1 to 20 status codes");
    config.expectStatus = [...new Set(raw.expectStatus.map((code) => integer(code, "config.expectStatus entries", 100, 599)))];
  }
  return config;
}

/** Validate and normalise a target for its kind. */
export function validateTarget(kind: Kind, raw: unknown): string {
  if (typeof raw !== "string" || raw.trim() === "" || raw.length > 2048) throw new ValidationError("target must be a non-empty string");
  const text = raw.trim();
  try {
    if (kind === "http") {
      const url = new URL(text);
      if (url.protocol !== "http:" && url.protocol !== "https:") throw new ValidationError("http targets must be http:// or https:// URLs");
      if (url.username || url.password) throw new ValidationError("URLs with embedded credentials are not supported");
      return url.href;
    }
    if (kind === "tls") {
      const { host, port } = parseHostPort(text, 443);
      const normalized = normalizeHost(host);
      return port === 443 ? normalized : normalized.includes(":") ? `[${normalized}]:${port}` : `${normalized}:${port}`;
    }
    return normalizeHost(text);
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    if (error instanceof PolicyError) throw new ValidationError(error.message);
    throw new ValidationError(kind === "http" ? "target is not a valid URL" : error instanceof Error ? error.message : "invalid target");
  }
}

function validateName(raw: unknown): string {
  if (typeof raw !== "string") throw new ValidationError("name must be a string");
  const name = raw.trim();
  // eslint-disable-next-line no-control-regex
  if (name.length < 1 || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) throw new ValidationError("name must be 1 to 80 characters, without control characters");
  return name;
}

export function validateNewMonitor(raw: unknown): MonitorInput {
  if (!isObject(raw)) throw new ValidationError("Body must be a JSON object");
  onlyKeys(raw, ["name", "kind", "target", "intervalS", "config"], "the monitor");
  if (typeof raw.kind !== "string" || !KINDS.includes(raw.kind as Kind)) throw new ValidationError(`kind must be one of: ${KINDS.join(", ")}`);
  const kind = raw.kind as Kind;
  const target = validateTarget(kind, raw.target);
  return {
    name: raw.name === undefined ? target.replace(/^https?:\/\//, "").replace(/\/$/, "").slice(0, 80) : validateName(raw.name),
    kind,
    target,
    intervalS: raw.intervalS === undefined ? DEFAULT_INTERVALS[kind] : integer(raw.intervalS, "intervalS", MIN_INTERVAL_S, MAX_INTERVAL_S),
    config: validateConfig(kind, raw.config),
  };
}

export interface MonitorPatch {
  name?: string;
  intervalS?: number;
  enabled?: boolean;
  config?: MonitorConfig;
}

/** PATCH accepts name, intervalS, enabled and config. The kind and target are fixed at creation. */
export function validatePatch(kind: Kind, raw: unknown): MonitorPatch {
  if (!isObject(raw)) throw new ValidationError("Body must be a JSON object");
  if ("kind" in raw || "target" in raw) throw new ValidationError("kind and target cannot be changed; create a new monitor instead");
  onlyKeys(raw, ["name", "intervalS", "enabled", "config"], "the update");
  const patch: MonitorPatch = {};
  if (raw.name !== undefined) patch.name = validateName(raw.name);
  if (raw.intervalS !== undefined) patch.intervalS = integer(raw.intervalS, "intervalS", MIN_INTERVAL_S, MAX_INTERVAL_S);
  if (raw.enabled !== undefined) {
    if (typeof raw.enabled !== "boolean") throw new ValidationError("enabled must be true or false");
    patch.enabled = raw.enabled;
  }
  if (raw.config !== undefined) patch.config = validateConfig(kind, raw.config);
  if (Object.keys(patch).length === 0) throw new ValidationError("Nothing to update");
  return patch;
}
