/** Shared types. */

export type Kind = "tls" | "http" | "dns" | "mail";
export const KINDS: readonly Kind[] = ["tls", "http", "dns", "mail"];

export type Status = "ok" | "warn" | "fail";

/** Per-kind options. Every field is optional; defaults live in `defaultsFor`. */
export interface MonitorConfig {
  /** tls: warn when the certificate expires within this many days. */
  warnDays?: number;
  /** tls: fail when it expires within this many days. */
  failDays?: number;
  /** http: status codes (after redirects) that count as healthy. Default 200-399. */
  expectStatus?: number[];
  /** http: warn when the response takes longer than this. */
  warnMs?: number;
  /** All network kinds: give up after this long. */
  timeoutMs?: number;
}

export interface Monitor {
  id: number;
  name: string;
  kind: Kind;
  /** tls: "host" or "host:port". http: a URL. dns and mail: a domain. */
  target: string;
  intervalS: number;
  enabled: boolean;
  config: MonitorConfig;
  createdAt: number;
}

/** What a check observed, before any judgement. */
export interface Observation {
  /** The check could not even complete (connection refused, DNS failure, timeout...). */
  error?: string;
  latencyMs?: number;
  /** Numeric facts exported as metrics (days_remaining, status_code, ...). */
  metrics: Record<string, number>;
  /** Everything else worth showing. Never contains secrets or response bodies. */
  detail: Record<string, unknown>;
}

export interface Verdict {
  status: Status;
  summary: string;
  latencyMs?: number;
  metrics: Record<string, number>;
  detail: Record<string, unknown>;
}

export interface CheckResult extends Verdict {
  id: number;
  monitorId: number;
  ts: number;
}

export type AlertKind = "down" | "recovered" | "warning" | "still_down";

export interface Alert {
  id: number;
  monitorId: number;
  ts: number;
  kind: AlertKind;
  message: string;
  delivered: boolean;
}

/** Per-monitor alerting state, persisted so restarts do not re-alert or forget an outage. */
export interface MonitorState {
  monitorId: number;
  /** The status the monitor is considered to be in (after the failure threshold). */
  status: Status;
  /** Consecutive failing checks. */
  failures: number;
  /** When the current status began (epoch seconds). */
  since: number;
  lastAlertTs: number;
  /** DNS: hash of the accepted baseline snapshot. */
  baseline: string | null;
}

export interface Clock {
  /** Epoch seconds. */
  now(): number;
}

export const systemClock: Clock = { now: () => Math.floor(Date.now() / 1000) };
