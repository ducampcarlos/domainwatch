/**
 * Judgement: turn what a check OBSERVED into a verdict (ok, warn or fail) with a summary a human
 * can act on. Pure functions of the observation, the monitor's settings and, for DNS, the last
 * accepted snapshot, so every rule is unit-tested without any network.
 */

import { type Snapshot, canonical, diffSnapshots } from "../checks/dns.js";
import type { Monitor, Observation, Status, Verdict } from "../types.js";

export const DEFAULT_WARN_DAYS = 21;
export const DEFAULT_FAIL_DAYS = 7;
export const DEFAULT_WARN_MS = 3000;

export interface Evaluation {
  verdict: Verdict;
  /** DNS only: the snapshot to remember as the new baseline. */
  baseline?: string;
}

const day = (n: number) => `${n} day${n === 1 ? "" : "s"}`;

export function evaluate(monitor: Monitor, obs: Observation, previousBaseline: string | null): Evaluation {
  const finish = (status: Status, summary: string, extra: Record<string, unknown> = {}): Verdict => ({
    status,
    summary,
    latencyMs: obs.latencyMs,
    metrics: { ...obs.metrics, up: status === "fail" ? 0 : 1 },
    detail: { ...obs.detail, ...extra },
  });

  if (obs.error) return { verdict: finish("fail", obs.error, { error: obs.error }) };

  switch (monitor.kind) {
    case "tls":
      return { verdict: tls(monitor, obs, finish) };
    case "http":
      return { verdict: http(monitor, obs, finish) };
    case "dns":
      return dns(obs, previousBaseline, finish);
    case "mail":
      return { verdict: mail(obs, finish) };
  }
}

type Finish = (status: Status, summary: string, extra?: Record<string, unknown>) => Verdict;

function tls(monitor: Monitor, obs: Observation, finish: Finish): Verdict {
  const d = obs.detail as { daysRemaining: number; validTo: string; issuer: string; hostnameMatches: boolean; trusted: boolean; trustError: string | null; host: string; selfSigned: boolean };
  const warnDays = monitor.config.warnDays ?? DEFAULT_WARN_DAYS;
  const failDays = monitor.config.failDays ?? DEFAULT_FAIL_DAYS;
  // Certificate problems are facts, not blips: alert straight away instead of waiting for a second check.
  const now = { immediate: true };

  if (d.daysRemaining < 0) return finish("fail", `Certificate expired ${day(-d.daysRemaining)} ago (${d.validTo.slice(0, 10)})`, now);
  if (!d.hostnameMatches) return finish("fail", `Certificate is not valid for ${d.host}`, now);
  if (!d.trusted && d.trustError !== "CERT_HAS_EXPIRED") {
    const why = d.selfSigned || /SELF_SIGNED/.test(d.trustError ?? "") ? "self-signed" : /UNABLE_TO_VERIFY_LEAF/.test(d.trustError ?? "") ? "incomplete chain (the server must also send its intermediate certificate)" : (d.trustError ?? "untrusted");
    return finish("fail", `Certificate is not trusted: ${why}`, now);
  }
  if (d.daysRemaining <= failDays) return finish("fail", `Certificate expires in ${day(d.daysRemaining)} (${d.validTo.slice(0, 10)})`, now);
  if (d.daysRemaining <= warnDays) return finish("warn", `Certificate expires in ${day(d.daysRemaining)} (${d.validTo.slice(0, 10)})`);
  return finish("ok", `Valid for ${day(d.daysRemaining)} (until ${d.validTo.slice(0, 10)}), issued by ${/CN=([^,]+)/.exec(d.issuer)?.[1] ?? d.issuer}`);
}

function http(monitor: Monitor, obs: Observation, finish: Finish): Verdict {
  const status = Number(obs.metrics.status_code);
  const expected = monitor.config.expectStatus;
  const healthy = expected && expected.length > 0 ? expected.includes(status) : status >= 200 && status < 400;
  if (!healthy) return finish("fail", `HTTP ${status}, expected ${expected && expected.length > 0 ? expected.join("/") : "2xx or 3xx"}`);
  const warnMs = monitor.config.warnMs ?? DEFAULT_WARN_MS;
  const latency = obs.latencyMs ?? 0;
  if (latency > warnMs) return finish("warn", `HTTP ${status} but slow: ${latency} ms (warns above ${warnMs} ms)`);
  const redirects = Number(obs.metrics.redirects);
  return finish("ok", `HTTP ${status} in ${latency} ms${redirects ? `, after ${redirects} redirect${redirects === 1 ? "" : "s"}` : ""}`);
}

function dns(obs: Observation, previousBaseline: string | null, finish: Finish): Evaluation {
  const snapshot = (obs.detail.snapshot ?? {}) as Snapshot;
  const current = canonical(snapshot);
  const count = Number(obs.metrics.record_count);

  if (count === 0) {
    // A domain that resolves to nothing is broken (expired, delegation removed); say so, but remember nothing.
    return { verdict: finish("fail", "The domain has no DNS records") };
  }
  if (previousBaseline === null) return { verdict: finish("ok", `Baseline recorded (${count} records)`, { changed: false }), baseline: current };
  if (previousBaseline === current) return { verdict: finish("ok", `No changes (${count} records)`, { changed: false }), baseline: current };

  let before: Snapshot = {};
  try {
    before = JSON.parse(previousBaseline) as Snapshot;
  } catch {
    /* an unreadable baseline is treated as empty, so everything shows as added */
  }
  const changes = diffSnapshots(before, snapshot);
  return { verdict: finish("warn", `DNS records changed. ${changes}`, { changed: true, changes }), baseline: current };
}

function mail(obs: Observation, finish: Finish): Verdict {
  const d = obs.detail as { spf: string | null; spfRecords: number; spfAll: string | null; dmarc: string | null; dmarcRecords: number; dmarcPolicy: string | null };
  const problems: string[] = [];
  const warnings: string[] = [];
  if (!d.spf) problems.push("no SPF record");
  else if (d.spfRecords > 1) problems.push("several SPF records (receivers treat that as an error)");
  else if (d.spfAll === "+" || d.spfAll === "?") warnings.push("SPF does not restrict senders (+all/?all)");
  else if (d.spfAll === null) warnings.push("SPF has no `all` terminator");
  if (!d.dmarc) problems.push("no DMARC record");
  else if (d.dmarcRecords > 1) problems.push("several DMARC records");
  else if (d.dmarcPolicy === "none") warnings.push("DMARC policy is p=none (monitoring only)");
  else if (d.dmarcPolicy === null) problems.push("DMARC record without a policy");

  if (problems.length > 0) return finish("fail", `Email authentication problems: ${problems.join(", ")}`);
  if (warnings.length > 0) return finish("warn", `Email authentication could be stronger: ${warnings.join(", ")}`);
  return finish("ok", `SPF and DMARC (p=${d.dmarcPolicy}) are published`);
}
