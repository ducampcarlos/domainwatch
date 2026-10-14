/** DNS check: snapshot the records so changes (hijacks, expired delegations, stray edits) are noticed. */

import { PolicyError, normalizeHost } from "../net/policy.js";
import type { DnsAnswer, RecordType } from "../net/dns.js";
import type { Observation } from "../types.js";
import type { CheckDeps } from "./deps.js";

export const DNS_TYPES: readonly RecordType[] = ["A", "AAAA", "NS", "MX", "TXT", "CAA"];
export type Snapshot = Partial<Record<RecordType, string[]>>;

const MAX_RECORD_LENGTH = 255;

export async function observeDns(deps: CheckDeps, target: string): Promise<Observation> {
  let name: string;
  try {
    name = normalizeHost(target);
    deps.policy.checkName(name);
  } catch (error) {
    return { error: error instanceof PolicyError ? error.message : "invalid domain", metrics: {}, detail: {} };
  }

  const started = performance.now();
  const answers = await Promise.all(DNS_TYPES.map(async (type) => [type, await deps.dns.resolve(name, type)] as const));
  const latencyMs = Math.round(performance.now() - started);

  const all = answers.map(([, answer]) => answer);
  if (all.every((a) => a.status === "nxdomain")) return { error: `${name} does not exist (NXDOMAIN)`, latencyMs, metrics: {}, detail: {} };
  const failedLookups = all.filter((a) => a.status === "error");
  if (failedLookups.length === all.length) return { error: `DNS lookup failed (${failedLookups[0]!.error ?? "error"})`, latencyMs, metrics: {}, detail: {} };

  const snapshot: Snapshot = {};
  let count = 0;
  for (const [type, answer] of answers) {
    if (answer.status === "error") continue; // a single failed record type should not look like a change
    if (answer.records.length > 0) {
      snapshot[type] = answer.records.map((r) => r.slice(0, MAX_RECORD_LENGTH));
      count += answer.records.length;
    }
  }
  return { latencyMs, metrics: { record_count: count, lookup_errors: failedLookups.length }, detail: { snapshot, lookupErrors: failedLookups.map((a: DnsAnswer) => a.error) } };
}

/** Human-readable diff between two snapshots: "A: +1.2.3.4 -5.6.7.8; NS: +ns3". */
export function diffSnapshots(before: Snapshot, after: Snapshot): string {
  const parts: string[] = [];
  for (const type of DNS_TYPES) {
    const a = new Set(before[type] ?? []);
    const b = new Set(after[type] ?? []);
    const added = [...b].filter((r) => !a.has(r));
    const removed = [...a].filter((r) => !b.has(r));
    if (added.length === 0 && removed.length === 0) continue;
    const show = (r: string) => (r.length > 60 ? `${r.slice(0, 57)}...` : r);
    parts.push(`${type}: ${[...added.map((r) => `+${show(r)}`), ...removed.map((r) => `-${show(r)}`)].join(" ")}`);
  }
  return parts.join("; ");
}

/** Canonical JSON, so equal snapshots always compare equal. */
export const canonical = (snapshot: Snapshot): string =>
  JSON.stringify(Object.fromEntries(DNS_TYPES.filter((t) => snapshot[t]?.length).map((t) => [t, [...snapshot[t]!].sort()])));
