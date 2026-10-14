/**
 * Alert state machine. Decides, from the stream of verdicts, when a human should hear about it.
 *
 *  - A failing monitor is only "down" after `failThreshold` consecutive failures, so one dropped
 *    packet does not page anyone. Certificate problems (verdict.detail.immediate) skip the wait.
 *  - Recovery is announced once, with how long it was down.
 *  - A monitor that stays down is re-announced every `renotifyAfterS`, not on every check.
 *  - ok -> warn is announced once; warn -> ok is quiet.
 *
 * Pure: no clock, no database, no network, so the rules are tested exhaustively.
 */

import type { AlertKind, Monitor, MonitorState, Verdict } from "../types.js";

export interface AlertRules {
  failThreshold: number;
  renotifyAfterS: number;
}

export const DEFAULT_RULES: AlertRules = { failThreshold: 2, renotifyAfterS: 6 * 3600 };

export interface PendingAlert {
  kind: AlertKind;
  message: string;
}

export interface Transition {
  state: MonitorState;
  alerts: PendingAlert[];
}

export function duration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 172_800) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86_400)}d`;
}

const label = (m: Pick<Monitor, "name" | "kind" | "target">) => `${m.name} (${m.kind} ${m.target})`;

export function advance(
  previous: MonitorState | null,
  monitor: Pick<Monitor, "id" | "name" | "kind" | "target">,
  verdict: Verdict,
  now: number,
  baseline: string | null | undefined,
  rules: AlertRules = DEFAULT_RULES,
): Transition {
  const state: MonitorState = previous ?? { monitorId: monitor.id, status: "ok", failures: 0, since: now, lastAlertTs: 0, baseline: null };
  const raw = verdict.status;
  const failures = raw === "fail" ? state.failures + 1 : 0;
  const immediate = raw === "fail" && verdict.detail.immediate === true;

  let effective = state.status;
  if (raw === "fail") {
    if (failures >= rules.failThreshold || immediate) effective = "fail";
  } else {
    effective = raw;
  }

  const alerts: PendingAlert[] = [];
  let since = state.since;
  let lastAlertTs = state.lastAlertTs;

  if (effective !== state.status) {
    since = now;
    if (effective === "fail") {
      alerts.push({ kind: "down", message: `[DOWN] ${label(monitor)}: ${verdict.summary}` });
    } else if (state.status === "fail") {
      alerts.push({ kind: "recovered", message: `[RECOVERED] ${label(monitor)} after ${duration(now - state.since)}: ${verdict.summary}` });
    } else if (effective === "warn") {
      alerts.push({ kind: "warning", message: `[WARNING] ${label(monitor)}: ${verdict.summary}` });
    }
    // warn -> ok is deliberately quiet.
  } else if (effective === "fail" && now - state.lastAlertTs >= rules.renotifyAfterS) {
    alerts.push({ kind: "still_down", message: `[STILL DOWN] ${label(monitor)} for ${duration(now - state.since)}: ${verdict.summary}` });
  } else if (effective === "warn" && raw === "warn" && verdict.detail.changed === true) {
    // DNS: a second change while the first is still in the warn state is news too.
    alerts.push({ kind: "warning", message: `[WARNING] ${label(monitor)}: ${verdict.summary}` });
  }

  if (alerts.length > 0) lastAlertTs = now;
  return {
    state: { monitorId: monitor.id, status: effective, failures, since, lastAlertTs, baseline: baseline === undefined ? state.baseline : baseline },
    alerts,
  };
}
