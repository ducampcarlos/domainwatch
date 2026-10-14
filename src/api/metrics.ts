/** Prometheus text exposition of the current state. One gauge family per fact, labelled by monitor. */

import type { MonitorOverview } from "../db.js";

const escape = (value: string) => value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");

export function renderMetrics(overview: MonitorOverview[], extra: { alertsStored: number; startedAt: number; now: number }): string {
  const lines: string[] = [];
  const family = (name: string, help: string, type: "gauge" | "counter", samples: Array<[string, number]>) => {
    if (samples.length === 0) return;
    lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
    for (const [labels, value] of samples) lines.push(`${name}${labels} ${Number.isFinite(value) ? value : 0}`);
  };
  const labels = (o: MonitorOverview, more = "") => `{monitor="${escape(o.monitor.name)}",kind="${o.monitor.kind}",target="${escape(o.monitor.target)}"${more}}`;
  const active = overview.filter((o) => o.monitor.enabled);

  family("domainwatch_up", "1 when the monitor is not failing, 0 when it is down.", "gauge", active.filter((o) => o.state).map((o) => [labels(o), o.state!.status === "fail" ? 0 : 1]));
  family("domainwatch_status", "Alert status: 0 ok, 1 warn, 2 fail.", "gauge", active.filter((o) => o.state).map((o) => [labels(o), { ok: 0, warn: 1, fail: 2 }[o.state!.status]]));
  family("domainwatch_last_check_timestamp_seconds", "Unix time of the last check.", "gauge", active.filter((o) => o.last).map((o) => [labels(o), o.last!.ts]));
  family("domainwatch_uptime_ratio_24h", "Share of checks in the last 24 hours that were not failing.", "gauge", active.filter((o) => o.uptime24h !== null).map((o) => [labels(o), Math.round(o.uptime24h!) / 100]));
  family("domainwatch_check_duration_ms", "Duration of the last check in milliseconds.", "gauge", active.filter((o) => o.last?.latencyMs !== undefined).map((o) => [labels(o), o.last!.latencyMs!]));

  // Per-fact gauges, such as certificate days remaining or the HTTP status code.
  const facts = new Map<string, Array<[string, number]>>();
  for (const o of active) {
    for (const [key, value] of Object.entries(o.last?.metrics ?? {})) {
      if (key === "up" || !/^[a-z][a-z0-9_]*$/.test(key)) continue;
      const list = facts.get(key) ?? [];
      list.push([labels(o), value]);
      facts.set(key, list);
    }
  }
  for (const [key, samples] of [...facts].sort(([a], [b]) => a.localeCompare(b))) family(`domainwatch_${key}`, `Last observed ${key.replace(/_/g, " ")}.`, "gauge", samples);

  family("domainwatch_monitors", "Number of configured monitors.", "gauge", [["", overview.length]]);
  family("domainwatch_alerts_stored", "Alerts currently stored (older ones are pruned).", "gauge", [["", extra.alertsStored]]);
  family("domainwatch_uptime_seconds", "Seconds since the process started.", "gauge", [["", Math.max(0, extra.now - extra.startedAt)]]);
  return `${lines.join("\n")}\n`;
}
