/** Command-line parsing and the one-off `check` command. Pure where possible, so it is unit-tested. */

import { validateConfig, validateTarget, ValidationError } from "./api/validate.js";
import { runCheck } from "./checks/index.js";
import type { CheckDeps } from "./checks/deps.js";
import { evaluate } from "./engine/evaluate.js";
import { KINDS, type Kind, type Monitor, type Status, type Verdict } from "./types.js";


export const USAGE = `domainwatch - self-hosted monitor for certificates, uptime, DNS changes and email authentication

Usage:
  domainwatch serve                         Run the monitor, API and dashboard
  domainwatch check <kind> <target> [opts]  Run one check now and print the result
  domainwatch --help | --version

Kinds for \`check\`:
  tls   <host[:port]>      certificate expiry, host name match, trust
  http  <url>              status code and latency, following redirects
  dns   <domain>           record snapshot (a one-off check has no baseline)
  mail  <domain>           SPF and DMARC

Options for \`check\`:
  --json                   print the verdict as JSON
  --allow-private          allow loopback and private addresses
  --warn-days <n>          tls: warn when the certificate expires within n days (default 21)
  --fail-days <n>          tls: fail within n days (default 7)
  --expect <codes>         http: comma-separated healthy status codes (default 200-399)
  --timeout <ms>           give up after this long (default 10000)

Exit status of \`check\`: 0 ok, 1 warning, 2 failing, 64 usage error.

Environment for \`serve\`:
  DOMAINWATCH_TOKEN        required, at least 16 characters (openssl rand -hex 32)
  HOST, PORT               listen address (default 127.0.0.1:8787)
  DOMAINWATCH_DATA         data directory (default ./data)
  DOMAINWATCH_WEBHOOKS     comma-separated webhook URLs (Slack, Discord, Mattermost, scripts)
  DOMAINWATCH_ALLOW_PRIVATE=1   allow monitoring private addresses
  DOMAINWATCH_RETENTION_DAYS, DOMAINWATCH_CONCURRENCY, DOMAINWATCH_MAX_MONITORS
`;

export type Command =
  | { name: "help" }
  | { name: "version" }
  | { name: "serve" }
  | { name: "check"; kind: Kind; target: string; json: boolean; allowPrivate: boolean; config: Record<string, unknown> };

export class UsageError extends Error {}

export function parseArgs(argv: string[]): Command {
  const [first, ...rest] = argv;
  if (first === undefined || first === "--help" || first === "-h" || first === "help") return { name: "help" };
  if (first === "--version" || first === "-v") return { name: "version" };
  if (first === "serve") {
    if (rest.length > 0) throw new UsageError(`serve takes no arguments (configure it with environment variables); got "${rest[0]}"`);
    return { name: "serve" };
  }
  if (first !== "check") throw new UsageError(`Unknown command "${first.slice(0, 40)}"`);

  const positional: string[] = [];
  const config: Record<string, unknown> = {};
  let json = false;
  let allowPrivate = false;
  const number = (flag: string, value: string | undefined) => {
    if (value === undefined || !/^\d+$/.test(value)) throw new UsageError(`${flag} needs a whole number`);
    return Number(value);
  };
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    switch (arg) {
      case "--json": json = true; break;
      case "--allow-private": allowPrivate = true; break;
      case "--warn-days": config.warnDays = number(arg, rest[++i]); break;
      case "--fail-days": config.failDays = number(arg, rest[++i]); break;
      case "--timeout": config.timeoutMs = number(arg, rest[++i]); break;
      case "--expect": {
        const value = rest[++i];
        if (!value || !/^\d+(,\d+)*$/.test(value)) throw new UsageError("--expect needs a comma-separated list of status codes");
        config.expectStatus = value.split(",").map(Number);
        break;
      }
      default:
        if (arg.startsWith("-")) throw new UsageError(`Unknown option "${arg.slice(0, 40)}"`);
        positional.push(arg);
    }
  }
  const [kind, target, ...extra] = positional;
  if (!kind || !KINDS.includes(kind as Kind)) throw new UsageError(`check needs a kind: ${KINDS.join(", ")}`);
  if (!target) throw new UsageError(`check ${kind} needs a target`);
  if (extra.length > 0) throw new UsageError(`Unexpected argument "${extra[0]!.slice(0, 40)}"`);
  return { name: "check", kind: kind as Kind, target, json, allowPrivate, config };
}

export const EXIT: Record<Status, number> = { ok: 0, warn: 1, fail: 2 };

/** Run one check and judge it. Throws UsageError for a target or option the monitor would not accept. */
export async function checkOnce(deps: CheckDeps, command: Extract<Command, { name: "check" }>): Promise<Verdict> {
  let target: string;
  let config;
  try {
    target = validateTarget(command.kind, command.target);
    const allowed: string[] = { tls: ["warnDays", "failDays", "timeoutMs"], http: ["expectStatus", "timeoutMs"], dns: [], mail: [] }[command.kind];
    const given = Object.keys(command.config);
    const wrong = given.find((key) => !allowed.includes(key));
    if (wrong) throw new UsageError(`--${wrong === "expectStatus" ? "expect" : wrong === "timeoutMs" ? "timeout" : wrong === "warnDays" ? "warn-days" : "fail-days"} does not apply to ${command.kind} checks`);
    config = validateConfig(command.kind, command.config);
  } catch (error) {
    if (error instanceof ValidationError) throw new UsageError(error.message);
    throw error;
  }
  const monitor: Monitor = { id: 0, name: target, kind: command.kind, target, intervalS: 60, enabled: true, config, createdAt: 0 };
  const observation = await runCheck(deps, monitor);
  return evaluate(monitor, observation, null).verdict;
}

const MARK: Record<Status, string> = { ok: "OK  ", warn: "WARN", fail: "FAIL" };

export function formatVerdict(command: Extract<Command, { name: "check" }>, verdict: Verdict, color: boolean): string {
  if (command.json) return JSON.stringify({ kind: command.kind, target: command.target, ...verdict }, null, 2);
  const paint = (status: Status, text: string) => (color ? `\u001b[${{ ok: 32, warn: 33, fail: 31 }[status]}m${text}\u001b[0m` : text);
  return `${paint(verdict.status, MARK[verdict.status])} ${command.kind} ${command.target}: ${verdict.summary}`;
}
