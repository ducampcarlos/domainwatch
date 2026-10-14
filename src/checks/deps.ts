import type { DnsClient } from "../net/dns.js";
import type { TargetPolicy } from "../net/policy.js";

export interface CheckDeps {
  policy: TargetPolicy;
  dns: DnsClient;
  /** Test hook: maps a validated address to the address actually dialled. */
  connectAddress?: (validatedAddress: string) => string;
}

/** Split "host", "host:port" or "[v6]:port" into its parts. Throws on nonsense. */
export function parseHostPort(target: string, defaultPort: number): { host: string; port: number } {
  const text = target.trim();
  const bracket = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(text);
  if (bracket) return { host: bracket[1]!.toLowerCase(), port: bracket[2] ? checkPort(bracket[2]) : defaultPort };
  const colons = (text.match(/:/g) ?? []).length;
  if (colons === 1) {
    const [host, port] = text.split(":") as [string, string];
    return { host: host.toLowerCase().replace(/\.$/, ""), port: checkPort(port) };
  }
  return { host: text.toLowerCase().replace(/\.$/, ""), port: defaultPort };
}

function checkPort(text: string): number {
  const port = Number(text);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Invalid port "${text}"`);
  return port;
}
