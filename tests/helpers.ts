import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import type { CheckDeps } from "../src/checks/deps.js";
import type { DnsAnswer, DnsClient, RecordType } from "../src/net/dns.js";
import { TargetPolicy } from "../src/net/policy.js";
import type { Monitor, Observation, Verdict } from "../src/types.js";

export const monitor = (overrides: Partial<Monitor> = {}): Monitor => ({
  id: 1,
  name: "Example",
  kind: "http",
  target: "https://example.test/",
  intervalS: 60,
  enabled: true,
  config: {},
  createdAt: 0,
  ...overrides,
});

export const verdict = (status: Verdict["status"], summary: string = status, detail: Record<string, unknown> = {}): Verdict => ({ status, summary, metrics: {}, detail });

export const observation = (overrides: Partial<Observation> = {}): Observation => ({ metrics: {}, detail: {}, ...overrides });

// ---- DNS ---------------------------------------------------------------------------------------

export type DnsTable = Record<string, Partial<Record<RecordType, string[]>>>;

export class FakeDns implements DnsClient {
  readonly queries: string[] = [];
  constructor(
    private readonly table: DnsTable = {},
    private readonly errors: Record<string, string> = {},
  ) {}

  async resolve(name: string, type: RecordType): Promise<DnsAnswer> {
    this.queries.push(`${type} ${name}`);
    const error = this.errors[`${type} ${name}`] ?? this.errors[name];
    if (error) return { status: "error", records: [], error };
    const zone = this.table[name];
    if (!zone) return { status: "nxdomain", records: [] };
    const records = zone[type];
    return records && records.length > 0 ? { status: "ok", records: [...records].sort() } : { status: "nodata", records: [] };
  }
}

/** A name that resolves to a public-looking address; the connection itself is redirected to localhost. */
export const FAKE_HOSTS: Record<string, string[]> = {
  "public.test": ["93.184.216.34"],
  "other.test": ["93.184.216.35"],
  "meta.test": ["169.254.169.254"],
  "internal.test": ["10.0.0.5"],
};

export function deps(overrides: { dns?: DnsClient; allowPrivate?: boolean; hosts?: Record<string, string[]> } = {}): CheckDeps {
  const hosts = overrides.hosts ?? FAKE_HOSTS;
  return {
    policy: new TargetPolicy(overrides.allowPrivate ?? false, async (host) => {
      const found = hosts[host];
      if (!found) throw Object.assign(new Error("nope"), { code: "ENOTFOUND" });
      return found;
    }),
    dns: overrides.dns ?? new FakeDns(),
    connectAddress: () => "127.0.0.1",
  };
}

// ---- HTTP server -------------------------------------------------------------------------------

export type Handler = (req: IncomingMessage, res: ServerResponse) => void;

export interface TestServer {
  port: number;
  server: Server;
  close(): Promise<void>;
}

export async function startServer(handler: Handler): Promise<TestServer> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as AddressInfo).port,
    server,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
