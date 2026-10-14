/** DNS behind a tiny interface so checks can be tested without a network. */

import { Resolver } from "node:dns/promises";

export type RecordType = "A" | "AAAA" | "NS" | "MX" | "TXT" | "CAA" | "CNAME";

export interface DnsAnswer {
  /** `nodata`: the name exists but has no records of this type. */
  status: "ok" | "nodata" | "nxdomain" | "error";
  /** Records already rendered as text (MX as "10 host", CAA as `0 issue "ca"`), sorted. */
  records: string[];
  error?: string;
}

export interface DnsClient {
  resolve(name: string, type: RecordType): Promise<DnsAnswer>;
}

export class SystemDnsClient implements DnsClient {
  private readonly resolver: Resolver;

  constructor(timeoutMs = 5000) {
    this.resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  }

  async resolve(name: string, type: RecordType): Promise<DnsAnswer> {
    try {
      return { status: "ok", records: (await this.query(name, type)).sort() };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "UNKNOWN";
      if (code === "ENODATA") return { status: "nodata", records: [] };
      if (code === "ENOTFOUND") return { status: "nxdomain", records: [] };
      return { status: "error", records: [], error: code };
    }
  }

  private async query(name: string, type: RecordType): Promise<string[]> {
    switch (type) {
      case "A": return this.resolver.resolve4(name);
      case "AAAA": return this.resolver.resolve6(name);
      case "NS": return (await this.resolver.resolveNs(name)).map((ns) => ns.toLowerCase());
      case "CNAME": return (await this.resolver.resolveCname(name)).map((c) => c.toLowerCase());
      case "TXT": return (await this.resolver.resolveTxt(name)).map((chunks) => chunks.join(""));
      case "MX": return (await this.resolver.resolveMx(name)).map((mx) => `${mx.priority} ${mx.exchange.toLowerCase()}`);
      case "CAA":
        return (await this.resolver.resolveCaa(name)).map((caa) => {
          const fields = caa as unknown as Record<string, unknown>;
          const tag = (["issue", "issuewild", "iodef"] as const).find((key) => key in fields) ?? "unknown";
          return `${Number(fields.critical ?? 0)} ${tag} ${JSON.stringify(String(fields[tag] ?? ""))}`;
        });
    }
  }
}
