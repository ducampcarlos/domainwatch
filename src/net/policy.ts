/**
 * Target policy: monitors point at hosts chosen through the API, so a stolen token must not turn
 * the monitor into a way to probe the internal network. Targets that resolve to loopback, private,
 * link-local (cloud metadata) or other special-purpose addresses are refused unless the operator
 * opts in with DOMAINWATCH_ALLOW_PRIVATE, and the connection goes to the address that was checked
 * (not to a second DNS answer), which closes the DNS-rebinding gap.
 */

import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export type Lookup = (hostname: string) => Promise<string[]>;

export const systemLookup: Lookup = async (hostname) => (await dnsLookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address);

// ---------------------------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------------------------

export function parseIPv4(input: string): number | null {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

export function parseIPv6(input: string): bigint | null {
  let text = input.split("%")[0]!.toLowerCase();
  const tail = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (tail) {
    const v4 = parseIPv4(tail[1]!);
    if (v4 === null) return null;
    text = `${text.slice(0, -tail[1]!.length)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups: string[];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<string>(missing).fill("0"), ...rest];
  }
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(`0x${group}`);
  }
  return value;
}

const V4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
]; // fmt: skip

const V6_BLOCKED: Array<[string, number]> = [
  ["::", 128], ["::1", 128], ["100::", 64], ["2001::", 32], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
]; // fmt: skip

const inV4 = (addr: number, base: string, prefix: number) => Math.floor(addr / 2 ** (32 - prefix)) === Math.floor(parseIPv4(base)! / 2 ** (32 - prefix));
const inV6 = (addr: bigint, base: string, prefix: number) => addr >> BigInt(128 - prefix) === parseIPv6(base)! >> BigInt(128 - prefix);

const publicV4 = (addr: number) => !V4_BLOCKED.some(([base, prefix]) => inV4(addr, base, prefix));

function publicV6(addr: bigint): boolean {
  // IPv6 forms that embed an IPv4 address are judged by the embedded address.
  if (addr >> 32n === 0xffffn) return publicV4(Number(addr & 0xffffffffn)); // ::ffff:a.b.c.d
  if (addr >> 32n === 0n && addr > 1n) return publicV4(Number(addr & 0xffffffffn)); // IPv4-compatible
  if (addr >> 32n === 0x0064ff9b0000000000000000n) return publicV4(Number(addr & 0xffffffffn)); // NAT64
  if (addr >> 112n === 0x2002n) return publicV4(Number((addr >> 80n) & 0xffffffffn)); // 6to4
  return !V6_BLOCKED.some(([base, prefix]) => inV6(addr, base, prefix));
}

/** True only for a parseable address outside every special-purpose range. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const parsed = parseIPv4(address);
    return parsed !== null && publicV4(parsed);
  }
  if (family === 6) {
    const parsed = parseIPv6(address);
    return parsed !== null && publicV6(parsed);
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// Names and resolution
// ---------------------------------------------------------------------------------------------

const INTERNAL_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home.arpa", ".corp", ".intranet", ".private"];

/** Normalise a bare host name. Throws PolicyError when it is not a plain host. */
export function normalizeHost(input: string): string {
  const raw = input.trim();
  if (!raw || raw.length > 253 || /[\s/\\@?#]/.test(raw)) throw new PolicyError(`"${input.slice(0, 80)}" is not a valid host name`);
  // URL() silently drops a port equal to the scheme's default ("host:80"), so a port must be caught here.
  if (/^[^[\]:]+:\d*$/.test(raw)) throw new PolicyError("Put the port after the host as host:port, not inside the host name");
  let url: URL;
  try {
    url = new URL(`http://${isIP(raw) === 6 ? `[${raw}]` : raw}`); // a bare IPv6 literal needs brackets inside a URL
  } catch {
    throw new PolicyError(`"${input.slice(0, 80)}" is not a valid host name`);
  }
  if (url.port !== "") throw new PolicyError("Put the port after the host as host:port, not inside the host name");
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!host) throw new PolicyError("Empty host name");
  return host;
}

export class TargetPolicy {
  constructor(
    private readonly allowPrivate: boolean,
    private readonly lookup: Lookup = systemLookup,
  ) {}

  /** Name-only check (no network): internal-looking names are refused. */
  checkName(host: string): void {
    if (this.allowPrivate || isIP(host) !== 0) return;
    if (host === "localhost" || INTERNAL_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
      throw new PolicyError(`${host} looks like an internal name; set DOMAINWATCH_ALLOW_PRIVATE=1 to monitor internal hosts`);
    }
  }

  /** Resolve a host and make sure EVERY address is public. Returns the validated addresses. */
  async resolve(host: string): Promise<string[]> {
    this.checkName(host);
    let addresses: string[];
    if (isIP(host) !== 0) {
      addresses = [host];
    } else {
      try {
        addresses = await this.lookup(host);
      } catch (error) {
        throw new PolicyError(`Could not resolve ${host} (${(error as NodeJS.ErrnoException).code ?? "unknown"})`);
      }
      if (addresses.length === 0) throw new PolicyError(`${host} has no A/AAAA records`);
    }
    if (!this.allowPrivate) {
      for (const address of addresses) {
        if (!isPublicAddress(address)) throw new PolicyError(`${isIP(host) !== 0 ? host : `${host} resolves to ${address}, which`} is a private or special-purpose address. Set DOMAINWATCH_ALLOW_PRIVATE=1 (or pass --allow-private to \`check\`) to monitor internal hosts`);
      }
    }
    return addresses;
  }
}
