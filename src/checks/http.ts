/**
 * HTTP check: one GET per hop, following up to five redirects, with every hop validated by the
 * target policy and the connection pinned to the validated address. The body is never read: the
 * response is dropped as soon as the headers arrive.
 */

import * as http from "node:http";
import * as https from "node:https";
import type { LookupFunction } from "node:net";
import { isIP } from "node:net";

import { PolicyError } from "../net/policy.js";
import type { Observation } from "../types.js";
import type { CheckDeps } from "./deps.js";

const MAX_REDIRECTS = 5;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

interface Hop {
  status: number;
  location?: string;
  address: string;
}

function pinned(addresses: string[]): LookupFunction {
  const all = addresses.map((address) => ({ address, family: isIP(address) }));
  return (_hostname, options, callback) => {
    const opts = typeof options === "object" && options !== null ? options : {};
    const list = all;
    if (opts.all) (callback as unknown as (e: null, a: typeof list) => void)(null, list);
    else callback(null, list[0]!.address, list[0]!.family);
  };
}

function requestOnce(url: URL, addresses: string[], timeoutMs: number): Promise<Hop> {
  return new Promise((resolve, reject) => {
    const client = url.protocol === "https:" ? https : http;
    const req = client.request(
      url,
      { method: "GET", lookup: pinned(addresses), headers: { "user-agent": "domainwatch/0.1 (+https://github.com/ducampcarlos/domainwatch)", accept: "*/*", "accept-encoding": "identity" } },
      (res) => {
        const location = typeof res.headers.location === "string" ? res.headers.location : undefined;
        const status = res.statusCode ?? 0;
        res.on("error", () => undefined); // dropping the body makes the socket emit an abort; it must not become an uncaught error
        res.destroy();
        clearTimeout(timer);
        resolve({ status, location, address: addresses[0]! });
      },
    );
    const timer = setTimeout(() => req.destroy(Object.assign(new Error("timed out"), { code: "ETIMEDOUT" })), timeoutMs);
    req.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    req.end();
  });
}

export function describeHttpError(error: unknown): string {
  const code = (error as NodeJS.ErrnoException).code ?? "";
  const hints: Record<string, string> = {
    ECONNREFUSED: "connection refused",
    ECONNRESET: "connection reset by the server",
    ETIMEDOUT: "timed out",
    EHOSTUNREACH: "host unreachable",
    ENETUNREACH: "network unreachable",
    CERT_HAS_EXPIRED: "TLS certificate has expired",
    DEPTH_ZERO_SELF_SIGNED_CERT: "TLS certificate is self-signed",
    SELF_SIGNED_CERT_IN_CHAIN: "TLS chain contains a self-signed certificate",
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: "TLS: the server did not send its intermediate certificate",
    UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "TLS: the certificate issuer is not trusted",
    ERR_TLS_CERT_ALTNAME_INVALID: "TLS certificate does not match the host name",
    ERR_SSL_WRONG_VERSION_NUMBER: "the server did not speak TLS on this port",
  };
  if (hints[code]) return hints[code];
  const message = error instanceof Error ? error.message : "";
  const openssl = /:SSL routines:[^:]*:([^:]+):/.exec(message);
  if (openssl) return `TLS handshake failed (${openssl[1]})`;
  return message ? message.slice(0, 200) : "request failed";
}

export async function observeHttp(deps: CheckDeps, target: string, timeoutMs: number): Promise<Observation> {
  let current: URL;
  try {
    current = new URL(target);
    if (current.protocol !== "http:" && current.protocol !== "https:") throw new Error("only http and https URLs are supported");
    if (current.username || current.password) throw new Error("URLs with credentials are not supported");
  } catch (error) {
    return { error: error instanceof Error ? error.message : "invalid URL", metrics: {}, detail: {} };
  }

  const started = performance.now();
  const visited = new Set<string>();
  let hops = 0;
  let last: Hop | undefined;

  for (;;) {
    if (visited.has(current.href)) return { error: "redirect loop", metrics: {}, detail: { hops } };
    visited.add(current.href);

    let addresses: string[];
    try {
      const host = current.hostname.replace(/^\[|\]$/g, "").toLowerCase();
      addresses = await deps.policy.resolve(host);
    } catch (error) {
      return { error: error instanceof PolicyError ? error.message : "could not resolve host", metrics: {}, detail: { hops } };
    }
    const dial = deps.connectAddress ? addresses.map(deps.connectAddress) : addresses;

    const remaining = Math.max(1000, timeoutMs - (performance.now() - started));
    try {
      last = await requestOnce(current, dial, remaining);
    } catch (error) {
      return { error: describeHttpError(error), latencyMs: Math.round(performance.now() - started), metrics: {}, detail: { hops } };
    }
    last = { ...last, address: addresses[0]! };

    if (!REDIRECTS.has(last.status) || !last.location) break;
    if (hops >= MAX_REDIRECTS) return { error: `more than ${MAX_REDIRECTS} redirects`, metrics: {}, detail: { hops } };
    try {
      current = new URL(last.location, current);
    } catch {
      return { error: "redirect to an invalid URL", metrics: {}, detail: { hops } };
    }
    hops++;
  }

  const latencyMs = Math.round(performance.now() - started);
  return {
    latencyMs,
    metrics: { status_code: last.status, latency_ms: latencyMs, redirects: hops },
    detail: { statusCode: last.status, redirects: hops, finalUrl: `${current.origin}${current.pathname}`, address: last.address },
  };
}
