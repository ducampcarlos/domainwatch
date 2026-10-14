/** TLS check: handshake, certificate expiry, name match and trust. Sends no application data. */

import { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import * as tls from "node:tls";

import { PolicyError, normalizeHost } from "../net/policy.js";
import type { Observation } from "../types.js";
import { type CheckDeps, parseHostPort } from "./deps.js";

const DAY_MS = 86_400_000;

export async function observeTls(deps: CheckDeps, target: string, timeoutMs: number, now: () => number = Date.now): Promise<Observation> {
  let host: string;
  let port: number;
  try {
    const parsed = parseHostPort(target, 443);
    host = normalizeHost(parsed.host);
    port = parsed.port;
  } catch (error) {
    return failed(error instanceof Error ? error.message : String(error));
  }

  let address: string;
  try {
    address = (await deps.policy.resolve(host))[0]!;
  } catch (error) {
    return failed(error instanceof PolicyError ? error.message : `Could not resolve ${host}`);
  }
  const dial = deps.connectAddress ? deps.connectAddress(address) : address;

  const started = performance.now();
  try {
    const socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
      const s = tls.connect({ host: dial, port, ...(isIP(host) === 0 ? { servername: host } : {}), rejectUnauthorized: false, ALPNProtocols: ["h2", "http/1.1"] });
      const timer = setTimeout(() => {
        s.destroy();
        reject(Object.assign(new Error("timed out"), { code: "ETIMEDOUT" }));
      }, timeoutMs);
      s.once("secureConnect", () => {
        clearTimeout(timer);
        resolve(s);
      });
      s.once("error", (error) => {
        clearTimeout(timer);
        s.destroy();
        reject(error);
      });
    });
    const handshakeMs = Math.round(performance.now() - started);
    try {
      const peer = socket.getPeerCertificate(true);
      if (!peer?.raw) return failed("The server presented no certificate", handshakeMs);
      const cert = new X509Certificate(peer.raw);
      const validTo = new Date(cert.validTo);
      const daysRemaining = Math.floor((validTo.getTime() - now()) / DAY_MS);
      const matches = isIP(host) !== 0 ? cert.checkIP(host) !== undefined : cert.checkHost(host) !== undefined;
      let chain = 0;
      for (let c: tls.DetailedPeerCertificate | undefined = peer; c?.raw && chain < 10; c = c.issuerCertificate === c ? undefined : c.issuerCertificate) chain++;
      const error = socket.authorizationError ? String(socket.authorizationError) : null;
      return {
        latencyMs: handshakeMs,
        metrics: { days_remaining: daysRemaining, handshake_ms: handshakeMs },
        detail: {
          host,
          port,
          subject: cert.subject.split("\n").join(", "),
          issuer: cert.issuer.split("\n").join(", "),
          validTo: validTo.toISOString(),
          daysRemaining,
          names: (cert.subjectAltName ?? "").split(/,\s*/).filter(Boolean).slice(0, 20),
          hostnameMatches: matches,
          trusted: socket.authorized,
          trustError: error,
          selfSigned: cert.subject === cert.issuer && cert.verify(cert.publicKey),
          protocol: socket.getProtocol(),
          chainLength: chain,
          fingerprint: cert.fingerprint256.slice(0, 29),
        },
      };
    } finally {
      socket.destroy();
    }
  } catch (error) {
    return failed(describe(error));
  }
}

const failed = (message: string, latencyMs?: number): Observation => ({ error: message, latencyMs, metrics: {}, detail: {} });

function describe(error: unknown): string {
  const code = (error as NodeJS.ErrnoException).code ?? "";
  const hints: Record<string, string> = {
    ECONNREFUSED: "connection refused (nothing listening on that port)",
    ECONNRESET: "connection reset by the server",
    ETIMEDOUT: "connection timed out",
    EHOSTUNREACH: "host unreachable",
    ENETUNREACH: "network unreachable",
    ERR_SSL_WRONG_VERSION_NUMBER: "the server did not speak TLS on this port",
    EPROTO: "TLS protocol error",
  };
  if (hints[code]) return hints[code];
  const message = error instanceof Error ? error.message : "";
  // OpenSSL errors look like "C09C...:error:0A0000C6:SSL routines:fn:reason:../deps/openssl/...": keep only the reason.
  const openssl = /:SSL routines:[^:]*:([^:]+):/.exec(message);
  if (openssl || code.startsWith("ERR_SSL_") || code.startsWith("ERR_TLS_")) return `TLS handshake failed (${openssl?.[1] ?? code.replace(/^ERR_(SSL|TLS)_/, "").toLowerCase().replace(/_/g, " ")})`;
  return message ? message.slice(0, 200) : "connection failed";
}
