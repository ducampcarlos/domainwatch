/** Mail check: SPF and DMARC are published and not obviously weak. */

import { PolicyError, normalizeHost } from "../net/policy.js";
import type { Observation } from "../types.js";
import type { CheckDeps } from "./deps.js";

export async function observeMail(deps: CheckDeps, target: string): Promise<Observation> {
  let domain: string;
  try {
    domain = normalizeHost(target);
    deps.policy.checkName(domain);
  } catch (error) {
    return { error: error instanceof PolicyError ? error.message : "invalid domain", metrics: {}, detail: {} };
  }

  const started = performance.now();
  const [txt, dmarcTxt, mx] = await Promise.all([deps.dns.resolve(domain, "TXT"), deps.dns.resolve(`_dmarc.${domain}`, "TXT"), deps.dns.resolve(domain, "MX")]);
  const latencyMs = Math.round(performance.now() - started);

  if (txt.status === "nxdomain" && mx.status === "nxdomain") return { error: `${domain} does not exist (NXDOMAIN)`, latencyMs, metrics: {}, detail: {} };
  if (txt.status === "error" && dmarcTxt.status === "error") return { error: `DNS lookup failed (${txt.error ?? "error"})`, latencyMs, metrics: {}, detail: {} };

  const spfRecords = txt.records.filter((r) => /^v=spf1(\s|$)/i.test(r));
  const dmarcRecords = dmarcTxt.records.filter((r) => /^v=dmarc1\b/i.test(r));
  const spf = spfRecords[0];
  const dmarc = dmarcRecords[0];
  const policy = /(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(dmarc ?? "")?.[1]?.toLowerCase() ?? null;
  const spfAll = spf ? /(?:^|\s)([+\-~?]?)all(?:\s|$)/i.exec(spf)?.[1] ?? (/(?:^|\s)all(?:\s|$)/i.test(spf) ? "+" : null) : null;

  return {
    latencyMs,
    metrics: {
      spf: spf ? 1 : 0,
      dmarc: dmarc ? 1 : 0,
      dmarc_enforced: policy === "quarantine" || policy === "reject" ? 1 : 0,
      mx_count: mx.records.length,
    },
    detail: { spf: spf?.slice(0, 255) ?? null, spfRecords: spfRecords.length, spfAll, dmarc: dmarc?.slice(0, 255) ?? null, dmarcRecords: dmarcRecords.length, dmarcPolicy: policy, mx: mx.records.length },
  };
}
