import { describe, expect, it } from "vitest";

import { canonical } from "../src/checks/dns.js";
import { evaluate } from "../src/engine/evaluate.js";
import { monitor, observation } from "./helpers.js";

const tlsObs = (over: Record<string, unknown> = {}, latencyMs = 40) =>
  observation({
    latencyMs,
    metrics: { days_remaining: Number(over.daysRemaining ?? 60), handshake_ms: latencyMs },
    detail: { host: "example.test", validTo: "2027-01-01T00:00:00.000Z", issuer: "CN=Test CA", daysRemaining: 60, hostnameMatches: true, trusted: true, trustError: null, selfSigned: false, ...over },
  });
const tlsMonitor = (config = {}) => monitor({ kind: "tls", target: "example.test", config });

describe("tls verdicts", () => {
  it("is ok with plenty of time left and says who issued it", () => {
    const { verdict } = evaluate(tlsMonitor(), tlsObs(), null);
    expect(verdict.status).toBe("ok");
    expect(verdict.summary).toMatch(/Valid for 60 days.*issued by Test CA/);
    expect(verdict.metrics).toMatchObject({ days_remaining: 60, up: 1 });
  });

  it.each([
    [30, "ok"], [21, "warn"], [8, "warn"], [7, "fail"], [1, "fail"], [0, "fail"],
  ])("with %i days left the default thresholds say %s", (daysRemaining, expected) => {
    expect(evaluate(tlsMonitor(), tlsObs({ daysRemaining }), null).verdict.status).toBe(expected);
  });

  it("honours custom thresholds", () => {
    expect(evaluate(tlsMonitor({ warnDays: 60, failDays: 30 }), tlsObs({ daysRemaining: 45 }), null).verdict.status).toBe("warn");
    expect(evaluate(tlsMonitor({ warnDays: 60, failDays: 30 }), tlsObs({ daysRemaining: 29 }), null).verdict.status).toBe("fail");
  });

  it("an expired certificate fails immediately and says for how long", () => {
    const { verdict } = evaluate(tlsMonitor(), tlsObs({ daysRemaining: -3 }), null);
    expect(verdict).toMatchObject({ status: "fail", summary: expect.stringMatching(/expired 3 days ago/) });
    expect(verdict.detail.immediate).toBe(true);
  });

  it("flags a wrong host name, a self-signed certificate and an incomplete chain, all immediately", () => {
    const wrong = evaluate(tlsMonitor(), tlsObs({ hostnameMatches: false }), null).verdict;
    expect(wrong.summary).toMatch(/not valid for example.test/);
    const self = evaluate(tlsMonitor(), tlsObs({ trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT", selfSigned: true }), null).verdict;
    expect(self.summary).toMatch(/self-signed/);
    const chain = evaluate(tlsMonitor(), tlsObs({ trusted: false, trustError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }), null).verdict;
    expect(chain.summary).toMatch(/incomplete chain/);
    for (const v of [wrong, self, chain]) expect(v).toMatchObject({ status: "fail", detail: { immediate: true } });
  });

  it("does not double-report an expired certificate as untrusted", () => {
    const { verdict } = evaluate(tlsMonitor(), tlsObs({ daysRemaining: -1, trusted: false, trustError: "CERT_HAS_EXPIRED" }), null);
    expect(verdict.summary).toMatch(/expired/);
    expect(verdict.summary).not.toMatch(/not trusted/);
  });

  it("a connection error is a plain failure without the immediate flag", () => {
    const { verdict } = evaluate(tlsMonitor(), observation({ error: "connection refused" }), null);
    expect(verdict).toMatchObject({ status: "fail", summary: "connection refused", metrics: { up: 0 } });
    expect(verdict.detail.immediate).toBeUndefined();
  });
});

describe("http verdicts", () => {
  const http = (status: number, latencyMs = 100, redirects = 0) => observation({ latencyMs, metrics: { status_code: status, latency_ms: latencyMs, redirects } });

  it("ok for 2xx and 3xx by default, fail for 4xx and 5xx", () => {
    expect(evaluate(monitor(), http(200), null).verdict).toMatchObject({ status: "ok", summary: "HTTP 200 in 100 ms" });
    expect(evaluate(monitor(), http(301), null).verdict.status).toBe("ok");
    expect(evaluate(monitor(), http(404), null).verdict).toMatchObject({ status: "fail", summary: "HTTP 404, expected 2xx or 3xx" });
    expect(evaluate(monitor(), http(503), null).verdict.status).toBe("fail");
  });

  it("expectStatus overrides the defaults", () => {
    const m = monitor({ config: { expectStatus: [401, 403] } });
    expect(evaluate(m, http(401), null).verdict.status).toBe("ok");
    expect(evaluate(m, http(200), null).verdict).toMatchObject({ status: "fail", summary: "HTTP 200, expected 401/403" });
  });

  it("warns when slow and mentions redirects", () => {
    expect(evaluate(monitor(), http(200, 3500), null).verdict).toMatchObject({ status: "warn", summary: expect.stringMatching(/slow: 3500 ms/) });
    expect(evaluate(monitor({ config: { warnMs: 100 } }), http(200, 150), null).verdict.status).toBe("warn");
    expect(evaluate(monitor(), http(200, 100, 2), null).verdict.summary).toMatch(/after 2 redirects/);
    expect(evaluate(monitor(), http(200, 100, 1), null).verdict.summary).toMatch(/after 1 redirect$/);
  });
});

describe("dns verdicts", () => {
  const dns = (snapshot: Record<string, string[]>) =>
    observation({ metrics: { record_count: Object.values(snapshot).flat().length }, detail: { snapshot } });
  const m = monitor({ kind: "dns", target: "example.test" });

  it("records a baseline the first time", () => {
    const e = evaluate(m, dns({ A: ["1.2.3.4"], NS: ["ns1.x"] }), null);
    expect(e.verdict).toMatchObject({ status: "ok", summary: "Baseline recorded (2 records)" });
    expect(e.baseline).toBe(canonical({ A: ["1.2.3.4"], NS: ["ns1.x"] }));
  });

  it("is quiet when nothing changed, regardless of record order", () => {
    const baseline = canonical({ A: ["1.2.3.4", "5.6.7.8"] });
    const e = evaluate(m, dns({ A: ["5.6.7.8", "1.2.3.4"] }), baseline);
    expect(e.verdict).toMatchObject({ status: "ok", detail: { changed: false } });
  });

  it("warns once with the exact difference, then accepts the new records", () => {
    const baseline = canonical({ A: ["1.2.3.4"], NS: ["ns1.x"] });
    const changed = evaluate(m, dns({ A: ["9.9.9.9"], NS: ["ns1.x"] }), baseline);
    expect(changed.verdict).toMatchObject({ status: "warn", detail: { changed: true } });
    expect(changed.verdict.summary).toContain("A: +9.9.9.9 -1.2.3.4");
    expect(changed.verdict.summary).not.toContain("NS:"); // NS did not change
    // Next check sees the same records against the new baseline: no longer a change.
    expect(evaluate(m, dns({ A: ["9.9.9.9"], NS: ["ns1.x"] }), changed.baseline!).verdict.status).toBe("ok");
  });

  it("an unreadable baseline counts everything as added instead of crashing", () => {
    const e = evaluate(m, dns({ A: ["1.2.3.4"] }), "not json");
    expect(e.verdict.status).toBe("warn");
    expect(e.verdict.summary).toContain("+1.2.3.4");
  });

  it("a domain with no records at all is a failure that does not touch the baseline", () => {
    const e = evaluate(m, dns({}), canonical({ A: ["1.2.3.4"] }));
    expect(e.verdict).toMatchObject({ status: "fail", summary: "The domain has no DNS records" });
    expect(e.baseline).toBeUndefined();
  });
});

describe("mail verdicts", () => {
  const m = monitor({ kind: "mail", target: "example.test" });
  const mail = (detail: Record<string, unknown>) => observation({ detail: { spf: "v=spf1 -all", spfRecords: 1, spfAll: "-", dmarc: "v=DMARC1; p=reject", dmarcRecords: 1, dmarcPolicy: "reject", ...detail } });

  it("is ok with SPF and an enforcing DMARC", () => {
    expect(evaluate(m, mail({}), null).verdict).toMatchObject({ status: "ok", summary: expect.stringContaining("p=reject") });
  });

  it("fails on missing or duplicated records", () => {
    expect(evaluate(m, mail({ spf: null }), null).verdict.summary).toMatch(/no SPF/);
    expect(evaluate(m, mail({ dmarc: null, dmarcPolicy: null }), null).verdict.summary).toMatch(/no DMARC/);
    expect(evaluate(m, mail({ spfRecords: 2 }), null).verdict.summary).toMatch(/several SPF/);
    expect(evaluate(m, mail({ dmarcRecords: 2 }), null).verdict.summary).toMatch(/several DMARC/);
    expect(evaluate(m, mail({ dmarcPolicy: null }), null).verdict.summary).toMatch(/without a policy/);
    expect(evaluate(m, mail({ spf: null, dmarc: null, dmarcPolicy: null }), null).verdict.summary).toMatch(/no SPF record, no DMARC record/);
  });

  it("warns on weak but present records", () => {
    expect(evaluate(m, mail({ dmarcPolicy: "none" }), null).verdict).toMatchObject({ status: "warn", summary: expect.stringMatching(/p=none/) });
    expect(evaluate(m, mail({ spfAll: "+" }), null).verdict.status).toBe("warn");
    expect(evaluate(m, mail({ spfAll: "?" }), null).verdict.status).toBe("warn");
    expect(evaluate(m, mail({ spfAll: null }), null).verdict.summary).toMatch(/no `all`/);
    expect(evaluate(m, mail({ spfAll: "~", dmarcPolicy: "quarantine" }), null).verdict.status).toBe("ok");
  });
});
