import { describe, expect, it } from "vitest";

import { EXIT, UsageError, checkOnce, formatVerdict, parseArgs } from "../src/cli.js";
import { FakeDns, deps, startServer } from "./helpers.js";

const parse = (...args: string[]) => parseArgs(args);

describe("parseArgs", () => {
  it("recognises help, version and serve", () => {
    expect(parse()).toEqual({ name: "help" });
    expect(parse("--help")).toEqual({ name: "help" });
    expect(parse("-v")).toEqual({ name: "version" });
    expect(parse("serve")).toEqual({ name: "serve" });
  });

  it("parses a check with options in any position", () => {
    expect(parse("check", "tls", "example.com:8443", "--warn-days", "30", "--json")).toEqual({
      name: "check", kind: "tls", target: "example.com:8443", json: true, allowPrivate: false, config: { warnDays: 30 },
    });
    expect(parse("check", "--expect", "200,204", "http", "https://x.test/", "--allow-private", "--timeout", "2000")).toMatchObject({
      kind: "http", allowPrivate: true, config: { expectStatus: [200, 204], timeoutMs: 2000 },
    });
  });

  it("reports mistakes as usage errors", () => {
    const bad: string[][] = [
      ["nope"], ["serve", "extra"], ["check"], ["check", "ping", "x"], ["check", "tls"], ["check", "tls", "a", "b"],
      ["check", "tls", "a", "--bogus"], ["check", "tls", "a", "--warn-days"], ["check", "tls", "a", "--warn-days", "x"],
      ["check", "http", "u", "--expect", "20x"], ["check", "http", "u", "--expect"],
    ];
    for (const args of bad) expect(() => parseArgs(args), args.join(" ")).toThrow(UsageError);
  });
});

describe("checkOnce", () => {
  it("judges an http check and maps the verdict to an exit status", async () => {
    const s = await startServer((_req, res) => void res.writeHead(503).end());
    try {
      const cmd = parse("check", "http", `http://public.test:${s.port}/`) as Parameters<typeof checkOnce>[1];
      const verdict = await checkOnce(deps(), cmd);
      expect(verdict.status).toBe("fail");
      expect(verdict.summary).toMatch(/HTTP 503/);
      expect(EXIT[verdict.status]).toBe(2);
      const ok = await checkOnce(deps(), { ...cmd, config: { expectStatus: [503] } });
      expect(ok.status).toBe("ok");
      expect(EXIT.ok).toBe(0);
      expect(EXIT.warn).toBe(1);
    } finally {
      await s.close();
    }
  });

  it("checks mail and dns against a resolver", async () => {
    const dns = new FakeDns({ "x.test": { A: ["93.184.216.34"], TXT: ["v=spf1 -all"] }, "_dmarc.x.test": { TXT: ["v=DMARC1; p=reject"] } });
    expect((await checkOnce(deps({ dns }), parse("check", "mail", "x.test") as never)).status).toBe("ok");
    const first = await checkOnce(deps({ dns }), parse("check", "dns", "x.test") as never);
    expect(first.summary).toMatch(/Baseline recorded/);
  });

  it("refuses options that do not apply and invalid targets", async () => {
    await expect(checkOnce(deps(), parse("check", "dns", "x.test", "--warn-days", "3") as never)).rejects.toThrow(/--warn-days does not apply to dns/);
    await expect(checkOnce(deps(), parse("check", "http", "ftp://x") as never)).rejects.toThrow(UsageError);
    await expect(checkOnce(deps(), parse("check", "tls", "x.test", "--warn-days", "3", "--fail-days", "9") as never)).rejects.toThrow(/smaller/);
  });

  it("does not let the CLI reach private addresses unless asked", async () => {
    const verdict = await checkOnce(deps(), parse("check", "http", "http://internal.test/") as never);
    expect(verdict.status).toBe("fail");
    expect(verdict.summary).toMatch(/10\.0\.0\.5/);
  });
});

describe("formatVerdict", () => {
  const cmd = parse("check", "tls", "x.test") as Extract<ReturnType<typeof parseArgs>, { name: "check" }>;
  const v = { status: "warn" as const, summary: "Certificate expires in 5 days", metrics: {}, detail: {} };
  it("prints one readable line, with or without colour", () => {
    expect(formatVerdict(cmd, v, false)).toBe("WARN tls x.test: Certificate expires in 5 days");
    expect(formatVerdict(cmd, v, true)).toBe("\u001b[33mWARN\u001b[0m tls x.test: Certificate expires in 5 days");
  });
  it("prints JSON on request", () => {
    expect(JSON.parse(formatVerdict({ ...cmd, json: true }, v, false))).toMatchObject({ kind: "tls", target: "x.test", status: "warn" });
  });
});
