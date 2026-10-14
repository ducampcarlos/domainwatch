import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { observeDns } from "../src/checks/dns.js";
import { observeHttp } from "../src/checks/http.js";
import { runCheck } from "../src/checks/index.js";
import { observeMail } from "../src/checks/mail.js";
import { observeTls } from "../src/checks/tls.js";
import { parseHostPort } from "../src/checks/deps.js";
import { makeIdentity, startTlsServer, trustRoots } from "./certs.js";
import { FakeDns, deps, monitor, startServer, type TestServer } from "./helpers.js";

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()));
});
const serve = async (handler: Parameters<typeof startServer>[0]): Promise<TestServer> => {
  const s = await startServer(handler);
  closers.push(s.close);
  return s;
};

describe("parseHostPort", () => {
  it("handles hosts, ports and IPv6 literals", () => {
    expect(parseHostPort("Example.COM.", 443)).toEqual({ host: "example.com", port: 443 });
    expect(parseHostPort("example.com:8443", 443)).toEqual({ host: "example.com", port: 8443 });
    expect(parseHostPort("[::1]:9", 443)).toEqual({ host: "::1", port: 9 });
    expect(parseHostPort("[2001:db8::1]", 443)).toEqual({ host: "2001:db8::1", port: 443 });
    expect(() => parseHostPort("example.com:99999", 443)).toThrow(/port/i);
    expect(() => parseHostPort("example.com:abc", 443)).toThrow(/port/i);
  });
});

describe("http check", () => {
  it("reports status, latency and redirect count", async () => {
    const s = await serve((req, res) => {
      if (req.url === "/old") return void res.writeHead(301, { location: "/new" }).end();
      res.writeHead(200).end("hello");
    });
    const obs = await observeHttp(deps(), `http://public.test:${s.port}/old`, 5000);
    expect(obs.error).toBeUndefined();
    expect(obs.metrics).toMatchObject({ status_code: 200, redirects: 1 });
    expect(obs.detail).toMatchObject({ statusCode: 200, finalUrl: `http://public.test:${s.port}/new` });
  });

  it("returns the final non-2xx status for the judge to decide", async () => {
    const s = await serve((_req, res) => void res.writeHead(503).end());
    const obs = await observeHttp(deps(), `http://public.test:${s.port}/`, 5000);
    expect(obs.metrics.status_code).toBe(503);
  });

  it("fails on a redirect loop, on too many redirects and on a bad redirect target", async () => {
    const loop = await serve((_req, res) => void res.writeHead(302, { location: "/" }).end());
    expect((await observeHttp(deps(), `http://public.test:${loop.port}/`, 5000)).error).toBe("redirect loop");
    const chain = await serve((req, res) => {
      const n = Number(req.url!.slice(1)) || 0;
      res.writeHead(302, { location: `/${n + 1}` }).end();
    });
    expect((await observeHttp(deps(), `http://public.test:${chain.port}/`, 5000)).error).toMatch(/more than 5 redirects/);
  });

  it("refuses a redirect into the private network (SSRF through a redirect)", async () => {
    const s = await serve((_req, res) => void res.writeHead(302, { location: "http://meta.test/latest/meta-data/" }).end());
    const obs = await observeHttp(deps(), `http://public.test:${s.port}/`, 5000);
    expect(obs.error).toMatch(/169\.254\.169\.254/);
    expect(obs.metrics).toEqual({});
  });

  it("refuses private targets up front, and allows them with the opt-in", async () => {
    expect((await observeHttp(deps(), "http://internal.test/", 1000)).error).toMatch(/10\.0\.0\.5/);
    expect((await observeHttp(deps(), "http://127.0.0.1/", 1000)).error).toMatch(/127\.0\.0\.1/);
    expect((await observeHttp(deps(), "http://[::1]/", 1000)).error).toMatch(/::1/);
    const s = await serve((_req, res) => void res.writeHead(204).end());
    const obs = await observeHttp(deps({ allowPrivate: true }), `http://internal.test:${s.port}/`, 5000);
    expect(obs.metrics.status_code).toBe(204);
  });

  it("rejects other schemes and credentials in the URL", async () => {
    expect((await observeHttp(deps(), "ftp://public.test/", 1000)).error).toMatch(/only http/);
    expect((await observeHttp(deps(), "http://user:pw@public.test/", 1000)).error).toMatch(/credentials/);
    expect((await observeHttp(deps(), "not a url", 1000)).error).toBeDefined();
  });

  it("describes connection failures and timeouts without leaking internals", async () => {
    const s = await serve((_req, res) => void res.writeHead(200).end());
    const port = s.port;
    await s.close();
    closers.length = 0;
    expect((await observeHttp(deps(), `http://public.test:${port}/`, 2000)).error).toBe("connection refused");
    const hang = await serve(() => undefined);
    const obs = await observeHttp(deps(), `http://public.test:${hang.port}/`, 1000);
    expect(obs.error).toBe("timed out");
    expect(obs.latencyMs).toBeGreaterThanOrEqual(900);
  });

  it("does not read the body (a huge response costs nothing)", async () => {
    const s = await serve((_req, res) => {
      res.writeHead(200, { "content-length": "1000000000" });
      res.write("x");
    });
    const obs = await observeHttp(deps(), `http://public.test:${s.port}/`, 5000);
    expect(obs.metrics.status_code).toBe(200);
  });
});

describe("tls check", () => {
  let root: ReturnType<typeof makeIdentity>;
  let restore: () => void;
  beforeAll(() => {
    root = makeIdentity({ cn: "Test Root", isCA: true, expiresInDays: 3650 });
    restore = trustRoots(root);
    return () => restore();
  });

  it("reads expiry, names and trust from a good certificate", async () => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root, expiresInDays: 40 });
    const s = await startTlsServer({ leaf });
    closers.push(s.close);
    const obs = await observeTls(deps(), `public.test:${s.port}`, 5000);
    expect(obs.error).toBeUndefined();
    expect(obs.metrics.days_remaining).toBeGreaterThanOrEqual(39);
    expect(obs.metrics.days_remaining).toBeLessThanOrEqual(40);
    expect(obs.detail).toMatchObject({ hostnameMatches: true, trusted: true, selfSigned: false, host: "public.test" });
  });

  it("flags expired, mismatched, self-signed and untrusted certificates", async () => {
    const expired = await startTlsServer({ leaf: makeIdentity({ cn: "public.test", issuer: root, startsInDays: -30, expiresInDays: -2 }) });
    closers.push(expired.close);
    const e = await observeTls(deps(), `public.test:${expired.port}`, 5000);
    expect(e.metrics.days_remaining).toBeLessThan(0);
    expect(e.detail.trusted).toBe(false);

    const wrong = await startTlsServer({ leaf: makeIdentity({ cn: "other.test", issuer: root }) });
    closers.push(wrong.close);
    expect((await observeTls(deps(), `public.test:${wrong.port}`, 5000)).detail.hostnameMatches).toBe(false);

    const self = await startTlsServer({ leaf: makeIdentity({ cn: "public.test" }) });
    closers.push(self.close);
    const s = await observeTls(deps(), `public.test:${self.port}`, 5000);
    expect(s.detail).toMatchObject({ selfSigned: true, trusted: false });
  });

  it("reports a plain-TCP port and a closed port plainly", async () => {
    const plain = await serve((_req, res) => void res.end());
    expect((await observeTls(deps(), `public.test:${plain.port}`, 3000)).error).toMatch(/^(the server did not speak TLS on this port|TLS handshake failed \([a-z ]+\))$/);
    const closed = await serve(() => undefined);
    const port = closed.port;
    await closed.close();
    closers.length = 0;
    expect((await observeTls(deps(), `public.test:${port}`, 3000)).error).toMatch(/refused/);
  });

  it("applies the target policy", async () => {
    expect((await observeTls(deps(), "internal.test:443", 1000)).error).toMatch(/10\.0\.0\.5/);
    expect((await observeTls(deps(), "meta.test", 1000)).error).toMatch(/169\.254/);
    expect((await observeTls(deps(), "nowhere.test", 1000)).error).toMatch(/resolve/);
    expect((await observeTls(deps(), "bad host", 1000)).error).toBeDefined();
    expect((await observeTls(deps(), "public.test:0", 1000)).error).toMatch(/port/i);
  });
});

describe("dns and mail checks", () => {
  const table = {
    "example.test": { A: ["93.184.216.34"], NS: ["ns1.example.test", "ns2.example.test"], MX: ["10 mx.example.test"], TXT: ["v=spf1 include:_spf.example.test -all", "hello"] },
    "_dmarc.example.test": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.test"] },
  };

  it("snapshots records, ignoring failed record types", async () => {
    const dns = new FakeDns(table, { "AAAA example.test": "SERVFAIL" });
    const obs = await observeDns(deps({ dns }), "Example.Test");
    expect(obs.error).toBeUndefined();
    expect(obs.detail.snapshot).toEqual({ A: ["93.184.216.34"], NS: ["ns1.example.test", "ns2.example.test"], MX: ["10 mx.example.test"], TXT: ["hello", "v=spf1 include:_spf.example.test -all"] });
    expect(obs.metrics).toMatchObject({ record_count: 6, lookup_errors: 1 });
  });

  it("reports NXDOMAIN and total lookup failure", async () => {
    expect((await observeDns(deps({ dns: new FakeDns() }), "gone.test")).error).toMatch(/NXDOMAIN/);
    expect((await observeDns(deps({ dns: new FakeDns({}, { "gone.test": "SERVFAIL" }) }), "gone.test")).error).toMatch(/SERVFAIL/);
    expect((await observeDns(deps(), "localhost")).error).toMatch(/internal name/);
    expect((await observeDns(deps(), "host:53")).error).toMatch(/port/i);
  });

  it("reads SPF and DMARC", async () => {
    const obs = await observeMail(deps({ dns: new FakeDns(table) }), "example.test");
    expect(obs.metrics).toEqual({ spf: 1, dmarc: 1, dmarc_enforced: 1, mx_count: 1 });
    expect(obs.detail).toMatchObject({ spfAll: "-", dmarcPolicy: "reject", spfRecords: 1, dmarcRecords: 1 });
  });

  it("notices missing, weak and duplicated records", async () => {
    const weak = new FakeDns({ "weak.test": { TXT: ["v=spf1 +all", "v=spf1 -all"], MX: ["10 mx.weak.test"] }, "_dmarc.weak.test": { TXT: ["v=DMARC1; p=none"] } });
    const obs = await observeMail(deps({ dns: weak }), "weak.test");
    expect(obs.detail).toMatchObject({ spfRecords: 2, dmarcPolicy: "none" });
    expect(obs.metrics.dmarc_enforced).toBe(0);
    const bare = await observeMail(deps({ dns: new FakeDns({ "bare.test": { A: ["93.184.216.34"] } }) }), "bare.test");
    expect(bare.metrics).toMatchObject({ spf: 0, dmarc: 0 });
    expect((await observeMail(deps(), "gone.test")).error).toMatch(/NXDOMAIN/);
  });
});

describe("runCheck", () => {
  it("dispatches on kind and never throws", async () => {
    const dns = new FakeDns({ "example.test": { A: ["93.184.216.34"] } });
    const d = deps({ dns });
    expect((await runCheck(d, monitor({ kind: "dns", target: "example.test" }))).detail.snapshot).toEqual({ A: ["93.184.216.34"] });
    expect((await runCheck(d, monitor({ kind: "http", target: "garbage" }))).error).toBeDefined();
    const broken = { ...d, policy: { resolve: () => { throw new TypeError("oops"); }, checkName: () => undefined } } as unknown as typeof d;
    const obs = await runCheck(broken, monitor({ kind: "tls", target: "example.test" }));
    expect(obs.error).toBeDefined();
  });
});

describe("error text", () => {
  it("http to a plain port over https does not leak OpenSSL internals", async () => {
    const plain = await serve((_req, res) => void res.end());
    const obs = await observeHttp(deps(), `https://public.test:${plain.port}/`, 3000);
    expect(obs.error).toBeDefined();
    expect(obs.error).not.toMatch(/openssl|\.c:\d+|deps\//i);
  });
});
