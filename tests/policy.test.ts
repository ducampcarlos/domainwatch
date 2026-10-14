import { describe, expect, it } from "vitest";

import { PolicyError, TargetPolicy, isPublicAddress, normalizeHost, parseIPv4, parseIPv6 } from "../src/net/policy.js";
import { parseHostPort } from "../src/checks/deps.js";

describe("address classification", () => {
  const blocked = [
    "127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1",
    "255.255.255.255", "240.0.0.1", "198.18.0.1", "192.0.2.5", "198.51.100.5", "203.0.113.5",
    "::", "::1", "fe80::1", "fc00::1", "fd00::1", "ff02::1", "2001:db8::1", "2001::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:169.254.169.254", "64:ff9b::7f00:1", "2002:7f00:1::1", "::127.0.0.1",
  ];
  const allowed = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.15.255.255", "172.32.0.1", "100.63.255.255", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1"];

  it.each(blocked)("blocks %s", (address) => expect(isPublicAddress(address), address).toBe(false));
  it.each(allowed)("allows %s", (address) => expect(isPublicAddress(address), address).toBe(true));

  it("never treats garbage as public", () => {
    for (const bad of ["", "localhost", "example.com", "1.2.3", "999.1.1.1", "01.2.3.4", "::g", "1:2:3"]) expect(isPublicAddress(bad), bad).toBe(false);
  });

  it("parses strictly", () => {
    expect(parseIPv4("1.2.3.4")).toBe(16909060);
    expect(parseIPv4("1.2.3.04")).toBeNull();
    expect(parseIPv6("::1")).toBe(1n);
    expect(parseIPv6("::ffff:127.0.0.1")).toBe(0xffff7f000001n);
    expect(parseIPv6("1::2::3")).toBeNull();
  });
});

describe("normalizeHost and parseHostPort", () => {
  it("normalises names and numeric IP tricks", () => {
    expect(normalizeHost("Example.COM.")).toBe("example.com");
    expect(normalizeHost("2130706433")).toBe("127.0.0.1");
    expect(normalizeHost("[::1]")).toBe("::1");
  });

  it.each(["", "a b", "x.com/path", "u@x.com", "x.com?q", "x.com#f", "host:80", "host:8080", "host:443", "host:"])("rejects %j", (input) => {
    expect(() => normalizeHost(input)).toThrow(PolicyError);
  });

  it("splits host and port", () => {
    expect(parseHostPort("Example.com", 443)).toEqual({ host: "example.com", port: 443 });
    expect(parseHostPort("example.com:8443", 443)).toEqual({ host: "example.com", port: 8443 });
    expect(parseHostPort("[::1]:9443", 443)).toEqual({ host: "::1", port: 9443 });
    expect(parseHostPort("[::1]", 443)).toEqual({ host: "::1", port: 443 });
    expect(parseHostPort("2001:db8::1", 443)).toEqual({ host: "2001:db8::1", port: 443 });
    expect(() => parseHostPort("x.com:99999", 443)).toThrow(/port/);
    expect(() => parseHostPort("x.com:abc", 443)).toThrow(/port/);
  });
});

describe("TargetPolicy", () => {
  const table: Record<string, string[]> = { "ok.test": ["93.184.216.34"], "mixed.test": ["93.184.216.34", "10.0.0.5"], "private.test": ["192.168.0.9"] };
  const lookup = async (host: string) => {
    if (!table[host]) throw Object.assign(new Error("x"), { code: "ENOTFOUND" });
    return table[host]!;
  };

  it("resolves public hosts", async () => {
    expect(await new TargetPolicy(false, lookup).resolve("ok.test")).toEqual(["93.184.216.34"]);
  });

  it("blocks private resolutions, even if only one record is private", async () => {
    const policy = new TargetPolicy(false, lookup);
    await expect(policy.resolve("private.test")).rejects.toThrow(/192\.168\.0\.9/);
    await expect(policy.resolve("mixed.test")).rejects.toThrow(/10\.0\.0\.5/);
    await expect(policy.resolve("127.0.0.1")).rejects.toThrow(/special-purpose/);
    await expect(policy.resolve("169.254.169.254")).rejects.toBeInstanceOf(PolicyError);
  });

  it("blocks internal-looking names before any DNS query", async () => {
    const policy = new TargetPolicy(false, async () => {
      throw new Error("must not look up");
    });
    for (const name of ["localhost", "nas.local", "db.internal", "x.corp", "printer.lan"]) await expect(policy.resolve(name), name).rejects.toThrow(/internal name/);
  });

  it("reports DNS failures and lets operators opt in to private targets", async () => {
    await expect(new TargetPolicy(false, lookup).resolve("nope.test")).rejects.toThrow(/Could not resolve nope.test \(ENOTFOUND\)/);
    await expect(new TargetPolicy(false, async () => []).resolve("empty.test")).rejects.toThrow(/no A\/AAAA/);
    const open = new TargetPolicy(true, lookup);
    expect(await open.resolve("private.test")).toEqual(["192.168.0.9"]);
    expect(await open.resolve("127.0.0.1")).toEqual(["127.0.0.1"]);
    expect(() => open.checkName("localhost")).not.toThrow();
  });
});

describe("normalizeHost with IPv6 literals", () => {
  it("accepts bare and bracketed IPv6 and keeps rejecting ports", () => {
    expect(normalizeHost("2001:DB8::1")).toBe("2001:db8::1");
    expect(normalizeHost("[2001:db8::1]")).toBe("2001:db8::1");
    expect(() => normalizeHost("[2001:db8::1]:443")).toThrow(/port/i);
    expect(() => normalizeHost("2001:db8::zz")).toThrow(/valid host/);
  });
});
