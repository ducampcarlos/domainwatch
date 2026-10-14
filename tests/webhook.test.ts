import { describe, expect, it, vi } from "vitest";

import { buildPayload, sendWebhook, type Fetch } from "../src/notify/webhook.js";
import { monitor } from "./helpers.js";

const payload = buildPayload({ kind: "down", ts: 5, message: "[DOWN] Example (http https://example.test/): HTTP 503" }, monitor());
const instant = async () => undefined;

describe("webhook payload", () => {
  it("works for chat tools and scripts", () => {
    expect(payload.text).toBe(payload.event.message);
    expect(payload.content).toBe(payload.text);
    expect(payload.event).toMatchObject({ kind: "down", ts: 5, monitor: { id: 1, name: "Example", kind: "http", target: "https://example.test/" } });
  });

  it("trims content to Discord's limit", () => {
    const long = buildPayload({ kind: "down", ts: 1, message: "x".repeat(5000) }, monitor());
    expect(long.content).toHaveLength(1900);
    expect(long.text).toHaveLength(5000);
  });
});

describe("sendWebhook", () => {
  it("posts JSON and reports success", async () => {
    const calls: Array<{ url: string; init: Parameters<Fetch>[1] }> = [];
    const fetchImpl: Fetch = async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 200 };
    };
    expect(await sendWebhook("https://hooks.test/x", payload, { fetchImpl, sleep: instant })).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(calls[0]!.init.body)).toEqual(JSON.parse(JSON.stringify(payload)));
  });

  it("retries server errors and network failures with growing delays, then succeeds", async () => {
    const delays: number[] = [];
    const fetchImpl = vi.fn<Fetch>().mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce({ ok: false, status: 503 }).mockResolvedValueOnce({ ok: true, status: 200 });
    expect(await sendWebhook("https://h.test/", payload, { fetchImpl, sleep: async (ms) => void delays.push(ms), backoffMs: 100 })).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(delays).toEqual([100, 200]);
  });

  it("gives up after the configured attempts", async () => {
    const fetchImpl = vi.fn<Fetch>().mockResolvedValue({ ok: false, status: 500 });
    expect(await sendWebhook("https://h.test/", payload, { fetchImpl, sleep: instant, attempts: 2 })).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("does not retry a client error, which will not fix itself, but does retry 429", async () => {
    const gone = vi.fn<Fetch>().mockResolvedValue({ ok: false, status: 404 });
    expect(await sendWebhook("https://h.test/", payload, { fetchImpl: gone, sleep: instant })).toBe(false);
    expect(gone).toHaveBeenCalledTimes(1);
    const limited = vi.fn<Fetch>().mockResolvedValueOnce({ ok: false, status: 429 }).mockResolvedValueOnce({ ok: true, status: 200 });
    expect(await sendWebhook("https://h.test/", payload, { fetchImpl: limited, sleep: instant })).toBe(true);
    expect(limited).toHaveBeenCalledTimes(2);
  });

  it("never throws, even if fetch does", async () => {
    const fetchImpl: Fetch = async () => {
      throw new TypeError("fetch failed");
    };
    await expect(sendWebhook("https://h.test/", payload, { fetchImpl, sleep: instant })).resolves.toBe(false);
  });
});
