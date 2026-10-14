/**
 * Webhook notifications. The JSON carries both `text` (Slack, Mattermost) and `content` (Discord)
 * plus a structured `event`, so the same URL works for chat tools and for scripts.
 * Failures are retried a couple of times and then reported, never thrown: a broken webhook must not
 * stop monitoring.
 */

import type { Alert, Monitor } from "../types.js";

export interface WebhookPayload {
  text: string;
  content: string;
  event: {
    kind: Alert["kind"];
    ts: number;
    message: string;
    monitor: Pick<Monitor, "id" | "name" | "kind" | "target">;
  };
}

export const buildPayload = (alert: Pick<Alert, "kind" | "ts" | "message">, monitor: Monitor): WebhookPayload => ({
  text: alert.message,
  content: alert.message.slice(0, 1900), // Discord's limit is 2000
  event: { kind: alert.kind, ts: alert.ts, message: alert.message, monitor: { id: monitor.id, name: monitor.name, kind: monitor.kind, target: monitor.target } },
});

export type Fetch = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal }) => Promise<{ ok: boolean; status: number }>;

export interface WebhookOptions {
  attempts?: number;
  timeoutMs?: number;
  backoffMs?: number;
  fetchImpl?: Fetch;
  sleep?: (ms: number) => Promise<void>;
}

/** Deliver a payload. Resolves true when the receiver accepted it, false after all attempts failed. */
export async function sendWebhook(url: string, payload: WebhookPayload, options: WebhookOptions = {}): Promise<boolean> {
  const { attempts = 3, timeoutMs = 5000, backoffMs = 500, fetchImpl = fetch as unknown as Fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = options;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const response = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "domainwatch/0.1" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (response.ok) return true;
      // A client error (bad URL, revoked hook) will not fix itself by retrying.
      if (response.status >= 400 && response.status < 500 && response.status !== 429) return false;
    } catch {
      /* network error or timeout: retry */
    }
    if (attempt < attempts) await sleep(backoffMs * 2 ** (attempt - 1));
  }
  return false;
}
