import type { Monitor, Observation } from "../types.js";
import type { CheckDeps } from "./deps.js";
import { observeDns } from "./dns.js";
import { observeHttp } from "./http.js";
import { observeMail } from "./mail.js";
import { observeTls } from "./tls.js";

export const DEFAULT_TIMEOUT_MS = 10_000;

/** Run the check a monitor describes. Never throws: failures become an Observation with an error. */
export async function runCheck(deps: CheckDeps, monitor: Monitor): Promise<Observation> {
  const timeoutMs = monitor.config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  try {
    switch (monitor.kind) {
      case "tls":
        return await observeTls(deps, monitor.target, timeoutMs);
      case "http":
        return await observeHttp(deps, monitor.target, timeoutMs);
      case "dns":
        return await observeDns(deps, monitor.target);
      case "mail":
        return await observeMail(deps, monitor.target);
    }
  } catch (error) {
    return { error: `Unexpected error: ${error instanceof Error ? error.message.slice(0, 150) : String(error)}`, metrics: {}, detail: {} };
  }
}
