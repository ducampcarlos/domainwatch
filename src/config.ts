/** Runtime configuration from the environment. Invalid values stop start-up with a clear message. */

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  /** Bearer token for the API and dashboard. */
  token: string;
  /** Webhook URLs notified on every alert. */
  webhooks: string[];
  /** Allow monitoring loopback and private addresses (off by default). */
  allowPrivate: boolean;
  retentionDays: number;
  concurrency: number;
  /** Maximum number of monitors. */
  maxMonitors: number;
}

type Env = Record<string, string | undefined>;

const int = (env: Env, name: string, fallback: number, min: number, max: number): number => {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} must be an integer between ${min} and ${max} (got "${raw}")`);
  return value;
};

export function loadConfig(env: Env = process.env, options: { requireToken?: boolean } = {}): Config {
  const token = env.DOMAINWATCH_TOKEN ?? "";
  if ((options.requireToken ?? true) && token.length < 16) {
    throw new Error("DOMAINWATCH_TOKEN must be set to a secret of at least 16 characters. Generate one with: openssl rand -hex 32");
  }
  const webhooks = (env.DOMAINWATCH_WEBHOOKS ?? "")
    .split(",")
    .map((url) => url.trim())
    .filter(Boolean);
  for (const url of webhooks) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("not http(s)");
    } catch {
      throw new Error(`DOMAINWATCH_WEBHOOKS contains an invalid URL: "${url.slice(0, 80)}"`);
    }
  }
  return {
    host: env.HOST || "127.0.0.1",
    port: int(env, "PORT", 8787, 1, 65535),
    dataDir: env.DOMAINWATCH_DATA || "./data",
    token,
    webhooks,
    allowPrivate: ["1", "true", "yes", "on"].includes((env.DOMAINWATCH_ALLOW_PRIVATE ?? "").toLowerCase()),
    retentionDays: int(env, "DOMAINWATCH_RETENTION_DAYS", 30, 1, 3650),
    concurrency: int(env, "DOMAINWATCH_CONCURRENCY", 4, 1, 32),
    maxMonitors: int(env, "DOMAINWATCH_MAX_MONITORS", 200, 1, 5000),
  };
}
