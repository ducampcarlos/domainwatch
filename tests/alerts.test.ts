import { describe, expect, it } from "vitest";

import { DEFAULT_RULES, advance, duration } from "../src/engine/alerts.js";
import type { MonitorState, Verdict } from "../src/types.js";
import { verdict } from "./helpers.js";

const m = { id: 1, name: "Site", kind: "http" as const, target: "https://x.test/" };
const rules = { failThreshold: 2, renotifyAfterS: 3600 };

/** Feed a sequence of [time, verdict] pairs through the machine and collect what it said. */
function run(steps: Array<[number, Verdict]>, start: MonitorState | null = null) {
  let state = start;
  const log: Array<{ t: number; kinds: string[]; status: string }> = [];
  for (const [t, v] of steps) {
    const transition = advance(state, m, v, t, undefined, rules);
    state = transition.state;
    log.push({ t, kinds: transition.alerts.map((a) => a.kind), status: state.status });
  }
  return { state: state!, log };
}

describe("alert state machine", () => {
  it("stays silent while everything is fine", () => {
    const { log } = run([[0, verdict("ok")], [60, verdict("ok")], [120, verdict("ok")]]);
    expect(log.flatMap((l) => l.kinds)).toEqual([]);
  });

  it("does not page on a single failure, only on the second consecutive one", () => {
    const { log } = run([[0, verdict("ok")], [60, verdict("fail", "timeout")], [120, verdict("fail", "timeout")]]);
    expect(log[1]).toMatchObject({ kinds: [], status: "ok" });
    expect(log[2]).toMatchObject({ kinds: ["down"], status: "fail" });
  });

  it("a success in between resets the failure count", () => {
    const { log } = run([[0, verdict("fail")], [60, verdict("ok")], [120, verdict("fail")], [180, verdict("ok")]]);
    expect(log.flatMap((l) => l.kinds)).toEqual([]);
  });

  it("announces the recovery once, with the downtime", () => {
    const steps: Array<[number, Verdict]> = [[0, verdict("fail")], [60, verdict("fail")], [120, verdict("fail")], [660, verdict("ok", "HTTP 200")]];
    const { log, state } = run(steps);
    expect(log[3]!.kinds).toEqual(["recovered"]);
    expect(state).toMatchObject({ status: "ok", failures: 0 });
    const message = advance(run(steps.slice(0, 3)).state, m, verdict("ok", "HTTP 200"), 660, undefined, rules).alerts[0]!.message;
    expect(message).toMatch(/^\[RECOVERED\] Site \(http https:\/\/x.test\/\) after 10m: HTTP 200$/);
  });

  it("repeats the alert for a long outage only after the renotify interval", () => {
    const down = verdict("fail", "refused");
    const steps: Array<[number, Verdict]> = [[0, down], [60, down], [120, down], [1000, down], [3000, down], [3660, down], [7000, down], [7300, down]];
    const kinds = run(steps).log.map((l) => l.kinds[0] ?? "-");
    expect(kinds).toEqual(["-", "down", "-", "-", "-", "still_down", "-", "still_down"]);
  });

  it("announces a warning once and is quiet when it clears", () => {
    const { log } = run([[0, verdict("ok")], [60, verdict("warn", "expires soon")], [120, verdict("warn", "expires soon")], [180, verdict("ok")]]);
    expect(log.map((l) => l.kinds)).toEqual([[], ["warning"], [], []]);
  });

  it("goes warn -> fail -> warn and announces both transitions that matter", () => {
    const { log } = run([[0, verdict("warn")], [60, verdict("fail")], [120, verdict("fail")], [180, verdict("warn")]]);
    expect(log.map((l) => l.kinds)).toEqual([["warning"], [], ["down"], ["recovered"]]);
  });

  it("certificate problems skip the failure threshold", () => {
    const expired = verdict("fail", "Certificate expired 1 day ago", { immediate: true });
    expect(advance(null, m, expired, 0, undefined, rules).alerts.map((a) => a.kind)).toEqual(["down"]);
    const slow = advance(null, m, verdict("fail", "refused"), 0, undefined, rules);
    expect(slow.alerts).toEqual([]);
    expect(slow.state.failures).toBe(1);
  });

  it("a monitor that is already failing on its first ever result and warns is handled", () => {
    expect(advance(null, m, verdict("warn", "w"), 5, undefined, rules).alerts.map((a) => a.kind)).toEqual(["warning"]);
    expect(advance(null, m, verdict("ok"), 5, undefined, rules).alerts).toEqual([]);
  });

  it("DNS: a second change while still in the warn state is announced again", () => {
    const changed = (s: string) => verdict("warn", s, { changed: true });
    const { log } = run([[0, changed("A: +1.1.1.1")], [60, changed("A: +2.2.2.2")], [120, verdict("warn", "plain warning")]]);
    expect(log.map((l) => l.kinds)).toEqual([["warning"], ["warning"], []]);
  });

  it("tracks since, lastAlertTs and the baseline", () => {
    const first = advance(null, m, verdict("ok"), 100, "BASE", rules);
    expect(first.state).toMatchObject({ since: 100, lastAlertTs: 0, baseline: "BASE" });
    const second = advance(first.state, m, verdict("ok"), 160, undefined, rules);
    expect(second.state.baseline).toBe("BASE"); // undefined means "keep it"
    const cleared = advance(second.state, m, verdict("ok"), 220, null, rules);
    expect(cleared.state.baseline).toBeNull();
    const down = advance(advance(cleared.state, m, verdict("fail"), 280, undefined, rules).state, m, verdict("fail"), 340, undefined, rules);
    expect(down.state).toMatchObject({ status: "fail", since: 340, lastAlertTs: 340 });
  });

  it("messages name the monitor, its kind and target", () => {
    const t = advance(null, m, verdict("fail", "x", { immediate: true }), 0, undefined, rules);
    expect(t.alerts[0]!.message).toBe("[DOWN] Site (http https://x.test/): x");
  });

  it("formats durations sensibly", () => {
    expect([30, 89, 90, 600, 5399, 5400, 7200, 100_000, 172_800, 500_000].map(duration)).toEqual(["30s", "89s", "2m", "10m", "90m", "2h", "2h", "28h", "2d", "6d"]);
    expect(duration(-5)).toBe("0s");
  });

  it("has sensible defaults", () => {
    expect(DEFAULT_RULES).toEqual({ failThreshold: 2, renotifyAfterS: 21_600 });
  });
});
