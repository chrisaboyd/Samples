// Range formatting. Fixed 1-decimal output rendered the step-latency range
// (~0.001 s) as "0.0–0.0 seconds" on screen — a real number, displayed as
// nothing. These pin the magnitudes the result view actually produces.

import { describe, expect, it } from "vitest";
import { formatRange, formatVerdict } from "./App";
import type { Range, Verdict } from "./types";

describe("formatVerdict", () => {
  it("replaces every underscore, not just the first", () => {
    // `replace` left this as "does not_fit" on screen.
    expect(formatVerdict("does_not_fit")).toBe("does not fit");
  });

  it("passes through single-word verdicts unchanged", () => {
    const single: Verdict[] = ["comfortable", "constrained", "unsupported"];
    for (const v of single) expect(formatVerdict(v)).toBe(v);
  });
});

const r = (min: number, max: number, unit: string): Range => ({ min, max, unit });

describe("formatRange", () => {
  it("renders sub-second durations in milliseconds", () => {
    // The exact regression: golden Laguna/B200 step latency.
    const out = formatRange(r(0.0009728299847847513, 0.0017024524733733146, "seconds"));
    expect(out).toBe("0.973–1.70 ms");
    expect(out).not.toContain("0.0–0.0");
  });

  it("keeps seconds for durations at or above one second", () => {
    expect(formatRange(r(1.04, 2.24, "seconds"))).toBe("1.04–2.24 seconds");
  });

  it("drops decimals on large throughput figures and groups thousands", () => {
    expect(formatRange(r(47225.1, 102321.06, "tokens/s"))).toBe("47,225–102,321 tokens/s");
  });

  it("keeps precision on small throughput figures", () => {
    expect(formatRange(r(45.3, 78.4, "tokens/s"))).toBe("45.3–78.4 tokens/s");
  });

  it("renders an em dash for an absent range", () => {
    expect(formatRange(null)).toBe("—");
  });

  it("never collapses a non-zero value to zero", () => {
    // Any positive input must render with at least one significant digit.
    for (const v of [0.0001, 0.001, 0.01, 0.1, 1, 10, 100, 1e6]) {
      const out = formatRange(r(v, v * 2, "tokens/s"));
      expect(out, `input ${v} formatted as ${out}`).not.toMatch(/^0(\.0+)?–/);
    }
  });
});
