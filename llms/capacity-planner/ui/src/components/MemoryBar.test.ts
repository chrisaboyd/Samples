// Geometry tests for the stacked memory-composition bar (PRD §22.1).
//
// The bar previously passed segment *widths* into CSS gradient *stop positions*.
// Browsers clamp a stop that precedes its predecessor, so the slices silently
// reordered: with weights 43% and KV 56%, KV collapsed to a thin band while a
// 0.3% "free" slice rendered as ~44% of the bar. Nothing failed — it just drew
// the wrong picture, which is exactly what a unit test on the gradient catches.

import { describe, expect, it } from "vitest";
import { stackGradient } from "./MemoryBar";

const identity = (v: number) => v;

/** Extract the numeric stop positions, in order, from a linear-gradient(). */
function stops(gradient: string): number[] {
  return [...gradient.matchAll(/([\d.]+)%/g)].map((m) => Number(m[1]));
}

describe("stackGradient", () => {
  const segments = [
    { label: "Weights", value: 43.38, color: "#7c3aed" },
    { label: "Runtime", value: 0.66, color: "#6b7280" },
    { label: "KV", value: 55.68, color: "#3b82f6" },
    { label: "Free", value: 0.27, color: "#22c55e" },
  ];

  it("emits monotonically non-decreasing stop positions", () => {
    const positions = stops(stackGradient(segments, identity));
    for (let i = 1; i < positions.length; i++) {
      expect(
        positions[i],
        `stop ${i} (${positions[i]}%) precedes stop ${i - 1} (${positions[i - 1]}%)`,
      ).toBeGreaterThanOrEqual(positions[i - 1]);
    }
  });

  it("gives each segment a width equal to its value", () => {
    const positions = stops(stackGradient(segments, identity));
    // Two stops per segment: [start, end, start, end, ...].
    segments.forEach((seg, i) => {
      const width = positions[i * 2 + 1] - positions[i * 2];
      expect(width).toBeCloseTo(seg.value, 6);
    });
  });

  it("renders hard edges, not blends, by doubling each boundary stop", () => {
    const gradient = stackGradient(segments, identity);
    // Each colour must appear exactly twice — once opening, once closing.
    for (const seg of segments) {
      const occurrences = gradient.split(seg.color).length - 1;
      expect(occurrences, `${seg.label} should have 2 stops`).toBe(2);
    }
  });

  it("keeps the largest segment visually largest", () => {
    // The specific regression: KV (55.68) must not render smaller than Free (0.27).
    const positions = stops(stackGradient(segments, identity));
    const kvWidth = positions[5] - positions[4];
    const freeWidth = positions[7] - positions[6];
    expect(kvWidth).toBeGreaterThan(freeWidth);
  });
});
