// Wire-contract tests for the `analyze` IPC call.
//
// The backend has its own test asserting that an `AnalyzeCommand` payload
// deserializes — but it hand-writes that payload, so it passed happily while the
// real frontend call was sending a differently-shaped object that Tauri rejected.
// These tests read the shape from the actual `analyzeArgs` used in production,
// which is the only place drift can be caught.

import { describe, expect, it } from "vitest";
import { analyzeArgs } from "./invoke";
import type { AnalyzeInput } from "../types";

const INPUT: AnalyzeInput = {
  configJson: "{}",
  gpu: "B200 SXM 180 GB",
  count: 1,
  tensorParallel: 1,
  weightPrecision: "nvfp4",
  kvPrecision: "fp8",
  avgContextTokens: 32768,
  maxContextTokens: 1048576,
  avgOutputTokens: 512,
  sloTargetSeconds: 10,
  isHypotheticalWeight: true,
};

// Mirrors the field list on the Rust `AnalyzeCommand` struct. Every one of these
// is `#[serde(deny_unknown_fields)]`-adjacent in practice: a missing field is a
// hard deserialization error at the IPC boundary, not a default.
const REQUIRED_FIELDS = [
  "configJson",
  "gpu",
  "count",
  "tensorParallel",
  "weightPrecision",
  "kvPrecision",
  "avgContextTokens",
  "maxContextTokens",
  "avgOutputTokens",
  "sloTargetSeconds",
  "isHypotheticalWeight",
] as const;

describe("analyzeArgs", () => {
  it("nests the payload under `cmd` to match the Rust parameter name", () => {
    // `fn analyze(cmd: AnalyzeCommand)` — Tauri keys arguments by parameter
    // name, so a flat payload fails with "missing required key cmd".
    const args = analyzeArgs(INPUT);
    expect(Object.keys(args)).toEqual(["cmd"]);
    expect(args.cmd).toBeTypeOf("object");
  });

  it("sends every field the backend requires", () => {
    const cmd = analyzeArgs(INPUT).cmd as Record<string, unknown>;
    for (const field of REQUIRED_FIELDS) {
      expect(cmd, `missing field \`${field}\``).toHaveProperty(field);
      expect(cmd[field], `\`${field}\` must not be undefined`).toBeDefined();
    }
  });

  it("sends no fields the backend does not know about", () => {
    const cmd = analyzeArgs(INPUT).cmd as Record<string, unknown>;
    expect(Object.keys(cmd).sort()).toEqual([...REQUIRED_FIELDS].sort());
  });

  it("forwards values verbatim rather than re-deriving them", () => {
    const cmd = analyzeArgs({
      ...INPUT,
      avgOutputTokens: 2048,
      sloTargetSeconds: 42.5,
    }).cmd as Record<string, unknown>;
    expect(cmd.avgOutputTokens).toBe(2048);
    expect(cmd.sloTargetSeconds).toBe(42.5);
  });
});
