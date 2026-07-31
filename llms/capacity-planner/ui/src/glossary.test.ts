// Contract tests for the explanation layer.
//
// Two kinds of drift are possible and neither shows up as a type error:
//   1. The backend adds/renames a verdict or confidence grade and the UI renders
//      a bare token with no definition behind it.
//   2. The backend renames a derivation id and every `Figure` silently loses its
//      "show the math" expander — the number still renders, so nothing looks
//      broken.
//
// The golden scenario asset is real engine output, so asserting against it
// catches (2) at the same commit the rename lands.

import { describe, expect, it } from "vitest";
import golden from "../../lib/tests/assets/laguna-b200-nvfp4.json";
import { GLOSSARY, indexDerivations, levelKey, lookup } from "./glossary";
import type { Derivation, ScenarioResult } from "./types";

const result = golden as unknown as ScenarioResult;

// Mirrors the Rust `Verdict` enum (serde snake_case).
const VERDICTS = ["comfortable", "constrained", "does_not_fit", "unsupported"];
// Mirrors the Rust `ConfidenceGrade` enum (serde lowercase).
const GRADES = ["measured", "calibrated", "analytical", "speculative"];
// Mirrors the Rust `AnalyzeLevel` enum.
const LEVELS = ["a", "b", "c", "d"];

// Every derivation id `App.tsx` and `MemoryBar.tsx` look up. A `Figure` with an
// unmatched id degrades silently, so the list is pinned here rather than being
// discovered from the component.
const REFERENCED_DERIVATIONS = [
  "c-comfortable",
  "c-mem-avg",
  "c-mem-max",
  "m-physical",
  "m-available",
  "m-checkpoint",
  "m-weights",
  "m-runtime",
  "m-free",
  "kv-avg",
  "kv-max",
  "p-decode",
  "p-prefill",
  "p-aggregate",
  "p-slo",
  "p-step",
  "p-ttft",
  "p-flops-token",
];

// Glossary keys passed as `termKey` by MemoryBar's segment list.
const SEGMENT_TERMS = ["weights", "runtime", "kv-at-concurrency", "free-headroom"];

describe("glossary", () => {
  it("defines every verdict the backend can emit", () => {
    for (const v of VERDICTS) {
      expect(lookup(v), `no definition for verdict \`${v}\``).toBeDefined();
    }
  });

  it("defines every confidence grade the backend can emit", () => {
    for (const g of GRADES) {
      expect(lookup(g), `no definition for grade \`${g}\``).toBeDefined();
    }
  });

  it("defines every analysis level the backend can emit", () => {
    for (const l of LEVELS) {
      expect(lookup(levelKey(l)), `no definition for level \`${l}\``).toBeDefined();
    }
  });

  it("defines every memory-bar segment label", () => {
    for (const t of SEGMENT_TERMS) {
      expect(lookup(t), `no definition for segment \`${t}\``).toBeDefined();
    }
  });

  it("has a non-empty title and definition for every entry", () => {
    for (const [key, entry] of Object.entries(GLOSSARY)) {
      expect(entry.title.length, `\`${key}\` has no title`).toBeGreaterThan(0);
      expect(entry.definition.length, `\`${key}\` has no definition`).toBeGreaterThan(20);
    }
  });

  it("returns undefined for an unknown term rather than throwing", () => {
    expect(lookup("not-a-real-term")).toBeUndefined();
  });
});

describe("indexDerivations", () => {
  it("keys derivations by id", () => {
    const list = [{ id: "a" }, { id: "b" }] as Derivation[];
    expect(Object.keys(indexDerivations(list)).sort()).toEqual(["a", "b"]);
  });

  // Scenarios saved before derivations existed deserialize with the field
  // absent; the result panel must render rather than crash.
  it("tolerates a missing derivations array", () => {
    expect(indexDerivations(undefined as unknown as Derivation[])).toEqual({});
  });
});

describe("engine derivation contract", () => {
  it("emits every derivation the result panel looks up", () => {
    const dv = indexDerivations(result.derivations);
    for (const id of REFERENCED_DERIVATIONS) {
      expect(dv[id], `engine emits no derivation \`${id}\``).toBeDefined();
    }
  });

  it("gives each derivation a meaning, formula, substitution, and result", () => {
    for (const d of result.derivations) {
      expect(d.meaning.length, `\`${d.id}\` has no meaning`).toBeGreaterThan(20);
      expect(d.formula.length, `\`${d.id}\` has no formula`).toBeGreaterThan(0);
      expect(d.substitution.length, `\`${d.id}\` has no substitution`).toBeGreaterThan(0);
      expect(d.result.length, `\`${d.id}\` has no result`).toBeGreaterThan(0);
    }
  });

  // The point of the substitution is that the reader can check the arithmetic,
  // which requires the actual numbers — not the symbolic form repeated.
  it("substitutes concrete numbers rather than repeating the formula", () => {
    for (const d of result.derivations) {
      expect(d.substitution, `\`${d.id}\` substitution has no digits`).toMatch(/\d/);
      expect(d.substitution, `\`${d.id}\` substitution is just the formula`).not.toBe(
        d.formula,
      );
    }
  });

  it("reports which inputs the formulas consumed", () => {
    expect(result.inputsUsed.length).toBeGreaterThan(10);
    for (const f of result.inputsUsed) {
      expect(f.group.length, `${f.name} has no group`).toBeGreaterThan(0);
      expect(f.value.length, `${f.name} has no value`).toBeGreaterThan(0);
      expect(f.usedFor.length, `${f.name} says what it is used for`).toBeGreaterThan(0);
    }
  });

  // Grouping drives the section headings in InputsUsed.
  it("groups inputs by origin", () => {
    const groups = new Set(result.inputsUsed.map((f) => f.group));
    expect([...groups].sort()).toEqual(["Engine", "GPU", "Model", "Workload"]);
  });
});
