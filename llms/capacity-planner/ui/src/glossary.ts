// Definitions for the vocabulary the result panel uses.
//
// These are *definitions*, not computed values, so they live in the frontend —
// unlike `Derivation.meaning`, which the Rust engine emits alongside the number
// it explains. Anything with a derivation gets its explanation from the engine;
// this file covers the labels that have no number of their own (verdicts,
// confidence grades, analysis levels, memory-bar segments).

import type { Derivation } from "./types";

export interface GlossaryEntry {
  /** Display name — what the reader sees. */
  title: string;
  definition: string;
}

export const GLOSSARY: Record<string, GlossaryEntry> = {
  // --- Verdict ---
  comfortable: {
    title: "Comfortable",
    definition:
      "The model fits with room to spare: weights load, and there is KV-cache " +
      "headroom for concurrent requests at both average and maximum context.",
  },
  constrained: {
    title: "Constrained",
    definition:
      "The model loads and can serve requests at average context, but there is " +
      "not enough KV-cache room for even one request at the full context window. " +
      "Long conversations will be evicted or rejected.",
  },
  does_not_fit: {
    title: "Does not fit",
    definition:
      "Either the weights plus runtime reserve exceed allocatable VRAM, or no " +
      "KV-cache room remains at average context. This configuration cannot serve.",
  },
  unsupported: {
    title: "Unsupported",
    definition:
      "The configuration could not be evaluated — typically an architecture the " +
      "adapter does not recognise.",
  },

  // --- Confidence grade (how the numbers were obtained) ---
  measured: {
    title: "Measured",
    definition:
      "Taken from a benchmark of this exact model on this exact hardware. The " +
      "strongest grade — nothing was inferred.",
  },
  calibrated: {
    title: "Calibrated",
    definition:
      "Derived from a benchmark of a closely related model or GPU, adjusted to " +
      "this configuration.",
  },
  analytical: {
    title: "Analytical",
    definition:
      "Calculated from the model architecture and hardware specifications using " +
      "closed-form formulas and a roofline model — no benchmark was involved. " +
      "Memory figures are near-exact; throughput figures are broad ranges.",
  },
  speculative: {
    title: "Speculative",
    definition:
      "Key architectural or engine details were missing, so parts of the result " +
      "are placeholders rather than estimates. Treat the numbers as illustrative.",
  },

  // --- Analysis level (what the numbers were derived FROM) ---
  "level-a": {
    title: "Level A — exact checkpoint inspection",
    definition:
      "Parameter counts read directly from safetensors tensor metadata. Exact.",
  },
  "level-b": {
    title: "Level B — checkpoint index and file sizes",
    definition:
      "Parameter counts derived from the checkpoint index and repository file " +
      "sizes. Very close to exact.",
  },
  "level-c": {
    title: "Level C — architecture-derived",
    definition:
      "Everything computed from the fields in config.json (layer counts, hidden " +
      "size, head geometry, expert counts). No checkpoint was downloaded, so " +
      "parameter counts are reconstructed from the architecture rather than read " +
      "off the tensors.",
  },
  "level-d": {
    title: "Level D — generic approximation",
    definition:
      "Required architecture fields were missing from the config, so generic " +
      "transformer assumptions were substituted. The least reliable level.",
  },

  // --- Memory-bar segments ---
  weights: {
    title: "Weights",
    definition:
      "VRAM the model parameters occupy once loaded, on one GPU. Fixed for the " +
      "life of the process — it does not change with load.",
  },
  runtime: {
    title: "Runtime reserve",
    definition:
      "Fixed allowance for the CUDA context, memory allocator, and compiled " +
      "kernels. Held back before any KV cache is budgeted.",
  },
  "kv-at-concurrency": {
    title: "KV @ avg ctx",
    definition:
      "KV cache in use when the memory ceiling at average context is fully " +
      "occupied — the per-sequence cost times that many concurrent requests.",
  },
  "free-headroom": {
    title: "Free (KV headroom)",
    definition:
      "Allocatable VRAM left unused after weights, runtime reserve, and a full " +
      "batch of average-context KV. Slack for longer-than-average requests.",
  },
};

export function lookup(key: string): GlossaryEntry | undefined {
  return GLOSSARY[key];
}

/// Glossary key for an analysis level letter as the backend emits it ("c").
export function levelKey(level: string): string {
  return `level-${level.toLowerCase()}`;
}

/// Index derivations by id for O(1) attachment to the figure they explain.
/// Returns a plain object rather than a Map so it survives the JSON round-trip
/// of a saved scenario without special handling.
export function indexDerivations(list: Derivation[]): Record<string, Derivation> {
  const out: Record<string, Derivation> = {};
  for (const d of list ?? []) out[d.id] = d;
  return out;
}
