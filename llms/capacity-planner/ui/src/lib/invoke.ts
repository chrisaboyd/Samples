import { invoke } from "@tauri-apps/api/core";
import type { AnalyzeInput, ScenarioResult } from "../types";

export async function analyze(input: AnalyzeInput): Promise<ScenarioResult> {
  // Tauri's `invoke` args must be `Record<string, unknown>`; an inline literal
  // satisfies that, whereas the named `AnalyzeInput` type does not carry an
  // index signature.
  return invoke<ScenarioResult>("analyze", {
    configJson: input.configJson,
    gpu: input.gpu,
    count: input.count,
    tensorParallel: input.tensorParallel,
    weightPrecision: input.weightPrecision,
    kvPrecision: input.kvPrecision,
    avgContextTokens: input.avgContextTokens,
    maxContextTokens: input.maxContextTokens,
    isHypotheticalWeight: input.isHypotheticalWeight,
  });
}

// Optional HuggingFace fetch (backend uses the lib's sources feature + env token).
export async function fetchConfig(url: string): Promise<string> {
  return invoke<string>("fetch_config", { url });
}
