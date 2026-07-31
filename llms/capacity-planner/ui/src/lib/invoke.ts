import { invoke } from "@tauri-apps/api/core";
import type { AnalyzeInput, ScenarioResult } from "../types";

/// Build the exact IPC argument object for the `analyze` command.
///
/// The backend signature is `fn analyze(cmd: AnalyzeCommand)`, and Tauri keys
/// command arguments by *parameter name*, so the payload must nest the struct
/// under `cmd` rather than spreading its fields at the top level.
///
/// `input` is forwarded whole rather than field-by-field: enumerating fields
/// here let `avgOutputTokens`/`sloTargetSeconds` silently go missing, which the
/// backend then rejected as `missing field`. Passing the object through means
/// adding a field to `AnalyzeInput` cannot drift from the wire again.
export function analyzeArgs(input: AnalyzeInput): Record<string, unknown> {
  return { cmd: { ...input } };
}

export async function analyze(input: AnalyzeInput): Promise<ScenarioResult> {
  return invoke<ScenarioResult>("analyze", analyzeArgs(input));
}

// Optional HuggingFace fetch (backend uses the lib's sources feature + env token).
export async function fetchConfig(url: string): Promise<string> {
  return invoke<string>("fetch_config", { url });
}
