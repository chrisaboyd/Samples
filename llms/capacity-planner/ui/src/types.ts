// Typed mirror of the Rust ScenarioResult JSON (PRD §25). Field names use the
// exact camelCase the backend emits (including the explicit GiB renames) so a
// mismatch fails at compile time rather than rendering silently.

export type Verdict = "comfortable" | "constrained" | "does_not_fit" | "unsupported";

export interface Range {
  min: number;
  max: number;
  unit: string;
}

export interface MemoryResult {
  weightGiBPerGpu: number;
  checkpointStorageGiB: number;
  checkpointPrecisionLabel: string;
  runtimeGiBPerGpu: number;
  kvGiBPerAverageSequence: number;
  kvGiBPerMaximumSequence: number;
  freeGiBPerGpu: number;
  memoryConcurrencyAverage: number;
  memoryConcurrencyMaximum: number;
  physicalGiBPerGpu: number;
}

export interface PerformanceResult {
  prefillTokensPerSecond: Range | null;
  decodeTokensPerSecondPerRequest: Range | null;
  aggregateDecodeTokensPerSecond: Range | null;
  estimatedTTFT: Range | null;
  estimatedStepLatency: Range | null;
  sloConcurrency: number | null;
  note: string;
}

export interface PracticalCapacity {
  comfortableActiveRequests: number;
  intermittentAgents: Range | null;
  humanUsers: Range | null;
  note: string;
}

export interface TopologyResult {
  tensorParallel: number;
  dataParallel: number;
  expertParallel: boolean;
  explanation: string[];
  alternatives: unknown[];
  note: string;
}

export interface ConfidenceSummary {
  memory: string;
  performance: string;
  concurrency: string;
  analyzeLevel: string;
  reasons: string[];
  primaryUncertainty: string;
}

export interface EvidenceRecord {
  what: string;
  value: string;
  source: string;
}

export interface AssumptionRecord {
  id: string;
  description: string;
  scope: string;
}

export interface Provenance {
  formulaVersion: string;
  hardwareDataRevision: string;
  modelSourceRevision: string | null;
  gpuSku: string;
}

/// A published figure shown as formula → substitution → result. Emitted by the
/// Rust engine from the same values the calculation used, so the UI never
/// re-derives (and never drifts from) the real math.
export interface Derivation {
  id: string;
  label: string;
  meaning: string;
  formula: string;
  /** May contain newlines — render in a pre-wrap block. */
  substitution: string;
  result: string;
}

/// One input value that actually reaches a formula.
export interface InputFact {
  group: string;
  name: string;
  /** Originating config.json key, when the value came from one. */
  key: string | null;
  value: string;
  usedFor: string;
}

export interface ScenarioResult {
  verdict: Verdict;
  memory: MemoryResult;
  performance: PerformanceResult;
  practicalCapacity: PracticalCapacity;
  topology: TopologyResult;
  confidence: ConfidenceSummary;
  provenance: Provenance;
  evidence: EvidenceRecord[];
  assumptions: AssumptionRecord[];
  warnings: string[];
  derivations: Derivation[];
  inputsUsed: InputFact[];
}

export type Precision = "fp32" | "fp16" | "bf16" | "fp8" | "nvfp4" | "int8" | "int4";

// Field names mirror the backend's AnalyzeCommand (camelCase).
export interface AnalyzeInput {
  configJson: string;
  gpu: string;
  count: number;
  tensorParallel: number;
  weightPrecision: Precision;
  kvPrecision: Precision;
  avgContextTokens: number;
  maxContextTokens: number;
  avgOutputTokens: number;
  sloTargetSeconds: number;
  isHypotheticalWeight: boolean;
}
