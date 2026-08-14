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
  /** Whole PRD §14 estimate: fixed + activation + per-sequence. */
  runtimeGiBPerGpu: number;
  runtimeFixedGiBPerGpu: number;
  runtimeActivationGiBPerGpu: number;
  runtimeSequenceGiBPerGpu: number;
  /** True when max_num_seqs bound concurrency rather than KV memory. */
  concurrencyCappedByScheduler: boolean;
  kvGiBPerAverageSequence: number;
  kvGiBPerMaximumSequence: number;
  freeGiBPerGpu: number;
  freeGiBAcrossGpusInUse: number;
  kvGiBPerMaximumSequenceAllRanks: number;
  kvReplicatedAcrossRanks: boolean;
  /** Per replica (one TP group), not cluster-wide. */
  memoryConcurrencyAverage: number;
  memoryConcurrencyMaximum: number;
  memoryConcurrencyAverageTotal: number;
  memoryConcurrencyMaximumTotal: number;
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

export type BindingConstraint =
  | "memory_at_maximum_context"
  | "memory_at_average_context"
  | "slo_latency";

export interface PracticalCapacity {
  comfortableActiveRequests: number;
  bindingConstraint: BindingConstraint;
  intermittentAgents: Range | null;
  humanUsers: Range | null;
  note: string;
}

export interface TopologyResult {
  tensorParallel: number;
  dataParallel: number;
  gpusInUse: number;
  gpusIdle: number;
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
export type MemoryProfile = "conservative" | "balanced" | "aggressive";

export interface AnalyzeInput {
  configJson: string;
  gpu: string;
  count: number;
  tensorParallel: number;
  /** null = fill the machine: floor(count / tensorParallel). */
  replicas: number | null;
  weightPrecision: Precision;
  kvPrecision: Precision;
  avgContextTokens: number;
  maxContextTokens: number;
  avgOutputTokens: number;
  sloTargetSeconds: number;
  isHypotheticalWeight: boolean;
  /** Engine `max_num_batched_tokens`: the widest scheduler step. Transient
   *  activation memory scales with it (PRD §14). */
  maxNumBatchedTokens: number;
  /** Engine `max_num_seqs`: reserves per-sequence logits and sampling buffers,
   *  and caps the reported concurrency. */
  maxNumSeqs: number;
  memoryProfile: MemoryProfile;
  /**
   * Raw `model.safetensors.index.json`. Its `metadata.total_size` is the
   * checkpoint's exact byte total and replaces the architecture-derived
   * estimate. null when none was supplied or the repository has no index.
   */
  indexJson: string | null;
  /// Serialized Speculator from `fetch_speculator`, or null.
  speculatorJson: string | null;
  /// Ignore a declared drafter, to model the same serve without it.
  disableSpeculator: boolean;
}
