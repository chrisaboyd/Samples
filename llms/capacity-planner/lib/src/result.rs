//! Scenario-result schema (PRD §25) with Phase-1 scoping.
//!
//! Phase 1 fully populates the **memory** block (fit verdict, weight/runtime/KV
//! breakdown, memory concurrency). The **performance**, **practical-capacity**
//! and **topology** blocks exist as typed-but-optional stubs (ranges `None`,
//! explanation strings) so the schema is forward-compatible with PRD §25 and
//! Phase 3/4 deliverables. This matches PRD §31 "Phase 1: Formula prototype".

use serde::{Deserialize, Serialize};

use crate::confidence::{AnalyzeLevel, ConfidenceGrade};

/// A half-open numerical range for a non-measured quantity (PRD §35 #6/#9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Range {
    pub min: f64,
    pub max: f64,
    pub unit: String,
}

impl Range {
    pub fn gib(min: f64, max: f64) -> Self {
        Self {
            min,
            max,
            unit: "GiB".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Comfortable,
    Constrained,
    DoesNotFit,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TopologyKind {
    PciE,
    NvLink4,
    NvLink5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyOption {
    pub tensor_parallel: u32,
    pub data_parallel: u32,
    pub expert_parallel: bool,
    pub description: String,
    pub best_when: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryResult {
    /// Loaded weight memory per GPU rank (after TP sharding), in GiB.
    #[serde(rename = "weightGiBPerGpu")]
    pub weight_gib_per_gpu: f64,
    /// Checkpoint storage at the selected precision (hypothetical label aside), GiB.
    #[serde(rename = "checkpointStorageGiB")]
    pub checkpoint_storage_gib: f64,
    pub checkpoint_precision_label: String,
    /// Fixed runtime reserve per GPU, GiB.
    #[serde(rename = "runtimeGiBPerGpu")]
    pub runtime_gib_per_gpu: f64,
    /// KV cache cost per average-maximum sequence, GiB.
    #[serde(rename = "kvGiBPerAverageSequence")]
    pub kv_gib_per_average_sequence: f64,
    #[serde(rename = "kvGiBPerMaximumSequence")]
    pub kv_gib_per_maximum_sequence: f64,
    /// Free GPU memory earmarked for KV cache, GiB.
    #[serde(rename = "freeGiBPerGpu")]
    pub free_gib_per_gpu: f64,
    pub memory_concurrency_average: u64,
    pub memory_concurrency_maximum: u64,
    /// Total physical memory per GPU, GiB (for context).
    #[serde(rename = "physicalGiBPerGpu")]
    pub physical_gib_per_gpu: f64,
}

/// Phase-1 stub: ranges are `None` and a note explains the deferral (PRD §31).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceResult {
    pub prefill_tokens_per_second: Option<Range>,
    pub decode_tokens_per_second_per_request: Option<Range>,
    pub aggregate_decode_tokens_per_second: Option<Range>,
    pub estimated_ttft: Option<Range>,
    pub estimated_step_latency: Option<Range>,
    pub slo_concurrency: Option<u64>,
    pub note: String,
}

/// Phase-1 stub: agent/user translation needs SLO concurrency (Phase 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PracticalCapacity {
    pub comfortable_active_requests: u64,
    pub intermittent_agents: Option<Range>,
    pub human_users: Option<Range>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyResult {
    pub tensor_parallel: u32,
    pub data_parallel: u32,
    pub expert_parallel: bool,
    pub explanation: Vec<String>,
    pub alternatives: Vec<TopologyOption>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfidenceSummary {
    pub memory: ConfidenceGrade,
    pub performance: ConfidenceGrade,
    pub concurrency: ConfidenceGrade,
    pub analyze_level: AnalyzeLevel,
    pub reasons: Vec<String>,
    pub primary_uncertainty: String,
}

/// Provenance record (PRD §22.6): versions and data sources for reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub formula_version: String,
    pub hardware_data_revision: String,
    pub model_source_revision: Option<String>,
    pub gpu_sku: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRecord {
    pub what: String,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssumptionRecord {
    pub id: String,
    pub description: String,
    pub scope: String, // "memory" | "performance" | ...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioResult {
    pub verdict: Verdict,
    pub memory: MemoryResult,
    pub performance: PerformanceResult,
    pub practical_capacity: PracticalCapacity,
    pub topology: TopologyResult,
    pub confidence: ConfidenceSummary,
    pub provenance: Provenance,
    pub evidence: Vec<EvidenceRecord>,
    pub assumptions: Vec<AssumptionRecord>,
    pub warnings: Vec<String>,
}

/// Bare-minimum result used by the CLI smoke entry point before real inputs.
impl ScenarioResult {
    pub fn stub_empty() -> Self {
        Self {
            verdict: Verdict::Unsupported,
            memory: MemoryResult {
                weight_gib_per_gpu: 0.0,
                checkpoint_storage_gib: 0.0,
                checkpoint_precision_label: "n/a".to_string(),
                runtime_gib_per_gpu: 0.0,
                kv_gib_per_average_sequence: 0.0,
                kv_gib_per_maximum_sequence: 0.0,
                free_gib_per_gpu: 0.0,
                memory_concurrency_average: 0,
                memory_concurrency_maximum: 0,
                physical_gib_per_gpu: 0.0,
            },
            performance: PerformanceResult {
                prefill_tokens_per_second: None,
                decode_tokens_per_second_per_request: None,
                aggregate_decode_tokens_per_second: None,
                estimated_ttft: None,
                estimated_step_latency: None,
                slo_concurrency: None,
                note: "Performance model deferred to Phase 3 (PRD §31).".to_string(),
            },
            practical_capacity: PracticalCapacity {
                comfortable_active_requests: 0,
                intermittent_agents: None,
                human_users: None,
                note: "Agent/user translation deferred to Phase 3 (requires SLO concurrency)."
                    .to_string(),
            },
            topology: TopologyResult {
                tensor_parallel: 1,
                data_parallel: 1,
                expert_parallel: false,
                explanation: vec!["Topology optimizer deferred to Phase 3 (PRD §31).".to_string()],
                alternatives: Vec::new(),
                note: "Phase 3".to_string(),
            },
            confidence: ConfidenceSummary {
                memory: ConfidenceGrade::Speculative,
                performance: ConfidenceGrade::Speculative,
                concurrency: ConfidenceGrade::Speculative,
                analyze_level: AnalyzeLevel::D,
                reasons: vec!["stub".to_string()],
                primary_uncertainty: "no input provided".to_string(),
            },
            provenance: Provenance {
                formula_version: env!("CARGO_PKG_VERSION").to_string(),
                hardware_data_revision: "PRD §9".to_string(),
                model_source_revision: None,
                gpu_sku: "unspecified".to_string(),
            },
            evidence: Vec::new(),
            assumptions: Vec::new(),
            warnings: vec!["stub result".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_serializes_camel_case() {
        let s = serde_json::to_string(&ScenarioResult::stub_empty()).unwrap();
        // PRD §25 uses camelCase fields like weightGiBPerGpu.
        assert!(s.contains("weightGiBPerGpu"));
        assert!(s.contains("memoryConcurrencyAverage"));
        assert!(s.contains("tensorParallel"));
        assert!(s.contains("analyzeLevel"));
    }

    #[test]
    fn verdict_round_trips() {
        assert_eq!(
            serde_json::from_str::<Verdict>("\"does_not_fit\"").unwrap(),
            Verdict::DoesNotFit
        );
    }
}
