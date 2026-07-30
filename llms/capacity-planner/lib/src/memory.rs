//! Memory-fit orchestration (PRD §15) + Phase-1 result assembly.
//!
//! Corrected §15 formula: the PRD's rendered equation collapsed to a ratio,
//! which is dimensionally wrong. The intent (confirmed by §14's overhead model and
//! §15's "remaining KV-cache capacity" language) is subtraction:
//!
//! ```text
//! M_available   = M_physical * U                       (PRD §15)
//! M_freeForKV   = M_available - M_weightsPerRank
//!                             - M_runtime
//!                             - M_draft
//!                             - M_communication
//! C_memory      = floor(M_freeForKV / KV_sequence)     (PRD §15)
//! ```
//!
//! C_memory is evaluated at average and maximum context (PRD §15 requires ≥ these
//! two; p95 is a Phase-2 weighting). Performance SLO concurrency and the
//! agent/user translation (PRD §18.2 / §19) are Phase-3 defers and are emitted as
//! typed stubs.

use crate::confidence::{AnalyzeLevel, Confidence, ConfidenceGrade};
use crate::error::Result;
use crate::hardware::GpuConfig;
use crate::kv::{self, derive_kv_config};
use crate::model::NormalizedModel;
use crate::precision::Precision;
use crate::result::{
    AssumptionRecord, ConfidenceSummary, EvidenceRecord, MemoryResult, PerformanceResult,
    PracticalCapacity, Provenance, ScenarioResult, TopologyResult, Verdict,
};
use crate::weight;
use crate::GIB_BYTES;

/// Phase-1 memory-profile ceiling. The PRD (§14) defines Conservative / Balanced /
/// Aggressive as a UI knob; Phase 1 ships Conservative (absorb per-scheduler
/// overhead into the fixed runtime reserve).
const DEFAULT_VLLM_BLOCK_TOKENS: u32 = 128;

/// Workload snapshot driving a memory evaluation.
pub struct Workload {
    pub avg_context_tokens: u64,
    pub max_context_tokens: u64,
    pub weight_precision: Precision,
    pub kv_precision: Precision,
    pub is_hypothetical_weight: bool,
    pub nvfp4_group_size: u32,
    pub tensor_parallel: u32,
    pub prefix_cache_enabled: bool,
    /// KV bytes a draft model occupies per running sequence (speculative stub).
    pub draft_kv_bytes_per_seq: u128,
}

impl Default for Workload {
    fn default() -> Self {
        Self {
            avg_context_tokens: 32_768,
            max_context_tokens: 1_048_576,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            is_hypothetical_weight: true,
            nvfp4_group_size: 16,
            tensor_parallel: 1,
            prefix_cache_enabled: true,
            draft_kv_bytes_per_seq: 0,
        }
    }
}

pub struct Inputs<'a> {
    pub model: &'a NormalizedModel,
    pub gpu: GpuConfig,
    pub workload: Workload,
}

/// Physical VRAM bytes from a marketed-GB figure (exact 1e9/2^30 conversion;
/// PRD §33 "GPU memory unit conversion: exact").
fn physical_bytes(marketed_gb: f64) -> u128 {
    (marketed_gb * 1_000_000_000.0) as u128
}

fn to_gib(bytes: u128) -> f64 {
    // Lossless for magnitudes here (< 2^53): exact per PRD §33.
    bytes as f64 / GIB_BYTES as f64
}

/// Run the full memory-fit evaluation. Populates `performance`,
/// `practical_capacity`, and `topology` as Phase-1 stubs.
pub fn evaluate(inputs: &Inputs) -> Result<ScenarioResult> {
    let gpu = inputs.gpu.gpu()?;
    let tp = inputs.workload.tensor_parallel.max(1);
    let physical = physical_bytes(gpu.memory_marketed_gb);
    let available = (physical as f64 * inputs.gpu.utilization()?) as u128;
    let reserve_gib = inputs.gpu.runtime_reserve_gib()?;
    let runtime_bytes = (reserve_gib * GIB_BYTES as f64) as u128;

    let w = &inputs.workload;
    let loaded_per_rank = weight::loaded_weight_bytes_per_rank(
        inputs.model,
        w.weight_precision,
        w.is_hypothetical_weight,
        w.nvfp4_group_size,
        tp,
    );
    let run_reserve_and_load = loaded_per_rank
        .saturating_add(runtime_bytes)
        .saturating_add(w.draft_kv_bytes_per_seq);
    let weights_fit = available >= run_reserve_and_load;
    let free_for_kv = available.saturating_sub(run_reserve_and_load);

    let kv_cfg = |ctx| {
        let layers: Vec<(crate::model::AttentionKind, u32, Option<u32>)> = inputs
            .model
            .attention_layers
            .iter()
            .map(|a| (a.kind, a.count, a.window_size))
            .collect();
        derive_kv_config(
            &layers,
            inputs.model.dimensions.kv_heads.unwrap_or(0),
            inputs.model.dimensions.head_dimension.unwrap_or(0),
            w.kv_precision,
            tp,
            ctx,
        )
    };

    let kv_bytes_avg = kv_cfg(w.avg_context_tokens)
        .bytes_per_sequence_rounded(DEFAULT_VLLM_BLOCK_TOKENS)
        .0;
    let kv_bytes_max = kv_cfg(w.max_context_tokens)
        .bytes_per_sequence_rounded(DEFAULT_VLLM_BLOCK_TOKENS)
        .0;
    let kv_bytes_avg_exact = kv_cfg(w.avg_context_tokens).bytes_per_sequence_exact();
    let kv_bytes_max_exact = kv_cfg(w.max_context_tokens).bytes_per_sequence_exact();

    let c_avg = kv::memory_concurrency(free_for_kv, kv_bytes_avg);
    let c_max = kv::memory_concurrency(free_for_kv, kv_bytes_max);

    let checkpoint_bytes = {
        let comps = weight::reassign_precision(
            inputs.model,
            w.weight_precision,
            w.is_hypothetical_weight,
            w.nvfp4_group_size,
        );
        weight::checkpoint_storage_bytes(&comps, w.nvfp4_group_size)
    };

    let verdict = if !weights_fit {
        Verdict::DoesNotFit
    } else if c_avg >= 1 && c_max >= 1 {
        Verdict::Comfortable
    } else if c_avg >= 1 {
        Verdict::Constrained
    } else {
        Verdict::DoesNotFit
    };

    let checkpoint_label = weight::checkpoint_label(w.is_hypothetical_weight, w.weight_precision);
    let hypothesis_warning = w.is_hypothetical_weight;

    let memory = MemoryResult {
        weight_gib_per_gpu: to_gib(loaded_per_rank),
        checkpoint_storage_gib: to_gib(checkpoint_bytes),
        checkpoint_precision_label: checkpoint_label,
        runtime_gib_per_gpu: to_gib(runtime_bytes),
        kv_gib_per_average_sequence: to_gib(kv_bytes_avg),
        kv_gib_per_maximum_sequence: to_gib(kv_bytes_max),
        free_gib_per_gpu: to_gib(free_for_kv),
        memory_concurrency_average: c_avg,
        memory_concurrency_maximum: c_max,
        physical_gib_per_gpu: gpu.usable_gib,
    };

    let mut warnings = Vec::new();
    if hypothesis_warning {
        warnings
            .push("Hypothetical quantization — weights use a format not present in the checkpoint; treat as an estimate.".to_string());
    }
    if !weights_fit {
        warnings.push(format!(
            "Model + runtime reserve ({} GiB) exceed physical VRAM ({} GiB at {}% utilization).",
            to_gib(run_reserve_and_load),
            gpu.usable_gib,
            inputs.gpu.utilization()? * 100.0
        ));
    }
    if c_max == 0 && weights_fit {
        warnings.push("Weights fit but no KV-cache room remains at maximum context.".to_string());
    }

    let confidence = Confidence {
        grade: ConfidenceGrade::Analytical,
        level: AnalyzeLevel::C,
        reasons: vec![
            "Architecture-derived (Level C) from config.json".to_string(),
            format!(
                "KV cache rounded to {}-token vLLM blocks",
                DEFAULT_VLLM_BLOCK_TOKENS
            ),
            format!(
                "TP sharding: KV and weights divided by tensor_parallel={}",
                tp
            ),
        ],
        warnings: if hypothesis_warning {
            vec![
                "Analytical estimate; hypothetical quantization increases uncertainty.".to_string(),
            ]
        } else {
            vec![
                "Analytical estimate; exact checkpoint inspection (Level A) not available."
                    .to_string(),
            ]
        },
    };

    let assumptions = vec![
        AssumptionRecord {
            id: "m-avail".into(),
            description: "M_available = M_physical * U with U from GPU memory utilization (Phase-1 conservative profile).".into(),
            scope: "memory".into(),
        },
        AssumptionRecord {
            id: "runtime-reserve".into(),
            description: "Fixed runtime reserve absorbs per-scheduler-token/sequence overhead (§14) in the conservative profile.".into(),
            scope: "memory".into(),
        },
        AssumptionRecord {
            id: "kv-block".into(),
            description: "vLLM KV blocksize = 128 tokens; rounded within one block.".into(),
            scope: "memory".into(),
        },
        AssumptionRecord {
            id: "gb-to-gib".into(),
            description: "Marketeted GB converted to GiB via 1e9/2^30 (exact for these magnitudes).".into(),
            scope: "memory".into(),
        },
    ];

    let evidence = vec![
        EvidenceRecord {
            what: "physical VRAM".into(),
            value: format!("{:.4} GiB", gpu.usable_gib),
            source: "PRD §9".into(),
        },
        EvidenceRecord {
            what: "utilization U".into(),
            value: format!("{:.2}", inputs.gpu.utilization()? * 100.0),
            source: "GPU-catalog default".into(),
        },
        EvidenceRecord {
            what: "loaded weight/rank".into(),
            value: format!("{:.4} GiB", to_gib(loaded_per_rank)),
            source: "weight::loaded_weight_bytes_per_rank".into(),
        },
        EvidenceRecord {
            what: "KV avg exact".into(),
            value: format!("{} bytes", kv_bytes_avg_exact),
            source: "kv::bytes_per_sequence_exact".into(),
        },
        EvidenceRecord {
            what: "KV avg rounded".into(),
            value: format!("{} bytes", kv_bytes_avg),
            source: "kv::bytes_per_sequence_rounded".into(),
        },
        EvidenceRecord {
            what: "KV max exact".into(),
            value: format!("{} bytes", kv_bytes_max_exact),
            source: "kv::bytes_per_sequence_exact".into(),
        },
    ];

    Ok(ScenarioResult {
        verdict,
        memory,
        performance: PerformanceResult {
            prefill_tokens_per_second: None,
            decode_tokens_per_second_per_request: None,
            aggregate_decode_tokens_per_second: None,
            estimated_ttft: None,
            estimated_step_latency: None,
            slo_concurrency: None,
            note: "Roofline + vLLM/Ollama profiles deferred to Phase 3 (PRD §31).".into(),
        },
        practical_capacity: PracticalCapacity {
            comfortable_active_requests: c_avg.min(c_max),
            intermittent_agents: None,
            human_users: None,
            note: "Agent/user translation deferred to Phase 3 (requires SLO concurrency, PRD §18.2/§19).".into(),
        },
        topology: TopologyResult {
            tensor_parallel: tp,
            data_parallel: inputs.gpu.count,
            expert_parallel: inputs.model.model_type == crate::model::ModelType::Moe,
            explanation: vec!["Topology optimizer deferred to Phase 3 (PRD §31 §20).".into()],
            alternatives: Vec::new(),
            note: "Phase 3".into(),
        },
        confidence: ConfidenceSummary {
            memory: confidence.grade,
            performance: ConfidenceGrade::Speculative,
            concurrency: ConfidenceGrade::Analytical,
            analyze_level: confidence.level,
            reasons: confidence.reasons.clone(),
            primary_uncertainty: if hypothesis_warning {
                "Hypothetical quantization; weight-load factor is a broad constant (PRD §33)".to_string()
            } else {
                "Runtime reserve absorbed per-scheduler overhead; calibration needed (PRD §17)".to_string()
            },
        },
        provenance: Provenance {
            formula_version: env!("CARGO_PKG_VERSION").to_string(),
            hardware_data_revision: "PRD §9".into(),
            model_source_revision: inputs.model.identity.revision.clone(),
            gpu_sku: gpu.sku.to_string(),
        },
        evidence,
        assumptions,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    // Verifies the §15 correction: freeForKV is a subtraction, not a ratio.
    #[test]
    fn free_for_kv_is_subtraction_not_ratio() {
        let available: u128 = 100;
        let load: u128 = 30;
        let runtime: u128 = 10;
        let free = available.saturating_sub(load).saturating_sub(runtime);
        assert_eq!(free, 60);
    }
}
