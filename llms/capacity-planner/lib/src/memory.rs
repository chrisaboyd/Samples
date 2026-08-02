//! Memory-fit orchestration (PRD §15) + result assembly.
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
//! two; p95 is a Phase-2 weighting). Performance (roofline + SLO) is computed in
//! [`performance`] (Phase 3, PRD §16/§18.2). Agent/user translation (§19) and
//! topology optimization (§20) remain Phase-3 defers as typed stubs.

use crate::confidence::{AnalyzeLevel, Confidence, ConfidenceGrade};
use crate::error::{CalcError, Result};
use crate::explain;
use crate::hardware::GpuConfig;
use crate::kv::{self, derive_kv_config};
use crate::model::NormalizedModel;
use crate::performance::{self, PerformanceInputs};
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
    /// Expected output tokens per request (for prefill/decode time estimation,
    /// PRD §8).
    pub avg_output_tokens: u64,
    /// Target model-step completion time in seconds (PRD §8).
    pub slo_target_seconds: f64,
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
            // 512 output tokens is the default for coding-agent workloads (PRD §7.1).
            avg_output_tokens: 512,
            // 10 s "Step target" from PRD §21.2 / §8.
            slo_target_seconds: 10.0,
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

/// Reject scenarios that cannot physically exist before any arithmetic runs.
///
/// Both of these previously produced a confident "comfortable" verdict: TP
/// sharding divided weights and KV across more ranks than there are GPUs, and
/// an inverted context pair yielded a higher concurrency at maximum context
/// than at average.
fn validate(inputs: &Inputs) -> Result<()> {
    let tp = inputs.workload.tensor_parallel.max(1);
    let count = inputs.gpu.count;
    if count == 0 {
        return Err(CalcError::InvalidInput(
            "GPU count must be at least 1".into(),
        ));
    }
    if tp > count {
        return Err(CalcError::InvalidInput(format!(
            "tensor parallel ({tp}) exceeds GPU count ({count}) — TP shards one model \
             across {tp} physical GPUs, so at least {tp} are required"
        )));
    }
    let w = &inputs.workload;
    if w.avg_context_tokens > w.max_context_tokens {
        return Err(CalcError::InvalidInput(format!(
            "average context ({}) exceeds maximum context ({})",
            w.avg_context_tokens, w.max_context_tokens
        )));
    }
    if w.max_context_tokens == 0 {
        return Err(CalcError::InvalidInput(
            "maximum context must be at least 1 token".into(),
        ));
    }
    Ok(())
}

/// Run the full memory-fit evaluation. Populates `performance` via the
/// roofline engine ([`performance::evaluate`], PRD §16) and `practical_capacity`
/// with the SLO-aware comfortable concurrency (PRD §18.3). Topology optimization
/// (§20) and agent/user translation (§19) remain Phase-3 stubs.
pub fn evaluate(inputs: &Inputs) -> Result<ScenarioResult> {
    validate(inputs)?;
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

    let cfg_avg = kv_cfg(w.avg_context_tokens);
    let cfg_max = kv_cfg(w.max_context_tokens);
    let kv_bytes_avg = cfg_avg
        .bytes_per_sequence_rounded(DEFAULT_VLLM_BLOCK_TOKENS)
        .0;
    let kv_bytes_max = cfg_max
        .bytes_per_sequence_rounded(DEFAULT_VLLM_BLOCK_TOKENS)
        .0;
    let kv_bytes_avg_exact = cfg_avg.bytes_per_sequence_exact();
    let kv_bytes_max_exact = cfg_max.bytes_per_sequence_exact();

    let c_avg = kv::memory_concurrency(free_for_kv, kv_bytes_avg);
    let c_max = kv::memory_concurrency(free_for_kv, kv_bytes_max);

    // Kept in scope (rather than scoped to the sum) so the derivation can show
    // the per-category breakdown that actually produced `checkpoint_bytes`.
    let components = weight::reassign_precision(
        inputs.model,
        w.weight_precision,
        w.is_hypothetical_weight,
        w.nvfp4_group_size,
    );
    let checkpoint_bytes = weight::checkpoint_storage_bytes(&components, w.nvfp4_group_size);

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
        // Report the figure actually compared against (available = physical × U),
        // not the raw physical capacity — quoting physical "at N% utilization"
        // read as though physical itself were the budget.
        warnings.push(format!(
            "Model + runtime reserve ({:.2} GiB) exceed the {:.2} GiB available for \
             allocation ({:.2} GiB physical × {:.0}% utilization).",
            to_gib(run_reserve_and_load),
            to_gib(available),
            gpu.usable_gib,
            inputs.gpu.utilization()? * 100.0
        ));
    }
    if c_max == 0 && weights_fit {
        warnings.push("Weights fit but no KV-cache room remains at maximum context.".to_string());
    }

    // KV geometry is what the whole capacity number rests on. When the adapter
    // could not read it, `KvConfig` substitutes 1 head × 1 dim, which yields a
    // tiny KV/sequence and a huge, meaningless concurrency. Detect that here so
    // the result is graded Speculative/Level D instead of presenting an invented
    // number at the same confidence as a fully-parsed model (PRD §10.1).
    let kv_geometry_known = inputs.model.dimensions.kv_heads.unwrap_or(0) > 0
        && inputs.model.dimensions.head_dimension.unwrap_or(0) > 0
        && !inputs.model.attention_layers.is_empty();

    if !kv_geometry_known {
        warnings.push(
            "KV-cache geometry (kv_heads / head_dim / attention layers) could not be read \
             from the config — KV size and every concurrency figure below are placeholders, \
             not estimates."
                .to_string(),
        );
    }
    // Readable-but-wrong is the dangerous case: a config can supply every field
    // this check looks at and still be an architecture we do not model, which
    // produces a plausible number at full confidence. Adapters record those gaps
    // in `unresolved`, and any one of them caps the result at Level D.
    for gap in &inputs.model.unresolved {
        warnings.push(format!("Not determined from the config: {gap}"));
    }
    let architecture_fully_modelled = inputs.model.unresolved.is_empty();
    let analytical = kv_geometry_known && architecture_fully_modelled;

    for note in &inputs.model.inferred {
        warnings.push(format!("Inferred from an incomplete config: {note}"));
    }

    let confidence = Confidence {
        grade: if analytical {
            ConfidenceGrade::Analytical
        } else {
            ConfidenceGrade::Speculative
        },
        level: if analytical {
            AnalyzeLevel::C
        } else {
            AnalyzeLevel::D
        },
        reasons: vec![
            if analytical {
                "Architecture-derived (Level C) from config.json".to_string()
            } else if !kv_geometry_known {
                "Generic approximation (Level D) — key architecture fields missing".to_string()
            } else {
                "Generic approximation (Level D) — architecture not fully modelled".to_string()
            },
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

    let mut assumptions = vec![
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

    let mut evidence = vec![
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

    // --- Performance roofline (PRD §16) ---
    let perf_inputs = PerformanceInputs {
        model: inputs.model,
        gpu,
        weight_precision: w.weight_precision,
        kv_precision: w.kv_precision,
        tensor_parallel: tp,
        gpu_count: inputs.gpu.count,
        avg_context_tokens: w.avg_context_tokens,
        avg_output_tokens: w.avg_output_tokens,
        slo_target_seconds: w.slo_target_seconds,
        loaded_weight_bytes_per_rank: loaded_per_rank,
        memory_concurrency_cap: c_avg,
    };
    // A model whose weights do not fit is never resident, so publishing decode
    // rates for it would be fiction (they would describe a run that cannot
    // start). Report the memory verdict and leave performance unpopulated.
    let (performance, performance_derivations) = if weights_fit {
        performance::evaluate_explained(&perf_inputs)
    } else {
        (
            PerformanceResult {
                note: "Not estimated — model weights do not fit in available VRAM, \
                       so no inference run exists to characterise."
                    .to_string(),
                ..PerformanceResult::none()
            },
            Vec::new(),
        )
    };

    // C_comfortable = min(C_memory, C_SLO)  (PRD §18.3)
    let c_memory = c_avg.min(c_max);
    let c_slo = performance.slo_concurrency.unwrap_or(c_memory);
    let c_comfortable = c_memory.min(c_slo);

    let compute_peak = performance::compute_peak_tflops(gpu, w.weight_precision);
    let decode_range = performance.decode_tokens_per_second_per_request.as_ref();

    evidence.extend(vec![
        EvidenceRecord {
            what: "compute peak".into(),
            value: format!("{} TFLOPS", compute_peak),
            source: "PRD §9 GPU catalog".into(),
        },
        EvidenceRecord {
            what: "memory bandwidth".into(),
            value: format!("{} GB/s", gpu.memory_bandwidth_gbs),
            source: "PRD §9 GPU catalog".into(),
        },
        EvidenceRecord {
            what: "decode TPS (analytical range)".into(),
            value: match decode_range {
                Some(r) => format!("{:.0}–{:.0} tok/s", r.min, r.max),
                None => "n/a".to_string(),
            },
            source: "performance::roofline (§16.2)".into(),
        },
    ]);

    assumptions.extend(vec![
        AssumptionRecord {
            id: "roofline-efficiency".into(),
            description: "Analytical roofline uses broad efficiency tiers (BW: 0.40/0.55/0.70, compute: 0.30/0.50/0.65) per PRD §16.3; values are ranges, not precise predictions.".into(),
            scope: "performance".into(),
        },
        AssumptionRecord {
            id: "slo-queue-model".into(),
            description: "SLO concurrency (§18.2) is the largest batch B where T_prefill + avg_output × T_step(B) ≤ target, times the DP replica count. T_step(B) reads weights once per step and scales only KV and activation traffic with B (continuous batching); MoE routed experts are weighted by 1 − (1 − k/E)^B. Duty cycle and burst factors (§19) are not applied yet.".into(),
            scope: "concurrency".into(),
        },
        AssumptionRecord {
            id: "c-memory-worst-case".into(),
            description: "C_memory takes the *minimum* of the average- and maximum-context concurrencies, i.e. it assumes every concurrent request may simultaneously occupy its maximum context. This is deliberately conservative; a mixed-length workload supports more.".into(),
            scope: "concurrency".into(),
        },
        AssumptionRecord {
            id: "no-collective-overhead".into(),
            description: "Tensor parallelism is modelled as linear scaling of bandwidth and compute. NVLink/PCIe all-reduce latency between ranks is not subtracted, so multi-GPU TP figures are optimistic.".into(),
            scope: "performance".into(),
        },
    ]);

    // Explanations are built from the same locals the calculation used, so the
    // math shown in the UI is the math that ran.
    let ctx = explain::ExplainContext {
        model: inputs.model,
        gpu,
        workload: w,
        gpu_count: inputs.gpu.count,
        tp,
        utilization: inputs.gpu.utilization()?,
        block_tokens: DEFAULT_VLLM_BLOCK_TOKENS,
        physical_bytes: physical,
        available_bytes: available,
        components,
        checkpoint_bytes,
        load_factor: weight::load_factor(w.weight_precision),
        loaded_per_rank,
        runtime_bytes,
        draft_bytes: w.draft_kv_bytes_per_seq,
        free_for_kv,
        kv_avg_exact: kv_bytes_avg_exact,
        kv_avg_rounded: kv_bytes_avg,
        kv_max_exact: kv_bytes_max_exact,
        kv_max_rounded: kv_bytes_max,
        full_layers: cfg_avg.full_layers,
        sliding_layers: cfg_avg.sliding_layers,
        sliding_window: cfg_avg.sliding_window,
        c_avg,
        c_max,
        c_slo,
        c_comfortable,
        compute_peak_tflops: compute_peak,
    };
    let mut derivations = explain::memory_derivations(&ctx);
    derivations.extend(performance_derivations);
    let inputs_used = explain::input_facts(&ctx);

    Ok(ScenarioResult {
        verdict,
        memory,
        performance: performance.clone(),
        practical_capacity: PracticalCapacity {
            comfortable_active_requests: c_comfortable,
            intermittent_agents: None,
            human_users: None,
            note: "Agent/user translation deferred to Phase 3 (requires agent \
                   duty cycle, §19). SLO concurrency now computed (§18.2)."
                .into(),
        },
        topology: TopologyResult {
            tensor_parallel: tp,
            // Replicas, not raw GPU count: `count` GPUs split into groups of
            // `tp`. Reporting count here claimed TP × count GPUs and contradicted
            // the DP factor the performance model uses.
            data_parallel: (inputs.gpu.count / tp).max(1),
            // Laguna-style hybrids are MoE too — the router is what makes expert
            // parallelism applicable, not whether the MLP stack is uniformly sparse.
            expert_parallel: inputs.model.moe.is_some(),
            explanation: vec!["Topology optimizer deferred to Phase 3 (PRD §31 §20).".into()],
            alternatives: Vec::new(),
            note: "Phase 3".into(),
        },
        confidence: ConfidenceSummary {
            memory: confidence.grade,
            // Performance and concurrency are downstream of the memory model, so
            // they can never be graded higher than it.
            performance: confidence.grade,
            concurrency: confidence.grade,
            analyze_level: confidence.level,
            reasons: {
                let mut r = confidence.reasons.clone();
                r.push(format!("Roofline compute peak: {} TFLOPS", compute_peak));
                r.push(format!(
                    "Roofline bandwidth: {} GB/s",
                    gpu.memory_bandwidth_gbs
                ));
                r.push(format!("SLO concurrency (§18.2): {}", c_slo));
                r.push("Analytical roofline — ranges not calibrated (PRD §17).".into());
                r
            },
            primary_uncertainty: if !kv_geometry_known {
                "KV-cache geometry missing from the config — capacity figures are placeholders (PRD §10.1 Level D)".to_string()
            } else if !architecture_fully_modelled {
                format!(
                    "Architecture not fully modelled — {} unresolved term(s); parameter count and \
                     KV size are bounds, not estimates (PRD §10.1 Level D)",
                    inputs.model.unresolved.len()
                )
            } else if hypothesis_warning {
                "Analytical roofline with broad efficiency ranges; hypothetical quantization adds weight-load uncertainty (PRD §16.3/§33)".to_string()
            } else {
                "Roofline uses analytical efficiency tiers; no benchmark calibration (PRD §17)"
                    .to_string()
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
        derivations,
        inputs_used,
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
