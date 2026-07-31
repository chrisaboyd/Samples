//! Integration tests (PRD §33 accuracy targets + MVP acceptance criteria).
//!
//! Full pipeline: `adapter::normalize` -> `memory::evaluate` -> `ScenarioResult`,
//! pinning the deterministic memory/KV math PRD §33 specifies.

use capacity_planner::adapter;
use capacity_planner::confidence::{AnalyzeLevel, ConfidenceGrade};
use capacity_planner::hardware::{GpuConfig, Topology};
use capacity_planner::memory::{Inputs, Workload};
use capacity_planner::model::{AttentionKind, NormalizedModel};
use capacity_planner::precision::Precision;
use capacity_planner::result::Verdict;
use capacity_planner::ScenarioResult;
use capacity_planner::GIB_BYTES;
use serde_json::Value;

const LAGUNA_JSON: &str = include_str!("assets/laguna-config.json");

fn laguna() -> Value {
    serde_json::from_str(LAGUNA_JSON).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn run(
    model: &Value,
    gpu_sku: &str,
    count: u32,
    tp: u32,
    weight_precision: Precision,
    hypothetical: bool,
    avg: u64,
    max: u64,
) -> ScenarioResult {
    let model = adapter::normalize(model).expect("model normalizes");
    let gpu = GpuConfig {
        sku: gpu_sku.to_string(),
        count,
        topology: Topology::PciE,
        tensor_parallel: tp,
        utilization: None,
        runtime_reserve_gib: None,
    };
    let wl = Workload {
        avg_context_tokens: avg,
        max_context_tokens: max,
        weight_precision,
        kv_precision: Precision::Fp8,
        is_hypothetical_weight: hypothetical,
        nvfp4_group_size: 16,
        tensor_parallel: tp,
        prefix_cache_enabled: true,
        draft_kv_bytes_per_seq: 0,
    };
    capacity_planner::memory::evaluate(&Inputs {
        model: &model,
        gpu,
        workload: wl,
    })
    .expect("evaluates")
}

fn laguna_layers(model: &NormalizedModel) -> Vec<(AttentionKind, u32, Option<u32>)> {
    model
        .attention_layers
        .iter()
        .map(|a| (a.kind, a.count, a.window_size))
        .collect()
}

const TINY_LLAMA: &str = r#"{
  "model_type": "llama",
  "architectures": ["LlamaForCausalLM"],
  "vocab_size": 10,
  "hidden_size": 8,
  "intermediate_size": 6,
  "num_hidden_layers": 2,
  "num_attention_heads": 4,
  "num_key_value_heads": 4,
  "head_dim": 2,
  "max_position_embeddings": 128,
  "tie_word_embeddings": false,
  "torch_dtype": "bfloat16"
}"#;

// ---------------- Laguna end-to-end ----------------

#[test]
fn laguna_param_count_is_architecture_exact() {
    let m = adapter::normalize(&laguna()).unwrap();
    // 116,759,497,728 (Level C, derived from config.json alone).
    assert_eq!(m.parameter_count(), Some(116_759_497_728));
}

#[test]
fn laguna_hybrid_moe_and_hybrid_attention_detected() {
    let m = adapter::normalize(&laguna()).unwrap();
    assert_eq!(m.model_type, capacity_planner::model::ModelType::Hybrid);
    assert_eq!(m.moe.as_ref().unwrap().expert_count, 256);
    assert_eq!(m.moe.as_ref().unwrap().active_experts_per_token, 10);
    let full = m
        .attention_layers
        .iter()
        .find(|l| l.kind == AttentionKind::Full)
        .unwrap();
    let sliding = m
        .attention_layers
        .iter()
        .find(|l| l.kind == AttentionKind::Sliding)
        .unwrap();
    assert_eq!(full.count, 12);
    assert_eq!(sliding.count, 36);
    assert_eq!(sliding.window_size, Some(512));
    // The real config supplies the per-layer head arrays fully, so the exact
    // 2,000,683,008 attention param count is derived without inference (tested
    // separately in attention_uses_per_layer_head_counts). Nothing is inferred.
    assert!(
        m.inferred.is_empty(),
        "config is complete; got inferred: {:?}",
        m.inferred
    );
}

#[test]
fn laguna_does_not_fit_on_48gb_gpu() {
    // RTX 6000 Ada: ~44.7 GiB usable; Laguna NVFP4 loads ~65 GiB -> no fit.
    let r = run(
        &laguna(),
        "RTX 6000 Ada",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert_eq!(r.verdict, Verdict::DoesNotFit);
    assert!(r.memory.free_gib_per_gpu < 1.0);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.to_lowercase().contains("exceed physical vram")));
}

#[test]
fn laguna_constrained_on_single_rtx_pro_6000() {
    // Weights fit (~65 GiB < ~80 GiB available) but max-context KV (24 GiB) does not.
    let r = run(
        &laguna(),
        "RTX PRO 6000 Blackwell Workstation Edition",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert_eq!(r.verdict, Verdict::Constrained);
    assert_eq!(r.memory.memory_concurrency_average, 17);
    assert_eq!(r.memory.memory_concurrency_maximum, 0);
    assert_eq!(r.confidence.memory, ConfidenceGrade::Analytical);
    assert_eq!(r.confidence.analyze_level, AnalyzeLevel::C);
    assert!(r
        .memory
        .checkpoint_precision_label
        .contains("Hypothetical quantization estimate"));
}

#[test]
fn laguna_comfortable_on_b200() {
    let r = run(
        &laguna(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert_eq!(r.verdict, Verdict::Comfortable);
    assert!(r.memory.memory_concurrency_average > 10);
    assert!(r.memory.memory_concurrency_maximum >= 1);
}

// ---------------- PRD §15 corrected formula: subtraction, not ratio ----------------

#[test]
fn free_for_kv_is_available_minus_weights_minus_runtime() {
    let r = run(
        &laguna(),
        "RTX PRO 6000 Blackwell Workstation Edition",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    let m = &r.memory;
    let expected_free =
        m.physical_gib_per_gpu * 0.90 - m.weight_gib_per_gpu - m.runtime_gib_per_gpu;
    assert!((m.free_gib_per_gpu - expected_free).abs() < 0.01);
    // A ratio (M_available / costs) would be ~1.2, not ~14.
    assert!(m.free_gib_per_gpu > 5.0);
}

// ---------------- §33 accuracy targets ----------------

#[test]
fn parameter_count_exact_for_synthetic_model() {
    let m = adapter::normalize(&serde_json::from_str(TINY_LLAMA).unwrap()).unwrap();
    assert_eq!(m.parameter_count(), Some(1000));
}

#[test]
fn kv_exact_before_rounding_and_within_one_block() {
    let m = adapter::normalize(&serde_json::from_str(TINY_LLAMA).unwrap()).unwrap();
    let cfg = capacity_planner::kv::derive_kv_config(
        &laguna_layers(&m),
        m.dimensions.kv_heads.unwrap(),
        m.dimensions.head_dimension.unwrap(),
        Precision::Bf16,
        1,
        128,
    );
    let exact = cfg.bytes_per_sequence_exact();
    let (rounded, block) = cfg.bytes_per_sequence_rounded(128);
    assert!(rounded >= exact);
    assert!(rounded - exact < block);
}

#[test]
fn kv_unit_conversion_is_exact() {
    let m = adapter::normalize(&serde_json::from_str(TINY_LLAMA).unwrap()).unwrap();
    let cfg = capacity_planner::kv::derive_kv_config(
        &laguna_layers(&m),
        m.dimensions.kv_heads.unwrap(),
        m.dimensions.head_dimension.unwrap(),
        Precision::Bf16,
        1,
        128,
    );
    let exact = cfg.bytes_per_sequence_exact();
    let gib_via_constant = exact as f64 / GIB_BYTES as f64;
    let gib_via_func = exact as f64 / (1024.0 * 1024.0 * 1024.0);
    assert!((gib_via_constant - gib_via_func).abs() < 1e-9);
}

// ---------------- hypothetical vs exact quantization labelling ----------------

#[test]
fn hypothetical_and_exact_labels_differ() {
    let hyp = run(
        &laguna(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    let exact = run(
        &laguna(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Bf16,
        false,
        32_768,
        1_048_576,
    );
    assert!(hyp
        .memory
        .checkpoint_precision_label
        .contains("Hypothetical"));
    assert!(exact
        .memory
        .checkpoint_precision_label
        .contains("Exact checkpoint"));
}

// ---------------- tiny end-to-end on a 48 GB GPU ----------------

#[test]
fn tiny_llama_fits_and_reports_confidence() {
    let r = run(
        &serde_json::from_str(TINY_LLAMA).unwrap(),
        "RTX 6000 Ada",
        1,
        1,
        Precision::Bf16,
        false,
        64,
        128,
    );
    assert_eq!(r.verdict, Verdict::Comfortable);
    assert!(r.memory.weight_gib_per_gpu < 0.001);
    assert_eq!(r.confidence.memory, ConfidenceGrade::Analytical);
    assert_eq!(r.confidence.analyze_level, AnalyzeLevel::C);
}

// ---------------- Golden snapshot (locks §25 schema + numbers) ----------------

#[test]
fn golden_laguna_b200_nvfp4_snapshot() {
    // Full pipeline: config -> normalize -> memory::evaluate -> ScenarioResult,
    // compared (as parsed JSON) against a committed golden file. Catches numeric
    // drift or schema/field-name regressions as the library evolves.
    let r = run(
        &laguna(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    let actual: serde_json::Value = serde_json::to_value(&r).expect("serializes");
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("assets/laguna-b200-nvfp4.json")).expect("golden parses");
    assert_eq!(
        actual, golden,
        "golden snapshot mismatch (regenerate via CLI)"
    );
}
