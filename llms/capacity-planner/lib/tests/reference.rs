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
use capacity_planner::result::{BindingConstraint, Verdict};
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
        replicas: None,
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
        avg_output_tokens: 512,
        slo_target_seconds: 10.0,
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
    // 117,561,965,568 (Level C, derived from config.json alone), including the
    // attention output gate and an `o_proj` shaped `heads × head_dim → hidden`
    // rather than `hidden → hidden`.
    assert_eq!(m.parameter_count(), Some(117_561_965_568));
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
    // 2,803,138,560 attention param count is derived without inference (tested
    // separately in attention_uses_per_layer_head_counts_and_projection_shapes).
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
        .any(|w| w.to_lowercase().contains("available for allocation")));
    // A model that cannot load has no run to characterise, so performance must
    // stay unpopulated rather than quoting decode rates for it.
    assert!(r.performance.decode_tokens_per_second_per_request.is_none());
    assert!(r.performance.slo_concurrency.is_none());
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

// ---------------- Quantized-checkpoint end-to-end ----------------

/// The public Laguna config with the `quantization_config` an llm-compressor
/// NVFP4 run emits: routed experts quantized, attention / embeddings / lm_head /
/// routers / shared experts / the layer-0 dense MLP / the last 8 layers' experts
/// all left at BF16.
fn laguna_nvfp4() -> Value {
    let mut cfg = laguna();
    cfg["quantization_config"] = serde_json::json!({
        "quant_method": "compressed-tensors",
        "format": "nvfp4-pack-quantized",
        "quantization_status": "compressed",
        "config_groups": {
            "group_0": {
                "targets": ["re:.*experts\\.[0-9]+\\.(gate_proj|up_proj|down_proj)$"],
                "weights": { "num_bits": 4, "type": "float", "group_size": 16 }
            }
        },
        "ignore": [
            "lm_head",
            "re:.*\\.self_attn\\.q_proj$",
            "re:.*\\.self_attn\\.k_proj$",
            "re:.*\\.self_attn\\.v_proj$",
            "re:.*\\.self_attn\\.o_proj$",
            "re:.*\\.self_attn\\.g_proj$",
            "re:.*\\.mlp\\.gate$",
            "model.layers.0.mlp.gate_proj",
            "model.layers.0.mlp.up_proj",
            "model.layers.0.mlp.down_proj",
            "re:.*\\.mlp\\.shared_expert\\.gate_proj$",
            "re:.*\\.mlp\\.shared_expert\\.up_proj$",
            "re:.*\\.mlp\\.shared_expert\\.down_proj$",
            "re:^model\\.layers\\.4[0-7]\\.mlp\\.experts(\\..*)?$"
        ]
    });
    cfg
}

/// End to end, the headline regression: a checkpoint that quantized 39 of its
/// 47 expert layers must be sized from what it actually stores. Reading the
/// `nvfp4-pack-quantized` format alone and applying it to all 117.56B
/// parameters reports ~61 GiB for a checkpoint that is ~93 GiB on disk — a 34%
/// under-count, and the same factor off on every bandwidth-bound decode figure.
#[test]
fn quantized_checkpoint_is_sized_from_its_ignore_list() {
    let exact = run(
        &laguna_nvfp4(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        false,
        32_768,
        1_048_576,
    );
    assert_eq!(
        exact.memory.checkpoint_precision_label,
        "Exact checkpoint — NVFP4 53% + BF16 47%"
    );
    let gib = exact.memory.checkpoint_storage_gib;
    assert!((92.0..94.0).contains(&gib), "checkpoint storage was {gib}");

    // Same config, precision override on: the blanket-NVFP4 reading.
    let overridden = run(
        &laguna_nvfp4(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert!(
        overridden.memory.checkpoint_storage_gib < gib * 0.7,
        "the override should differ sharply from the checkpoint; got {} vs {gib}",
        overridden.memory.checkpoint_storage_gib
    );
    // ...and must say so rather than presenting itself as the checkpoint.
    assert!(
        overridden
            .warnings
            .iter()
            .any(|w| w.contains("overriding the checkpoint") && w.contains("nvfp4-pack-quantized")),
        "override warning missing: {:?}",
        overridden.warnings
    );
}

/// The override warning is specific to checkpoints that declare quantization.
/// An unquantized BF16 config asked for an NVFP4 what-if is an ordinary
/// estimate, not a contradiction of anything the config said.
#[test]
fn unquantized_checkpoint_gets_the_plain_hypothetical_warning() {
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
    assert!(!r
        .warnings
        .iter()
        .any(|w| w.contains("overriding the checkpoint")));
    assert!(r
        .warnings
        .iter()
        .any(|w| w.starts_with("Hypothetical quantization — weights use a format")));
}

/// Weight memory drives the bandwidth-bound decode estimate, so mis-sizing the
/// checkpoint mis-reports performance by the same factor.
#[test]
fn quantized_checkpoint_lowers_decode_versus_the_blanket_reading() {
    let exact = run(
        &laguna_nvfp4(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        false,
        32_768,
        1_048_576,
    );
    let blanket = run(
        &laguna_nvfp4(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    let decode = |r: &ScenarioResult| {
        r.performance
            .decode_tokens_per_second_per_request
            .as_ref()
            .expect("decode range")
            .max
    };
    assert!(
        decode(&exact) < decode(&blanket),
        "heavier weights must decode slower: {} vs {}",
        decode(&exact),
        decode(&blanket)
    );
}

// ---------------- Golden snapshot (locks §25 schema + numbers) ----------------

#[test]
fn golden_laguna_b200_nvfp4_snapshot() {
    // Full pipeline: config -> normalize -> memory::evaluate -> ScenarioResult,
    // compared (as pretty-printed JSON string) against a committed golden file.
    // Catches numeric drift or schema/field-name regressions as the library
    // evolves.
    //
    // String comparison, not parsed `Value`: `serde_json::from_str` rounds some
    // f64 literals 1 ULP away from the value `to_value` produces for the same
    // number (e.g. the step latency 0.0009728299847847513 parses back as
    // ...512), so a parsed comparison fails on a byte-identical file.
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
    let actual = serde_json::to_string_pretty(&r).expect("serializes");
    let golden = include_str!("assets/laguna-b200-nvfp4.json").trim_end();
    assert_eq!(
        actual, golden,
        "golden snapshot mismatch (regenerate via CLI)"
    );
}

// ---------------- Regression tests for the Phase-3 review findings ----------------

/// Same as `run` but surfaces the error instead of unwrapping, for the
/// validation cases that must be rejected outright.
#[allow(clippy::too_many_arguments)]
fn try_run(
    model: &Value,
    gpu_sku: &str,
    count: u32,
    tp: u32,
    avg: u64,
    max: u64,
) -> capacity_planner::Result<ScenarioResult> {
    let model = adapter::normalize(model).expect("model normalizes");
    let gpu = GpuConfig {
        sku: gpu_sku.to_string(),
        count,
        topology: Topology::PciE,
        tensor_parallel: tp,
        replicas: None,
        utilization: None,
        runtime_reserve_gib: None,
    };
    let wl = Workload {
        avg_context_tokens: avg,
        max_context_tokens: max,
        tensor_parallel: tp,
        ..Workload::default()
    };
    capacity_planner::memory::evaluate(&Inputs {
        model: &model,
        gpu,
        workload: wl,
    })
}

#[test]
fn tensor_parallel_beyond_gpu_count_is_rejected() {
    // Previously returned "comfortable" with 1443 concurrent requests by
    // sharding one model across 8 ranks that do not physically exist.
    let err = try_run(&laguna(), "B200 SXM 180 GB", 1, 8, 32_768, 1_048_576)
        .expect_err("TP=8 on one GPU must be rejected");
    let msg = err.to_string();
    assert!(msg.contains("tensor parallel"), "message was: {msg}");
    assert!(msg.contains('8') && msg.contains('1'), "message was: {msg}");
}

#[test]
fn inverted_context_pair_is_rejected() {
    // Previously accepted, yielding a higher concurrency at maximum context
    // than at average context.
    let err = try_run(&laguna(), "B200 SXM 180 GB", 1, 1, 100_000, 1_000)
        .expect_err("avg > max context must be rejected");
    assert!(
        err.to_string().contains("average context"),
        "message was: {err}"
    );
}

#[test]
fn tensor_parallel_equal_to_gpu_count_is_allowed() {
    let r = try_run(&laguna(), "B200 SXM 180 GB", 8, 8, 32_768, 1_048_576)
        .expect("TP == count is a valid configuration");
    assert_eq!(r.topology.tensor_parallel, 8);
    // 8 GPUs in groups of 8 = one replica, not 8.
    assert_eq!(r.topology.data_parallel, 1);
}

#[test]
fn data_parallel_is_replicas_not_raw_gpu_count() {
    let r = try_run(&laguna(), "B200 SXM 180 GB", 8, 2, 32_768, 1_048_576).expect("evaluates");
    assert_eq!(r.topology.tensor_parallel, 2);
    assert_eq!(r.topology.data_parallel, 4, "8 GPUs / TP2 = 4 replicas");
}

#[test]
fn laguna_hybrid_is_expert_parallel() {
    // Laguna normalizes to ModelType::Hybrid, but it still has a 256-expert
    // router, so expert parallelism applies.
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
    assert!(r.topology.expert_parallel);
}

#[test]
fn missing_kv_geometry_degrades_confidence_and_warns() {
    // A config with no attention metadata: KvConfig substitutes 1 head x 1 dim,
    // which used to yield ~76k "comfortable" sequences at Analytical/Level C.
    let raw: Value = serde_json::from_str(
        r#"{"model_type":"mystery","architectures":["MysteryForCausalLM"],
            "hidden_size":4096,"num_hidden_layers":32,"vocab_size":32000}"#,
    )
    .unwrap();
    let r = try_run(&raw, "B200 SXM 180 GB", 1, 1, 32_768, 1_048_576).expect("evaluates");
    assert_eq!(r.confidence.memory, ConfidenceGrade::Speculative);
    assert_eq!(r.confidence.analyze_level, AnalyzeLevel::D);
    assert_eq!(r.confidence.performance, ConfidenceGrade::Speculative);
    assert!(
        r.warnings.iter().any(|w| w.contains("KV-cache geometry")),
        "warnings were: {:?}",
        r.warnings
    );
    // The adapter's `inferred` notes must reach the result, not be discarded.
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("model_type unrecognized")),
        "warnings were: {:?}",
        r.warnings
    );
}

#[test]
fn fully_parsed_model_keeps_analytical_confidence() {
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
    assert_eq!(r.confidence.memory, ConfidenceGrade::Analytical);
    assert_eq!(r.confidence.analyze_level, AnalyzeLevel::C);
    assert!(!r.warnings.iter().any(|w| w.contains("KV-cache geometry")));
}

/// Dense 70B FP8 on one B200, 8K context, 512 output tokens.
fn dense_70b_on_b200(slo_target_seconds: f64) -> ScenarioResult {
    let raw: Value = serde_json::from_str(
        r#"{"model_type":"llama","architectures":["LlamaForCausalLM"],
            "vocab_size":128256,"hidden_size":8192,"intermediate_size":28672,
            "num_hidden_layers":80,"num_attention_heads":64,"num_key_value_heads":8,
            "head_dim":128,"max_position_embeddings":131072,
            "tie_word_embeddings":false,"torch_dtype":"bfloat16"}"#,
    )
    .unwrap();
    let model = adapter::normalize(&raw).unwrap();
    let gpu = GpuConfig {
        sku: "B200 SXM 180 GB".to_string(),
        count: 1,
        topology: Topology::NvLink5,
        tensor_parallel: 1,
        replicas: None,
        utilization: None,
        runtime_reserve_gib: None,
    };
    let wl = Workload {
        avg_context_tokens: 8_192,
        max_context_tokens: 32_768,
        weight_precision: Precision::Fp8,
        kv_precision: Precision::Fp8,
        slo_target_seconds,
        ..Workload::default()
    };
    capacity_planner::memory::evaluate(&Inputs {
        model: &model,
        gpu,
        workload: wl,
    })
    .expect("evaluates")
}

#[test]
fn batching_amortises_weights_so_concurrency_scales_with_slo_headroom() {
    // The old model multiplied decode time by concurrency, so C_SLO grew only
    // linearly with the target and topped out around 2 no matter how much
    // headroom existed. Reading weights once per step means a modest increase
    // in the target buys a large increase in servable concurrency.
    let tight = dense_70b_on_b200(10.0).performance.slo_concurrency.unwrap();
    let loose = dense_70b_on_b200(20.0).performance.slo_concurrency.unwrap();
    assert!(
        loose > tight * 10,
        "doubling the SLO target should multiply concurrency (batching), \
         got {tight} -> {loose}"
    );
}

#[test]
fn slo_concurrency_never_exceeds_the_memory_ceiling() {
    // A batch that does not fit in KV memory is not a candidate however fast it
    // would run, so a very loose target must converge on C_memory, not diverge.
    let r = dense_70b_on_b200(600.0);
    let slo = r.performance.slo_concurrency.unwrap();
    assert_eq!(
        slo, r.memory.memory_concurrency_average,
        "with unlimited time budget the binding constraint is KV memory"
    );
}

#[test]
fn aggregate_throughput_exceeds_single_stream_when_batched() {
    // Aggregate was previously per-request x DP replicas, i.e. it credited
    // batching with nothing at all and reported 45-78 tok/s for a whole B200.
    let r = dense_70b_on_b200(20.0);
    let per_req = r
        .performance
        .decode_tokens_per_second_per_request
        .expect("populated");
    let agg = r
        .performance
        .aggregate_decode_tokens_per_second
        .expect("populated");
    assert!(
        agg.min > per_req.min * 10.0,
        "aggregate {} should far exceed single-stream {}",
        agg.min,
        per_req.min
    );
    // Single-stream decode is a per-request figure and must not inherit the
    // batch speedup.
    assert!(per_req.min > 20.0 && per_req.max < 200.0, "{per_req:?}");
}

#[test]
fn moe_expert_activation_saturates_with_batch_size() {
    // 10-of-256 routing: one token touches ~4% of experts, but a large batch
    // touches nearly all of them, which is what erodes MoE's batch-1 bandwidth
    // advantage. A model that ignored this would over-credit MoE at scale.
    let f1 = capacity_planner::performance::expert_activation_fraction(10, 256, 1);
    let f32 = capacity_planner::performance::expert_activation_fraction(10, 256, 32);
    let f512 = capacity_planner::performance::expert_activation_fraction(10, 256, 512);
    assert!(
        (f1 - 10.0 / 256.0).abs() < 1e-12,
        "f(1) must be k/E, got {f1}"
    );
    assert!(f32 > f1 && f32 < 1.0, "f(32) = {f32}");
    assert!(f512 > 0.99, "f(512) should be near-total, got {f512}");
    // Dense models have no routed experts to discount.
    assert_eq!(
        capacity_planner::performance::expert_activation_fraction(0, 0, 8),
        1.0
    );
}

#[test]
fn kv_write_per_token_counts_every_cached_layer() {
    // Previously omitted the layer count, understating prefill KV write traffic
    // by 48x for Laguna.
    let model = adapter::normalize(&laguna()).unwrap();
    let bytes = capacity_planner::performance::kv_write_bytes_per_token(&model, Precision::Fp8, 1);
    // 2 (K+V) * 8 kv_heads * 128 head_dim * 1 byte * 48 layers.
    assert_eq!(bytes, 2.0 * 8.0 * 128.0 * 1.0 * 48.0);
}

#[test]
fn hopper_parts_have_no_fp4_compute_path() {
    // H200 was catalogued as Blackwell with an invented 4000 TFLOPS NVFP4 peak.
    for sku in ["H100 SXM 80 GB", "H200 SXM 141 GB"] {
        let g = capacity_planner::hardware::find(sku).unwrap();
        assert_eq!(g.architecture, "Hopper", "{sku}");
        assert!(g.nvfp4_tflops.is_none(), "{sku} must not claim FP4 compute");
        // FP8 is 2x BF16 on Hopper; both parts must agree on the convention.
        assert_eq!(g.fp8_tflops, Some(g.bf16_fp16_tflops * 2.0), "{sku}");
    }
}

// ---- generic-adapter regression: sparse models must not report as small dense
// models (see `adapter::generic`). DeepSeek-V4-Flash has no dedicated adapter,
// declares its MLP width only as `moe_intermediate_size`, and carries a blanket
// `sliding_window` with no `layer_types`.

const DEEPSEEK_V4_JSON: &str = include_str!("assets/deepseek-v4-flash-config.json");

fn deepseek_v4() -> Value {
    serde_json::from_str(DEEPSEEK_V4_JSON).unwrap()
}

#[test]
fn generic_adapter_counts_routed_experts() {
    let m = adapter::normalize(&deepseek_v4()).expect("normalizes");
    // 256 routed + 1 shared expert, each 3 * 4096 * 2048, over 43 layers.
    let experts_per_layer: u128 = 257 * 3 * 4096 * 2048;
    let params = m.parameter_count().expect("has a parameter count");
    assert!(
        params > experts_per_layer * 43,
        "expert tensors omitted: got {params} params"
    );
    // The pre-fix generic path reported 7.73B for this config.
    assert!(params > 250_000_000_000, "got {params} params");
    let moe = m.moe.as_ref().expect("MoE detected");
    assert_eq!(moe.expert_count, 256);
    assert_eq!(moe.active_experts_per_token, 6);
}

/// Expert tensors are ~97% of this model's parameters, so their *precision*
/// matters as much as their presence. The config declares `quant_method: "fp8"`;
/// sizing those experts at the BF16 `torch_dtype` reported 542 GiB for a
/// checkpoint that stores 272.
#[test]
fn generic_adapter_sizes_experts_at_the_checkpoints_precision() {
    let m = adapter::normalize(&deepseek_v4()).expect("normalizes");
    let routed: Vec<_> = m
        .weights
        .components
        .iter()
        .filter(|c| c.category == capacity_planner::precision::WeightCategory::RoutedExperts)
        .collect();
    assert!(!routed.is_empty(), "no routed experts");
    assert!(
        routed.iter().all(|c| c.precision == Precision::Fp8),
        "experts were not sized as FP8: {:?}",
        routed.iter().map(|c| c.precision).collect::<Vec<_>>()
    );

    // Embeddings and the output head are not Linear conversions, so they keep
    // the base dtype — the checkpoint is a mix, not uniformly FP8.
    let r = run(
        &deepseek_v4(),
        "B200 SXM 180 GB",
        8,
        8,
        Precision::Nvfp4,
        false,
        32_768,
        1_048_576,
    );
    assert!(
        r.memory
            .checkpoint_precision_label
            .starts_with("Exact checkpoint — FP8"),
        "label was {:?}",
        r.memory.checkpoint_precision_label
    );
    let gib = r.memory.checkpoint_storage_gib;
    assert!(
        (265.0..280.0).contains(&gib),
        "checkpoint storage was {gib} GiB (BF16 would be ~542)"
    );
}

#[test]
fn blanket_sliding_window_does_not_freeze_kv_against_context() {
    // `sliding_window: 128` with no per-layer pattern previously capped every
    // layer at 128 tokens, making KV identical at 32K and 1M context.
    let r = run(
        &deepseek_v4(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert!(
        r.memory.kv_gib_per_maximum_sequence > r.memory.kv_gib_per_average_sequence,
        "KV did not scale with context: avg {} / max {}",
        r.memory.kv_gib_per_average_sequence,
        r.memory.kv_gib_per_maximum_sequence
    );
}

#[test]
fn unmodelled_architecture_is_capped_at_level_d() {
    let r = run(
        &deepseek_v4(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    // Every field the KV-geometry check looks at is present and readable here,
    // so only the `unresolved` gate can catch this.
    assert_eq!(r.confidence.analyze_level, AnalyzeLevel::D);
    assert_eq!(r.confidence.memory, ConfidenceGrade::Speculative);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("no dedicated adapter")),
        "warnings were: {:?}",
        r.warnings
    );
}

#[test]
fn missing_mlp_width_is_reported_not_silently_zero() {
    // Dense config with no `intermediate_size`: the MLP term used to evaluate to
    // 0 and disappear into a confident-looking parameter count.
    let raw: Value = serde_json::from_str(
        r#"{"model_type":"mystery","architectures":["MysteryForCausalLM"],
            "hidden_size":4096,"num_hidden_layers":32,"vocab_size":32000,
            "num_attention_heads":32,"num_key_value_heads":8,"head_dim":128}"#,
    )
    .unwrap();
    let m = adapter::normalize(&raw).expect("normalizes");
    assert!(
        m.unresolved.iter().any(|u| u.contains("no MLP width")),
        "unresolved was: {:?}",
        m.unresolved
    );
}

// ---- KV sharding, replicas, and the binding constraint ---------------------

#[test]
fn kv_is_replicated_when_tp_exceeds_kv_heads() {
    // DeepSeek-V4-Flash has num_key_value_heads = 1. A single KV head cannot be
    // split across 4 ranks, so TP must not divide per-GPU KV here.
    let r1 = run(
        &deepseek_v4(),
        "RTX PRO 6000 Blackwell Workstation Edition",
        4,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    let r4 = run(
        &deepseek_v4(),
        "RTX PRO 6000 Blackwell Workstation Edition",
        4,
        4,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert!(r4.memory.kv_replicated_across_ranks);
    assert_eq!(
        r4.memory.kv_gib_per_maximum_sequence, r1.memory.kv_gib_per_maximum_sequence,
        "TP divided a single KV head across ranks"
    );
    assert!(
        r4.warnings
            .iter()
            .any(|w| w.contains("KV head cannot be split")),
        "warnings were: {:?}",
        r4.warnings
    );
}

#[test]
fn kv_still_shards_when_heads_allow_it() {
    // Laguna has 8 KV heads, so TP=2 genuinely halves per-rank KV.
    let r1 = run(
        &laguna(),
        "B200 SXM 180 GB",
        2,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    let r2 = run(
        &laguna(),
        "B200 SXM 180 GB",
        2,
        2,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert!(!r2.memory.kv_replicated_across_ranks);
    assert!(
        (r2.memory.kv_gib_per_maximum_sequence * 2.0 - r1.memory.kv_gib_per_maximum_sequence).abs()
            < 1e-9
    );
}

#[test]
fn replicas_default_to_filling_the_machine_and_can_be_capped() {
    let gpu = |replicas| GpuConfig {
        sku: "B200 SXM 180 GB".to_string(),
        count: 8,
        topology: Topology::NvLink5,
        tensor_parallel: 4,
        replicas,
        utilization: None,
        runtime_reserve_gib: None,
    };
    assert_eq!(gpu(None).replicas(), 2);
    assert_eq!(gpu(None).gpus_in_use(), 8);
    // Deliberately running one copy on half the machine.
    assert_eq!(gpu(Some(1)).replicas(), 1);
    assert_eq!(gpu(Some(1)).gpus_in_use(), 4);
}

#[test]
fn idle_gpus_are_reported_not_silently_assumed_busy() {
    let model = adapter::normalize(&laguna()).unwrap();
    let gpu = GpuConfig {
        sku: "B200 SXM 180 GB".to_string(),
        count: 8,
        topology: Topology::NvLink5,
        tensor_parallel: 4,
        replicas: Some(1),
        utilization: None,
        runtime_reserve_gib: None,
    };
    let r = capacity_planner::memory::evaluate(&Inputs {
        model: &model,
        gpu,
        workload: Workload {
            tensor_parallel: 4,
            ..Workload::default()
        },
    })
    .expect("evaluates");
    assert_eq!(r.topology.data_parallel, 1);
    assert_eq!(r.topology.gpus_in_use, 4);
    assert_eq!(r.topology.gpus_idle, 4);
    assert!(
        r.warnings.iter().any(|w| w.contains("hold no model copy")),
        "warnings were: {:?}",
        r.warnings
    );
}

#[test]
fn replicas_beyond_gpu_count_are_rejected() {
    let model = adapter::normalize(&laguna()).unwrap();
    let gpu = GpuConfig {
        sku: "B200 SXM 180 GB".to_string(),
        count: 4,
        topology: Topology::NvLink5,
        tensor_parallel: 2,
        replicas: Some(3),
        utilization: None,
        runtime_reserve_gib: None,
    };
    let err = capacity_planner::memory::evaluate(&Inputs {
        model: &model,
        gpu,
        workload: Workload {
            tensor_parallel: 2,
            ..Workload::default()
        },
    });
    assert!(err.is_err(), "3 replicas x TP2 needs 6 GPUs, only 4 given");
}

#[test]
fn binding_constraint_names_the_limit_that_bound() {
    // Laguna at 1M max context is memory-bound at 3 sequences.
    let memory_bound = run(
        &laguna(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert_eq!(
        memory_bound.practical_capacity.binding_constraint,
        BindingConstraint::MemoryAtMaximumContext
    );
    // Shrink max context until VRAM is no longer the wall and the SLO is.
    let slo_bound = run(
        &laguna(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        4_096,
        4_096,
    );
    assert_eq!(
        slo_bound.practical_capacity.binding_constraint,
        BindingConstraint::SloLatency
    );
}

// ---- cluster-wide vs per-replica concurrency, and unified-memory parts ------

#[test]
fn memory_ceiling_scales_with_replicas() {
    // The per-replica ceilings previously fed straight into a comparison with a
    // cluster-wide SLO figure, so 4 replicas reported the same capacity as 1.
    let one = run(
        &laguna(),
        "B200 SXM 180 GB",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    let four = run(
        &laguna(),
        "B200 SXM 180 GB",
        4,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert_eq!(four.topology.data_parallel, 4);
    // Per-replica figures are identical — one replica's VRAM does not change.
    assert_eq!(
        four.memory.memory_concurrency_maximum,
        one.memory.memory_concurrency_maximum
    );
    // Cluster-wide figures scale.
    assert_eq!(
        four.memory.memory_concurrency_maximum_total,
        one.memory.memory_concurrency_maximum * 4
    );
    assert_eq!(
        four.practical_capacity.comfortable_active_requests,
        one.practical_capacity.comfortable_active_requests * 4
    );
}

#[test]
fn comfortable_never_exceeds_either_cluster_ceiling() {
    for count in [1u32, 2, 4, 8] {
        let r = run(
            &laguna(),
            "B200 SXM 180 GB",
            count,
            1,
            Precision::Nvfp4,
            true,
            32_768,
            1_048_576,
        );
        let c = r.practical_capacity.comfortable_active_requests;
        assert!(
            c <= r.memory.memory_concurrency_maximum_total,
            "{count} GPUs"
        );
        assert!(
            c <= r.memory.memory_concurrency_average_total,
            "{count} GPUs"
        );
        assert!(
            c <= r.performance.slo_concurrency.unwrap(),
            "{count} GPUs: comfortable {c} exceeded the SLO ceiling"
        );
    }
}

#[test]
fn gb10_parts_are_unified_memory_and_bandwidth_bound() {
    for sku in ["DGX Spark (GB10)", "Dell Pro Max with GB10"] {
        let g = capacity_planner::hardware::find(sku).expect("in catalog");
        assert!(g.unified_memory, "{sku}");
        // Host OS and serving process come out of the same pool, so neither the
        // 0.90 ceiling nor the 1 GiB reserve a discrete card gets applies.
        assert!(g.default_utilization < 0.90, "{sku}");
        assert!(g.typical_runtime_reserve_gib > 1.0, "{sku}");
        assert_eq!(g.memory_marketed_gb, 128.0, "{sku}");
        assert_eq!(g.memory_bandwidth_gbs, 273.0, "{sku}");
    }
    // Every discrete part keeps the flag off.
    for sku in ["B200 SXM 180 GB", "H100 SXM 80 GB", "RTX 6000 Ada"] {
        assert!(
            !capacity_planner::hardware::find(sku)
                .unwrap()
                .unified_memory
        );
    }
}

#[test]
fn unified_memory_is_surfaced_as_a_warning() {
    let r = run(
        &laguna(),
        "DGX Spark (GB10)",
        1,
        1,
        Precision::Nvfp4,
        true,
        32_768,
        1_048_576,
    );
    assert!(
        r.warnings.iter().any(|w| w.contains("shares one")),
        "warnings were: {:?}",
        r.warnings
    );
}

// ---- laguna-adapter regression: a config with no `layer_types` -------------
// Laguna-M.1 declares `mlp_layer_types` but no *attention* `layer_types`, and
// spells "no sliding window" as `sliding_window: 0`. Both previously produced a
// model with zero KV-bearing layers: KV_seq collapsed to 0 bytes, and
// `memory_concurrency` returned its u64::MAX divide-by-zero sentinel — surfacing
// in the UI as 18,446,744,073,709,551,615 concurrent requests.

const LAGUNA_M1_JSON: &str = include_str!("assets/laguna-m1-config.json");

fn laguna_m1() -> Value {
    serde_json::from_str(LAGUNA_M1_JSON).unwrap()
}

#[test]
fn config_without_layer_types_still_has_kv_bearing_layers() {
    let m = adapter::normalize(&laguna_m1()).expect("normalizes");
    let kv_layers: u32 = m
        .attention_layers
        .iter()
        .filter(|l| l.kind != AttentionKind::Ssm)
        .map(|l| l.count)
        .sum();
    assert_eq!(
        kv_layers, 70,
        "all 70 layers must carry KV when no per-layer pattern is given"
    );
    // `sliding_window: 0` means disabled, not a zero-token window.
    assert!(m
        .attention_layers
        .iter()
        .all(|l| l.window_size.is_none_or(|w| w > 0)));
}

#[test]
fn config_without_layer_types_reports_finite_concurrency() {
    let r = run(
        &laguna_m1(),
        "B200 SXM 180 GB",
        8,
        4,
        Precision::Fp8,
        true,
        32_768,
        262_144,
    );
    assert!(
        r.memory.kv_gib_per_average_sequence > 0.0,
        "KV per sequence was {} GiB",
        r.memory.kv_gib_per_average_sequence
    );
    // 2 × 70 layers × 32768 tokens × 2 kv-heads-per-rank × 128 × 1 B (FP8).
    let expected = (2u64 * 70 * 32_768 * 2 * 128) as f64 / GIB_BYTES as f64;
    let got = r.memory.kv_gib_per_average_sequence;
    assert!(
        (got - expected).abs() < 1e-3,
        "KV was {got} GiB, expected ~{expected}"
    );
    for c in [
        r.memory.memory_concurrency_average,
        r.memory.memory_concurrency_maximum,
        r.memory.memory_concurrency_average_total,
        r.memory.memory_concurrency_maximum_total,
    ] {
        assert!(c < 1_000_000, "concurrency sentinel leaked: {c}");
    }
}
