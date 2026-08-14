//! Runtime and activation memory (PRD §14).
//!
//! Weights and KV cache are not the whole budget. An engine also holds a fixed
//! per-GPU footprint and a per-scheduler-step footprint, and PRD §14 gives the
//! shape:
//!
//! ```text
//! M_runtime = M_fixed
//!           + M_token    × N_scheduledTokens
//!           + M_sequence × N_runningSequences
//! ```
//!
//! Only `M_fixed` used to exist here, as the catalog's flat
//! `typical_runtime_reserve_gib`. The two scaling terms were absorbed into it,
//! which made every concurrency figure optimistic: a 48-layer MoE serving 8192
//! batched tokens holds over a gibibyte of transient activations that the 1 GiB
//! reserve was also supposed to cover on its own.
//!
//! # What `N_runningSequences` resolves to
//!
//! Read literally the formula is circular, because the running-sequence count is
//! what the capacity math solves for. vLLM settles it by profiling: it runs a
//! forward pass at the *configured maxima* (`max_num_batched_tokens`,
//! `max_num_seqs`), measures the peak, and subtracts that before allocating a
//! single KV block. The reservation does not shrink when fewer requests are in
//! flight. So `N_runningSequences` is `max_num_seqs`, and concurrency is capped
//! by it — you cannot exceed a bound you already reserved for.
//!
//! # Activation traffic is a different quantity
//!
//! [`crate::performance::temp_bytes_per_token`] also says "activations" and must
//! not be confused with this. It sums activation bytes over every layer because
//! it measures DRAM *traffic* for the bandwidth roofline. Peak *residency* is set
//! by one layer, since the buffers are reused down the stack. For a 48-layer
//! model the two differ by about 48×.
//!
//! # Calibration status
//!
//! These coefficients are derived from architecture — hidden size, head counts,
//! MoE top-k and expert width, vocabulary — in the same spirit as
//! [`crate::weight::load_factor`], and like those factors they are broad
//! constants awaiting benchmark calibration (PRD §17). They model vLLM's
//! allocator rather than measuring it. Two known approximations:
//!
//!   * Per-layer attention head counts are not visible here, so a model with a
//!     `num_attention_heads_per_layer` array (Laguna's sliding layers run 72
//!     heads against a nominal 48) has its attention term computed from the
//!     nominal count. That understates `M_token` by under 10% on such models —
//!     inside the spread between memory profiles.
//!   * CUDA-graph capture is calibrated against a single measured run (see
//!     [`cuda_graph_bytes`]), so its dependence on hidden size and TP width is
//!     folded into one constant.
//!   * Speculative decoding is not modelled at all. A draft model carries its own
//!     weights and KV, and `num_spec_tokens` multiplies the tokens a decode step
//!     carries per sequence, which scales `M_token` with it.

use serde::{Deserialize, Serialize};

use crate::hardware::Gpu;
use crate::model::NormalizedModel;
use crate::precision::Precision;

/// Bytes per MiB / GiB, for readability in the coefficient tables below.
const MIB: f64 = 1024.0 * 1024.0;

/// Memory profile (PRD §14). Scales the whole runtime estimate: the coefficients
/// are approximations, and which direction to err in is the user's call.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MemoryProfile {
    /// Procurement and production planning. Assume the engine wants more than
    /// the model says, because being wrong here means an OOM in production.
    Conservative,
    /// Typical deployment estimate. The coefficients as derived.
    #[default]
    Balanced,
    /// Maximum technical fit. What the hardware can be made to do with the
    /// scheduler tuned down; not what it will do out of the box.
    Aggressive,
}

impl MemoryProfile {
    pub fn label(self) -> &'static str {
        match self {
            MemoryProfile::Conservative => "Conservative",
            MemoryProfile::Balanced => "Balanced",
            MemoryProfile::Aggressive => "Aggressive",
        }
    }

    /// Multiplier applied to every runtime term.
    pub fn factor(self) -> f64 {
        match self {
            MemoryProfile::Conservative => 1.25,
            MemoryProfile::Balanced => 1.00,
            MemoryProfile::Aggressive => 0.80,
        }
    }

    pub fn purpose(self) -> &'static str {
        match self {
            MemoryProfile::Conservative => "procurement and production planning",
            MemoryProfile::Balanced => "typical deployment estimate",
            MemoryProfile::Aggressive => "maximum technical fit",
        }
    }
}

/// The three PRD §14 coefficients, in bytes, for one GPU rank.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMemory {
    /// CUDA context, kernels, allocator reserve, CUDA graphs, NCCL buffers.
    pub fixed_bytes: u128,
    /// Peak transient activation per scheduled token.
    pub per_token_bytes: u128,
    /// Logits and sampling buffers per running sequence.
    pub per_sequence_bytes: u128,
}

impl RuntimeMemory {
    /// `M_fixed + M_token × tokens + M_sequence × sequences`.
    pub fn total_bytes(&self, scheduled_tokens: u64, running_sequences: u64) -> u128 {
        self.fixed_bytes
            .saturating_add(
                self.per_token_bytes
                    .saturating_mul(scheduled_tokens as u128),
            )
            .saturating_add(
                self.per_sequence_bytes
                    .saturating_mul(running_sequences as u128),
            )
    }

    /// The part that does not depend on the running-sequence count, which is
    /// what comes off the budget before KV blocks are allocated.
    pub fn step_bytes(&self, scheduled_tokens: u64) -> u128 {
        self.fixed_bytes.saturating_add(
            self.per_token_bytes
                .saturating_mul(scheduled_tokens as u128),
        )
    }
}

/// How many batch shapes vLLM captures graphs for, given `max_num_seqs`.
///
/// Reproduces vLLM's default `cudagraph_capture_sizes`: 1, 2, 4, then eights to
/// 256, then sixteens to 512, truncated at `min(max_num_seqs, 512)`. A run at
/// `max_cudagraph_capture_size=512` reconstructs to exactly the 51 entries the
/// engine logged, which is why this is worth deriving rather than guessing —
/// graph memory scales with the length of this list, and the list is a function
/// of a setting the user already supplies.
pub fn cudagraph_capture_count(max_num_seqs: u64) -> u32 {
    let cap = max_num_seqs.min(512);
    let small = [1u64, 2, 4].iter().filter(|&&s| s <= cap).count();
    let eights = (8..=256.min(cap)).step_by(8).count();
    let sixteens = (272..=cap).step_by(16).count();
    (small + eights + sixteens) as u32
}

/// CUDA-graph memory *as reserved by the profiler*, which is the figure that
/// decides how much KV cache gets allocated.
///
/// Since v0.21 vLLM estimates graph memory during profiling and subtracts it
/// before sizing the KV cache. A measured run reported the estimate as an
/// effective utilization haircut — "the current --gpu-memory-utilization=0.9000
/// is equivalent to --gpu-memory-utilization=0.8836" — which on a 95.5928 GiB
/// card is 1.5677 GiB for 48 layers at 51 captured shapes, or 0.656 MiB per
/// layer per shape.
///
/// Capture then actually took 2.06 GiB on the same run, 0.49 GiB more than was
/// reserved. That overrun lands in the memory left outside the utilization
/// ceiling, so it does not shrink the KV cache and must not be modelled here:
/// what determines concurrency is the reservation, not the eventual footprint.
/// The Conservative profile's 1.25× puts the estimate at 0.820 MiB, close to the
/// 0.862 the capture really cost, which is the risk that profile exists to cover.
///
/// Single-point calibration. The constant almost certainly also absorbs hidden
/// size and TP width, which one observation cannot separate.
const CUDAGRAPH_MIB_PER_LAYER_PER_SHAPE: f64 = 0.656;

fn cuda_graph_bytes(layer_count: u32, max_num_seqs: u64) -> f64 {
    layer_count as f64
        * cudagraph_capture_count(max_num_seqs) as f64
        * CUDAGRAPH_MIB_PER_LAYER_PER_SHAPE
        * MIB
}

/// Cross-rank collective buffers. Only allocated when there is a rank to talk to.
fn collective_bytes(tensor_parallel: u32) -> f64 {
    if tensor_parallel > 1 {
        256.0 * MIB
    } else {
        0.0
    }
}

/// Allocations vLLM attributes to `non_torch_increase`: the CUDA context, the
/// attention backend's workspace, driver-side buffers, and anything else that
/// grows device memory without passing through the PyTorch caching allocator.
///
/// vLLM measures this during its profile run and subtracts it before sizing the
/// KV cache, so it comes straight off capacity. Nothing in a `config.json`
/// predicts it, which is why it is a measured constant rather than a derivation.
///
/// # Calibration
///
/// Two Laguna-S serves on RTX PRO 6000 Blackwell, both at
/// `max_num_batched_tokens=16384`, backing this out as
/// `budget - weights - kv_pool - rope - cudagraph_estimate - modelled_scaling_terms`:
///
/// ```text
/// TP=2, FP8 KV, 262144 ctx, FLASHINFER : 5.078 GiB residual
/// TP=4, BF16 KV, 1048576 ctx, FLASH_ATTN: 4.978 GiB residual
/// ```
///
/// Flat across both TP widths, both attention backends, and a 4x spread in
/// context, which is what a context-and-driver term should look like. The
/// modelled activation and per-sequence terms already account for 1.6–1.9 GiB
/// of that, so what remains here is the rest.
///
/// Two data points cannot separate a TP dependence from a constant, so this
/// stays constant rather than inventing a slope. Both runs land within 2% of
/// measured concurrency with it (see `tests/reference.rs`); treat it as
/// provisional until the calibration set is wider (PRD §17).
fn non_torch_bytes() -> f64 {
    2.75 * (crate::GIB_BYTES as f64)
}

/// Peak transient activation for one scheduled token, on one rank.
///
/// Buffers are reused layer to layer, so this is the widest single layer, not a
/// sum over the stack. Row-parallel and column-parallel projections shard with
/// TP; the residual stream does not, since every rank carries it at full width.
fn per_token_bytes(model: &NormalizedModel, tensor_parallel: u32) -> f64 {
    let b = Precision::Bf16.bytes_per_element();
    let tp = tensor_parallel.max(1) as f64;
    let h = model.dimensions.hidden_size as f64;
    let hd = model.dimensions.head_dimension.unwrap_or(0) as f64;
    let heads = model.dimensions.attention_heads.unwrap_or(0) as f64;
    let kv_heads = model
        .dimensions
        .kv_heads
        .filter(|&v| v != 0)
        .unwrap_or(model.dimensions.attention_heads.unwrap_or(1)) as f64;

    // Residual stream plus the layer's input copy. Full width on every rank.
    let residual = 2.0 * h * b;

    // Q, K and V projection outputs live together, then the attention output
    // before `o_proj` folds it back to hidden width.
    let qkv = (heads * hd + 2.0 * kv_heads * hd) / tp * b;
    let attn_out = heads * hd / tp * b;

    // MLP. `gate_proj` and `up_proj` outputs are both live before the SiLU
    // multiply, which is what makes the MLP the widest point in most layers.
    let mlp = match &model.moe {
        Some(moe) => {
            // A fused MoE kernel expands each token to its top-k experts, so the
            // intermediate buffer is `topk ×` wider than a dense layer of the
            // same expert width. This is the term that dominates on sparse
            // models and the one a dense-MLP estimate misses entirely.
            let topk = moe.active_experts_per_token.max(1) as f64;
            let expert_i = moe.expert_intermediate_size as f64;
            let routed = topk * expert_i * 2.0 / tp * b;
            // Gather/scatter copies of the token itself, one per chosen expert.
            let permute = topk * h * b;
            // A shared expert runs for every token in addition to the routed ones.
            let shared = moe
                .shared_expert_intermediate_size
                .map(|s| s as f64 * 2.0 / tp * b)
                .unwrap_or(0.0);
            routed + permute + shared
        }
        None => {
            let intermediate = model.dimensions.intermediate_size.unwrap_or(0) as f64;
            intermediate * 2.0 / tp * b
        }
    };

    residual + qkv + attn_out + mlp
}

/// Logits and sampling buffers for one running sequence, on one rank.
///
/// vLLM computes logits in FP32 over the whole vocabulary. With TP the vocab is
/// sharded for the projection and then all-gathered, so each rank holds the full
/// row — this does not divide by TP. One sampling workspace of the same shape is
/// counted alongside it for the probability and top-k/top-p temporaries.
fn per_sequence_bytes(model: &NormalizedModel) -> f64 {
    let vocab = model.dimensions.vocabulary_size.unwrap_or(0) as f64;
    let logits = vocab * Precision::Fp32.bytes_per_element();
    logits * 2.0
}

/// Bytes held by rotary-embedding cos/sin tables.
///
/// These are *buffers*, not weights: `RotaryEmbedding` builds them from a
/// formula at load and registers them with `persistent=False`, so they appear in
/// no checkpoint file and summing `model.safetensors.index.json` can never
/// reach vLLM's figure. vLLM still counts them inside its "Model loading took"
/// line, because that line is a GPU allocation delta rather than a parameter
/// tally.
///
/// Three properties make them worth a term of their own:
///
///   * **Sized by the config, not the deployment.** The table spans
///     `max_position_embeddings`, so `--max-model-len 262144` on a model that
///     declares 1M still builds 1M positions.
///   * **Not sharded.** Every rank holds the whole table.
///   * **One per distinct rope configuration, not per layer.** `get_rope()`
///     memoizes on a config key (`_ROPE_DICT`), so an interleaved model with
///     one rope for its full-attention layers and another for its sliding
///     layers builds two tables regardless of layer count.
///
/// Measured against Laguna-S: 0.125 GiB for the full-attention table (partial
/// rotary 0.5, so 64 of 128 dims) plus 0.25 GiB for the sliding table, against
/// 0.375 GiB predicted here.
pub fn rope_table_bytes(model: &NormalizedModel) -> f64 {
    let positions = model.context.native_maximum as f64;
    let head_dim = model.dimensions.head_dimension.unwrap_or(0) as f64;
    if positions <= 0.0 || head_dim <= 0.0 {
        return 0.0;
    }
    // cos and sin are stored concatenated as [positions, rotary_dim] at the
    // model dtype. BF16 is the near-universal case and the only one observed.
    let elem = Precision::Bf16.bytes_per_element();

    let partial_of = |v: &serde_json::Value| -> f64 {
        v.get("partial_rotary_factor")
            .and_then(|p| p.as_f64())
            .unwrap_or(1.0)
            .clamp(0.0, 1.0)
    };

    let factors: Vec<f64> = match &model.context.rope_scaling {
        // A map whose values are themselves objects is a per-attention-type
        // rope block (Laguna's `rope_parameters`), one table per entry.
        Some(serde_json::Value::Object(map))
            if !map.is_empty() && map.values().all(|v| v.is_object()) =>
        {
            map.values().map(partial_of).collect()
        }
        Some(v @ serde_json::Value::Object(_)) => vec![partial_of(v)],
        // No rope block still means one table, at the full head dimension.
        _ => vec![1.0],
    };

    let target: f64 = factors
        .iter()
        .map(|f| positions * (head_dim * f).round() * elem)
        .sum();

    // A drafter builds its own table. Its rope differs from the target's by at
    // least the theta base (Laguna's DFlash uses 500000 against the sliding
    // layers' 10000), so `_ROPE_DICT` cannot hand it an existing one. Full head
    // dimension: drafters observed so far do not use partial rotary.
    let draft = match &model.speculator {
        Some(s) if s.full_context_layers > 0 => {
            let hd = s
                .head_dimension
                .unwrap_or(model.dimensions.head_dimension.unwrap_or(0));
            positions * hd as f64 * elem
        }
        _ => 0.0,
    };

    target + draft
}

/// Estimate the PRD §14 coefficients for a model on a GPU.
///
/// `fixed_override` replaces the fixed term outright (the user's
/// `runtime_reserve_gib`); the scaling terms still apply, because a hand-set
/// fixed reserve says nothing about how wide the scheduler runs.
pub fn estimate(
    model: &NormalizedModel,
    gpu: &Gpu,
    tensor_parallel: u32,
    profile: MemoryProfile,
    fixed_override_gib: Option<f64>,
    max_num_seqs: u64,
) -> RuntimeMemory {
    let factor = profile.factor();
    let gib = crate::GIB_BYTES as f64;

    let fixed = match fixed_override_gib {
        Some(g) => g * gib,
        None => {
            // The catalog figure covers context, kernels and allocator reserve —
            // larger on unified-memory parts, where the host OS shares the pool.
            gpu.typical_runtime_reserve_gib * gib
                + non_torch_bytes()
                + cuda_graph_bytes(model.dimensions.layer_count, max_num_seqs)
                + collective_bytes(tensor_parallel)
        }
    };

    RuntimeMemory {
        // Rope tables are added outside the profile factor and outside the
        // override: their size is arithmetic on the config, not an estimate to
        // be scaled, and a hand-set reserve does not make them go away.
        fixed_bytes: (fixed * factor) as u128 + rope_table_bytes(model) as u128,
        per_token_bytes: (per_token_bytes(model, tensor_parallel) * factor) as u128,
        per_sequence_bytes: (per_sequence_bytes(model) * factor) as u128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::find;

    fn laguna() -> NormalizedModel {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        crate::adapter::normalize(&raw).unwrap()
    }

    /// The MoE expansion is the dominant per-token term. Sizing a sparse model's
    /// activations as though it had a dense MLP of `moe_intermediate_size` width
    /// under-counts by roughly the top-k factor.
    #[test]
    fn moe_top_k_expansion_dominates_the_per_token_term() {
        let m = laguna();
        let with_moe = per_token_bytes(&m, 1);

        let mut dense = m.clone();
        dense.moe = None;
        dense.dimensions.intermediate_size = Some(1024); // one expert's width
        let as_dense = per_token_bytes(&dense, 1);

        assert!(
            with_moe > as_dense * 3.0,
            "MoE per-token {with_moe} vs dense {as_dense}"
        );
    }

    /// Projections shard with TP; the residual stream does not. So the per-token
    /// figure falls with TP but never to `1/tp` of the single-rank value.
    #[test]
    fn tensor_parallel_shards_projections_but_not_the_residual() {
        let m = laguna();
        let (one, eight) = (per_token_bytes(&m, 1), per_token_bytes(&m, 8));
        assert!(eight < one, "{eight} should be below {one}");
        assert!(
            eight > one / 8.0,
            "{eight} fell to or below 1/8 of {one} — the residual stream was sharded"
        );
    }

    /// Logits are FP32 over the whole vocabulary and are all-gathered, so TP does
    /// not reduce them. 100,352 × 4 × 2 buffers ≈ 784 KiB.
    #[test]
    fn per_sequence_is_fp32_logits_plus_one_workspace() {
        let m = laguna();
        assert_eq!(per_sequence_bytes(&m), 100_352.0 * 4.0 * 2.0);
    }

    /// Reconstructs the exact `cudagraph_capture_sizes` list vLLM logged for a
    /// run with `max_cudagraph_capture_size=512`. If this drifts, the graph term
    /// is being scaled by the wrong shape count.
    #[test]
    fn capture_count_matches_vllms_default_list() {
        assert_eq!(cudagraph_capture_count(512), 51);
        assert_eq!(cudagraph_capture_count(4096), 51, "capped at 512");
        // 1, 2, 4 + eights to 256.
        assert_eq!(cudagraph_capture_count(256), 3 + 32);
        assert_eq!(cudagraph_capture_count(1), 1);
    }

    /// Anchored to a real serve: vLLM 0.23 on a 95.5928 GiB card reported the
    /// graph estimate as a utilization haircut from 0.9000 to 0.8836, i.e.
    /// 1.5677 GiB reserved for a 48-layer Laguna at 51 captured shapes.
    ///
    /// The reservation is modelled, not the 2.06 GiB the capture actually took:
    /// only the reservation shrinks the KV cache. Conservative is expected to
    /// reach past the reservation toward the real footprint, which is the
    /// headroom that profile exists to provide.
    #[test]
    fn cuda_graph_term_matches_the_measured_reservation() {
        let reserved_gib = (0.9000 - 0.8836) * 95.5928;
        let modelled = cuda_graph_bytes(48, 512) / crate::GIB_BYTES as f64;
        assert!(
            (modelled - reserved_gib).abs() < 0.02,
            "modelled {modelled:.3} GiB vs reserved {reserved_gib:.3} GiB"
        );

        let conservative = modelled * MemoryProfile::Conservative.factor();
        let actual_capture_gib = 2.06;
        assert!(
            conservative > reserved_gib && conservative < actual_capture_gib * 1.05,
            "conservative {conservative:.3} should sit between the {reserved_gib:.3} reserved \
             and the {actual_capture_gib} actually captured"
        );
    }

    #[test]
    fn profiles_order_conservative_above_aggressive() {
        let m = laguna();
        let gpu = find("B200").unwrap();
        let at = |p| estimate(&m, gpu, 1, p, None, 256).total_bytes(8192, 256);
        let (c, b, a) = (
            at(MemoryProfile::Conservative),
            at(MemoryProfile::Balanced),
            at(MemoryProfile::Aggressive),
        );
        assert!(
            a < b && b < c,
            "aggressive {a}, balanced {b}, conservative {c}"
        );
    }

    /// An explicit reserve replaces the *estimated* fixed term and nothing
    /// else: the scheduler still runs as wide as it was configured to, and the
    /// rope tables are arithmetic on the config rather than part of the reserve
    /// being overridden.
    #[test]
    fn fixed_override_does_not_silence_the_scaling_terms() {
        let m = laguna();
        let gpu = find("B200").unwrap();
        let r = estimate(&m, gpu, 1, MemoryProfile::Balanced, Some(2.0), 256);
        assert_eq!(
            r.fixed_bytes,
            (2.0 * crate::GIB_BYTES as f64) as u128 + rope_table_bytes(&m) as u128
        );
        assert!(r.per_token_bytes > 0);
        assert!(r.per_sequence_bytes > 0);
    }

    /// The step term is what comes off the budget before KV blocks exist; the
    /// per-sequence term is reserved on top of it.
    #[test]
    fn step_bytes_excludes_the_sequence_term() {
        let m = laguna();
        let gpu = find("B200").unwrap();
        let r = estimate(&m, gpu, 1, MemoryProfile::Balanced, None, 256);
        assert_eq!(
            r.total_bytes(8192, 256) - r.step_bytes(8192),
            r.per_sequence_bytes * 256
        );
    }

    #[test]
    fn rope_tables_are_one_per_config_sized_by_the_config_context() {
        let m = laguna();
        // Laguna declares rope_parameters with two entries: full_attention at
        // partial_rotary_factor 0.5 and sliding_attention at 1.0. Head dim 128,
        // 1,048,576 positions, BF16.
        let expect = 1_048_576.0 * 64.0 * 2.0 + 1_048_576.0 * 128.0 * 2.0;
        assert_eq!(rope_table_bytes(&m), expect);
        // 0.375 GiB, and not divided by anything.
        assert!((rope_table_bytes(&m) / crate::GIB_BYTES as f64 - 0.375).abs() < 1e-6);
    }

    #[test]
    fn rope_tables_ignore_the_deployed_context_length() {
        // The table spans max_position_embeddings from the config. Nothing in
        // this function reads a workload context, so a shorter --max-model-len
        // cannot shrink it.
        let mut m = laguna();
        let full = rope_table_bytes(&m);
        m.context.checkpoint_maximum = Some(262_144);
        assert_eq!(rope_table_bytes(&m), full);
    }
}
