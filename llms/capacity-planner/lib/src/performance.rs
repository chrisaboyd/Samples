//! Performance-estimation engine (PRD §16).
//!
//! Analytical roofline baseline (§16.2). The unit of work is one **decode step**
//! at batch size `B`, which emits one token for each of `B` running sequences:
//!
//! ```text
//! T_step(B) = max( Bytes_step(B) / BW_effective,
//!                  B × FLOPs_per_token / Compute_effective )
//! ```
//!
//! Three efficiency tiers (pessimistic / expected / optimistic, §16.3) produce
//! broad [`Range`] outputs rather than false precision (PRD §33 "Tokens-per-second
//! result: displayed as a broad range").
//!
//! ## Why the step is modelled at batch `B` rather than per request
//!
//! Continuous batching reads each weight matrix **once per step** and reuses it
//! for every sequence in the batch; only KV and activation traffic scale with
//! `B`. Treating decode as `B ×` the single-stream cost (i.e. assuming no
//! batching benefit at all) understates both aggregate throughput and SLO
//! concurrency by roughly an order of magnitude for dense models. The batch
//! term is therefore applied to KV/activations only:
//!
//! ```text
//! Bytes_step(B) = W_step(B) + B × (KV_sequence + temp_per_token)
//! ```
//!
//! ## Key model
//!
//! **FLOPs per token** = `2 × active_params + attention_scores`
//!
//! - `2 × active_params`: each forward-pass parameter contributes one
//!   multiply-accumulate (2 FLOPs). MoE routed experts are weighted by
//!   `active/total` because each *token* selects only a fraction of them. This
//!   is per-token work and so is independent of batch size.
//! - `attention_scores = 4 × heads × head_dim × Σ(count × context_or_window)`
//!   the Q·Kᵀ and attention·V matmuls on cached KV (no stored parameters).
//!
//! **Weight bytes per step** `W_step(B)` = `dense_bytes + routed_bytes × f(B)`
//!
//! - Dense weights are read every step regardless of batch size.
//! - MoE routed experts are read only if *some* token in the batch selected
//!   them, so the touched fraction is `f(B) = 1 − (1 − k/E)^B`
//!   ([`expert_activation_fraction`]). At `B = 1` this is `k/E`; as `B` grows it
//!   saturates toward 1, which is why large MoE batches lose their bandwidth
//!   advantage. Models larger than L2 are assumed DRAM-resident (streamed).
//!
//! **Bytes per token** (prefill) = `weight_bytes / S + kv_write + temp_bytes`
//! — weight matrices are read once and amortised across the context, so prefill
//! is typically compute-limited while decode is bandwidth-limited for large
//! models. A prefill of `S` tokens touches essentially every expert, so `f(S)`
//! is used rather than the per-token fraction.

use crate::explain::Derivation;
use crate::hardware::Gpu;
use crate::kv;
use crate::model::{AttentionKind, NormalizedModel};
use crate::precision::Precision;
use crate::result::{PerformanceResult, Range};

/// Efficiency tiers `(pessimistic, expected, optimistic)` as fractions of peak.
///
/// Bandwidth utilization — fraction of peak memory bandwidth achievable per
/// decode stream (PRD §16.3 "effective bandwidth utilization").
const BW_UTIL: [f64; 3] = [0.40, 0.55, 0.70];

/// Compute utilization — fraction of peak tensor throughput (§16.3 "effective
/// tensor-core utilization").
const COMPUTE_UTIL: [f64; 3] = [0.30, 0.50, 0.65];

/// Inputs for the analytical performance roofline.
pub struct PerformanceInputs<'a> {
    pub model: &'a NormalizedModel,
    pub gpu: &'a Gpu,
    /// Weight storage precision (selects compute peak + weight bytes).
    pub weight_precision: Precision,
    pub kv_precision: Precision,
    pub tensor_parallel: u32,
    pub gpu_count: u32,
    pub avg_context_tokens: u64,
    pub avg_output_tokens: u64,
    pub slo_target_seconds: f64,
    /// Loaded weight bytes on one TP rank (includes load factor; §12.1).
    pub loaded_weight_bytes_per_rank: u128,
    /// Sequences that fit in free KV memory on one rank at average context
    /// (PRD §15 `C_memory`). Caps the SLO batch search: a batch that does not
    /// fit in VRAM is not a candidate no matter how fast it would run.
    pub memory_concurrency_cap: u64,
}

// ---------------------------------------------------------------------------
// Helpers — pub(crate) so memory::evaluate and integration tests can inspect
// ---------------------------------------------------------------------------

/// Fraction of model parameters that are *active* per decode token.
///
/// Dense: 1.0.  MoE: `(dense + shared) + (active/total) × routed`, all divided
/// by total. Only routed experts are discounted — dense, attention, embeddings,
/// and shared experts always participate (PRD §16.2).
pub(crate) fn active_param_fraction(model: &NormalizedModel) -> f64 {
    param_fraction_at_batch(model, 1)
}

/// Fraction of routed experts touched by *at least one* token in a batch of
/// `batch` tokens.
///
/// Each token independently routes to `k` of `E` experts, so an individual
/// expert is missed by one token with probability `1 − k/E` and by the whole
/// batch with probability `(1 − k/E)^batch`:
///
/// ```text
/// f(B) = 1 − (1 − k/E)^B
/// ```
///
/// `f(1) = k/E` (the per-token active fraction) and `f(B) → 1` as the batch
/// grows. This is what makes a large MoE batch read nearly the full weight set
/// per step, eroding the bandwidth advantage MoE has at batch 1.
///
/// The independence assumption is optimistic — real routers are load-balanced
/// and correlated across tokens, which drives the fraction toward 1 faster.
pub fn expert_activation_fraction(k: u32, experts: u32, batch: u64) -> f64 {
    if experts == 0 || k == 0 || k >= experts {
        return 1.0;
    }
    let miss = 1.0 - (k as f64 / experts as f64);
    (1.0 - miss.powf(batch.max(1) as f64)).clamp(0.0, 1.0)
}

/// Fraction of model parameters read in one decode step at batch size `batch`.
///
/// Dense: 1.0. MoE: `(dense + shared) + f(batch) × routed`, all divided by
/// total. Only routed experts are discounted — dense, attention, embeddings,
/// and shared experts always participate (PRD §16.2).
pub(crate) fn param_fraction_at_batch(model: &NormalizedModel, batch: u64) -> f64 {
    let Some(moe) = &model.moe else {
        return 1.0;
    };
    let total: u128 = model
        .weights
        .components
        .iter()
        .map(|c| c.element_count)
        .sum();
    if total == 0 {
        return 1.0;
    }
    let routed: u128 = model
        .weights
        .components
        .iter()
        .filter(|c| c.category == crate::precision::WeightCategory::RoutedExperts)
        .map(|c| c.element_count)
        .sum();
    let touched = expert_activation_fraction(moe.active_experts_per_token, moe.expert_count, batch);
    let dense = (total - routed) as f64;
    (dense + routed as f64 * touched) / total as f64
}

/// Select the peak tensor-throughput (TFLOPS) for the given weight precision.
/// NVFP4/INT4 dequantize to a supported compute precision; fall back to the
/// next-higher native precision.
pub(crate) fn compute_peak_tflops(gpu: &Gpu, precision: Precision) -> f64 {
    match precision {
        Precision::Nvfp4 => gpu
            .nvfp4_tflops
            .or(gpu.fp8_tflops)
            .unwrap_or(gpu.bf16_fp16_tflops),
        Precision::Fp8 => gpu.fp8_tflops.unwrap_or(gpu.bf16_fp16_tflops),
        _ => gpu.bf16_fp16_tflops,
    }
}

/// Attention-score FLOPs per decode token: `4 × heads × head_dim ×
/// Σ(count × context_or_window)`.
///
/// 4 = 2 (Q·Kᵀ MAC) + 2 (attention·V MAC). Uses **query heads** (`heads`),
/// not `kv_heads`, because every query head computes scores. Sliding windows
/// cap the effective context at `min(S, W)`.
pub(crate) fn attention_score_floors(model: &NormalizedModel, context: u64) -> f64 {
    let s = context.max(1) as f64;
    let heads = model
        .dimensions
        .attention_heads
        .map(|h| h as f64)
        .or_else(|| {
            let hd = model.dimensions.head_dimension.map(|hd| hd as f64)?;
            let hidden = model.dimensions.hidden_size as f64;
            Some(hidden / hd)
        })
        .unwrap_or(0.0);
    let head_dim = model.dimensions.head_dimension.unwrap_or(0) as f64;
    if heads == 0.0 || head_dim == 0.0 {
        return 0.0;
    }
    let mut total = 0.0;
    for layer in &model.attention_layers {
        let window = layer.window_size.map(|w| w as f64).unwrap_or(s);
        let eff_ctx = s.min(window);
        match layer.kind {
            AttentionKind::Full | AttentionKind::Local | AttentionKind::Mla => {
                total += 4.0 * heads * head_dim * layer.count as f64 * s;
            }
            AttentionKind::Sliding => {
                total += 4.0 * heads * head_dim * layer.count as f64 * eff_ctx;
            }
            AttentionKind::Ssm => {} // recurrent state — no cached-attention FLOPs
        }
    }
    total
}

/// Per-token activation/temporary DRAM traffic (total across TP group, bytes).
///
/// Rough estimate: ~4 hidden-size vectors per layer (residual, attention-out,
/// MLP gate+up, MLP down) × read+write × BF16 activations.
pub(crate) fn temp_bytes_per_token(model: &NormalizedModel) -> f64 {
    let h = model.dimensions.hidden_size as f64;
    let layers = model.dimensions.layer_count as f64;
    let b_act = Precision::Bf16.bytes_per_element();
    layers * 4.0 * h * 2.0 * b_act
}

/// Exact KV-cache bytes for one sequence at `context` (per-rank, before block
/// rounding). Used for the decode bandwidth roofline (reading cached K/V).
pub(crate) fn kv_bytes_exact(
    model: &NormalizedModel,
    kv_precision: Precision,
    tp: u32,
    context: u64,
) -> u128 {
    let layers: Vec<(AttentionKind, u32, Option<u32>)> = model
        .attention_layers
        .iter()
        .map(|a| (a.kind, a.count, a.window_size))
        .collect();
    let kv_cfg = kv::derive_kv_config(
        &layers,
        model.dimensions.kv_heads.unwrap_or(0),
        model.dimensions.head_dimension.unwrap_or(0),
        kv_precision,
        tp,
        context,
    );
    kv_cfg.bytes_per_sequence_exact()
}

/// KV bytes appended per token across **every** cache-bearing layer, per rank.
///
/// `2 × kv_heads × head_dim × B_kv` is the cost for a *single* layer; the model
/// caches K/V once per attention layer, so the layer count is part of the
/// formula. Omitting it understates prefill KV write traffic by the layer count
/// (48× for Laguna).
pub fn kv_write_bytes_per_token(model: &NormalizedModel, kv_precision: Precision, tp: u32) -> f64 {
    let kv_heads = model.dimensions.kv_heads.unwrap_or(0) as f64;
    let head_dim = model.dimensions.head_dimension.unwrap_or(0) as f64;
    let cache_layers: u32 = model
        .attention_layers
        .iter()
        .filter(|a| a.kind != AttentionKind::Ssm) // recurrent state is not a KV cache
        .map(|a| a.count)
        .sum();
    let per_layer = 2.0 * kv_heads * head_dim * kv_precision.bytes_per_element();
    per_layer * cache_layers as f64 / tp.max(1) as f64
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Analytical roofline evaluation (PRD §16.2/§16.3 + §18.2 SLO concurrency).
///
/// Returns a fully-populated [`PerformanceResult`] with pessimistic/expected/
/// optimistic ranges and the SLO-based concurrency ceiling.
pub fn evaluate(inputs: &PerformanceInputs) -> PerformanceResult {
    evaluate_explained(inputs).0
}

/// As [`evaluate`], plus the worked derivation of each published figure.
///
/// The derivations are built from the same locals the roofline computed, so a
/// change to the model cannot leave the displayed math describing the old one.
pub fn evaluate_explained(inputs: &PerformanceInputs) -> (PerformanceResult, Vec<Derivation>) {
    let model = inputs.model;
    let gpu = inputs.gpu;
    let tp = inputs.tensor_parallel.max(1) as f64;
    let tp_u32 = inputs.tensor_parallel.max(1);

    // --- Per-token FLOPs (per-token work; independent of batch size) ---
    let total_params = model.parameter_count().unwrap_or(0) as f64;
    let active_params = total_params * active_param_fraction(model);
    let matmul_flops = 2.0 * active_params; // multiply-accumulate
    let attn_flops = attention_score_floors(model, inputs.avg_context_tokens);
    let flops_per_token = matmul_flops + attn_flops;

    // --- Per-step byte terms for the bandwidth roofline (total across TP) ---

    // Loaded weight bytes across the TP group, before MoE discounting.
    let full_weight_bytes = inputs.loaded_weight_bytes_per_rank as f64 * tp;

    // KV read bytes per running sequence (reading cached K/V for attention).
    let kv_read_per_seq = kv_bytes_exact(
        model,
        inputs.kv_precision,
        tp_u32,
        inputs.avg_context_tokens,
    ) as f64
        * tp;

    // Temp / activation traffic per token.
    let temp_bytes = temp_bytes_per_token(model);

    // --- Roofline peaks ---
    let compute_peak = compute_peak_tflops(gpu, inputs.weight_precision) * 1e12; // FLOPs/s
    let bw_total = tp * gpu.memory_bandwidth_gbs * 1e9; // bytes/s across the TP group
    let compute_total = tp * compute_peak; // FLOPs/s across the TP group

    // Seconds for one decode step at batch `b` under efficiency tier `i`.
    // Weights are read once per step; KV and activations scale with the batch.
    let step_seconds = |b: u64, i: usize| -> f64 {
        let batch = b.max(1) as f64;
        let weight_bytes = full_weight_bytes * param_fraction_at_batch(model, b.max(1));
        let bytes = weight_bytes + batch * (kv_read_per_seq + temp_bytes);
        let t_bw = bytes / (bw_total * BW_UTIL[i]).max(1.0);
        let t_compute = batch * flops_per_token / (compute_total * COMPUTE_UTIL[i]).max(1.0);
        t_bw.max(t_compute)
    };

    // --- Single-stream decode (batch 1): the per-request best case ---
    let mut decode_tps = [0.0f64; 3];
    for (i, slot) in decode_tps.iter_mut().enumerate() {
        *slot = 1.0 / step_seconds(1, i).max(f64::MIN_POSITIVE);
    }
    let decode_bottleneck_is_bandwidth = {
        let weight_bytes = full_weight_bytes * param_fraction_at_batch(model, 1);
        let t_bw = (weight_bytes + kv_read_per_seq + temp_bytes) / (bw_total * BW_UTIL[1]).max(1.0);
        let t_compute = flops_per_token / (compute_total * COMPUTE_UTIL[1]).max(1.0);
        t_bw > t_compute
    };

    // --- Prefill TPS (weight traffic amortised over the context) ---
    // A prefill of S tokens is a large batch, so essentially every expert is
    // touched: use the batch-S fraction, not the per-token one.
    let ctx = inputs.avg_context_tokens.max(1);
    let prefill_weight_bytes = full_weight_bytes * param_fraction_at_batch(model, ctx);
    let kv_write_per_token = kv_write_bytes_per_token(model, inputs.kv_precision, tp_u32) * tp;
    let prefill_bytes_per_token =
        prefill_weight_bytes / ctx as f64 + kv_write_per_token + temp_bytes;
    let mut prefill_tps = [0.0f64; 3];
    for (i, slot) in prefill_tps.iter_mut().enumerate() {
        let tps_bw = bw_total * BW_UTIL[i] / prefill_bytes_per_token.max(1.0);
        let tps_compute = compute_total * COMPUTE_UTIL[i] / flops_per_token.max(1.0);
        *slot = tps_bw.min(tps_compute);
    }

    // --- SLO concurrency (§18.2) ---
    // Per-request latency at batch b:  T_prefill + avg_output × T_step(b).
    // T_step is monotonically increasing in b, so the largest satisfying batch
    // is found by binary search, capped by what fits in KV memory (§15).
    let dp_replicas = ((inputs.gpu_count as f64 / tp).floor().max(1.0)) as u64;
    let t_prefill = ctx as f64 / prefill_tps[1].max(f64::MIN_POSITIVE);
    let out_tokens = inputs.avg_output_tokens.max(1) as f64;
    let meets_slo = |b: u64| -> bool {
        t_prefill + out_tokens * step_seconds(b, 1) <= inputs.slo_target_seconds
    };
    let batch_cap = inputs.memory_concurrency_cap.max(1);
    let slo_batch = if !meets_slo(1) {
        0
    } else if meets_slo(batch_cap) {
        batch_cap
    } else {
        // Invariant: meets_slo(lo) && !meets_slo(hi).
        let (mut lo, mut hi) = (1u64, batch_cap);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if meets_slo(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    };
    let slo_concurrency = slo_batch * dp_replicas;

    // --- Aggregate decode throughput across the whole deployment ---
    // At the SLO batch each group emits `slo_batch` tokens per step.
    let served_batch = slo_batch.max(1);
    let agg_at =
        |i: usize| served_batch as f64 / step_seconds(served_batch, i) * dp_replicas as f64;
    let (agg_min, agg_max) = (agg_at(0), agg_at(2));

    // --- TTFT (prefill time + one decode step) ---
    let ttf_min = ctx as f64 / prefill_tps[2].max(f64::MIN_POSITIVE) + step_seconds(1, 2);
    let ttf_max = ctx as f64 / prefill_tps[0].max(f64::MIN_POSITIVE) + step_seconds(1, 0);

    // --- Step latency (per output token, single stream) ---
    let step_min = step_seconds(1, 2); // fastest tier = lowest latency
    let step_max = step_seconds(1, 0);

    let bottleneck = if decode_bottleneck_is_bandwidth {
        "bandwidth"
    } else {
        "compute"
    };

    let result = PerformanceResult {
        prefill_tokens_per_second: Some(Range::tokens_per_second(prefill_tps[0], prefill_tps[2])),
        decode_tokens_per_second_per_request: Some(Range::tokens_per_second(
            decode_tps[0],
            decode_tps[2],
        )),
        aggregate_decode_tokens_per_second: Some(Range::tokens_per_second(agg_min, agg_max)),
        estimated_ttft: Some(Range::seconds(ttf_min.max(0.0), ttf_max.max(0.0))),
        estimated_step_latency: Some(Range::seconds(step_min, step_max)),
        slo_concurrency: Some(slo_concurrency),
        note: format!(
            "Analytical roofline (PRD §16.2). Three efficiency tiers \
             (pessimistic/expected/optimistic, §16.3). Decode is {bottleneck}-limited \
             at batch 1 on this GPU. Per-request decode and step latency are \
             single-stream; aggregate throughput is at the SLO batch of \
             {slo_batch} per group × {dp_replicas} replica(s), where continuous \
             batching amortises the weight read across the batch (§18.2)."
        ),
    };

    // --- Derivations, built from the locals above ---
    use crate::explain::{big, bytes_h, commas, d};

    // The published range spans the pessimistic and optimistic tiers; the
    // substitution is worked at the expected tier so there is one concrete
    // arithmetic chain to check rather than three.
    let weight_bytes_b1 = full_weight_bytes * param_fraction_at_batch(model, 1);
    let bytes_b1 = weight_bytes_b1 + kv_read_per_seq + temp_bytes;
    let t_bw_b1 = bytes_b1 / (bw_total * BW_UTIL[1]).max(1.0);
    let t_compute_b1 = flops_per_token / (compute_total * COMPUTE_UTIL[1]).max(1.0);

    let derivations = vec![
        d(
            "p-flops-token",
            "FLOPs per token",
            "Arithmetic one token costs on a forward pass. Sets the compute side \
             of the roofline — the floor on latency even with infinite bandwidth.",
            "FLOPs/token = 2 × active_params + 4 × H_q × D_head × sum(L × S_eff)",
            format!(
                "matmul     2 × {} active params = {} FLOPs\n\
                 attention  4 × H_q × D_head × sum(layers × context) = {} FLOPs\n\
                 total                                             = {} FLOPs",
                big(active_params),
                big(matmul_flops),
                big(attn_flops),
                big(flops_per_token),
            ),
            format!("{} FLOPs/token", big(flops_per_token)),
        ),
        d(
            "p-step",
            "Step latency",
            "Wall-clock time to emit one token for one request. The roofline takes \
             whichever is slower — moving the bytes, or doing the arithmetic.",
            "T_step(B) = max( Bytes_step(B) / (BW × eff_bw), B × FLOPs/token / (Compute × eff_c) )\n\
             where Bytes_step(B) = W_step(B) + B × (KV_seq + activations)",
            format!(
                "at B = 1, expected tier (eff_bw = {:.0}%, eff_c = {:.0}%):\n\
                 Bytes_step = {} weights + {} KV + {} activations = {}\n\
                 t_bandwidth = {} / ({} GB/s × {} rank(s) × {:.2}) = {}\n\
                 t_compute   = {} FLOPs / ({} TFLOPS × {} rank(s) × {:.2}) = {}\n\
                 max(...) → {}-limited",
                BW_UTIL[1] * 100.0,
                COMPUTE_UTIL[1] * 100.0,
                bytes_h(weight_bytes_b1),
                bytes_h(kv_read_per_seq),
                bytes_h(temp_bytes),
                bytes_h(bytes_b1),
                bytes_h(bytes_b1),
                commas(gpu.memory_bandwidth_gbs as u128),
                tp as u64,
                BW_UTIL[1],
                fmt_secs(t_bw_b1),
                big(flops_per_token),
                commas(compute_peak_tflops(gpu, inputs.weight_precision) as u128),
                tp as u64,
                COMPUTE_UTIL[1],
                fmt_secs(t_compute_b1),
                bottleneck,
            ),
            format!("{} – {}", fmt_secs(step_min), fmt_secs(step_max)),
        ),
        d(
            "p-decode",
            "Decode rate per request",
            "Tokens per second a single request sees once it starts generating. \
             This is the number a user experiences as typing speed.",
            "decode_tps = 1 / T_step(1)",
            format!(
                "1 / {} = {:.0} tok/s   (optimistic tier)\n1 / {} = {:.0} tok/s   (pessimistic tier)",
                fmt_secs(step_min),
                decode_tps[2],
                fmt_secs(step_max),
                decode_tps[0],
            ),
            format!("{:.0} – {:.0} tokens/s", decode_tps[0], decode_tps[2]),
        ),
        d(
            "p-prefill",
            "Prefill rate",
            "Tokens per second while reading the prompt. Much faster than decode \
             because one weight read is amortised across the whole prompt, which \
             usually leaves prefill compute-limited rather than bandwidth-limited.",
            "prefill_tps = min( BW × eff_bw / bytes_per_token , Compute × eff_c / FLOPs_per_token )",
            format!(
                "bytes/token = {} weights / {} ctx + {} KV write + {} activations\n\
                 = {}\nbandwidth-bound: {:.0} tok/s   compute-bound: {:.0} tok/s   (expected tier)",
                bytes_h(prefill_weight_bytes),
                commas(ctx as u128),
                bytes_h(kv_write_per_token),
                bytes_h(temp_bytes),
                bytes_h(prefill_bytes_per_token),
                bw_total * BW_UTIL[1] / prefill_bytes_per_token.max(1.0),
                compute_total * COMPUTE_UTIL[1] / flops_per_token.max(1.0),
            ),
            format!("{:.0} – {:.0} tokens/s", prefill_tps[0], prefill_tps[2]),
        ),
        d(
            "p-ttft",
            "Time to first token",
            "How long a request waits before the first token appears: read the \
             whole prompt, then run one decode step.",
            "TTFT = S / prefill_tps + T_step(1)",
            format!(
                "{} tokens / {:.0} tok/s + {} = {}   (optimistic)\n\
                 {} tokens / {:.0} tok/s + {} = {}   (pessimistic)",
                commas(ctx as u128),
                prefill_tps[2],
                fmt_secs(step_seconds(1, 2)),
                fmt_secs(ttf_min),
                commas(ctx as u128),
                prefill_tps[0],
                fmt_secs(step_seconds(1, 0)),
                fmt_secs(ttf_max),
            ),
            format!("{} – {}", fmt_secs(ttf_min), fmt_secs(ttf_max)),
        ),
        d(
            "p-slo",
            "SLO concurrency",
            "The largest batch that still meets your latency target, times the \
             number of independent replicas. Purely a speed limit — memory is \
             accounted separately.",
            "C_SLO = DP × max{ B <= C_memory(avg) : T_prefill + N_out × T_step(B) <= target }",
            format!(
                "T_prefill = {} tokens / {:.0} tok/s = {}\n\
                 at B = {}: {} + {} output × {} = {}  <=  {:.1} s target\n\
                 C_SLO = {} × {} replica(s)",
                commas(ctx as u128),
                prefill_tps[1],
                fmt_secs(t_prefill),
                slo_batch,
                fmt_secs(t_prefill),
                commas(out_tokens as u128),
                fmt_secs(step_seconds(slo_batch.max(1), 1)),
                fmt_secs(t_prefill + out_tokens * step_seconds(slo_batch.max(1), 1)),
                inputs.slo_target_seconds,
                slo_batch,
                dp_replicas,
            ),
            format!("{slo_concurrency} concurrent requests"),
        ),
        d(
            "p-aggregate",
            "Aggregate decode throughput",
            "Total tokens per second the whole deployment emits with every slot \
             busy. Continuous batching reads the weights once per step and shares \
             them across the batch, so this is far above one request's rate.",
            "aggregate = B_slo / T_step(B_slo) × DP",
            format!(
                "{} / {} × {} replica(s) = {:.0} tok/s   (optimistic)\n\
                 {} / {} × {} replica(s) = {:.0} tok/s   (pessimistic)",
                served_batch,
                fmt_secs(step_seconds(served_batch, 2)),
                dp_replicas,
                agg_max,
                served_batch,
                fmt_secs(step_seconds(served_batch, 0)),
                dp_replicas,
                agg_min,
            ),
            format!("{:.0} – {:.0} tokens/s", agg_min, agg_max),
        ),
    ];

    (result, derivations)
}

/// Seconds, switching to milliseconds below 1 s so sub-second step latencies do
/// not all render as "0.00 s".
fn fmt_secs(v: f64) -> String {
    if v.abs() < 1.0 {
        format!("{:.2} ms", v * 1000.0)
    } else {
        format!("{v:.2} s")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TINY_LLAMA: &str = r#"{
        "model_type": "llama",
        "architectures": ["LlamaForCausalLM"],
        "vocab_size": 100,
        "hidden_size": 64,
        "intermediate_size": 128,
        "num_hidden_layers": 2,
        "num_attention_heads": 4,
        "num_key_value_heads": 4,
        "head_dim": 16,
        "max_position_embeddings": 2048,
        "tie_word_embeddings": true,
        "torch_dtype": "bfloat16"
    }"#;

    fn tiny_llama() -> NormalizedModel {
        let raw: serde_json::Value = serde_json::from_str(TINY_LLAMA).unwrap();
        crate::adapter::normalize(&raw).unwrap()
    }

    #[test]
    fn dense_model_has_full_active_fraction() {
        let m = tiny_llama();
        assert_eq!(active_param_fraction(&m), 1.0);
    }

    #[test]
    fn laguna_moe_reduces_active_fraction() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let m = crate::adapter::normalize(&raw).unwrap();
        let frac = active_param_fraction(&m);
        // Routed experts ~97% of params, 10/256 active → fraction ≈ 0.065
        assert!(frac > 0.05 && frac < 0.10, "active fraction = {frac}");
    }

    #[test]
    fn compute_peak_prefers_native_precision() {
        let g = crate::hardware::find("B200 SXM 180 GB").unwrap().clone();
        assert_eq!(compute_peak_tflops(&g, Precision::Nvfp4), 4_000.0);
        assert_eq!(compute_peak_tflops(&g, Precision::Fp8), 2_000.0);
        assert_eq!(compute_peak_tflops(&g, Precision::Bf16), 1_000.0);
    }

    #[test]
    fn attention_floors_grow_with_context() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let m = crate::adapter::normalize(&raw).unwrap();
        let matmul = 2.0 * m.parameter_count().unwrap() as f64;
        let attn_32k = attention_score_floors(&m, 32_768);
        let attn_1m = attention_score_floors(&m, 1_048_576);
        assert!(
            attn_32k / matmul < 0.20,
            "attn/matmul at 32K = {}",
            attn_32k / matmul
        );
        assert!(
            attn_1m / matmul > 1.0,
            "attn/matmul at 1M = {}",
            attn_1m / matmul
        );
    }

    #[test]
    fn decode_range_is_bandwidth_limited_and_ordered() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let model = crate::adapter::normalize(&raw).unwrap();
        let gpu = crate::hardware::find("B200 SXM 180 GB").unwrap().clone();
        let loaded =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 1);
        let inputs = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 1,
            gpu_count: 1,
            avg_context_tokens: 32_768,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded,
        };
        let result = evaluate(&inputs);
        let decode = result.decode_tokens_per_second_per_request.unwrap();
        assert!(
            decode.min < decode.max,
            "decode min={} max={}",
            decode.min,
            decode.max
        );
        assert!(decode.min > 100.0, "decode min = {}", decode.min);
        assert!(decode.max < 100_000.0, "decode max = {}", decode.max);
        assert_eq!(decode.unit, "tokens/s");
    }

    #[test]
    fn prefill_tps_exceeds_decode_tps() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let model = crate::adapter::normalize(&raw).unwrap();
        let gpu = crate::hardware::find("B200 SXM 180 GB").unwrap().clone();
        let loaded =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 1);
        let inputs = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 1,
            gpu_count: 1,
            avg_context_tokens: 32_768,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded,
        };
        let result = evaluate(&inputs);
        let decode = result.decode_tokens_per_second_per_request.unwrap();
        let prefill = result.prefill_tokens_per_second.unwrap();
        // Prefill amortises weight traffic across context → usually compute-bound
        // and much faster per token than decode.
        assert!(
            prefill.min > decode.max,
            "prefill min {} should exceed decode max {}",
            prefill.min,
            decode.max
        );
    }

    #[test]
    fn slo_concurrency_is_positive_and_reasonable() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let model = crate::adapter::normalize(&raw).unwrap();
        let gpu = crate::hardware::find("B200 SXM 180 GB").unwrap().clone();
        let loaded =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 1);
        let inputs = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 1,
            gpu_count: 1,
            avg_context_tokens: 32_768,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded,
        };
        let result = evaluate(&inputs);
        let slo = result.slo_concurrency.unwrap();
        assert!(
            slo > 0,
            "SLO concurrency should be positive for Laguna on B200"
        );
        assert!(slo < 200, "SLO = {slo}");
    }

    #[test]
    fn step_latency_is_inverse_of_decode_tps() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let model = crate::adapter::normalize(&raw).unwrap();
        let gpu = crate::hardware::find("B200 SXM 180 GB").unwrap().clone();
        let loaded =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 1);
        let inputs = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 1,
            gpu_count: 1,
            avg_context_tokens: 32_768,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded,
        };
        let result = evaluate(&inputs);
        let step = result.estimated_step_latency.unwrap();
        let decode = result.decode_tokens_per_second_per_request.unwrap();
        assert!(step.min >= 1.0 / decode.max * 0.9);
        assert!(step.max <= 1.0 / decode.min * 1.1);
    }

    #[test]
    fn longer_context_lowers_decode_tps() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let model = crate::adapter::normalize(&raw).unwrap();
        let gpu = crate::hardware::find("B200 SXM 180 GB").unwrap().clone();
        let loaded =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 1);

        let inputs_short = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 1,
            gpu_count: 1,
            avg_context_tokens: 4_096,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded,
        };
        let result_short = evaluate(&inputs_short);

        let loaded2 =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 1);
        let inputs_long = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 1,
            gpu_count: 1,
            avg_context_tokens: 1_048_576,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded2,
        };
        let result_long = evaluate(&inputs_long);

        let short = result_short.decode_tokens_per_second_per_request.unwrap();
        let long = result_long.decode_tokens_per_second_per_request.unwrap();
        // At max context, KV read traffic grows ~linearly → decode slows.
        assert!(
            long.max < short.max,
            "long-context decode ({}) should be slower than short ({})",
            long.max,
            short.max
        );
    }

    #[test]
    fn tp_increases_aggregate_throughput() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/assets/laguna-config.json")).unwrap();
        let model = crate::adapter::normalize(&raw).unwrap();
        let gpu = crate::hardware::find("B200 SXM 180 GB").unwrap().clone();

        let loaded_tp1 =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 1);
        let inputs_tp1 = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 1,
            gpu_count: 1,
            avg_context_tokens: 32_768,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded_tp1,
        };
        let result_tp1 = evaluate(&inputs_tp1);
        let agg1 = result_tp1.aggregate_decode_tokens_per_second.unwrap();

        let loaded_tp2 =
            crate::weight::loaded_weight_bytes_per_rank(&model, Precision::Nvfp4, true, 16, 2);
        let inputs_tp2 = PerformanceInputs {
            model: &model,
            gpu: &gpu,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            tensor_parallel: 2,
            gpu_count: 2,
            avg_context_tokens: 32_768,
            memory_concurrency_cap: 128,
            avg_output_tokens: 512,
            slo_target_seconds: 10.0,
            loaded_weight_bytes_per_rank: loaded_tp2,
        };
        let result_tp2 = evaluate(&inputs_tp2);
        let agg2 = result_tp2.aggregate_decode_tokens_per_second.unwrap();

        // With TP=2 on 2 GPUs, aggregate should be ≥ single-GPU (same GPU count).
        assert!(
            agg2.min >= agg1.min * 0.9,
            "TP=2 aggregate min {} should be ≥ TP=1 min {}",
            agg2.min,
            agg1.min
        );
    }
}
