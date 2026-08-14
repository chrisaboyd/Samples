//! KV-cache memory model (PRD §13).
//!
//! Two closed-form cases are implemented exactly (PRD §33: "analytical KV cache:
//! exact before engine block rounding"):
//!
//! - Dense / conventional MHA|GQA|MQA:
//!   `KV_seq = 2 * L * S * H_kv * D_head * B_kv`
//! - Hybrid full + sliding-window attention:
//!   `KV_seq = 2 * H_kv * D_head * B_kv * [ L_full * S + L_sliding * R_sliding ]`
//!
//! Engine block rounding (vLLM), TP sharding, draft-model KV, and prefix-cache
//! retention are applied on top as explicit, separately-billed terms.
//!
//! # `R_sliding` is not the window
//!
//! The PRD's hybrid formula used `min(S, W)`, which reads as "a windowed layer
//! holds at most a window of tokens". vLLM reserves more than that. From
//! `SlidingWindowSpec::max_memory_usage_bytes`:
//!
//! ```text
//! num_tokens = min(sliding_window - 1 + max_num_batched_tokens, max_model_len)
//! ```
//!
//! During chunked prefill a windowed layer holds the trailing `W-1` computed
//! tokens *plus* every token of the scheduler step that is landing on top of
//! them, because the step's KV is written before the window slides. So the
//! bound is set by `max_num_batched_tokens`, not by `W`. On Laguna-S at a 512
//! window and a 16384-token step that is 16895 tokens per layer against 512,
//! a 33x difference, worth 0.58 GiB per request out of 5.08.
//!
//! # Group padding
//!
//! vLLM's hybrid allocator packs layers into equal-sized groups
//! (`_get_kv_cache_groups_uniform_page_size`), sizing a group at the *smaller*
//! of the two attention-type counts and padding the larger type up to a whole
//! number of groups. Padding layers occupy real memory, so the billable layer
//! counts are the padded ones. Laguna-S divides evenly (18 full, 36 sliding,
//! group size 18) and pays nothing; a 12/42 split would pad to 12/48.

use crate::confidence::{AnalyzeLevel, Confidence, ConfidenceGrade};
use crate::model::AttentionKind;
use crate::precision::Precision;

/// Bytes per KV-cache element. KV cache is typically stored in half precision,
/// but vLLM supports FP8 KV cache.
fn kv_bytes(precision: Precision) -> f64 {
    precision.bytes_per_element()
}

/// Inputs describing one sequence's KV residency on a single TP rank.
#[derive(Debug, Clone)]
pub struct KvConfig {
    pub full_layers: u32,
    pub sliding_layers: u32,
    pub sliding_window: Option<u32>,
    pub kv_heads: u32,
    pub head_dimension: u32,
    /// KV-cache data type bytes-per-element multiplier is selected via
    /// `kv_precision`.
    pub kv_precision: Precision,
    /// Tensor-parallel size. KV heads are sharded across TP ranks, so this
    /// divides per-rank KV memory.
    pub tensor_parallel: u32,
    /// Optional draft model occupying KV cache (speculative decoding stub).
    pub draft_kv_bytes_per_seq: u128,
    /// Sequence length (context) in tokens this KV cost is computed for.
    pub context_tokens: u64,
    /// Engine `max_num_batched_tokens`. Sets what a sliding-window layer
    /// reserves per request, which is the scheduler step and not the window.
    pub max_num_batched_tokens: u64,
}

impl KvConfig {
    /// KV heads resident on one TP rank.
    ///
    /// The KV head is the unit of sharding — a rank cannot hold a fraction of
    /// one. When `kv_heads < tensor_parallel` (MQA, MLA-style single-head
    /// latents, aggressive GQA) engines replicate the whole KV cache onto every
    /// rank instead of splitting it, so TP stops reducing per-GPU KV at all.
    /// Dividing by `tp` unconditionally understates per-GPU KV by up to `tp`×.
    pub fn kv_heads_per_rank(&self) -> u32 {
        let kv_heads = self.kv_heads.max(1);
        kv_heads.div_ceil(self.tensor_parallel.max(1)).max(1)
    }

    /// True when TP exceeds the KV head count, forcing replication rather than
    /// sharding. Surfaced as an assumption because it is the difference between
    /// KV shrinking with TP and not shrinking at all.
    pub fn kv_is_replicated(&self) -> bool {
        self.kv_heads.max(1) < self.tensor_parallel.max(1)
    }

    /// Layers per KV cache group in vLLM's hybrid allocator.
    ///
    /// `_get_kv_cache_groups_uniform_page_size` takes the *minimum* layer count
    /// across attention types as the group size, on the reasoning that hybrid
    /// models repeat an n:1 pattern and the "1" is the natural group. It falls
    /// back to the maximum when the two counts are within 1.5x, which avoids
    /// splitting a barely-larger type into two groups of mostly padding.
    pub fn group_size(&self) -> u32 {
        let (full, sliding) = (self.full_layers, self.sliding_layers);
        if full == 0 || sliding == 0 {
            return full.max(sliding).max(1);
        }
        let (lo, hi) = (full.min(sliding), full.max(sliding));
        if (hi as f64) < (lo as f64) * 1.5 {
            hi
        } else {
            lo
        }
    }

    /// Full and sliding layer counts after padding each type up to a whole
    /// number of groups. Padding layers hold no useful KV but still occupy a
    /// slot in every allocated block, so they are billable.
    fn padded_layers(&self) -> (u128, u128) {
        let g = self.group_size().max(1) as u128;
        let full = self.full_layers as u128;
        let sliding = self.sliding_layers as u128;
        (full.div_ceil(g) * g, sliding.div_ceil(g) * g)
    }

    /// Tokens one sliding-window layer reserves for a single request.
    ///
    /// Mirrors vLLM's `SlidingWindowSpec::max_memory_usage_bytes`: the trailing
    /// `W-1` tokens plus a full scheduler step, capped at the context length.
    pub fn sliding_reserve_tokens(&self) -> u128 {
        let s = self.context_tokens as u128;
        match self.sliding_window {
            None => s,
            Some(w) => {
                let step = self.max_num_batched_tokens.max(1) as u128;
                ((w as u128).saturating_sub(1) + step).min(s)
            }
        }
    }

    /// Bytes for a layer-token count on this rank. 2 = keys + values (PRD §13).
    fn bytes_for(&self, layer_tokens: u128) -> u128 {
        let b_kv = kv_bytes(self.kv_precision);
        let kv_heads = self.kv_heads_per_rank() as u128;
        let head_dim = self.head_dimension.max(1) as u128;
        ((2 * kv_heads * head_dim * layer_tokens) as f64 * b_kv).floor() as u128
    }

    /// KV cache bytes **reserved** for one sequence, before engine block
    /// rounding and before draft-cache addition, on this TP rank.
    ///
    /// This is a residency figure and drives capacity. It bills padded layer
    /// counts and the scheduler-step sliding reservation, because that is what
    /// the allocator takes out of the pool.
    pub fn bytes_per_sequence_exact(&self) -> u128 {
        let (full, sliding) = self.padded_layers();
        let s = self.context_tokens as u128;
        self.bytes_for(full * s + sliding * self.sliding_reserve_tokens())
    }

    /// KV cache bytes an attention kernel **reads** for one sequence.
    ///
    /// Distinct from [`Self::bytes_per_sequence_exact`] and smaller: a decode
    /// step attends over at most a window on a sliding layer, and padding
    /// layers hold nothing to read. Reserved memory is the capacity question,
    /// attended bytes are the bandwidth question, and using the reservation for
    /// a roofline would overstate decode traffic by up to 33x on Laguna.
    pub fn bytes_attended_per_sequence(&self) -> u128 {
        let s = self.context_tokens as u128;
        let full = self.full_layers as u128;
        let sliding = self.sliding_layers as u128;
        let window = self.sliding_window.map(u128::from).unwrap_or(s);
        self.bytes_for(full * s + sliding * s.min(window))
    }

    /// Round a per-sequence KV byte cost up to the engine's allocation block
    /// (vLLM default block = 128 tokens). Returns (rounded_bytes, block_bytes).
    pub fn bytes_per_sequence_rounded(&self, block_tokens: u32) -> (u128, u128) {
        let exact = self.bytes_per_sequence_exact();
        // Block size in bytes = block_tokens * bytes_per_kv_token_on_rank.
        let bytes_per_token = self.bytes_per_kv_token_exact();
        let block_bytes = (bytes_per_token.saturating_mul(block_tokens as u128)).max(1);
        let blocks = exact.div_ceil(block_bytes);
        (blocks * block_bytes, block_bytes)
    }

    /// Exact bytes attributable to a single KV token on this rank (used to size
    /// an allocation block).
    fn bytes_per_kv_token_exact(&self) -> u128 {
        let b_kv = kv_bytes(self.kv_precision);
        let kv_heads = self.kv_heads_per_rank() as u128;
        let head_dim = self.head_dimension.max(1) as u128;
        ((2 * kv_heads * head_dim) as f64 * b_kv).floor() as u128
    }
}

/// Derive a `KvConfig` from a normalized layer layout, computing full vs
/// sliding counts. Shared/expert-KV and cross-attention (encoder) caches are
/// out of scope for MVP dense/MoE decoders and are left as `+0` stubs (PRD §13).
#[allow(clippy::too_many_arguments)]
pub fn derive_kv_config(
    attention_layers: &[(AttentionKind, u32, Option<u32>)],
    kv_heads: u32,
    head_dimension: u32,
    kv_precision: Precision,
    tensor_parallel: u32,
    context_tokens: u64,
    max_num_batched_tokens: u64,
) -> KvConfig {
    let mut full = 0u32;
    let mut sliding = 0u32;
    let mut window: Option<u32> = None;
    for (kind, count, w) in attention_layers {
        match kind {
            AttentionKind::Full => full += *count,
            AttentionKind::Sliding | AttentionKind::Local => {
                sliding += *count;
                window = w.or(window);
            }
            AttentionKind::Mla => {
                // MLA compresses KV; treat as a separate Tier in a future
                // adapter. For now model as a full layer with a note.
                full += *count;
            }
            AttentionKind::Ssm => {
                // Recurrent state, not KV. Stubs to 0 by not incrementing
                // either bucket — reported via confidence assumptions.
            }
        }
    }
    KvConfig {
        full_layers: full,
        sliding_layers: sliding,
        sliding_window: window,
        kv_heads,
        head_dimension,
        kv_precision,
        tensor_parallel,
        draft_kv_bytes_per_seq: 0,
        context_tokens,
        max_num_batched_tokens,
    }
}

/// Number of whole sequences that fit in `free_for_kv` given per-sequence KV
/// (already rounded) cost. PRD §15: `C_memory = floor(M_freeForKV / KV_seq)`.
pub fn memory_concurrency(free_for_kv_bytes: u128, kv_bytes_per_seq: u128) -> u64 {
    if kv_bytes_per_seq == 0 {
        return u64::MAX;
    }
    (free_for_kv_bytes / kv_bytes_per_seq) as u64
}

pub fn confidence_for_kv() -> Confidence {
    Confidence::new(
        AnalyzeLevel::C,
        ConfidenceGrade::Analytical,
        "KV cache derived from architecture config.json (Level C).",
    )
    .with_warning("Exact before engine block rounding; rounded within one allocation block.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precision::WeightCategory;

    fn cfg(
        full: u32,
        sliding: u32,
        window: Option<u32>,
        kv_heads: u32,
        head_dim: u32,
        s: u64,
    ) -> KvConfig {
        KvConfig {
            full_layers: full,
            sliding_layers: sliding,
            sliding_window: window,
            kv_heads,
            head_dimension: head_dim,
            kv_precision: Precision::Bf16,
            tensor_parallel: 1,
            draft_kv_bytes_per_seq: 0,
            context_tokens: s,
            max_num_batched_tokens: 8_192,
        }
    }

    #[test]
    fn dense_kv_matches_formula() {
        // KV_seq = 2 * L * S * H_kv * D_head * B_kv
        // 2 * 48 * 32768 * 8 * 128 * 2 = 6_442_450_944 bytes
        let c = cfg(48, 0, None, 8, 128, 32768);
        assert_eq!(c.bytes_per_sequence_exact(), 6_442_450_944);
    }

    #[test]
    fn sliding_reserve_is_the_scheduler_step_not_the_window() {
        // A windowed layer reserves min(W-1 + max_num_batched_tokens, S), so a
        // small window does not shrink the reservation below a scheduler step.
        // W=8, step=8192, S=1024 -> min(8199, 1024) = 1024, the whole context.
        let mut c = cfg(3, 1, Some(8), 2, 128, 1024);
        assert_eq!(c.sliding_reserve_tokens(), 1024);

        // Widen the context past a step and the reservation stops growing.
        c.context_tokens = 262_144;
        assert_eq!(c.sliding_reserve_tokens(), 8_199);

        // A smaller step shrinks it proportionally.
        c.max_num_batched_tokens = 2_048;
        assert_eq!(c.sliding_reserve_tokens(), 2_055);
    }

    #[test]
    fn group_size_takes_the_smaller_type_then_pads() {
        // Laguna-S with the DFlash drafter folded in: 18 full, 36 sliding.
        // min=18, max=36, 36 >= 27 so the group is 18 and nothing pads.
        let c = cfg(18, 36, Some(512), 2, 128, 1024);
        assert_eq!(c.group_size(), 18);

        // Without the drafter: 12 full, 36 sliding -> group 12, still even.
        let c = cfg(12, 36, Some(512), 2, 128, 1024);
        assert_eq!(c.group_size(), 12);

        // The 1.5x fallback: 12 sliding vs 13 full pads to 13/13 rather than
        // splitting the 13 into two groups of mostly padding.
        let c = cfg(13, 12, Some(512), 2, 128, 1024);
        assert_eq!(c.group_size(), 13);
    }

    #[test]
    fn padding_layers_are_billed() {
        // 12 full + 42 sliding -> group 12, sliding pads 42 up to 48.
        // Context below the window keeps both terms at S, so the padded
        // sliding count is directly visible: 2*2*128*2*(12*64 + 48*64).
        let c = cfg(12, 42, Some(512), 2, 128, 64);
        assert_eq!(c.bytes_per_sequence_exact(), 1024 * (12 * 64 + 48 * 64));
    }

    #[test]
    fn rolling_beyond_cache_zero() {
        // laguna: 2*8*128*2*[12*S + 36*min(S,512)]
        let c = cfg(12, 36, Some(512), 8, 128, 256);
        // 256 < window 512, so min(256,512)=256 -> all full-equivalent
        // 2*8*128*2*(12*256 + 36*256) = 4096 * 48*256 = 4096*12288 = 50331648
        assert_eq!(c.bytes_per_sequence_exact(), 50_331_648);
    }

    #[test]
    fn tp_shards_kv() {
        let mut c = cfg(48, 0, None, 8, 128, 32768);
        c.tensor_parallel = 2;
        assert_eq!(c.bytes_per_sequence_exact(), 6_442_450_944 / 2);
    }

    #[test]
    fn block_rounding_within_one_block() {
        let c = cfg(48, 0, None, 8, 128, 32768);
        let exact = c.bytes_per_sequence_exact();
        let (rounded, block) = c.bytes_per_sequence_rounded(128);
        assert!(rounded >= exact);
        assert!(rounded - exact < block);
    }

    #[test]
    fn category_is_quantizable() {
        assert!(WeightCategory::RoutedExperts.is_quantizable());
        assert!(!WeightCategory::Norms.is_quantizable());
    }
}
