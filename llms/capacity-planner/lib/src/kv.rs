//! KV-cache memory model (PRD §13).
//!
//! Two closed-form cases are implemented exactly (PRD §33: "analytical KV cache:
//! exact before engine block rounding"):
//!
//! - Dense / conventional MHA|GQA|MQA:
//!   `KV_seq = 2 * L * S * H_kv * D_head * B_kv`
//! - Hybrid full + sliding-window attention:
//!   `KV_seq = 2 * H_kv * D_head * B_kv * [ L_full * S + L_sliding * min(S, W) ]`
//!
//! Engine block rounding (vLLM), TP sharding, draft-model KV, and prefix-cache
//! retention are applied on top as explicit, separately-billed terms.

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
}

impl KvConfig {
    /// KV cache bytes for one sequence **before** engine block rounding and
    /// before draft-cache addition, exactly on this TP rank.
    pub fn bytes_per_sequence_exact(&self) -> u128 {
        let b_kv = kv_bytes(self.kv_precision);
        let kv_heads = self.kv_heads.max(1) as u128;
        let head_dim = self.head_dimension.max(1) as u128;
        let full = self.full_layers as u128;
        let sliding = self.sliding_layers as u128;
        let s = self.context_tokens as u128;
        let window = self.sliding_window.map(|w| w as u128).unwrap_or(s);
        let tp = (self.tensor_parallel.max(1)) as u128;

        // min(S, W) per the PRD hybrid formula.
        let sliding_term = sliding * s.min(window);

        // 2 = keys + values (PRD §13).
        let tokens_term = full * s + sliding_term;
        let per_rank = (2 * kv_heads * head_dim * tokens_term) as f64 * b_kv;
        (per_rank / tp as f64).floor() as u128
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
        let kv_heads = self.kv_heads.max(1) as u128;
        let head_dim = self.head_dimension.max(1) as u128;
        let tp = (self.tensor_parallel.max(1)) as u128;
        let per_token = (2 * kv_heads * head_dim) as f64 * b_kv;
        (per_token / tp as f64).floor() as u128
    }
}

/// Derive a `KvConfig` from a normalized layer layout, computing full vs
/// sliding counts. Shared/expert-KV and cross-attention (encoder) caches are
/// out of scope for MVP dense/MoE decoders and are left as `+0` stubs (PRD §13).
pub fn derive_kv_config(
    attention_layers: &[(AttentionKind, u32, Option<u32>)],
    kv_heads: u32,
    head_dimension: u32,
    kv_precision: Precision,
    tensor_parallel: u32,
    context_tokens: u64,
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
    fn sliding_min_caps_context() {
        // 2 * kv_heads * head_dim * B_kv * (L_full*S + L_sliding*min(S,W))
        // = 2 * 2 * 128 * 2 * (3*64 + 1*8) = 204_800
        let c = cfg(3, 1, Some(8), 2, 128, 64);
        assert_eq!(c.bytes_per_sequence_exact(), 204_800);
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
