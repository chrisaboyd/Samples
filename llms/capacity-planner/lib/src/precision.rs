//! Precision formats and weight categories (PRD §12.2).
//!
//! PRD §12.2: a hypothetical quantization "applies the selected format only to
//! compatible tensor categories." NVFP4 is the key nuance — per the PRD it
//! "includes per-group FP8 scales rather than costing exactly half a byte per
//! parameter" — so [`Precision::bytes_for`] accounts for scale overhead.

use serde::{Deserialize, Serialize};

/// Weight/KV data precision. Serialized here only as a label; the PRD orders
/// the MVP set FP32, FP16, BF16, FP8, NVFP4, INT8, INT4.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Precision {
    Fp32,
    Fp16,
    Bf16,
    Fp8,
    Nvfp4,
    Int8,
    Int4,
}

impl Precision {
    /// Parse a HuggingFace `torch_dtype` string. `None` for anything not
    /// recognized, so an unexpected value surfaces rather than defaulting to a
    /// width that happens to be common.
    pub fn from_torch_dtype(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bfloat16" | "bf16" => Some(Precision::Bf16),
            "float16" | "fp16" | "half" => Some(Precision::Fp16),
            "float32" | "fp32" | "float" => Some(Precision::Fp32),
            "float8_e4m3fn" | "float8_e5m2" | "fp8" => Some(Precision::Fp8),
            _ => None,
        }
    }

    /// Weight element size in bytes for a single tensor element (no scales).
    pub fn bytes_per_element(self) -> f64 {
        match self {
            Precision::Fp32 => 4.0,
            Precision::Fp16 | Precision::Bf16 => 2.0,
            Precision::Fp8 | Precision::Int8 => 1.0,
            Precision::Int4 | Precision::Nvfp4 => 0.5,
        }
    }

    /// Human-readable label used in results/UI.
    pub fn label(self) -> &'static str {
        match self {
            Precision::Fp32 => "FP32",
            Precision::Fp16 => "FP16",
            Precision::Bf16 => "BF16",
            Precision::Fp8 => "FP8",
            Precision::Nvfp4 => "NVFP4",
            Precision::Int8 => "INT8",
            Precision::Int4 => "INT4",
        }
    }

    /// NVFP4 uses 4-bit weights plus a per-group FP8 scale. Default group size
    /// of 16 gives 1 extra byte per 16 weights (0.0625 B/param), matching the
    /// PRD's "not exactly half a byte" note.
    pub fn nvfp4_bytes_per_element(group_size: u32) -> f64 {
        let weight = Precision::Nvfp4.bytes_per_element(); // 0.5
        let scale = if group_size == 0 {
            0.0
        } else {
            1.0 / (group_size as f64)
        };
        weight + scale
    }
}

/// Tensor grouping used for hypothetical-quantization targeting (PRD §12.2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum WeightCategory {
    #[serde(rename = "attention_projections")]
    Attention,
    #[serde(rename = "dense_mlp")]
    DenseMlp,
    #[serde(rename = "routed_experts")]
    RoutedExperts,
    #[serde(rename = "shared_experts")]
    SharedExperts,
    Embeddings,
    #[serde(rename = "output_head")]
    OutputHead,
    Norms,
    Routers,
    Biases,
}

/// Per-category quantization compatibility.
///
/// Conservative table: most categories can take a compressed format; the PRD's
/// mixed-precision NVFP4 example leaves attention/embeddings in BF16 while
/// experts go NVFP4 — the scenario layer decides which categories are
/// reassigned.
///
/// Norms and routers are the exceptions, and routers for a reason worth stating:
/// top-k expert selection is sensitive to precision, so vLLM's fused-MoE path
/// keeps the gate at the base dtype and llm-compressor's ignore lists name it
/// explicitly. Every MoE checkpoint examined stores `mlp.gate` in BF16 even when
/// the surrounding experts are FP8. Treating it as quantizable meant a scheme
/// that did not bother to list the router got it sized at half its real weight.
impl WeightCategory {
    pub fn is_quantizable(self) -> bool {
        !matches!(self, WeightCategory::Norms | WeightCategory::Routers)
    }

    /// True when tensor parallelism copies this category whole onto every rank
    /// instead of splitting it, so per-GPU cost is the full tensor and not
    /// `bytes / tp`.
    ///
    /// Tensor parallelism exists to split the large matmuls. After each block's
    /// all-reduce every rank holds an identical copy of the full hidden vector,
    /// and anything that reads that vector and produces something small is
    /// cheaper to recompute redundantly than to shard, because sharding it
    /// would put a collective back in.
    ///
    /// - **Norms** need the sum of squares over the whole hidden dimension, so
    ///   a hidden-dim split would need a collective just to normalize. The
    ///   weight is one scalar per channel, 6 KB at BF16 on a 3072-wide model.
    /// - **Routers** must produce byte-identical top-k expert selections on
    ///   every rank or the dispatch desynchronizes. Column-sharding the logits
    ///   would need an all-gather before the top-k.
    ///
    /// vLLM states this in the model structure it prints at load: sharded
    /// modules are `ColumnParallelLinear` / `RowParallelLinear` / `QKVParallelLinear`
    /// / `VocabParallelEmbedding` and carry a `tp_size=` field, while replicated
    /// ones are `ReplicatedLinear` or a bare `RMSNorm` and carry none.
    pub fn replicates_under_tp(self) -> bool {
        matches!(self, WeightCategory::Norms | WeightCategory::Routers)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuantizationMetadata {
    pub flavor: String,
    pub group_size: Option<u32>,
    pub is_hypothetical: bool,
}
