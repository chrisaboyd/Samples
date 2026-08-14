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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuantizationMetadata {
    pub flavor: String,
    pub group_size: Option<u32>,
    pub is_hypothetical: bool,
}
