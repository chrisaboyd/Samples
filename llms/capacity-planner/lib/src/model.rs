//! Normalized internal model representation (PRD §11).
//!
//! Architecture adapters convert raw `config.json` blobs into this structure so
//! downstream calculations never depend on arbitrary model-specific field names.
//! Fields that had to be inferred (rather than read verbatim) are listed in
//! [`NormalizedModel::inferred`]; unknown/incompatible values are represented as
//! `Option::None` and surfaced through the confidence/assumption system.
//!
//! Serialized as camelCase to match the PRD §11 TypeScript interface.

use serde::{Deserialize, Serialize};

use crate::precision::{Precision, QuantizationMetadata};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub repository: Option<String>,
    pub revision: Option<String>,
    pub architecture_names: Vec<String>,
    #[serde(rename = "modelType")]
    pub model_type: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ModelType {
    Dense,
    Moe,
    Hybrid,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Dimensions {
    pub vocabulary_size: Option<u64>,
    pub hidden_size: u64,
    pub intermediate_size: Option<u64>,
    pub layer_count: u32,
    pub attention_heads: Option<u32>,
    pub kv_heads: Option<u32>,
    pub head_dimension: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttentionKind {
    Full,
    Sliding,
    Local,
    Mla,
    Ssm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttentionLayer {
    #[serde(rename = "type")]
    pub kind: AttentionKind,
    pub count: u32,
    pub window_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MoeSpec {
    pub expert_count: u32,
    pub active_experts_per_token: u32,
    pub expert_intermediate_size: u64,
    pub shared_expert_intermediate_size: Option<u64>,
    pub shared_expert_parameters: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Context {
    pub native_maximum: u64,
    pub checkpoint_maximum: Option<u64>,
    pub rope_scaling: Option<serde_json::Value>,
}

/// One architectural weight component keyed to a [`WeightCategory`].
///
/// `precision` is the precision the component is *stored* in at parse time
/// (the checkpoint's native precision). A scenario later reassigns precision
/// via a [`crate::weight::QuantizationProfile`] to compute memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WeightComponent {
    pub category: crate::precision::WeightCategory,
    pub element_count: u128,
    pub precision: Precision,
    pub is_hypothetical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Weights {
    pub components: Vec<WeightComponent>,
    pub exact_parameter_count: Option<u128>,
    pub estimated_parameter_count: Option<u128>,
    pub source_precision: Option<String>,
    pub quantization: Option<QuantizationMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedModel {
    pub identity: Identity,
    pub model_type: ModelType,
    pub dimensions: Dimensions,
    pub attention_layers: Vec<AttentionLayer>,
    pub moe: Option<MoeSpec>,
    pub context: Context,
    pub weights: Weights,
    /// Field names that had to be inferred rather than read verbatim from the
    /// source config, so the UI can surface them as "inferred".
    pub inferred: Vec<String>,
    /// Architectural facts the math *needs* that could not be determined from
    /// the config at all. Distinct from [`Self::inferred`]: an inference is a
    /// defensible substitution, an unresolved entry means a term is missing or
    /// assumed at a bound. Any entry here forces the result to Level D /
    /// Speculative (PRD §10.1) so a guess is never graded like a parse.
    #[serde(default)]
    pub unresolved: Vec<String>,
}

impl NormalizedModel {
    /// Exact parameter count when tensor metadata is available, else an
    /// architecture-derived estimate.
    pub fn parameter_count(&self) -> Option<u128> {
        self.weights
            .exact_parameter_count
            .or(self.weights.estimated_parameter_count)
    }
}
