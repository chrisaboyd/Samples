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
    /// `metadata.total_size` from the checkpoint's `model.safetensors.index.json`
    /// — every tensor byte the repository actually holds, scales included.
    ///
    /// An adapter can never set this: it is not in `config.json`. It is filled in
    /// by whoever fetched the index, and when present it replaces the
    /// architecture-derived total outright (Level B beats Level C). It describes
    /// the checkpoint as built, so the hypothetical-requantization path ignores
    /// it.
    #[serde(default)]
    pub checkpoint_total_size_bytes: Option<u128>,
}

/// A speculative-decoding draft model attached to a target checkpoint.
///
/// The drafter is a second checkpoint that costs GPU memory twice over: its
/// weights load alongside the target's, and its attention layers take KV cache
/// out of the same pool. On Laguna-S the KV half is the larger of the two by an
/// order of magnitude.
///
/// # Why `full_context_layers` is not read from the drafter's config
///
/// A drafter may declare a sliding window and still allocate full-context KV.
/// Laguna's DFlash declares `"layer_types": ["sliding_attention", ...]` with a
/// 512-token window on all six layers, and `laguna_dflash.py` then clears the
/// window immediately after constructing the attention module:
///
/// ```text
/// if sliding_window is not None:
///     # Keep full KV allocation: context K/V is inserted manually at
///     # absolute slots, while SWA is only a compute-time attention limit.
///     self.attn.sliding_window = None
/// ```
///
/// vLLM picks `SlidingWindowSpec` only when that attribute survives, so all six
/// layers take `FullAttentionSpec`. The window is enforced as an attention mask
/// at compute time and has no effect on allocation. No config file records this;
/// it is a property of the serving implementation, so [`SpeculatorMethod`]
/// carries the rule instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Speculator {
    /// `speculative_config.method`, e.g. `dflash`, `eagle`, `mtp`, `ngram`.
    pub method: String,
    /// Repository or path the drafter was resolved from, for provenance.
    pub source: Option<String>,
    /// Draft tokens proposed per step. Does not change KV residency, but scales
    /// the tokens a decode step carries.
    pub num_speculative_tokens: Option<u32>,
    /// Drafter layers holding KV across the full context.
    pub full_context_layers: u32,
    /// Drafter KV heads before TP sharding. Falls back to the target's when the
    /// drafter config omits it.
    pub kv_heads: Option<u32>,
    /// Drafter head dimension. Falls back to the target's.
    pub head_dimension: Option<u32>,
    /// Drafter checkpoint bytes, from its safetensors index or blob sizes.
    pub weight_bytes: Option<u128>,
    /// Drafter storage precision, which is independent of the target's. The FP8
    /// Laguna-S repo pairs with a BF16 drafter.
    pub weight_precision: Option<Precision>,
}

/// Whether a speculative method loads a draft model that occupies KV cache.
///
/// Prompt-lookup methods (`ngram`) propose tokens from the prompt itself and
/// load no model at all, so they cost nothing here.
pub fn method_loads_draft_model(method: &str) -> bool {
    !matches!(
        method.trim().to_ascii_lowercase().as_str(),
        "ngram" | "lookahead" | "suffix" | "none" | ""
    )
}

/// Whether a drafter's declared sliding window should be ignored for KV sizing.
///
/// True for the EAGLE-family drafters (DFlash included), which write K/V at
/// absolute sequence positions so their block tables line up with the target's
/// and therefore allocate across the whole context.
pub fn method_allocates_full_context(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_lowercase().as_str(),
        "dflash" | "eagle" | "eagle3" | "mtp" | "medusa"
    )
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
    /// Speculative-decoding drafter, when the checkpoint declares one in
    /// `generation_config.json` or the user supplied one.
    ///
    /// An adapter can never set this: it is not in `config.json`. It is filled
    /// in by whoever resolved the drafter, the same way
    /// [`Weights::checkpoint_total_size_bytes`] is.
    #[serde(default)]
    pub speculator: Option<Speculator>,
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
