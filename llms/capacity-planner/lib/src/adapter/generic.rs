//! Generic decoder-only fallback adapter (PRD Level D / §10.2 last adapter).
//!
//! Used when `model_type` is unrecognized. Applies the standard decoder
//! formula (MHA/GQA/MQA depending on head/kv ratio) and emits a Speculative
//! confidence signal. Recognizes `architectures`/`model_type` via pattern
//! matching rather than executing any custom code.

use serde_json::Value;

use crate::error::Result;
use crate::model::{Context, ModelType, NormalizedModel, WeightComponent, Weights};
use crate::precision::WeightCategory;

use super::{
    embedding_components, opt_u64, parse_identity, parse_source_precision, quantization_marker,
    standard_attention_layers, standard_dimensions,
};

pub(crate) fn normalize_family(raw: &Value) -> Result<NormalizedModel> {
    let mut inferred = Vec::new();
    let model_type_str = raw
        .get("model_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let identity = parse_identity(raw, &model_type_str);
    let dims = standard_dimensions(raw, &mut inferred)?;
    let attention_layers = standard_attention_layers(raw);
    let precision = parse_source_precision(raw, &mut inferred);
    inferred.push("model_type unrecognized — generic decoder formula applied".to_string());

    let hidden: u128 = dims.hidden_size as u128;
    let vocab: u128 = dims.vocabulary_size.unwrap_or(0) as u128;
    let tied = raw
        .get("tie_word_embeddings")
        .and_then(|x| x.as_bool())
        .unwrap_or(true);
    let layers = dims.layer_count as u128;
    let heads: u128 = dims.attention_heads.unwrap_or(0) as u128;
    let kv_heads: u128 = dims
        .kv_heads
        .map(|v| v as u128)
        .filter(|&v| v != 0)
        .unwrap_or(heads);
    let head_dim: u128 = dims.head_dimension.unwrap_or(0) as u128;
    let intermediate: u128 = dims.intermediate_size.unwrap_or(0) as u128;

    let mut components: Vec<WeightComponent> = Vec::new();
    components.extend(embedding_components(vocab, hidden, tied, precision));

    // Dense attention + MLP (GQA/MQA when kv_heads < heads).
    let q = hidden * heads * head_dim;
    let kv_each = hidden * kv_heads * head_dim;
    let o_attn = hidden * hidden;
    components.push(WeightComponent {
        category: WeightCategory::Attention,
        element_count: (q + kv_each + kv_each + o_attn) * layers,
        precision,
        is_hypothetical: false,
    });
    components.push(WeightComponent {
        category: WeightCategory::DenseMlp,
        element_count: 3 * hidden * intermediate * layers,
        precision,
        is_hypothetical: false,
    });
    components.push(WeightComponent {
        category: WeightCategory::Norms,
        element_count: (2 * layers + 1) * hidden,
        precision,
        is_hypothetical: false,
    });

    let exact: u128 = components.iter().map(|c| c.element_count).sum();
    // Generic path: claim estimate, not exact (Level D).
    let weights = Weights {
        components,
        exact_parameter_count: None,
        estimated_parameter_count: Some(exact),
        source_precision: Some(precision.label().to_string()),
        quantization: quantization_marker(precision, false, 16),
    };

    Ok(NormalizedModel {
        identity,
        model_type: ModelType::Unknown,
        dimensions: dims,
        attention_layers,
        moe: None,
        context: Context {
            native_maximum: opt_u64(raw, "max_position_embeddings").unwrap_or(4096),
            checkpoint_maximum: None,
            rope_scaling: raw.get("rope_scaling").cloned(),
        },
        weights,
        inferred,
    })
}

pub fn normalize(raw: &Value) -> Result<NormalizedModel> {
    normalize_family(raw)
}
