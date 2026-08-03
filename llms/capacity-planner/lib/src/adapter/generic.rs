//! Generic decoder-only fallback adapter (PRD Level D / §10.2 last adapter).
//!
//! Used when `model_type` is unrecognized. Applies the standard decoder
//! formula (MHA/GQA/MQA depending on head/kv ratio) and emits a Speculative
//! confidence signal. Recognizes `architectures`/`model_type` via pattern
//! matching rather than executing any custom code.

use serde_json::Value;

use crate::error::Result;
use crate::model::{Context, ModelType, NormalizedModel, Weights};
use crate::precision::WeightCategory;
use crate::quant::CheckpointQuantization;

use super::{
    add_attention_projections, add_dense_mlp, add_embeddings, checkpoint_marker, opt_u64,
    parse_identity, parse_source_precision, standard_attention_layers, standard_dimensions,
    ComponentBuilder,
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

    // What the checkpoint says it quantized; `None` leaves every tensor at
    // `precision`.
    let quantization = CheckpointQuantization::parse(raw, &mut inferred);
    let mut builder = ComponentBuilder::new(quantization.as_ref(), precision);
    add_embeddings(&mut builder, vocab, hidden, tied);

    // Dense attention + MLP (GQA/MQA when kv_heads < heads), per layer so an
    // `ignore` list that names specific layers is honoured.
    for i in 0..layers as usize {
        add_attention_projections(&mut builder, i, hidden, heads, kv_heads, head_dim);
        add_dense_mlp(&mut builder, i, hidden, intermediate);
    }
    builder.add_unquantized(WeightCategory::Norms, (2 * layers + 1) * hidden);

    let components = builder.finish();
    let exact: u128 = components.iter().map(|c| c.element_count).sum();
    // Generic path: claim estimate, not exact (Level D).
    let weights = Weights {
        components,
        exact_parameter_count: None,
        estimated_parameter_count: Some(exact),
        source_precision: Some(precision.label().to_string()),
        quantization: checkpoint_marker(quantization.as_ref(), precision),
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
