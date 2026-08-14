//! Mixtral-style MoE decoder adapter (PRD §10.2).
//!
//! Dense attention + MoE MLP with `num_local_experts` routed experts and
//! `num_experts_per_tok` active experts, no shared experts (Mixtral-8x7B).
//! Model type is [`ModelType::Moe`] (dense attention, MoE MLP), distinct from
//! Laguna's [`ModelType::Hybrid`].

use serde_json::Value;

use crate::error::Result;
use crate::model::{Context, ModelType, MoeSpec, NormalizedModel, Weights};
use crate::precision::WeightCategory;
use crate::quant::CheckpointQuantization;

use super::{
    add_attention_projections, add_embeddings, as_u64, checkpoint_marker, opt_u64, parse_identity,
    parse_source_precision, standard_attention_layers, standard_dimensions, ComponentBuilder,
};

pub(crate) fn normalize_family(raw: &Value) -> Result<NormalizedModel> {
    let mut inferred = Vec::new();
    let identity = parse_identity(raw, "mixtral");
    let dims = standard_dimensions(raw, &mut inferred)?;
    let attention_layers = standard_attention_layers(raw);
    let precision = parse_source_precision(raw, &mut inferred);

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

    let num_experts = as_u64(raw, "num_local_experts").unwrap_or(0) as u128;
    let active_per_tok = opt_u64(raw, "num_experts_per_tok").unwrap_or(1) as u128;

    // What the checkpoint says it quantized; `None` leaves every tensor at
    // `precision`.
    let quantization = CheckpointQuantization::parse(raw, &mut inferred);
    let mut builder = ComponentBuilder::new(quantization.as_ref(), precision);
    add_embeddings(&mut builder, vocab, hidden, tied);

    // Per layer so an `ignore` list that names specific layers is honoured.
    // Mixtral's MoE block is `block_sparse_moe`, and its expert projections are
    // `w1`/`w2`/`w3` rather than gate/up/down — the names an `ignore`/`targets`
    // rule for this family is written against. Expert precision is resolved
    // from expert 0 (rules select by layer and projection, not expert index).
    for i in 0..layers as usize {
        add_attention_projections(&mut builder, i, hidden, heads, kv_heads, head_dim);
        for proj in ["w1", "w2", "w3"] {
            builder.add(
                WeightCategory::RoutedExperts,
                &format!("model.layers.{i}.block_sparse_moe.experts.0.{proj}"),
                num_experts * hidden * intermediate,
            );
        }
        builder.add(
            WeightCategory::Routers,
            &format!("model.layers.{i}.block_sparse_moe.gate"),
            hidden * num_experts,
        );
    }

    builder.add_unquantized(WeightCategory::Norms, (2 * layers + 1) * hidden);
    let _ = active_per_tok; // gating config, no params

    let components = builder.finish();
    let exact: u128 = components.iter().map(|c| c.element_count).sum();
    let weights = Weights {
        components,
        exact_parameter_count: Some(exact),
        estimated_parameter_count: None,
        source_precision: Some(precision.label().to_string()),
        quantization: checkpoint_marker(quantization.as_ref(), precision),
        // Not in config.json; filled in by the caller when an index was fetched.
        checkpoint_total_size_bytes: None,
    };

    Ok(NormalizedModel {
        identity,
        model_type: ModelType::Moe,
        dimensions: dims,
        attention_layers,
        moe: Some(MoeSpec {
            expert_count: num_experts as u32,
            active_experts_per_token: active_per_tok as u32,
            expert_intermediate_size: intermediate as u64,
            shared_expert_intermediate_size: None,
            shared_expert_parameters: None,
        }),
        context: Context {
            native_maximum: opt_u64(raw, "max_position_embeddings").unwrap_or(4096),
            checkpoint_maximum: None,
            rope_scaling: raw.get("rope_scaling").cloned(),
        },
        weights,
        inferred,
        unresolved: Vec::new(),
    })
}

pub fn normalize(raw: &Value) -> Result<NormalizedModel> {
    normalize_family(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_mixtral() -> Value {
        serde_json::json!({
            "model_type": "mixtral",
            "architectures": ["MixtralForCausalLM"],
            "vocab_size": 10,
            "hidden_size": 8,
            "intermediate_size": 6,
            "num_hidden_layers": 2,
            "num_attention_heads": 4,
            "num_key_value_heads": 2,
            "head_dim": 2,
            "max_position_embeddings": 128,
            "num_local_experts": 4,
            "num_experts_per_tok": 2,
            "tie_word_embeddings": true,
            "torch_dtype": "bfloat16",
        })
    }

    #[test]
    fn tiny_mixtral_param_count() {
        // emb 80, attn/layer (64+32+32+64)=192 *2=384, routed 4*3*8*6=576 *2=1152,
        // router 8*4=32 *2=64, norms (5)*8=40. total = 80+384+1152+64+40 = 1720
        let m = normalize(&tiny_mixtral()).unwrap();
        assert_eq!(m.model_type, ModelType::Moe);
        assert_eq!(m.parameter_count(), Some(1720));
        assert_eq!(m.moe.as_ref().unwrap().expert_count, 4);
        assert_eq!(m.moe.as_ref().unwrap().active_experts_per_token, 2);
    }
}
