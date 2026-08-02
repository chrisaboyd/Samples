//! Mixtral-style MoE decoder adapter (PRD §10.2).
//!
//! Dense attention + MoE MLP with `num_local_experts` routed experts and
//! `num_experts_per_tok` active experts, no shared experts (Mixtral-8x7B).
//! Model type is [`ModelType::Moe`] (dense attention, MoE MLP), distinct from
//! Laguna's [`ModelType::Hybrid`].

use serde_json::Value;

use crate::error::Result;
use crate::model::{Context, ModelType, MoeSpec, NormalizedModel, WeightComponent, Weights};
use crate::precision::WeightCategory;

use super::{
    as_u64, embedding_components, opt_u64, parse_identity, parse_source_precision,
    quantization_marker, standard_attention_layers, standard_dimensions,
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

    let mut components: Vec<WeightComponent> = Vec::new();
    components.extend(embedding_components(vocab, hidden, tied, precision));

    // Attention (same as dense decoder).
    let q = hidden * heads * head_dim;
    let kv_each = hidden * kv_heads * head_dim;
    let o_attn = hidden * hidden;
    components.push(WeightComponent {
        category: WeightCategory::Attention,
        element_count: (q + kv_each + kv_each + o_attn) * layers,
        precision,
        is_hypothetical: false,
    });

    // Routed experts: num_experts * (3 * H * I) per layer.
    let routed_per_layer = num_experts * 3 * hidden * intermediate;
    components.push(WeightComponent {
        category: WeightCategory::RoutedExperts,
        element_count: routed_per_layer * layers,
        precision,
        is_hypothetical: false,
    });

    // Router logits: H -> num_experts per layer.
    components.push(WeightComponent {
        category: WeightCategory::Routers,
        element_count: hidden * num_experts * layers,
        precision,
        is_hypothetical: false,
    });

    // Norms.
    components.push(WeightComponent {
        category: WeightCategory::Norms,
        element_count: (2 * layers + 1) * hidden,
        precision,
        is_hypothetical: false,
    });
    let _ = active_per_tok; // gating config, no params

    let exact: u128 = components.iter().map(|c| c.element_count).sum();
    let weights = Weights {
        components,
        exact_parameter_count: Some(exact),
        estimated_parameter_count: None,
        source_precision: Some(precision.label().to_string()),
        quantization: quantization_marker(precision, false, 16),
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
