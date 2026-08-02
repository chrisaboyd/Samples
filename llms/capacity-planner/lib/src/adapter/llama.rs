//! Llama-like dense decoder adapter (PRD §10.2 initial adapter set).
//!
//! Supports the standard HF `decoder_config` family (Llama 2/3/N, Gemma-style
//! dense decoders). Dense MLP per layer: `3 * H * I` (gate + up + down SiLU).
//! Attention per layer: `q + k + v + o` with GQA when `num_key_value_heads`
//! < `num_attention_heads`. Embeddings respect `tie_word_embeddings` (PRD §29).

use serde_json::Value;

use crate::error::Result;
use crate::model::{Context, ModelType, NormalizedModel, WeightComponent, Weights};
use crate::precision::{Precision, WeightCategory};

use super::{
    embedding_components, get_str, opt_str, opt_u64, parse_identity, parse_source_precision,
    quantization_marker, standard_attention_layers, standard_dimensions,
};

pub(crate) fn normalize_family(raw: &Value, model_type: &str) -> Result<NormalizedModel> {
    let mut inferred = Vec::new();
    let identity = parse_identity(raw, model_type);
    let dims = standard_dimensions(raw, &mut inferred)?;
    let attention_layers = standard_attention_layers(raw);
    let precision = parse_source_precision(raw, &mut inferred);

    let hidden: u128 = dims.hidden_size as u128;
    let vocab: u128 = dims.vocabulary_size.unwrap_or(0) as u128;
    let tied = raw
        .get("tie_word_embeddings")
        .and_then(|x| x.as_bool())
        .unwrap_or(true);
    if !tied {
        // explicit untied flag is informational, not an inference.
    }
    let layers = dims.layer_count as u128;
    let heads: u128 = dims.attention_heads.unwrap_or(0) as u128;
    let kv_heads: u128 = dims
        .kv_heads
        .map(|v| v as u128)
        .filter(|&v| v != 0)
        .unwrap_or(heads);
    let head_dim: u128 = dims.head_dimension.unwrap_or(0) as u128;
    let intermediate: u128 = dims.intermediate_size.unwrap_or(0) as u128;
    if head_dim == 0 {
        inferred.push("head_dimension (inferred 0; cannot derive attention params)".to_string());
    }

    let mut components: Vec<WeightComponent> = Vec::new();
    let zero = |cat, precision: Precision| WeightComponent {
        category: cat,
        element_count: 0,
        precision,
        is_hypothetical: false,
    };
    components.extend(embedding_components(vocab, hidden, tied, precision));

    // Attention: q(H·heads·d) + k + v(H·kv·d each) + o(H·H)
    let q = hidden * heads * head_dim;
    let kv_each = hidden * kv_heads * head_dim;
    let o_attn = hidden * hidden;
    let attn_per_layer = q + kv_each + kv_each + o_attn;
    components.push(WeightComponent {
        category: WeightCategory::Attention,
        element_count: attn_per_layer * layers,
        precision,
        is_hypothetical: false,
    });

    // Dense MLP: 3 * H * I per layer.
    let mlp_per_layer = 3 * hidden * intermediate;
    components.push(WeightComponent {
        category: WeightCategory::DenseMlp,
        element_count: mlp_per_layer * layers,
        precision,
        is_hypothetical: false,
    });

    // RMSNorms: 2 per layer (post-attn, post-mlp) + 1 final. (no bias — biases unused by RMSNorm)
    let norm_params = (2 * layers + 1) * hidden;
    components.push(WeightComponent {
        category: WeightCategory::Norms,
        element_count: norm_params,
        precision,
        is_hypothetical: false,
    });
    let _ = zero(WeightCategory::Biases, precision); // Llama has no biases; category empty.

    let exact: u128 = components.iter().map(|c| c.element_count).sum();

    let model_type_enum = ModelType::Dense;
    let weights = Weights {
        components,
        exact_parameter_count: Some(exact),
        estimated_parameter_count: None,
        source_precision: Some(precision.label().to_string()),
        quantization: quantization_marker(precision, false, 16),
    };

    Ok(NormalizedModel {
        identity,
        model_type: model_type_enum,
        dimensions: dims,
        attention_layers,
        moe: None,
        context: Context {
            native_maximum: opt_str(raw, "max_position_embeddings")
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| opt_u64(raw, "max_position_embeddings"))
                .unwrap_or(4096),
            checkpoint_maximum: None,
            rope_scaling: raw.get("rope_scaling").cloned(),
        },
        weights,
        inferred,
        unresolved: Vec::new(),
    })
}

pub fn normalize(raw: &Value) -> Result<NormalizedModel> {
    let mt = get_str(raw, "model_type")?;
    normalize_family(raw, &mt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precision::Precision;

    fn tiny_llama_json(tied: bool) -> Value {
        serde_json::json!({
            "model_type": "llama",
            "architectures": ["LlamaForCausalLM"],
            "vocab_size": 10,
            "hidden_size": 8,
            "intermediate_size": 6,
            "num_hidden_layers": 2,
            "num_attention_heads": 4,
            "num_key_value_heads": 4,
            "head_dim": 2,
            "max_position_embeddings": 128,
            "tie_word_embeddings": tied,
            "torch_dtype": "bfloat16",
        })
    }

    #[test]
    fn tiny_untied_param_count_is_exact() {
        // emb 10*8=80 (x2 untied=160), attn/layer q(8*4*2=64)+k(64)+v(64)+o(8*8=64)=256 *2=512,
        // mlp/layer 3*8*6=144 *2=288, norms (2*2+1)*8=40. total=160+512+288+40=1000
        let m = normalize(&tiny_llama_json(false)).unwrap();
        assert_eq!(m.parameter_count(), Some(1000));
        assert_eq!(m.model_type, ModelType::Dense);
        assert_eq!(m.attention_layers.len(), 1);
        assert_eq!(m.attention_layers[0].count, 2);
    }

    #[test]
    fn tied_halves_embedding_params() {
        let m = normalize(&tiny_llama_json(true)).unwrap();
        assert_eq!(m.parameter_count(), Some(920)); // emb 80 not 160
    }

    #[test]
    fn bf16_precision_parsed() {
        let m = normalize(&tiny_llama_json(true)).unwrap();
        assert_eq!(m.weights.source_precision.as_deref(), Some("BF16"));
    }

    #[test]
    fn component_precision_default_bf16() {
        let m = normalize(&tiny_llama_json(true)).unwrap();
        assert!(m
            .weights
            .components
            .iter()
            .all(|c| c.precision == Precision::Bf16));
    }
}
