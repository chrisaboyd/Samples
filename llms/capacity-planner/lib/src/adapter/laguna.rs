//! Laguna custom hybrid-MoE adapter (PRD §10.2, §29, §32 criterion #3/#4).
//!
//! Laguna-S-2.1 (from the public `poolside/Laguna-S-2.1` config) is a *hybrid
//! MoE* decoder: MoE MLP + hybrid (full + sliding-window) attention, with a
//! per-layer head-count array (`num_attention_heads_per_layer`) and a dense
//! MLP at layer 0 (`mlp_only_layers`/`mlp_layer_types`). This adapter reads those
//! arrays directly so the architecture-derived parameter count is exact from
//! config.json alone (PRD Level C), rather than projected from a single global
//! head count.
//!
//! Parameter layout per layer (no bias terms — RMSNorm + SiLU):
//!   attention = q(H·heads_i·d) + k + v(H·kv·d each) + o_proj(H·H)
//!   dense MLP = 3·H·I_dense            (gate + up + down)
//!   MoE layer = num_experts·(3·H·moeI)  routed
//!             + 3·H·sharedI           shared experts
//!             + H·num_experts          router logits

use serde_json::Value;

use crate::error::Result;
use crate::model::{
    AttentionKind, AttentionLayer, Context, Dimensions, ModelType, MoeSpec, NormalizedModel,
    WeightComponent, Weights,
};
use crate::precision::{Precision, WeightCategory};

use super::{
    as_u64, embedding_components, opt_u64, parse_identity, parse_source_precision,
    quantization_marker,
};

/// Interpret the per-layer attention type list into grouped layers.
fn attention_layers_from(layer_types: &[String]) -> (Vec<AttentionLayer>, u32, u32) {
    let is_full = |s: &str| s == "full_attention" || s == "full" || s == "mla";
    let is_sliding =
        |s: &str| s == "sliding_attention" || s == "sliding" || s == "local" || s == "windowed";
    let (mut full, mut sliding) = (0u32, 0u32);
    for t in layer_types {
        if is_full(t) {
            full += 1;
        } else if is_sliding(t) {
            sliding += 1;
        }
    }
    let layers = vec![
        AttentionLayer {
            kind: AttentionKind::Full,
            count: full,
            window_size: None,
        },
        AttentionLayer {
            kind: AttentionKind::Sliding,
            count: sliding,
            window_size: None,
        },
    ];
    (layers, full, sliding)
}

pub(crate) fn normalize_family(raw: &Value) -> Result<NormalizedModel> {
    let mut inferred = Vec::new();
    let identity = parse_identity(raw, "laguna");

    let hidden: u128 = as_u64(raw, "hidden_size")? as u128;
    let vocab = opt_u64(raw, "vocab_size").unwrap_or(0) as u128;
    let layer_count = as_u64(raw, "num_hidden_layers")? as u32;
    let kv_heads = as_u64(raw, "num_key_value_heads")? as u128;
    let head_dim = as_u64(raw, "head_dim")? as u128;
    let tied = raw
        .get("tie_word_embeddings")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let dense_intermediate: u128 = opt_u64(raw, "intermediate_size").unwrap_or(0) as u128;
    let num_experts: u128 = opt_u64(raw, "num_experts").unwrap_or(0) as u128;
    let moe_intermediate: u128 = opt_u64(raw, "moe_intermediate_size").unwrap_or(0) as u128;
    let shared_intermediate: Option<u128> =
        opt_u64(raw, "shared_expert_intermediate_size").map(|v| v as u128);
    let active_per_tok: u128 = opt_u64(raw, "num_experts_per_tok").unwrap_or(1) as u128;
    let window = opt_u64(raw, "sliding_window").map(|v| v as u32);

    let precision = parse_source_precision(raw, &mut inferred);

    // Per-layer arrays (the source of truth for Laguna's variable layout).
    let layer_types: Vec<String> = raw
        .get("layer_types")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mlp_types: Vec<String> = raw
        .get("mlp_layer_types")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let head_per_layer: Vec<u128> = raw
        .get("num_attention_heads_per_layer")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|v| v as u128)
                .collect()
        })
        .unwrap_or_default();

    if layer_types.is_empty() || head_per_layer.len() != layer_types.len() {
        inferred.push(format!(
            "layer_types/head arrays (len={}/{}/{}); per-layer head counts approximated",
            layer_types.len(),
            head_per_layer.len(),
            layer_count
        ));
    }

    let (mut attention_layers, _full_layers, _sliding_layers) = attention_layers_from(&layer_types);
    // Attach the shared sliding window.
    if let Some(w) = window {
        if let Some(sl) = attention_layers
            .iter_mut()
            .find(|l| l.kind == AttentionKind::Sliding)
        {
            sl.window_size = Some(w);
        }
    }
    if attention_layers.is_empty() {
        // Fallback if layer_types absent.
        attention_layers = vec![AttentionLayer {
            kind: AttentionKind::Full,
            count: layer_count,
            window_size: None,
        }];
    }

    // Iterate layers to accumulate per-category param counts.
    let mut attention_elems: u128 = 0;
    let mut dense_mlp: u128 = 0;
    let mut routed: u128 = 0;
    let mut shared: u128 = 0;
    let mut router: u128 = 0;

    for i in 0..layer_count as usize {
        let heads_i = if i < head_per_layer.len() {
            head_per_layer[i]
        } else {
            as_u64(raw, "num_attention_heads")
                .map(|h| h as u128)
                .unwrap_or_else(|_| hidden / head_dim)
        };
        let q = hidden * heads_i * head_dim;
        let kv_each = hidden * kv_heads * head_dim;
        let o = hidden * hidden;
        attention_elems += q + 2 * kv_each + o;

        let mlp_type = if i < mlp_types.len() {
            mlp_types[i].as_str()
        } else {
            "sparse"
        };
        if mlp_type == "dense" {
            dense_mlp += 3 * hidden * dense_intermediate;
        } else {
            routed += num_experts * 3 * hidden * moe_intermediate;
            shared += shared_intermediate.map(|s| 3 * hidden * s).unwrap_or(0);
            router += hidden * num_experts;
        }
    }

    let dims = Dimensions {
        vocabulary_size: opt_u64(raw, "vocab_size"),
        hidden_size: hidden as u64,
        intermediate_size: Some(dense_intermediate as u64),
        layer_count,
        attention_heads: Some(as_u64(raw, "num_attention_heads")? as u32),
        kv_heads: Some(kv_heads as u32),
        head_dimension: Some(head_dim as u32),
    };

    let mut components: Vec<WeightComponent> = Vec::new();
    components.extend(embedding_components(vocab, hidden, tied, precision));
    let mut push = |cat: WeightCategory, n: u128, p: Precision| {
        components.push(WeightComponent {
            category: cat,
            element_count: n,
            precision: p,
            is_hypothetical: false,
        });
    };
    push(WeightCategory::Attention, attention_elems, precision);
    if dense_mlp > 0 {
        push(WeightCategory::DenseMlp, dense_mlp, precision);
    }
    if routed > 0 {
        push(WeightCategory::RoutedExperts, routed, precision);
    }
    if shared > 0 {
        push(WeightCategory::SharedExperts, shared, precision);
    }
    if router > 0 {
        push(WeightCategory::Routers, router, precision);
    }
    // RMSNorms: 2 per layer + final.
    let norms = (2 * layer_count as u128 + 1) * hidden;
    push(WeightCategory::Norms, norms, precision);

    let exact: u128 = components.iter().map(|c| c.element_count).sum();

    let moe = if num_experts > 0 {
        Some(MoeSpec {
            expert_count: num_experts as u32,
            active_experts_per_token: active_per_tok as u32,
            expert_intermediate_size: moe_intermediate as u64,
            shared_expert_intermediate_size: shared_intermediate.map(|v| v as u64),
            shared_expert_parameters: None,
        })
    } else {
        None
    };

    let weights = Weights {
        components,
        exact_parameter_count: Some(exact),
        estimated_parameter_count: None,
        source_precision: Some(precision.label().to_string()),
        quantization: quantization_marker(precision, false, 16),
    };

    Ok(NormalizedModel {
        identity,
        model_type: ModelType::Hybrid,
        dimensions: dims,
        attention_layers,
        moe,
        context: Context {
            native_maximum: opt_u64(raw, "max_position_embeddings").unwrap_or(0),
            checkpoint_maximum: None,
            rope_scaling: raw
                .get("rope_parameters")
                .or(raw.get("rope_scaling"))
                .cloned(),
        },
        weights,
        inferred,
    })
}

pub fn normalize(raw: &Value) -> Result<NormalizedModel> {
    normalize_family(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precision::WeightCategory;

    fn laguna() -> Value {
        // real public config, trimmed to the fields the adapter consumes.
        serde_json::from_str(include_str!("../../tests/assets/laguna-config.json")).unwrap()
    }

    #[test]
    fn identified_as_hybrid_moe_with_hybrid_attention() {
        let m = normalize(&laguna()).unwrap();
        assert_eq!(m.model_type, ModelType::Hybrid);
        assert_eq!(m.moe.as_ref().unwrap().expert_count, 256);
        assert_eq!(m.moe.as_ref().unwrap().active_experts_per_token, 10);
        // full vs sliding attention recognized (criterion #4).
        let (full, sliding) = (
            m.attention_layers
                .iter()
                .find(|l| l.kind == AttentionKind::Full),
            m.attention_layers
                .iter()
                .find(|l| l.kind == AttentionKind::Sliding),
        );
        assert_eq!(full.unwrap().count, 12);
        assert_eq!(sliding.unwrap().count, 36);
        assert_eq!(sliding.unwrap().window_size, Some(512));
    }

    #[test]
    fn parameter_count_matches_hand_calc() {
        let m = normalize(&laguna()).unwrap();
        let p = m.parameter_count().unwrap();
        // Hand calc: emb 616,562,688 + attn 2,000,683,008 + dense mlp 113,246,208
        // + routed (47 sparse layers) 113,548,197,888 + shared 443,547,648
        // + router 36,962,304 + norms 297,984 = 116,759,497,728 (~116.76B).
        assert_eq!(p, 116_759_497_728);
    }

    #[test]
    fn attention_uses_per_layer_head_counts() {
        let m = normalize(&laguna()).unwrap();
        let att = m
            .weights
            .components
            .iter()
            .find(|c| c.category == WeightCategory::Attention)
            .unwrap();
        assert_eq!(att.element_count, 2_000_683_008);
    }

    #[test]
    fn routed_moe_dominates_storage() {
        let m = normalize(&laguna()).unwrap();
        let routed = m
            .weights
            .components
            .iter()
            .find(|c| c.category == WeightCategory::RoutedExperts)
            .unwrap();
        // 47 sparse MoE layers: 47 * 256 * (3*3072*1024) = 113,548,197,888
        assert_eq!(routed.element_count, 113_548_197_888);
    }
}
