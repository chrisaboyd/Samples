//! Generic decoder-only fallback adapter (PRD Level D / §10.2 last adapter).
//!
//! Used when `model_type` is unrecognized. Applies the standard decoder
//! formula (MHA/GQA/MQA depending on head/kv ratio) and emits a Speculative
//! confidence signal. Recognizes `architectures`/`model_type` via pattern
//! matching rather than executing any custom code.
//!
//! MoE keys are read under their common spellings (`n_routed_experts`,
//! `num_experts`, `num_local_experts`) because expert tensors dominate the
//! parameter count on every sparse model — omitting them silently reports a
//! sparse model as a small dense one.

use serde_json::Value;

use crate::error::Result;
use crate::model::{
    AttentionKind, AttentionLayer, Context, ModelType, MoeSpec, NormalizedModel, WeightComponent,
    Weights,
};
use crate::precision::WeightCategory;

use super::{
    embedding_components, opt_u64, parse_identity, parse_source_precision, quantization_marker,
    standard_dimensions,
};

/// Expert count under any of the spellings in common use.
fn expert_count(raw: &Value) -> Option<u64> {
    opt_u64(raw, "n_routed_experts")
        .or_else(|| opt_u64(raw, "num_experts"))
        .or_else(|| opt_u64(raw, "num_local_experts"))
        .filter(|&n| n > 0)
}

/// Per-layer attention pattern.
///
/// A blanket `sliding_window` caps KV at the window for *every* layer, which
/// makes KV-cache size independent of context length — the difference between a
/// real capacity number and a meaningless one. On the generic path we only
/// believe that when `layer_types` states it per layer; otherwise we take the
/// upper bound (all layers full) and say so.
fn generic_attention_layers(raw: &Value, unresolved: &mut Vec<String>) -> Vec<AttentionLayer> {
    let layer_count = opt_u64(raw, "num_hidden_layers").unwrap_or(0) as u32;
    let window = opt_u64(raw, "sliding_window").map(|w| w as u32);

    if let Some(types) = raw.get("layer_types").and_then(|x| x.as_array()) {
        let sliding = types
            .iter()
            .filter(|t| {
                t.as_str()
                    .is_some_and(|s| s.contains("sliding") || s.contains("local"))
            })
            .count() as u32;
        let full = types.len() as u32 - sliding;
        let mut out = Vec::new();
        if full > 0 {
            out.push(AttentionLayer {
                kind: AttentionKind::Full,
                count: full,
                window_size: None,
            });
        }
        if sliding > 0 {
            out.push(AttentionLayer {
                kind: AttentionKind::Sliding,
                count: sliding,
                window_size: window,
            });
        }
        return out;
    }

    if let Some(w) = window {
        unresolved.push(format!(
            "sliding_window ({w}) is present but the config gives no per-layer attention pattern \
             (`layer_types`) — KV is computed as if every layer is full attention (upper bound)"
        ));
    }
    vec![AttentionLayer {
        kind: AttentionKind::Full,
        count: layer_count,
        window_size: None,
    }]
}

pub(crate) fn normalize_family(raw: &Value) -> Result<NormalizedModel> {
    let mut inferred = Vec::new();
    let mut unresolved = Vec::new();
    let model_type_str = raw
        .get("model_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let identity = parse_identity(raw, &model_type_str);
    let dims = standard_dimensions(raw, &mut inferred)?;
    let attention_layers = generic_attention_layers(raw, &mut unresolved);
    let precision = parse_source_precision(raw, &mut inferred);
    inferred.push("model_type unrecognized — generic decoder formula applied".to_string());
    unresolved.push(format!(
        "no dedicated adapter for model_type '{model_type_str}' — architecture-specific weight \
         and KV layouts (MLA/latent KV, LoRA-factored projections, per-layer compression) are \
         not modelled"
    ));

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

    let experts: u128 = expert_count(raw).unwrap_or(0) as u128;
    let moe_intermediate: u128 = opt_u64(raw, "moe_intermediate_size").unwrap_or(0) as u128;
    let shared_experts: u128 = opt_u64(raw, "n_shared_experts")
        .or_else(|| opt_u64(raw, "num_shared_experts"))
        .unwrap_or(0) as u128;
    let shared_intermediate: u128 = opt_u64(raw, "shared_expert_intermediate_size")
        .map(|v| v as u128)
        .unwrap_or(moe_intermediate);
    let is_moe = experts > 0 && moe_intermediate > 0;

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

    if is_moe {
        // Which layers are dense vs sparse is model-specific (`first_k_dense_replace`,
        // `mlp_only_layers`, `decoder_sparse_step`, …). Applying the expert stack to
        // every layer is the upper bound; under-counting experts is what produces a
        // false "fits comfortably".
        if intermediate > 0 {
            unresolved.push(
                "both intermediate_size and moe_intermediate_size are present but the dense/sparse \
                 layer split is not readable — every layer is counted as MoE (upper bound)"
                    .to_string(),
            );
        } else {
            inferred.push(
                "intermediate_size absent — every layer treated as MoE (no dense MLP)".to_string(),
            );
        }
        components.push(WeightComponent {
            category: WeightCategory::RoutedExperts,
            element_count: experts * 3 * hidden * moe_intermediate * layers,
            precision,
            is_hypothetical: false,
        });
        if shared_experts > 0 {
            components.push(WeightComponent {
                category: WeightCategory::SharedExperts,
                element_count: shared_experts * 3 * hidden * shared_intermediate * layers,
                precision,
                is_hypothetical: false,
            });
        }
        components.push(WeightComponent {
            category: WeightCategory::Routers,
            element_count: hidden * experts * layers,
            precision,
            is_hypothetical: false,
        });
    } else {
        if intermediate == 0 {
            unresolved.push(
                "no MLP width in the config (intermediate_size / moe_intermediate_size) — MLP \
                 parameters are omitted entirely, so the parameter count is a floor, not an estimate"
                    .to_string(),
            );
        }
        components.push(WeightComponent {
            category: WeightCategory::DenseMlp,
            element_count: 3 * hidden * intermediate * layers,
            precision,
            is_hypothetical: false,
        });
    }

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
        model_type: if is_moe {
            ModelType::Moe
        } else {
            ModelType::Unknown
        },
        dimensions: dims,
        attention_layers,
        moe: is_moe.then(|| MoeSpec {
            expert_count: experts as u32,
            active_experts_per_token: opt_u64(raw, "num_experts_per_tok").unwrap_or(1) as u32,
            expert_intermediate_size: moe_intermediate as u64,
            shared_expert_intermediate_size: (shared_experts > 0).then_some(shared_intermediate as u64),
            shared_expert_parameters: (shared_experts > 0)
                .then(|| shared_experts * 3 * hidden * shared_intermediate * layers),
        }),
        context: Context {
            native_maximum: opt_u64(raw, "max_position_embeddings").unwrap_or(4096),
            checkpoint_maximum: None,
            rope_scaling: raw.get("rope_scaling").cloned(),
        },
        weights,
        inferred,
        unresolved,
    })
}

pub fn normalize(raw: &Value) -> Result<NormalizedModel> {
    normalize_family(raw)
}
