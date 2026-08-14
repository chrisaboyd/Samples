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
//!   attention = q(H·heads_i·d) + k + v(H·kv·d each) + o_proj(heads_i·d·H)
//!             + g_proj(H·g_out) + q_norm/k_norm(d each)
//!   dense MLP = 3·H·I_dense            (gate + up + down)
//!   MoE layer = num_experts·(3·H·moeI)  routed
//!             + 3·H·sharedI           shared experts
//!             + H·num_experts          router logits
//!
//! Two shapes here are *not* the dense-decoder defaults, and both come from the
//! reference `modeling_laguna.py`:
//!
//!   * `o_proj = Linear(heads_i · head_dim, hidden)`. Laguna's sliding layers run
//!     72 heads × 128 = 9216 against a hidden size of 3072, so the usual
//!     `hidden × hidden` shortcut under-counts `o_proj` by 3× on those layers.
//!   * `g_proj = Linear(hidden, g_out)` — the attention output gate — where
//!     `g_out = heads_i` under `"gating": "per-head"` and `heads_i · head_dim`
//!     otherwise. It is absent when `gating` is `false`.

use serde_json::Value;

use crate::error::Result;
use crate::model::{
    AttentionKind, AttentionLayer, Context, Dimensions, ModelType, MoeSpec, NormalizedModel,
    Weights,
};
use crate::precision::WeightCategory;
use crate::quant::CheckpointQuantization;

use super::{
    add_attention_projections, add_dense_mlp, add_embeddings, as_u64, checkpoint_marker, opt_u64,
    parse_identity, parse_source_precision, sliding_window, ComponentBuilder,
};

/// Interpret the per-layer attention type list into grouped layers.
///
/// Only buckets that actually have layers are emitted. A zero-count bucket still
/// makes the returned vector non-empty, which would suppress the caller's
/// "no `layer_types`" fallback and leave the model with *no* KV-bearing layers at
/// all — a zero-byte KV cache, and a division by zero in concurrency.
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
    let mut layers = Vec::new();
    if full > 0 {
        layers.push(AttentionLayer {
            kind: AttentionKind::Full,
            count: full,
            window_size: None,
        });
    }
    if sliding > 0 {
        layers.push(AttentionLayer {
            kind: AttentionKind::Sliding,
            count: sliding,
            window_size: None,
        });
    }
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
    let window = sliding_window(raw);

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
        // Fallback when `layer_types` is absent or names nothing recognizable
        // (Laguna-M.1 carries only `mlp_layer_types`). Every layer is treated as
        // full attention — the KV upper bound.
        attention_layers = vec![AttentionLayer {
            kind: AttentionKind::Full,
            count: layer_count,
            window_size: None,
        }];
        inferred.push(format!(
            "attention pattern (no `layer_types`) — all {layer_count} layers treated as full \
             attention (KV upper bound)"
        ));
    }

    // What the checkpoint says it quantized. `None` for an unquantized
    // checkpoint; every tensor then keeps `precision`.
    let quantization = CheckpointQuantization::parse(raw, &mut inferred);

    // Attention output gating (`gating`/`gating_types`). `false` disables the
    // gate entirely; `"per-head"` emits one scalar per head, anything else
    // truthy emits one per channel.
    let gating = raw.get("gating");
    let gate_per_head = gating.and_then(|g| g.as_str()) == Some("per-head");
    let gate_enabled = !matches!(gating, None | Some(Value::Bool(false)));

    let mut builder = ComponentBuilder::new(quantization.as_ref(), precision);
    add_embeddings(&mut builder, vocab, hidden, tied);

    for i in 0..layer_count as usize {
        let heads_i = if i < head_per_layer.len() {
            head_per_layer[i]
        } else {
            as_u64(raw, "num_attention_heads")
                .map(|h| h as u128)
                .unwrap_or_else(|_| hidden / head_dim)
        };
        add_attention_projections(&mut builder, i, hidden, heads_i, kv_heads, head_dim);
        if gate_enabled {
            let gate_out = if gate_per_head {
                heads_i
            } else {
                heads_i * head_dim
            };
            builder.add(
                WeightCategory::Attention,
                &format!("model.layers.{i}.self_attn.g_proj"),
                hidden * gate_out,
            );
        }

        let mlp_type = if i < mlp_types.len() {
            mlp_types[i].as_str()
        } else {
            "sparse"
        };
        if mlp_type == "dense" {
            add_dense_mlp(&mut builder, i, hidden, dense_intermediate);
        } else {
            // Precision is resolved from expert 0 and applied to all
            // `num_experts`: compressed-tensors rules select by layer and
            // projection, never by expert index, so enumerating every expert
            // would cost 36k regex matches to reach the same answer.
            for proj in ["gate_proj", "up_proj", "down_proj"] {
                builder.add(
                    WeightCategory::RoutedExperts,
                    &format!("model.layers.{i}.mlp.experts.0.{proj}"),
                    num_experts * hidden * moe_intermediate,
                );
                if let Some(s) = shared_intermediate {
                    builder.add(
                        WeightCategory::SharedExperts,
                        &format!("model.layers.{i}.mlp.shared_expert.{proj}"),
                        hidden * s,
                    );
                }
            }
            builder.add(
                WeightCategory::Routers,
                &format!("model.layers.{i}.mlp.gate"),
                hidden * num_experts,
            );
            // `experts.e_score_correction_bias`: one bias per expert, for the
            // aux-loss-free load balancing this config selects with
            // `router_aux_loss_coef: 0.0`. Tiny, and always BF16, but it is in
            // the checkpoint, so omitting it stops the total short of exact.
            builder.add_unquantized(WeightCategory::Routers, num_experts);
        }
    }

    // RMSNorms: input + post-attention per layer, q_norm/k_norm (head_dim each)
    // inside every attention module, and one final norm.
    builder.add_unquantized(
        WeightCategory::Norms,
        (2 * layer_count as u128 + 1) * hidden + 2 * layer_count as u128 * head_dim,
    );

    let components = builder.finish();

    let dims = Dimensions {
        vocabulary_size: opt_u64(raw, "vocab_size"),
        hidden_size: hidden as u64,
        intermediate_size: Some(dense_intermediate as u64),
        layer_count,
        attention_heads: Some(as_u64(raw, "num_attention_heads")? as u32),
        kv_heads: Some(kv_heads as u32),
        head_dimension: Some(head_dim as u32),
    };

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
        quantization: checkpoint_marker(quantization.as_ref(), precision),
        // Not in config.json; filled in by the caller when an index was fetched.
        checkpoint_total_size_bytes: None,
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
        unresolved: Vec::new(),
        speculator: None,
    })
}

pub fn normalize(raw: &Value) -> Result<NormalizedModel> {
    normalize_family(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precision::{Precision, WeightCategory};

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
        // Hand calc: emb 616,562,688 + attn 2,803,138,560 + dense mlp 113,246,208
        // + routed (47 sparse layers) 113,548,197,888 + shared 443,547,648
        // + router 36,962,304 + e_score_correction_bias 12,032 + norms 310,272
        // = 117,561,977,600 (~117.56B).
        assert_eq!(p, 117_561_977_600);
    }

    /// `o_proj` maps `heads × head_dim → hidden`, not `hidden → hidden`. Laguna's
    /// 36 sliding layers run 72 heads × 128 = 9216 against `hidden_size` 3072, so
    /// treating `o_proj` as `hidden × hidden` under-counts it 3× on those layers
    /// — 803M parameters (1.5 GiB at BF16) missing from the model total.
    #[test]
    fn attention_uses_per_layer_head_counts_and_projection_shapes() {
        let m = normalize(&laguna()).unwrap();
        let att: u128 = m
            .weights
            .components
            .iter()
            .filter(|c| c.category == WeightCategory::Attention)
            .map(|c| c.element_count)
            .sum();
        // Σheads = 12×48 + 36×72 = 3168.
        //   q_proj  3072 × 3168 × 128 = 1,245,708,288
        //   o_proj  3168 × 128 × 3072 = 1,245,708,288  (not 48 × 3072² = 452,984,832)
        //   k+v     2 × 48 × 3072 × 8 × 128 =  301,989,888
        //   g_proj  3072 × 3168 (per-head gating) = 9,732,096
        assert_eq!(att, 2_803_138_560);
    }

    /// `"gating": "per-head"` emits one gate per head; the per-channel default
    /// emits `heads × head_dim`, which is 128× larger.
    #[test]
    fn gating_mode_sizes_the_attention_gate() {
        let per_head = normalize(&laguna()).unwrap().parameter_count().unwrap();

        let mut per_channel_cfg = laguna();
        per_channel_cfg["gating"] = serde_json::json!(true);
        let per_channel = normalize(&per_channel_cfg)
            .unwrap()
            .parameter_count()
            .unwrap();
        // g_proj grows from 3072×3168 to 3072×3168×128.
        assert_eq!(per_channel - per_head, 3072 * 3168 * 127);

        let mut ungated_cfg = laguna();
        ungated_cfg["gating"] = serde_json::json!(false);
        let ungated = normalize(&ungated_cfg).unwrap().parameter_count().unwrap();
        assert_eq!(per_head - ungated, 3072 * 3168);
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

    /// The public config plus the `quantization_config` an llm-compressor NVFP4
    /// run emits: routed experts quantized, everything else — attention,
    /// embeddings, lm_head, the layer-0 dense MLP, shared experts, routers, and
    /// the experts of the last 8 layers — left at BF16.
    fn laguna_nvfp4() -> Value {
        let mut cfg = laguna();
        cfg["quantization_config"] = serde_json::json!({
            "quant_method": "compressed-tensors",
            "format": "nvfp4-pack-quantized",
            "quantization_status": "compressed",
            "config_groups": {
                "group_0": {
                    "targets": ["re:.*experts\\.[0-9]+\\.(gate_proj|up_proj|down_proj)$"],
                    "weights": { "num_bits": 4, "type": "float", "group_size": 16 }
                }
            },
            "ignore": [
                "lm_head",
                "re:.*\\.self_attn\\.q_proj$",
                "re:.*\\.self_attn\\.k_proj$",
                "re:.*\\.self_attn\\.v_proj$",
                "re:.*\\.self_attn\\.o_proj$",
                "re:.*\\.self_attn\\.g_proj$",
                "re:.*\\.mlp\\.gate$",
                "model.layers.0.mlp.gate_proj",
                "model.layers.0.mlp.up_proj",
                "model.layers.0.mlp.down_proj",
                "re:.*\\.mlp\\.shared_expert\\.gate_proj$",
                "re:.*\\.mlp\\.shared_expert\\.up_proj$",
                "re:.*\\.mlp\\.shared_expert\\.down_proj$",
                "re:^model\\.layers\\.4[0-7]\\.mlp\\.experts(\\..*)?$"
            ]
        });
        cfg
    }

    /// A partially-quantized checkpoint must split its routed experts into two
    /// components, not report one global precision. Reading the format alone and
    /// applying NVFP4 to all 117.56B parameters is what produced a 61 GiB figure
    /// for a checkpoint that is 93 GiB on disk.
    #[test]
    fn nvfp4_ignore_list_splits_routed_experts_by_precision() {
        let m = normalize(&laguna_nvfp4()).unwrap();
        let routed: Vec<_> = m
            .weights
            .components
            .iter()
            .filter(|c| c.category == WeightCategory::RoutedExperts)
            .collect();
        assert_eq!(routed.len(), 2, "experts split across two precisions");

        let per_layer: u128 = 256 * 3 * 3072 * 1024;
        let quantized = routed
            .iter()
            .find(|c| c.precision == Precision::Nvfp4)
            .expect("layers 1–39 quantized");
        let untouched = routed
            .iter()
            .find(|c| c.precision == Precision::Bf16)
            .expect("layers 40–47 ignored");
        assert_eq!(quantized.element_count, 39 * per_layer);
        assert_eq!(untouched.element_count, 8 * per_layer);

        // Parameter count is a property of the architecture, so quantizing must
        // not change it — only the bytes those parameters occupy.
        assert_eq!(m.parameter_count().unwrap(), 117_561_977_600);
    }

    /// Everything the `ignore` list names stays at the checkpoint's base dtype.
    #[test]
    fn ignored_categories_stay_bf16() {
        let m = normalize(&laguna_nvfp4()).unwrap();
        for category in [
            WeightCategory::Attention,
            WeightCategory::Embeddings,
            WeightCategory::OutputHead,
            WeightCategory::DenseMlp,
            WeightCategory::SharedExperts,
            WeightCategory::Routers,
            WeightCategory::Norms,
        ] {
            let comps: Vec<_> = m
                .weights
                .components
                .iter()
                .filter(|c| c.category == category)
                .collect();
            assert!(!comps.is_empty(), "{category:?} missing");
            assert!(
                comps.iter().all(|c| c.precision == Precision::Bf16),
                "{category:?} should be untouched by the ignore list"
            );
        }
        let q = m.weights.quantization.as_ref().expect("marker present");
        assert_eq!(q.flavor, "nvfp4-pack-quantized");
        assert_eq!(q.group_size, Some(16));
        assert!(!q.is_hypothetical, "this is what the checkpoint is");
    }

    /// The same architecture, quantized and not, must differ only in bytes.
    #[test]
    fn quantization_shrinks_storage_without_changing_the_model() {
        use crate::weight::checkpoint_storage_bytes;
        let plain = normalize(&laguna()).unwrap();
        let quant = normalize(&laguna_nvfp4()).unwrap();
        assert_eq!(plain.parameter_count(), quant.parameter_count());

        let bytes = |m: &NormalizedModel| checkpoint_storage_bytes(&m.weights.components, 16);
        let (plain_bytes, quant_bytes) = (bytes(&plain), bytes(&quant));
        // BF16 throughout: 117.56B × 2 B.
        assert_eq!(plain_bytes, 117_561_977_600 * 2);
        // NVFP4 on 39 of 47 expert layers takes it to ~42% of the BF16 size.
        // A blanket NVFP4 reading — the bug — claims ~28%, because it also
        // shrinks the 22.5B parameters the checkpoint left alone.
        let ratio = quant_bytes as f64 / plain_bytes as f64;
        assert!(
            (0.42..0.43).contains(&ratio),
            "mixed-precision storage ratio was {ratio:.4}"
        );
    }
}
