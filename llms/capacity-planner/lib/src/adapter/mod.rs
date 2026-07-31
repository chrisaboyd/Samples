//! Architecture adapters (PRD §10.2).
//!
//! Each adapter converts a raw `config.json` blob into a [`NormalizedModel`].
//! Adapters return a *normalized* internal representation so downstream math
//! never keys off arbitrary model-specific field names, and they record which
//! fields were inferred (§248) so confidence can be scored.
//!
//! No adapter executes model code. `auto_map` / `trust_remote_code` references
//! are parsed as text only (PRD §10.3).

use serde_json::Value;

use crate::error::{CalcError, Result};
use crate::model::{
    AttentionKind, AttentionLayer, Dimensions, Identity, NormalizedModel, WeightComponent,
};
use crate::precision::{Precision, QuantizationMetadata};

pub mod generic;
pub mod laguna;
pub mod llama;
pub mod mixtral;

/// Entry point: dispatch on `model_type`, with safe fallbacks.
pub fn normalize(raw: &Value) -> Result<NormalizedModel> {
    let model_type = raw
        .get("model_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    match model_type.as_str() {
        "laguna" => laguna::normalize(raw),
        "mixtral" => mixtral::normalize(raw),
        "llama" => llama::normalize(raw),
        "qwen" | "qwen2" | "qwen2_moe" => generic::normalize(raw), // falls through generic decoder path
        _ => generic::normalize(raw),
    }
}

// ---- shared helpers ------------------------------------------------------

pub(crate) fn as_u64(v: &Value, key: &str) -> Result<u64> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| CalcError::MissingField(key.to_string()))
}

pub(crate) fn opt_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| x.as_u64())
}

pub(crate) fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

pub(crate) fn get_str(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CalcError::MissingField(key.to_string()))
}

/// Present a normalized identity from a raw config blob.
pub(crate) fn parse_identity(raw: &Value, model_type: &str) -> Identity {
    let arch_names: Vec<String> = raw
        .get("architectures")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let repository = raw
        .get("_repository_url")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .or_else(|| opt_str(raw, "repository"));
    Identity {
        repository,
        revision: opt_str(raw, "_commit_hash").or_else(|| opt_str(raw, "revision")),
        architecture_names: arch_names,
        model_type: model_type.to_string(),
    }
}

/// Map a raw `torch_dtype` to a [`Precision`]; flag when inferred.
pub(crate) fn parse_source_precision(raw: &Value, inferred: &mut Vec<String>) -> Precision {
    match opt_str(raw, "torch_dtype").as_deref() {
        Some("bfloat16") => Precision::Bf16,
        Some("float16") => Precision::Fp16,
        Some("float32") => Precision::Fp32,
        Some("float8_e4m3fn") | Some("fp8") | Some("float8") => Precision::Fp8,
        Some("int8") => Precision::Int8,
        Some("int4") => Precision::Int4,
        _ => {
            inferred.push("torch_dtype (defaulted to BF16)".to_string());
            Precision::Bf16
        }
    }
}

/// Build a confidence-bearing quantization marker from a hypothetical selection.
pub(crate) fn quantization_marker(
    precision: Precision,
    is_hypothetical: bool,
    group_size: u32,
) -> Option<QuantizationMetadata> {
    Some(QuantizationMetadata {
        flavor: precision.label().to_lowercase(),
        group_size: if matches!(precision, Precision::Nvfp4) {
            Some(group_size)
        } else {
            None
        },
        is_hypothetical,
    })
}

/// Standard decoder attention-layer decomposition. Detects full vs sliding
/// attention when a `sliding_window` field is present.
pub(crate) fn standard_attention_layers(raw: &Value) -> Vec<AttentionLayer> {
    let layers = as_u64(raw, "num_hidden_layers").unwrap_or(0) as u32;
    if let Some(w) = raw.get("sliding_window").and_then(|x| x.as_u64()) {
        // Assume all layers are sliding-window with the given window.
        vec![AttentionLayer {
            kind: AttentionKind::Sliding,
            count: layers,
            window_size: Some(w as u32),
        }]
    } else {
        vec![AttentionLayer {
            kind: AttentionKind::Full,
            count: layers,
            window_size: None,
        }]
    }
}

/// Standard dense-decoder dimension block.
pub(crate) fn standard_dimensions(raw: &Value, inferred: &mut Vec<String>) -> Result<Dimensions> {
    let hidden = as_u64(raw, "hidden_size")? as u64;
    let head_dim = opt_u64(raw, "head_dim").or_else(|| {
        // infer head_dim = hidden / heads when not given
        let heads = opt_u64(raw, "num_attention_heads")?;
        if heads == 0 {
            None
        } else {
            let d = (hidden as f64 / heads as f64) as u64;
            inferred.push("head_dim (inferred from hidden_size/heads)".to_string());
            Some(d)
        }
    });
    Ok(Dimensions {
        vocabulary_size: opt_u64(raw, "vocab_size"),
        hidden_size: hidden,
        intermediate_size: opt_u64(raw, "intermediate_size"),
        layer_count: as_u64(raw, "num_hidden_layers")? as u32,
        attention_heads: opt_u64(raw, "num_attention_heads").map(|v| v as u32),
        kv_heads: opt_u64(raw, "num_key_value_heads").map(|v| v as u32),
        head_dimension: head_dim.map(|v| v as u32),
    })
}

/// Build NN-VLM embedding/output categories. `tied` mirrors `tie_word_embeddings`
/// (PRD §29: "Untied or tied embeddings").
pub(crate) fn embedding_components(
    vocab: u128,
    hidden: u128,
    tied: bool,
    precision: Precision,
) -> Vec<WeightComponent> {
    let emb = vocab * hidden;
    let mut out = vec![WeightComponent {
        category: crate::precision::WeightCategory::Embeddings,
        element_count: emb,
        precision,
        is_hypothetical: false,
    }];
    if !tied {
        out.push(WeightComponent {
            category: crate::precision::WeightCategory::OutputHead,
            element_count: emb,
            precision,
            is_hypothetical: false,
        });
    }
    out
}
