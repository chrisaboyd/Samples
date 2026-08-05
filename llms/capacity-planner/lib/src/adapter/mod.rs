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
use crate::precision::{Precision, QuantizationMetadata, WeightCategory};
use crate::quant::CheckpointQuantization;

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

/// Describe what the checkpoint itself declares, falling back to the base dtype
/// when it declares nothing. Never hypothetical — this is what is on disk.
pub(crate) fn checkpoint_marker(
    quant: Option<&CheckpointQuantization>,
    base: Precision,
) -> Option<QuantizationMetadata> {
    match quant {
        Some(q) => Some(QuantizationMetadata {
            flavor: q.format.clone(),
            group_size: matches!(q.primary_precision(), Precision::Nvfp4).then(|| q.group_size()),
            is_hypothetical: false,
        }),
        None => quantization_marker(base, false, 16),
    }
}

/// Accumulates a model's tensors into `(category, precision)` buckets.
///
/// Adapters name each tensor as it is added (`model.layers.3.self_attn.q_proj`)
/// so the checkpoint's own `ignore`/`targets` rules decide that tensor's stored
/// precision. Tensors of the same category that resolve to different precisions
/// become separate [`WeightComponent`]s — which is how a checkpoint with NVFP4
/// experts in layers 1–39 and BF16 experts in 40–47 is represented without a
/// per-tensor explosion in the result payload.
///
/// Insertion order is preserved so derivations render deterministically.
pub(crate) struct ComponentBuilder<'a> {
    quant: Option<&'a CheckpointQuantization>,
    base: Precision,
    buckets: Vec<(WeightCategory, Precision, u128)>,
}

impl<'a> ComponentBuilder<'a> {
    pub(crate) fn new(quant: Option<&'a CheckpointQuantization>, base: Precision) -> Self {
        Self {
            quant,
            base,
            buckets: Vec::new(),
        }
    }

    /// Add `count` elements of a tensor at module path `module`.
    pub(crate) fn add(&mut self, category: WeightCategory, module: &str, count: u128) {
        if count == 0 {
            return;
        }
        let precision = match self.quant {
            Some(q) => q.precision_for(module, self.base),
            None => self.base,
        };
        match self
            .buckets
            .iter_mut()
            .find(|(c, p, _)| *c == category && *p == precision)
        {
            Some((_, _, n)) => *n += count,
            None => self.buckets.push((category, precision, count)),
        }
    }

    /// Add a tensor that no quantization scheme applies to (norms, biases).
    pub(crate) fn add_unquantized(&mut self, category: WeightCategory, count: u128) {
        if count == 0 {
            return;
        }
        match self
            .buckets
            .iter_mut()
            .find(|(c, p, _)| *c == category && *p == self.base)
        {
            Some((_, _, n)) => *n += count,
            None => self.buckets.push((category, self.base, count)),
        }
    }

    pub(crate) fn finish(self) -> Vec<WeightComponent> {
        self.buckets
            .into_iter()
            .map(|(category, precision, element_count)| WeightComponent {
                category,
                element_count,
                precision,
                is_hypothetical: false,
            })
            .collect()
    }
}

/// The declared sliding window, treating `0` the same as `null`.
///
/// HF configs spell "this model has no sliding window" both ways, and `0` is the
/// more dangerous spelling: taken literally it caps every sliding layer at
/// `min(S, 0)` tokens, which zeroes the KV cache and makes concurrency divide by
/// zero. A window of 0 attends to nothing, so it can only mean "disabled".
pub(crate) fn sliding_window(raw: &Value) -> Option<u32> {
    opt_u64(raw, "sliding_window")
        .filter(|&w| w > 0)
        .map(|w| w as u32)
}

/// Standard decoder attention-layer decomposition. Detects full vs sliding
/// attention when a `sliding_window` field is present.
pub(crate) fn standard_attention_layers(raw: &Value) -> Vec<AttentionLayer> {
    let layers = as_u64(raw, "num_hidden_layers").unwrap_or(0) as u32;
    if let Some(w) = sliding_window(raw) {
        // Assume all layers are sliding-window with the given window.
        vec![AttentionLayer {
            kind: AttentionKind::Sliding,
            count: layers,
            window_size: Some(w),
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

/// Add embedding / output-head categories. `tied` mirrors `tie_word_embeddings`
/// (PRD §29: "Untied or tied embeddings"). `lm_head` is the module name almost
/// every `ignore` list uses to keep the output head at full precision.
pub(crate) fn add_embeddings(b: &mut ComponentBuilder, vocab: u128, hidden: u128, tied: bool) {
    let emb = vocab * hidden;
    b.add(WeightCategory::Embeddings, "model.embed_tokens", emb);
    if !tied {
        b.add(WeightCategory::OutputHead, "lm_head", emb);
    }
}

/// Add the four standard attention projections for one layer.
///
/// `o_proj` maps `heads × head_dim → hidden`, which only equals `hidden × hidden`
/// when `heads × head_dim == hidden`. Models that over-project attention (a
/// per-layer head count above `hidden / head_dim`) have a correspondingly larger
/// `o_proj`, so the two dimensions are kept separate here.
pub(crate) fn add_attention_projections(
    b: &mut ComponentBuilder,
    layer: usize,
    hidden: u128,
    heads: u128,
    kv_heads: u128,
    head_dim: u128,
) {
    let prefix = format!("model.layers.{layer}.self_attn");
    let q_dim = heads * head_dim;
    let kv_dim = kv_heads * head_dim;
    b.add(
        WeightCategory::Attention,
        &format!("{prefix}.q_proj"),
        hidden * q_dim,
    );
    b.add(
        WeightCategory::Attention,
        &format!("{prefix}.k_proj"),
        hidden * kv_dim,
    );
    b.add(
        WeightCategory::Attention,
        &format!("{prefix}.v_proj"),
        hidden * kv_dim,
    );
    b.add(
        WeightCategory::Attention,
        &format!("{prefix}.o_proj"),
        q_dim * hidden,
    );
}

/// Add the three dense-MLP projections for one layer.
pub(crate) fn add_dense_mlp(
    b: &mut ComponentBuilder,
    layer: usize,
    hidden: u128,
    intermediate: u128,
) {
    let prefix = format!("model.layers.{layer}.mlp");
    for proj in ["gate_proj", "up_proj", "down_proj"] {
        b.add(
            WeightCategory::DenseMlp,
            &format!("{prefix}.{proj}"),
            hidden * intermediate,
        );
    }
}
