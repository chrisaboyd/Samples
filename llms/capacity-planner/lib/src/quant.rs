//! Checkpoint quantization declared by `config.json` (PRD §12.1).
//!
//! A quantized checkpoint states its own format in `quantization_config`, and —
//! critically — states which tensors it did *not* quantize. Reading only
//! `torch_dtype` and painting the whole model one precision is wrong in both
//! directions: it under-counts a checkpoint whose attention/embeddings stay
//! BF16, and over-counts one whose experts are all NVFP4.
//!
//! The `compressed-tensors` scheme (the one llm-compressor emits) is expressed
//! as module-name rules:
//!
//! ```json
//! "config_groups": { "group_0": {
//!     "targets": ["re:.*experts\\.[0-9]+\\.(gate_proj|up_proj|down_proj)$"],
//!     "weights": { "num_bits": 4, "type": "float", "group_size": 16 } } },
//! "ignore": ["lm_head", "re:.*\\.self_attn\\.q_proj$", ...]
//! ```
//!
//! `ignore` wins over `targets`; anything matching neither keeps the
//! checkpoint's base dtype. [`CheckpointQuantization::precision_for`] answers
//! that question for one module path, which is what lets an adapter emit
//! mixed-precision weight components instead of a single global precision.

use regex::Regex;
use serde_json::Value;

use crate::precision::Precision;

/// One entry of a compressed-tensors `ignore` / `targets` list.
///
/// Entries are either a literal module path (`"lm_head"`,
/// `"model.layers.0.mlp.gate_proj"`), a `re:`-prefixed regex, or a torch class
/// name such as `"Linear"` that stands for "every module of this type".
#[derive(Debug)]
enum Rule {
    Literal(String),
    Pattern(Regex),
    /// A bare class name (`Linear`, `Conv1D`): matches every quantizable module.
    ClassName,
}

impl Rule {
    fn parse(entry: &str) -> Option<Self> {
        if let Some(expr) = entry.strip_prefix("re:") {
            // A malformed pattern is skipped rather than fatal: the rest of the
            // scheme still describes the checkpoint more accurately than
            // ignoring quantization entirely. The caller records it as inferred.
            return Regex::new(expr).ok().map(Rule::Pattern);
        }
        // Class names are capitalized identifiers with no module-path separator.
        if !entry.contains('.') && entry.chars().next().is_some_and(char::is_uppercase) {
            return Some(Rule::ClassName);
        }
        Some(Rule::Literal(entry.to_string()))
    }

    fn matches(&self, module: &str) -> bool {
        match self {
            Rule::Literal(name) => name == module,
            Rule::Pattern(re) => re.is_match(module),
            Rule::ClassName => true,
        }
    }
}

/// One `config_groups` entry: a precision plus the modules it applies to.
#[derive(Debug)]
struct QuantGroup {
    precision: Precision,
    group_size: u32,
    targets: Vec<Rule>,
}

/// The quantization a checkpoint declares for itself.
#[derive(Debug)]
pub struct CheckpointQuantization {
    /// Verbatim `format` string, e.g. `nvfp4-pack-quantized`.
    pub format: String,
    groups: Vec<QuantGroup>,
    ignore: Vec<Rule>,
}

/// Map compressed-tensors `num_bits` + `type` onto a [`Precision`].
fn precision_from(num_bits: u64, kind: &str) -> Option<Precision> {
    match (num_bits, kind) {
        (4, "float") => Some(Precision::Nvfp4),
        (8, "float") => Some(Precision::Fp8),
        (8, "int") => Some(Precision::Int8),
        (4, "int") => Some(Precision::Int4),
        _ => None,
    }
}

fn rules_from(value: Option<&Value>) -> Vec<Rule> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .filter_map(Rule::parse)
                .collect()
        })
        .unwrap_or_default()
}

impl CheckpointQuantization {
    /// Read `quantization_config` from a raw config blob.
    ///
    /// Returns `None` when the checkpoint declares no quantization (an
    /// unquantized checkpoint is not an error). Notes appended to `inferred`
    /// flow into the confidence grade, so a scheme we only partly understand
    /// never presents as an exact figure.
    pub fn parse(raw: &Value, inferred: &mut Vec<String>) -> Option<Self> {
        let cfg = raw.get("quantization_config")?.as_object()?;

        let method = cfg
            .get("quant_method")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let format = cfg
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or(method)
            .to_string();

        if method != "compressed-tensors" {
            inferred.push(format!(
                "quantization_config declares quant_method `{method}` \
                 (only `compressed-tensors` is parsed) — per-tensor precision \
                 not applied; weights are sized at the checkpoint's base dtype"
            ));
            return None;
        }

        let ignore = rules_from(cfg.get("ignore"));

        let mut groups = Vec::new();
        if let Some(config_groups) = cfg.get("config_groups").and_then(|v| v.as_object()) {
            // BTreeMap-ordered by serde_json's default; deterministic either way
            // because a module may match at most one group in practice.
            for (name, group) in config_groups {
                let weights = group.get("weights");
                let num_bits = weights
                    .and_then(|w| w.get("num_bits"))
                    .and_then(|v| v.as_u64());
                let kind = weights
                    .and_then(|w| w.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("float");
                let Some(precision) = num_bits.and_then(|b| precision_from(b, kind)) else {
                    inferred.push(format!(
                        "quantization_config.config_groups.{name} has an unrecognized \
                         weight format ({num_bits:?} bits, {kind}) — its tensors are \
                         sized at the checkpoint's base dtype"
                    ));
                    continue;
                };
                let group_size = weights
                    .and_then(|w| w.get("group_size"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(16) as u32;
                groups.push(QuantGroup {
                    precision,
                    group_size,
                    targets: rules_from(group.get("targets")),
                });
            }
        }

        if groups.is_empty() {
            inferred.push(
                "quantization_config declares no usable config_groups — weights are \
                 sized at the checkpoint's base dtype"
                    .to_string(),
            );
            return None;
        }

        Some(CheckpointQuantization {
            format,
            groups,
            ignore,
        })
    }

    /// Stored precision of one module, given the checkpoint's base dtype.
    ///
    /// `ignore` takes priority over `targets`, matching compressed-tensors:
    /// a module named in `ignore` stays at `base` even if a group targets it.
    pub fn precision_for(&self, module: &str, base: Precision) -> Precision {
        if self.ignore.iter().any(|r| r.matches(module)) {
            return base;
        }
        self.groups
            .iter()
            .find(|g| g.targets.iter().any(|r| r.matches(module)))
            .map(|g| g.precision)
            .unwrap_or(base)
    }

    /// Group size for the NVFP4 scale overhead. Groups in practice share one
    /// value; the first is used when they differ.
    pub fn group_size(&self) -> u32 {
        self.groups.first().map(|g| g.group_size).unwrap_or(16)
    }

    /// The compressed format the checkpoint is built around, for labelling and
    /// as the default compute precision. First group wins.
    pub fn primary_precision(&self) -> Precision {
        self.groups
            .first()
            .map(|g| g.precision)
            .unwrap_or(Precision::Bf16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape llm-compressor emits for an NVFP4 MoE checkpoint: routed
    /// experts quantized, attention / lm_head / a layer range left alone.
    fn nvfp4_config() -> Value {
        serde_json::json!({
            "quantization_config": {
                "quant_method": "compressed-tensors",
                "format": "nvfp4-pack-quantized",
                "config_groups": {
                    "group_0": {
                        "targets": ["re:.*experts\\.[0-9]+\\.(gate_proj|up_proj|down_proj)$"],
                        "weights": { "num_bits": 4, "type": "float", "group_size": 16 }
                    }
                },
                "ignore": [
                    "lm_head",
                    "re:.*\\.self_attn\\.q_proj$",
                    "model.layers.0.mlp.gate_proj",
                    "re:^model\\.layers\\.4[0-7]\\.mlp\\.experts(\\..*)?$"
                ]
            }
        })
    }

    fn parsed() -> CheckpointQuantization {
        CheckpointQuantization::parse(&nvfp4_config(), &mut Vec::new()).expect("parses")
    }

    #[test]
    fn targeted_experts_are_quantized() {
        let q = parsed();
        assert_eq!(
            q.precision_for("model.layers.7.mlp.experts.31.gate_proj", Precision::Bf16),
            Precision::Nvfp4
        );
        assert_eq!(q.group_size(), 16);
        assert_eq!(q.format, "nvfp4-pack-quantized");
    }

    /// The regression that made a 95 GiB checkpoint read as 61 GiB: a layer
    /// range excluded from quantization must stay at the base dtype even though
    /// its module names also match the `targets` pattern.
    #[test]
    fn ignored_layer_range_overrides_targets() {
        let q = parsed();
        assert_eq!(
            q.precision_for("model.layers.44.mlp.experts.3.up_proj", Precision::Bf16),
            Precision::Bf16
        );
        // ...while the same tensor one layer group down is quantized.
        assert_eq!(
            q.precision_for("model.layers.39.mlp.experts.3.up_proj", Precision::Bf16),
            Precision::Nvfp4
        );
    }

    #[test]
    fn untargeted_and_ignored_modules_keep_base_precision() {
        let q = parsed();
        // Ignored by regex.
        assert_eq!(
            q.precision_for("model.layers.2.self_attn.q_proj", Precision::Bf16),
            Precision::Bf16
        );
        // Ignored by literal name.
        assert_eq!(q.precision_for("lm_head", Precision::Bf16), Precision::Bf16);
        assert_eq!(
            q.precision_for("model.layers.0.mlp.gate_proj", Precision::Bf16),
            Precision::Bf16
        );
        // Matches no rule at all.
        assert_eq!(
            q.precision_for("model.embed_tokens", Precision::Bf16),
            Precision::Bf16
        );
    }

    #[test]
    fn absent_quantization_config_is_not_an_error() {
        let mut inferred = Vec::new();
        assert!(CheckpointQuantization::parse(&serde_json::json!({}), &mut inferred).is_none());
        assert!(inferred.is_empty());
    }

    /// An unrecognized scheme must degrade to "base dtype" *and* say so, rather
    /// than silently reporting a quantized checkpoint at full precision.
    #[test]
    fn unknown_quant_method_records_an_inference() {
        let mut inferred = Vec::new();
        let raw = serde_json::json!({
            "quantization_config": { "quant_method": "awq", "bits": 4 }
        });
        assert!(CheckpointQuantization::parse(&raw, &mut inferred).is_none());
        assert_eq!(inferred.len(), 1);
        assert!(inferred[0].contains("awq"));
    }

    #[test]
    fn fp8_and_int_schemes_map_to_their_precisions() {
        let mk = |bits: u64, kind: &str| {
            let raw = serde_json::json!({
                "quantization_config": {
                    "quant_method": "compressed-tensors",
                    "format": "float-quantized",
                    "config_groups": { "group_0": {
                        "targets": ["Linear"],
                        "weights": { "num_bits": bits, "type": kind, "group_size": 128 }
                    }},
                    "ignore": ["lm_head"]
                }
            });
            CheckpointQuantization::parse(&raw, &mut Vec::new())
                .expect("parses")
                .precision_for("model.layers.0.self_attn.q_proj", Precision::Bf16)
        };
        assert_eq!(mk(8, "float"), Precision::Fp8);
        assert_eq!(mk(8, "int"), Precision::Int8);
        assert_eq!(mk(4, "int"), Precision::Int4);
    }

    /// `"Linear"` is a torch class name, not a module path: it targets every
    /// quantizable module rather than a tensor literally called "Linear".
    #[test]
    fn class_name_target_matches_every_module() {
        let raw = serde_json::json!({
            "quantization_config": {
                "quant_method": "compressed-tensors",
                "format": "float-quantized",
                "config_groups": { "group_0": {
                    "targets": ["Linear"],
                    "weights": { "num_bits": 8, "type": "float", "group_size": 128 }
                }},
                "ignore": ["lm_head"]
            }
        });
        let q = CheckpointQuantization::parse(&raw, &mut Vec::new()).unwrap();
        assert_eq!(
            q.precision_for("model.layers.9.mlp.down_proj", Precision::Bf16),
            Precision::Fp8
        );
        assert_eq!(q.precision_for("lm_head", Precision::Bf16), Precision::Bf16);
    }
}
