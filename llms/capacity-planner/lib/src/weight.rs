//! Weight-memory calculation (PRD §12).
//!
//! Two distinct outputs are reported (PRD §12.1):
//!   * `checkpoint_storage` — `Σ N_i * B_i + W_scales + W_metadata` at a chosen
//!     precision, exact; and
//!   * `loaded_weight` — an estimate of GPU-resident weight memory after engine
//!     repack/dequant, scaled by a conservative per-precision load factor
//!     (PRD §33 target: within 5–10%).
//!
//! Per PRD §12.2, hypothetical quantization is a *separate path* that reassigns
//! precision per [`WeightCategory`] and is flagged `is_hypothetical`. NVFP4 also
//! carries per-group FP8 scale overhead.

use crate::model::WeightComponent;
use crate::precision::Precision;
use crate::NormalizedModel;

/// Apply a selected precision to a model's weight components.
///
/// When `is_hypothetical` is true every *quantizable* category is reassigned to
/// `target` precision and flagged hypothetical; non-quantizable categories
/// (norms) keep their native precision. When false, components are left as-is
/// (the checkpoint's native precision), and `exact` quantization is implied.
pub fn reassign_precision(
    model: &NormalizedModel,
    target: Precision,
    is_hypothetical: bool,
    _group_size: u32,
) -> Vec<WeightComponent> {
    model
        .weights
        .components
        .iter()
        .map(|c| {
            let precision = if is_hypothetical && c.category.is_quantizable() {
                target
            } else {
                c.precision
            };
            WeightComponent {
                category: c.category,
                element_count: c.element_count,
                precision,
                is_hypothetical,
            }
        })
        .collect()
}

/// Bytes for one weight component, including NVFP4 scale overhead when relevant.
/// PRD §12.2: NVFP4 "includes per-group FP8 scales rather than costing exactly
/// half a byte per parameter."
pub fn component_bytes(component: &WeightComponent, nvfp4_group_size: u32) -> f64 {
    let base = (component.element_count as f64) * component.precision.bytes_per_element();
    let scale = match component.precision {
        Precision::Nvfp4 => {
            let group = nvfp4_group_size.max(1) as u64;
            // one FP8 (1 byte) scale per group
            let groups = (component.element_count as u64).div_ceil(group);
            groups as f64
        }
        _ => 0.0,
    };
    base + scale
}

/// Exact checkpoint storage bytes for a set of components (Σ N_i·B_i + scales),
/// before engine repack/dequant.
pub fn checkpoint_storage_bytes(components: &[WeightComponent], nvfp4_group_size: u32) -> u128 {
    components
        .iter()
        .map(|c| component_bytes(c, nvfp4_group_size))
        .sum::<f64>()
        .round() as u128
}

/// Exact parameter count from components (Σ N_i). Falls back to the model's
/// exact/estimated parameter count when components are absent.
pub fn parameter_count(model: &NormalizedModel) -> Option<u128> {
    if !model.weights.components.is_empty() {
        Some(
            model
                .weights
                .components
                .iter()
                .map(|c| c.element_count)
                .sum(),
        )
    } else {
        model.parameter_count()
    }
}

/// Conservative load-factor (engine repack / dequant / padding / comm buffers)
/// for converting checkpoint storage into *loaded* weight memory. These are
/// broad constants; the PRD intends them to be calibrated by benchmark (§17).
pub fn load_factor(precision: Precision) -> f64 {
    match precision {
        // No dequant needed; weights resident at storage width.
        Precision::Bf16 | Precision::Fp16 | Precision::Fp32 => 1.00,
        // FP8 resident storage; dequant-to-BF16 compute buffers not included here.
        Precision::Fp8 => 1.00,
        // NVFP4 requires a dequant buffer path.
        Precision::Nvfp4 => 1.07,
        // INT8/INT4 dequantize up to BF16 for kernels that lack int compute.
        Precision::Int8 => 1.15,
        Precision::Int4 => 1.25,
    }
}

/// Estimated loaded weight memory on one GPU rank, after TP sharding.
pub fn loaded_weight_bytes_per_rank(
    model: &NormalizedModel,
    target: Precision,
    is_hypothetical: bool,
    group_size: u32,
    tensor_parallel: u32,
) -> u128 {
    let components = reassign_precision(model, target, is_hypothetical, group_size);
    let storage = checkpoint_storage_bytes(&components, group_size);
    let factor = load_factor(target);
    let tp = (tensor_parallel.max(1)) as f64;
    ((storage as f64 * factor) / tp).floor() as u128
}

pub fn checkpoint_label(is_hypothetical: bool, precision: Precision) -> String {
    if is_hypothetical {
        format!("Hypothetical quantization estimate — {}", precision.label())
    } else {
        format!("Exact checkpoint — {}", precision.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precision::WeightCategory;

    fn comp(cat: WeightCategory, n: u128, p: Precision) -> WeightComponent {
        WeightComponent {
            category: cat,
            element_count: n,
            precision: p,
            is_hypothetical: false,
        }
    }

    #[test]
    fn nvfp4_scales_not_half_byte() {
        // 16 params NVFP4, group 16: weights 0.5*16=8 + 1 scale byte = 9
        let c = comp(WeightCategory::Attention, 16, Precision::Nvfp4);
        assert_eq!(component_bytes(&c, 16), 9.0);
        // vs exactly-half would be 8
        assert_ne!(component_bytes(&c, 16), 8.0);
    }

    #[test]
    fn bf16_checkpoint_bytes() {
        // 100 elements * 2 bytes = 200
        let c = comp(WeightCategory::DenseMlp, 100, Precision::Bf16);
        assert_eq!(component_bytes(&c, 16), 200.0);
    }

    #[test]
    fn hypothetical_reassigns_quantizable_only() {
        let m: NormalizedModel = serde_json::from_str(
            r#"{
              "identity": {"repository": null, "revision": null, "architectureNames": ["x"], "modelType": "laguna"},
              "modelType": "moe",
              "dimensions": {"hiddenSize": 64, "layerCount": 1},
              "attentionLayers": [],
              "moe": null,
              "context": {"nativeMaximum": 2048},
              "weights": {
                "components": [
                  {"category":"norms","elementCount":10,"precision":"bf16","isHypothetical":false},
                  {"category":"attention_projections","elementCount":100,"precision":"bf16","isHypothetical":false}
                ],
                "exactParameterCount": 110,
                "estimatedParameterCount": null,
                "sourcePrecision": "bfloat16",
                "quantization": null
              },
              "inferred": []
            }"#,
        )
        .unwrap();
        let reassigned = reassign_precision(&m, Precision::Nvfp4, true, 16);
        let att = reassigned
            .iter()
            .find(|c| c.category == WeightCategory::Attention)
            .unwrap();
        let norm = reassigned
            .iter()
            .find(|c| c.category == WeightCategory::Norms)
            .unwrap();
        assert_eq!(att.precision, Precision::Nvfp4);
        assert!(att.is_hypothetical);
        assert_eq!(norm.precision, Precision::Bf16); // norms not quantizable
        assert!(norm.is_hypothetical); // flag still propagates
    }
}
