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

/// Elements covered by one FP8 block scale, and the width of that scale.
///
/// HF's native FP8 scheme declares `weight_block_size: [128, 128]`, so one FP32
/// `weight_scale_inv` covers a 128×128 tile. At 0.02% this is small next to the
/// weights, but it is inside the `total_size` a checkpoint reports, so leaving
/// it out puts a floor under how exact the analytic path can be.
const FP8_BLOCK_ELEMENTS: u64 = 128 * 128;
const FP8_SCALE_BYTES: f64 = 4.0;

/// Bytes for one weight component, including scale overhead when relevant.
/// PRD §12.2: NVFP4 "includes per-group FP8 scales rather than costing exactly
/// half a byte per parameter." FP8 block quantization carries the same kind of
/// overhead at coarser granularity.
pub fn component_bytes(component: &WeightComponent, nvfp4_group_size: u32) -> f64 {
    let base = (component.element_count as f64) * component.precision.bytes_per_element();
    let scale = match component.precision {
        Precision::Nvfp4 => {
            let group = nvfp4_group_size.max(1) as u64;
            // one FP8 (1 byte) scale per group
            let groups = (component.element_count as u64).div_ceil(group);
            groups as f64
        }
        // Block size is not taken from `nvfp4_group_size`: that is a workload
        // knob for the hypothetical-NVFP4 path, not the checkpoint's FP8 tile.
        Precision::Fp8 => {
            let blocks = (component.element_count as u64).div_ceil(FP8_BLOCK_ELEMENTS);
            blocks as f64 * FP8_SCALE_BYTES
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
        //
        // Checked against a real serve rather than fitted to it: a Laguna NVFP4
        // checkpoint holding 92.8354 GiB of tensor data loaded as 98.08 GiB
        // across TP=4, a whole-model factor of 1.0565. This constant is
        // per-precision and that checkpoint is only 53% NVFP4 by stored bytes,
        // so the two are not the same quantity — 1.07 here byte-weights to 1.037
        // and predicts 24.08 GiB/rank against 24.52 observed, 1.8% low.
        //
        // Closing that 1.8% by raising this to 1.106 would assume every byte of
        // overhead belongs to the NVFP4 tensors. It does not: allocator
        // alignment across 126,625 tensors is precision-independent, and the run
        // also had a speculative draft model whose weights may sit inside the
        // 98.08. One mixed checkpoint cannot separate those, so the constant
        // stays put and the measurement stands as a validation.
        Precision::Nvfp4 => 1.07,
        // INT8/INT4 dequantize up to BF16 for kernels that lack int compute.
        Precision::Int8 => 1.15,
        Precision::Int4 => 1.25,
    }
}

/// Byte-weighted load factor across a mixed-precision component set.
///
/// A checkpoint that is NVFP4 in its experts and BF16 everywhere else does not
/// pay the NVFP4 dequant-buffer penalty on the BF16 half, so applying a single
/// precision's factor to the whole model is wrong in both directions. Weighting
/// by stored bytes reduces to `load_factor(p)` when every component shares one
/// precision.
pub fn effective_load_factor(components: &[WeightComponent], nvfp4_group_size: u32) -> f64 {
    let mut total = 0.0;
    let mut weighted = 0.0;
    for c in components {
        let bytes = component_bytes(c, nvfp4_group_size);
        total += bytes;
        weighted += bytes * load_factor(c.precision);
    }
    if total == 0.0 {
        1.0
    } else {
        weighted / total
    }
}

/// Fraction of a component set's bytes that tensor parallelism replicates
/// rather than shards.
///
/// Returned as a fraction so it can be applied to a *measured* checkpoint total
/// from `model.safetensors.index.json`, which gives no per-category breakdown of
/// its own. The architecture-derived components supply the ratio, the index
/// supplies the magnitude.
pub fn replicated_fraction(components: &[WeightComponent], nvfp4_group_size: u32) -> f64 {
    let mut replicated = 0.0;
    let mut total = 0.0;
    for c in components {
        let bytes = component_bytes(c, nvfp4_group_size);
        total += bytes;
        if c.category.replicates_under_tp() {
            replicated += bytes;
        }
    }
    if total == 0.0 {
        0.0
    } else {
        replicated / total
    }
}

/// Per-GPU bytes for a whole-model byte total under tensor parallelism.
///
/// `sharded / tp + replicated`, rather than `total / tp`. Norms and routers are
/// copied onto every rank (see [`WeightCategory::replicates_under_tp`]), so the
/// flat divide understates every rank by `replicated × (1 - 1/tp)`. Small in
/// absolute terms and TP-invariant, which means its share of the per-GPU
/// footprint grows as TP widens.
pub fn per_rank_bytes(
    total_bytes: u128,
    components: &[WeightComponent],
    nvfp4_group_size: u32,
    tensor_parallel: u32,
) -> u128 {
    let tp = tensor_parallel.max(1);
    if tp == 1 {
        return total_bytes;
    }
    let total = total_bytes as f64;
    let replicated = total * replicated_fraction(components, nvfp4_group_size);
    ((total - replicated) / tp as f64 + replicated).floor() as u128
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
    let factor = effective_load_factor(&components, group_size);
    let loaded = (storage as f64 * factor) as u128;
    per_rank_bytes(loaded, &components, group_size, tensor_parallel)
}

/// Every distinct precision present, ordered by descending stored bytes.
///
/// Drives the checkpoint label: reporting a single precision for a checkpoint
/// that quantized only part of itself is how "Exact checkpoint — NVFP4" came to
/// sit above a number computed entirely in BF16.
pub fn precision_mix(
    components: &[WeightComponent],
    nvfp4_group_size: u32,
) -> Vec<(Precision, f64)> {
    let mut mix: Vec<(Precision, f64)> = Vec::new();
    for c in components {
        let bytes = component_bytes(c, nvfp4_group_size);
        match mix.iter_mut().find(|(p, _)| *p == c.precision) {
            Some((_, b)) => *b += bytes,
            None => mix.push((c.precision, bytes)),
        }
    }
    mix.sort_by(|a, b| b.1.total_cmp(&a.1));
    mix
}

/// Name the precision(s) a component set is stored in — `"NVFP4"` when uniform,
/// `"NVFP4 53% + BF16 47%"` when not.
///
/// Shares are of stored *bytes*, so a mostly-BF16 "NVFP4 checkpoint" cannot read
/// as uniformly NVFP4.
pub fn precision_summary(components: &[WeightComponent], nvfp4_group_size: u32) -> String {
    let mix = precision_mix(components, nvfp4_group_size);
    let total: f64 = mix.iter().map(|(_, b)| b).sum();
    // Norms are never quantizable, so even a uniform NVFP4 model carries a
    // fraction of a percent of BF16. Listing that as "BF16 0%" is noise; a
    // format has to hold a real share of the weights to be worth naming.
    let significant: Vec<_> = mix
        .iter()
        .filter(|(_, b)| total > 0.0 && b / total >= 0.005)
        .collect();
    match significant.as_slice() {
        [] => "unknown".to_string(),
        [(p, _)] => p.label().to_string(),
        many => many
            .iter()
            .map(|(p, b)| format!("{} {:.0}%", p.label(), b / total * 100.0))
            .collect::<Vec<_>>()
            .join(" + "),
    }
}

/// Label the figure a user is looking at: what precision(s) produced it, and
/// whether it describes the checkpoint or a hypothetical requantization.
pub fn checkpoint_label(
    is_hypothetical: bool,
    components: &[WeightComponent],
    nvfp4_group_size: u32,
) -> String {
    let described = precision_summary(components, nvfp4_group_size);
    if is_hypothetical {
        format!("Hypothetical quantization estimate — {described}")
    } else {
        format!("Exact checkpoint — {described}")
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

    /// The label must not claim a single precision for a checkpoint that
    /// quantized only part of itself — the failure mode that put
    /// "Exact checkpoint — NVFP4" above an all-BF16 number.
    #[test]
    fn label_names_every_significant_precision() {
        let mixed = [
            comp(WeightCategory::RoutedExperts, 8_000, Precision::Nvfp4),
            comp(WeightCategory::Attention, 2_000, Precision::Bf16),
        ];
        // NVFP4: 8000×0.5 + 500 scales = 4500 B. BF16: 2000×2 = 4000 B.
        assert_eq!(
            checkpoint_label(false, &mixed, 16),
            "Exact checkpoint — NVFP4 53% + BF16 47%"
        );
        assert_eq!(
            checkpoint_label(true, &mixed, 16),
            "Hypothetical quantization estimate — NVFP4 53% + BF16 47%"
        );
    }

    /// Norms can never be quantized, so a uniformly-NVFP4 estimate still carries
    /// a sliver of BF16. Naming it would read as a mixed checkpoint.
    #[test]
    fn label_ignores_sub_half_percent_slivers() {
        let nearly_uniform = [
            comp(WeightCategory::RoutedExperts, 1_000_000, Precision::Nvfp4),
            comp(WeightCategory::Norms, 100, Precision::Bf16),
        ];
        assert_eq!(
            checkpoint_label(false, &nearly_uniform, 16),
            "Exact checkpoint — NVFP4"
        );
    }

    /// A mixed checkpoint pays the NVFP4 dequant penalty only on its NVFP4
    /// bytes; applying one precision's factor to the whole model over-counts.
    #[test]
    fn load_factor_is_weighted_across_a_mixed_checkpoint() {
        let mixed = [
            comp(WeightCategory::RoutedExperts, 8_000, Precision::Nvfp4),
            comp(WeightCategory::Attention, 2_000, Precision::Bf16),
        ];
        let f = effective_load_factor(&mixed, 16);
        assert!(f > 1.0 && f < load_factor(Precision::Nvfp4), "got {f}");
        // 4500 B at the NVFP4 factor + 4000 B at 1.00, over 8500 B.
        let nvfp4 = load_factor(Precision::Nvfp4);
        assert!((f - (4500.0 * nvfp4 + 4000.0) / 8500.0).abs() < 1e-12);

        // Uniform sets must reduce to the plain per-precision factor.
        let uniform = [comp(WeightCategory::RoutedExperts, 8_000, Precision::Nvfp4)];
        assert_eq!(
            effective_load_factor(&uniform, 16),
            load_factor(Precision::Nvfp4)
        );
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

    #[test]
    fn replicated_weights_are_not_divided_by_tp() {
        // BF16 so no scale bytes muddy the arithmetic:
        // 1000 attention elements = 2000 B (shards),
        //  100 norm      elements =  200 B (replicates). Total 2200.
        let comps = vec![
            WeightComponent {
                category: WeightCategory::Attention,
                element_count: 1000,
                precision: Precision::Bf16,
                is_hypothetical: false,
            },
            WeightComponent {
                category: WeightCategory::Norms,
                element_count: 100,
                precision: Precision::Bf16,
                is_hypothetical: false,
            },
        ];
        assert!((replicated_fraction(&comps, 16) - 200.0 / 2200.0).abs() < 1e-9);

        // TP1 is the identity.
        assert_eq!(per_rank_bytes(2200, &comps, 16, 1), 2200);
        // TP4: 2000/4 + 200 = 700, against a flat divide's 550.
        assert_eq!(per_rank_bytes(2200, &comps, 16, 4), 700);
        // TP2: 2000/2 + 200 = 1200.
        assert_eq!(per_rank_bytes(2200, &comps, 16, 2), 1200);
    }

    #[test]
    fn a_model_without_replicated_categories_matches_a_flat_divide() {
        let comps = vec![WeightComponent {
            category: WeightCategory::Attention,
            element_count: 800,
            precision: Precision::Bf16,
            is_hypothetical: false,
        }];
        assert_eq!(replicated_fraction(&comps, 16), 0.0);
        assert_eq!(per_rank_bytes(1600, &comps, 16, 4), 400);
    }
}
