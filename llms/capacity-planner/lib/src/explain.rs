//! Worked derivations for every published figure, plus the input values each
//! formula consumes.
//!
//! A number with no visible derivation is an assertion, not an estimate. Each
//! [`Derivation`] carries the symbolic formula, that same formula with this
//! scenario's numbers substituted in, and the result — built from the *same*
//! intermediate values the calculation used, so the shown math cannot drift
//! from the math that ran.
//!
//! [`InputFact`] is the complementary half: of the ~40 keys a `config.json`
//! carries, only a handful reach the formulas. This lists exactly those, with
//! the originating key and the symbol each one feeds.

use serde::{Deserialize, Serialize};

use crate::hardware::Gpu;
use crate::memory::Workload;
use crate::model::{AttentionKind, NormalizedModel, WeightComponent};
use crate::precision::WeightCategory;
use crate::GIB_BYTES;

/// One published figure, shown as formula → substitution → result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Derivation {
    /// Stable key the UI attaches to a specific displayed figure.
    pub id: String,
    /// Display name of the figure being derived.
    pub label: String,
    /// What the number represents, in plain language.
    pub meaning: String,
    /// Symbolic formula.
    pub formula: String,
    /// The formula with this scenario's values substituted. May be multi-line.
    pub substitution: String,
    /// Final value with its unit.
    pub result: String,
}

/// One input value that actually reaches a formula.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InputFact {
    /// "Model", "GPU", "Workload", or "Engine" — for grouping in the UI.
    pub group: String,
    pub name: String,
    /// Originating `config.json` key, when the value came from one.
    pub key: Option<String>,
    pub value: String,
    /// The formula symbol(s) this value feeds.
    pub used_for: String,
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Thousands separators. Substituted values are meant to be read by a human
/// checking arithmetic, and `843055104` is not readable at a glance.
pub(crate) fn commas(n: u128) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub(crate) fn gib(bytes: u128) -> f64 {
    bytes as f64 / GIB_BYTES as f64
}

/// GiB with 2 decimals, e.g. "124.83 GiB".
pub(crate) fn gib_s(bytes: u128) -> String {
    format!("{:.2} GiB", gib(bytes))
}

/// GiB with enough precision to stay non-zero for small KV footprints.
pub(crate) fn gib_precise(bytes: u128) -> String {
    let v = gib(bytes);
    if v >= 10.0 {
        format!("{v:.2} GiB")
    } else if v >= 0.1 {
        format!("{v:.3} GiB")
    } else {
        format!("{v:.5} GiB")
    }
}

/// Auto-scaled byte size. Per-step byte terms span from a few KiB of activations
/// to tens of GiB of weights, so a fixed GiB unit renders half of them as 0.00.
pub fn bytes_h(bytes: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let a = bytes.abs();
    if a >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if a >= MIB {
        format!("{:.2} MiB", bytes / MIB)
    } else if a >= KIB {
        format!("{:.2} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

/// Engineering-suffixed magnitude for parameter counts and FLOPs.
pub(crate) fn big(x: f64) -> String {
    let a = x.abs();
    if a >= 1e12 {
        format!("{:.2}T", x / 1e12)
    } else if a >= 1e9 {
        format!("{:.2}B", x / 1e9)
    } else if a >= 1e6 {
        format!("{:.2}M", x / 1e6)
    } else if a >= 1e3 {
        format!("{:.1}K", x / 1e3)
    } else {
        format!("{x:.0}")
    }
}

fn category_label(c: WeightCategory) -> &'static str {
    match c {
        WeightCategory::Attention => "attention projections",
        WeightCategory::DenseMlp => "dense MLP",
        WeightCategory::RoutedExperts => "routed experts",
        WeightCategory::SharedExperts => "shared experts",
        WeightCategory::Embeddings => "embeddings",
        WeightCategory::OutputHead => "output head",
        WeightCategory::Norms => "norms",
        WeightCategory::Routers => "routers",
        WeightCategory::Biases => "biases",
    }
}

pub(crate) fn d(
    id: &str,
    label: &str,
    meaning: &str,
    formula: &str,
    substitution: String,
    result: String,
) -> Derivation {
    Derivation {
        id: id.to_string(),
        label: label.to_string(),
        meaning: meaning.to_string(),
        formula: formula.to_string(),
        substitution,
        result,
    }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Every intermediate value the memory chain produced, captured at the point
/// the calculation produced it.
pub struct ExplainContext<'a> {
    pub model: &'a NormalizedModel,
    pub gpu: &'a Gpu,
    pub workload: &'a Workload,
    pub gpu_count: u32,
    pub tp: u32,
    pub utilization: f64,
    pub block_tokens: u32,

    pub physical_bytes: u128,
    pub available_bytes: u128,
    /// Weight components after precision reassignment (what was actually summed).
    pub components: Vec<WeightComponent>,
    pub checkpoint_bytes: u128,
    pub load_factor: f64,
    pub loaded_per_rank: u128,
    pub runtime_bytes: u128,
    /// The PRD §14 coefficients behind `runtime_bytes`, so the derivation can
    /// show which term dominates rather than a single opaque reserve.
    pub runtime: crate::runtime::RuntimeMemory,
    pub draft_bytes: u128,
    pub free_for_kv: u128,

    pub kv_avg_exact: u128,
    pub kv_avg_rounded: u128,
    pub kv_max_exact: u128,
    pub kv_max_rounded: u128,
    pub full_layers: u32,
    pub sliding_layers: u32,
    pub sliding_window: Option<u32>,

    /// Per replica (one TP group).
    pub c_avg: u64,
    pub c_max: u64,
    /// Replica count, so the derivations can show where the cluster-wide
    /// figures come from rather than silently comparing mismatched units.
    pub replicas: u64,
    pub c_slo: u64,
    pub c_comfortable: u64,
    pub compute_peak_tflops: f64,
}

// ---------------------------------------------------------------------------
// Memory + concurrency derivations
// ---------------------------------------------------------------------------

/// The memory-fit chain, in dependency order: physical VRAM → allocatable →
/// weights → free-for-KV → KV per sequence → concurrency.
pub fn memory_derivations(c: &ExplainContext) -> Vec<Derivation> {
    let w = c.workload;
    let kv_b = w.kv_precision.bytes_per_element();
    let mut out = Vec::new();

    out.push(d(
        "m-physical",
        "Physical VRAM per GPU",
        "What the driver reports the card has, which is not the number on the \
         box. NVIDIA overprovisions each part so it can retire bad memory cells \
         over its service life, by ~0.6% on Ada-class cards and ~7% on HBM and \
         GDDR7 ones, so no arithmetic gets you from the marketed figure to this \
         one. It is read from the catalog, measured per SKU.",
        "M_physical = nvidia-smi memory.total",
        format!(
            "{} reports {} MiB\n= {} bytes  (marketed as {} GB)",
            c.gpu.sku,
            commas(c.physical_bytes / (1024 * 1024)),
            commas(c.physical_bytes),
            c.gpu.memory_marketed_gb,
        ),
        gib_s(c.physical_bytes),
    ));

    out.push(d(
        "m-available",
        "Allocatable VRAM per GPU",
        "How much of the card the inference engine is allowed to claim. The \
         remainder is left to the driver and fragmentation headroom, so the \
         engine never runs the card to its literal limit.",
        "M_available = M_physical × U",
        format!(
            "{} × {:.2}\n(U = memory utilization ceiling, {} catalog default)",
            gib_s(c.physical_bytes),
            c.utilization,
            c.gpu.sku
        ),
        gib_s(c.available_bytes),
    ));

    // Per-component checkpoint breakdown: this is literally the sum the
    // calculation performed, one line per weight category.
    let mut lines = Vec::new();
    for comp in &c.components {
        let base = comp.element_count as f64 * comp.precision.bytes_per_element();
        let scales = if comp.precision == crate::precision::Precision::Nvfp4 {
            (comp.element_count as u64).div_ceil(w.nvfp4_group_size.max(1) as u64) as f64
        } else {
            0.0
        };
        let scale_note = if scales > 0.0 {
            format!(" + {} scale bytes", big(scales))
        } else {
            String::new()
        };
        lines.push(format!(
            "  {:<22} {:>9} × {} B ({}){} = {}",
            category_label(comp.category),
            big(comp.element_count as f64),
            comp.precision.bytes_per_element(),
            comp.precision.label().to_lowercase(),
            scale_note,
            gib_precise((base + scales) as u128),
        ));
    }
    let total_params: u128 = c.components.iter().map(|x| x.element_count).sum();
    out.push(d(
        "m-checkpoint",
        "Checkpoint storage",
        "On-disk size of the weights at the selected precision — what you would \
         download. NVFP4 is not exactly half a byte per parameter: each group of \
         weights carries an extra FP8 scale byte.",
        "M_checkpoint = sum over components of  N × bytes(P)  +  ceil(N / G) scale bytes for NVFP4",
        format!(
            "{}\n  {:<22} {:>9} params{:>28}",
            lines.join("\n"),
            "total",
            big(total_params as f64),
            gib_s(c.checkpoint_bytes)
        ),
        gib_s(c.checkpoint_bytes),
    ));

    out.push(d(
        "m-weights",
        "Weights resident per GPU",
        "VRAM the model parameters occupy once loaded. Larger than the checkpoint \
         because the engine needs repack/dequantization buffers, and divided by TP \
         because tensor parallelism splits the model across ranks.",
        "M_weights = M_checkpoint × loadFactor(P_weight) / TP",
        format!(
            "{} × {:.2} / {}\n(load factor {:.2} for {}; TP = {})",
            gib_s(c.checkpoint_bytes),
            c.load_factor,
            c.tp,
            c.load_factor,
            w.weight_precision.label(),
            c.tp
        ),
        gib_s(c.loaded_per_rank),
    ));

    out.push(d(
        "m-runtime",
        "Runtime memory per GPU",
        "Everything the engine holds that is neither weights nor KV blocks: the \
         CUDA context, allocator, compiled kernels, captured CUDA graphs and \
         collective buffers, plus the transient activations of the widest \
         scheduler step and the logits and sampling buffers for every running \
         sequence. Held back before any KV cache is budgeted.",
        "M_runtime = M_fixed + M_token × N_scheduledTokens + M_sequence × N_runningSequences",
        format!(
            "{} fixed ({} catalog reserve + CUDA graphs{})\n\
             + {}/token × {} scheduled tokens = {}\n\
             + {}/seq × {} running sequences = {}\n\
             ({} profile, ×{:.2})",
            gib_s(c.runtime.fixed_bytes),
            c.gpu.sku,
            if c.tp > 1 { " + collectives" } else { "" },
            bytes_h(c.runtime.per_token_bytes as f64),
            commas(c.workload.max_num_batched_tokens as u128),
            gib_s(
                c.runtime
                    .per_token_bytes
                    .saturating_mul(c.workload.max_num_batched_tokens as u128)
            ),
            bytes_h(c.runtime.per_sequence_bytes as f64),
            commas(c.workload.max_num_seqs as u128),
            gib_s(
                c.runtime
                    .per_sequence_bytes
                    .saturating_mul(c.workload.max_num_seqs as u128)
            ),
            c.workload.memory_profile.label(),
            c.workload.memory_profile.factor(),
        ),
        gib_s(c.runtime_bytes),
    ));

    out.push(d(
        "m-free",
        "Free for KV cache",
        "What is left on each GPU after weights and runtime overhead. This is the \
         entire budget available to hold conversation context for concurrent \
         requests — it is what caps concurrency.",
        "M_freeForKV = M_available - M_weights - M_runtime - M_draft",
        format!(
            "{} - {} - {} - {}",
            gib_s(c.available_bytes),
            gib_s(c.loaded_per_rank),
            gib_s(c.runtime_bytes),
            gib_s(c.draft_bytes)
        ),
        gib_s(c.free_for_kv),
    ));

    out.push(kv_derivation(
        c,
        "kv-avg",
        "KV cache per sequence @ average context",
        "Memory one in-flight request holds to keep its attention cache at the \
         average context length. Every concurrent request pays this.",
        w.avg_context_tokens,
        c.kv_avg_exact,
        c.kv_avg_rounded,
        kv_b,
    ));

    out.push(kv_derivation(
        c,
        "kv-max",
        "KV cache per sequence @ maximum context",
        "The same cost for a request that has filled the context window — the \
         worst case a single request can cost.",
        w.max_context_tokens,
        c.kv_max_exact,
        c.kv_max_rounded,
        kv_b,
    ));

    out.push(d(
        "c-mem-avg",
        "Concurrent requests @ avg context",
        "How many requests fit in VRAM at once if each holds an average-length \
         context. A pure memory limit — it ignores whether the GPU is fast \
         enough to serve them within your latency target.",
        "C_memory(avg) = floor( M_freeForKV / KV_seq(avg) ) × replicas",
        format!(
            "floor( {} / {} )\n= floor( {} bytes / {} bytes )\n= {} per replica × {} replica(s)",
            gib_s(c.free_for_kv),
            gib_precise(c.kv_avg_rounded),
            commas(c.free_for_kv),
            commas(c.kv_avg_rounded),
            c.c_avg,
            c.replicas
        ),
        format!("{} concurrent requests", c.c_avg.saturating_mul(c.replicas)),
    ));

    out.push(d(
        "c-mem-max",
        "Concurrent requests @ max context",
        "The same count in the worst case, where every concurrent request has \
         filled the full context window simultaneously. Usually much smaller — \
         it is the floor under which the deployment cannot be starved.",
        "C_memory(max) = floor( M_freeForKV / KV_seq(max) ) × replicas",
        format!(
            "floor( {} / {} )\n= floor( {} bytes / {} bytes )\n= {} per replica × {} replica(s)",
            gib_s(c.free_for_kv),
            gib_precise(c.kv_max_rounded),
            commas(c.free_for_kv),
            commas(c.kv_max_rounded),
            c.c_max,
            c.replicas
        ),
        format!("{} concurrent requests", c.c_max.saturating_mul(c.replicas)),
    ));

    out.push(d(
        "c-comfortable",
        "Comfortable active requests",
        "The headline number: requests that can be in flight at the same time \
         while still meeting your latency target. It is the tightest of the three \
         limits — running out of memory and missing the SLO are both failures, so \
         the smallest one governs.",
        "C_comfortable = min( C_memory(avg), C_memory(max), C_SLO )   [all cluster-wide]",
        format!(
            "min( {}, {}, {} )\n  C_memory(avg) = {} — memory at average context ({} per replica × {})\n  \
             C_memory(max) = {} — memory at full context ({} per replica × {})\n  C_SLO         = {} — \
             latency target of {:.1} s",
            c.c_avg.saturating_mul(c.replicas),
            c.c_max.saturating_mul(c.replicas),
            c.c_slo,
            c.c_avg.saturating_mul(c.replicas),
            c.c_avg,
            c.replicas,
            c.c_max.saturating_mul(c.replicas),
            c.c_max,
            c.replicas,
            c.c_slo,
            w.slo_target_seconds
        ),
        format!("{} concurrent requests", c.c_comfortable),
    ));

    out
}

/// KV-per-sequence share the same formula at average and maximum context; only
/// the sequence length `s` and the resulting byte counts differ.
#[allow(clippy::too_many_arguments)]
fn kv_derivation(
    c: &ExplainContext,
    id: &str,
    label: &str,
    meaning: &str,
    s: u64,
    exact: u128,
    rounded: u128,
    kv_b: f64,
) -> Derivation {
    let w = c.workload;
    let kv_heads = c.model.dimensions.kv_heads.unwrap_or(0).max(1);
    let head_dim = c.model.dimensions.head_dimension.unwrap_or(0).max(1);
    let window = c.sliding_window.unwrap_or(s as u32) as u64;
    let eff_window = s.min(window);
    let full_tokens = c.full_layers as u64 * s;
    let sliding_tokens = c.sliding_layers as u64 * eff_window;

    let sliding_part = if c.sliding_layers > 0 {
        format!(
            " + {} × min({}, {})",
            c.sliding_layers,
            commas(s as u128),
            commas(window as u128)
        )
    } else {
        String::new()
    };

    let rounding_note = if rounded > exact {
        format!(
            "\nrounded up to whole {}-token vLLM blocks: {} → {} bytes",
            c.block_tokens,
            commas(exact),
            commas(rounded)
        )
    } else {
        format!(
            "\nalready block-aligned ({}-token vLLM blocks)",
            c.block_tokens
        )
    };

    d(
        id,
        label,
        meaning,
        "KV_seq = 2 × H_kv × D_head × B_kv × (L_full × S + L_sliding × min(S, W)) / TP",
        format!(
            "2 × {} × {} × {} B ({}) × ({} × {}{}) / {}\n= 2 × {} × {} × {} × ({}) / {}\n= {} bytes exact{}",
            kv_heads,
            head_dim,
            kv_b,
            w.kv_precision.label().to_lowercase(),
            c.full_layers,
            commas(s as u128),
            sliding_part,
            c.tp,
            kv_heads,
            head_dim,
            kv_b,
            commas((full_tokens + sliding_tokens) as u128),
            c.tp,
            commas(exact),
            rounding_note,
        ),
        gib_precise(rounded),
    )
}

// ---------------------------------------------------------------------------
// Input facts
// ---------------------------------------------------------------------------

fn fact(group: &str, name: &str, key: Option<&str>, value: String, used_for: &str) -> InputFact {
    InputFact {
        group: group.to_string(),
        name: name.to_string(),
        key: key.map(str::to_string),
        value,
        used_for: used_for.to_string(),
    }
}

/// The subset of the model config, GPU catalog, and workload settings that
/// actually reaches a formula. Everything else in `config.json` is ignored.
pub fn input_facts(c: &ExplainContext) -> Vec<InputFact> {
    let m = c.model;
    let dim = &m.dimensions;
    let w = c.workload;
    let mut f = Vec::new();

    // --- Model (config.json) ---
    f.push(fact(
        "Model",
        "Architecture",
        Some("model_type"),
        m.identity.model_type.clone(),
        "adapter selection",
    ));
    if let Some(p) = m.parameter_count() {
        let exact = m.weights.exact_parameter_count.is_some();
        f.push(fact(
            "Model",
            "Total parameters",
            None,
            format!(
                "{} ({})",
                big(p as f64),
                if exact { "exact" } else { "estimated" }
            ),
            "M_checkpoint, FLOPs/token",
        ));
    }
    f.push(fact(
        "Model",
        "Hidden size",
        Some("hidden_size"),
        commas(dim.hidden_size as u128),
        "activation traffic",
    ));
    f.push(fact(
        "Model",
        "Layers",
        Some("num_hidden_layers"),
        dim.layer_count.to_string(),
        "activation traffic",
    ));
    if let Some(v) = dim.vocabulary_size {
        f.push(fact(
            "Model",
            "Vocabulary size",
            Some("vocab_size"),
            commas(v as u128),
            "embedding + output-head parameters",
        ));
    }
    if let Some(v) = dim.intermediate_size {
        f.push(fact(
            "Model",
            "MLP intermediate size",
            Some("intermediate_size"),
            commas(v as u128),
            "dense MLP parameters",
        ));
    }
    if let Some(v) = dim.attention_heads {
        f.push(fact(
            "Model",
            "Query heads",
            Some("num_attention_heads"),
            v.to_string(),
            "H_q — attention-score FLOPs",
        ));
    }
    f.push(fact(
        "Model",
        "KV heads",
        Some("num_key_value_heads"),
        dim.kv_heads
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        "H_kv — KV_seq",
    ));
    f.push(fact(
        "Model",
        "Head dimension",
        Some("head_dim"),
        dim.head_dimension
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        "D_head — KV_seq",
    ));

    // Attention composition drives L_full / L_sliding, the single biggest lever
    // on KV size for hybrid models.
    for layer in &m.attention_layers {
        let kind = match layer.kind {
            AttentionKind::Full => "full attention",
            AttentionKind::Sliding => "sliding-window attention",
            AttentionKind::Local => "local attention",
            AttentionKind::Mla => "MLA (counted as full)",
            AttentionKind::Ssm => "SSM / recurrent (no KV cache)",
        };
        let window = layer
            .window_size
            .map(|v| format!(", window {}", commas(v as u128)))
            .unwrap_or_default();
        f.push(fact(
            "Model",
            kind,
            Some("layer_types"),
            format!("{} layers{}", layer.count, window),
            "L_full / L_sliding / W — KV_seq",
        ));
    }
    if let Some(moe) = &m.moe {
        f.push(fact(
            "Model",
            "Experts",
            Some("num_experts"),
            commas(moe.expert_count as u128),
            "E — expert activation fraction",
        ));
        f.push(fact(
            "Model",
            "Active experts per token",
            Some("num_experts_per_tok"),
            moe.active_experts_per_token.to_string(),
            "k — active parameters, weight bytes per step",
        ));
    }
    if let Some(src) = &m.weights.source_precision {
        f.push(fact(
            "Model",
            "Checkpoint precision",
            Some("torch_dtype"),
            src.clone(),
            "native weight precision",
        ));
    }
    f.push(fact(
        "Model",
        "Native context window",
        Some("max_position_embeddings"),
        commas(m.context.native_maximum as u128),
        "reference only — not a calculation input",
    ));

    // --- GPU (catalog) ---
    f.push(fact(
        "GPU",
        "SKU",
        None,
        format!("{} × {}", c.gpu_count, c.gpu.sku),
        "hardware figures below",
    ));
    f.push(fact(
        "GPU",
        "Marketed memory",
        None,
        format!("{} GB", c.gpu.memory_marketed_gb),
        "M_physical",
    ));
    f.push(fact(
        "GPU",
        "Memory utilization ceiling",
        None,
        format!("{:.0}%", c.utilization * 100.0),
        "U — M_available",
    ));
    f.push(fact(
        "GPU",
        "Runtime reserve",
        None,
        gib_s(c.runtime_bytes),
        "M_runtime",
    ));
    f.push(fact(
        "GPU",
        "Memory bandwidth",
        None,
        format!("{} GB/s", commas(c.gpu.memory_bandwidth_gbs as u128)),
        "BW — decode/prefill roofline",
    ));
    f.push(fact(
        "GPU",
        "Compute peak",
        None,
        format!(
            "{} TFLOPS @ {}",
            commas(c.compute_peak_tflops as u128),
            w.weight_precision.label()
        ),
        "Compute — roofline",
    ));

    // --- Workload (user input) ---
    f.push(fact(
        "Workload",
        "Tensor parallel",
        None,
        c.tp.to_string(),
        "TP — divides weights and KV",
    ));
    f.push(fact(
        "Workload",
        "Data-parallel replicas",
        None,
        (c.gpu_count / c.tp.max(1)).max(1).to_string(),
        "DP — C_SLO, aggregate throughput",
    ));
    f.push(fact(
        "Workload",
        "Average context",
        None,
        format!("{} tokens", commas(w.avg_context_tokens as u128)),
        "S — KV_seq(avg), attention FLOPs",
    ));
    f.push(fact(
        "Workload",
        "Maximum context",
        None,
        format!("{} tokens", commas(w.max_context_tokens as u128)),
        "S — KV_seq(max)",
    ));
    f.push(fact(
        "Workload",
        "Average output tokens",
        None,
        commas(w.avg_output_tokens as u128),
        "N_out — C_SLO",
    ));
    f.push(fact(
        "Workload",
        "Latency target",
        None,
        format!("{:.1} s", w.slo_target_seconds),
        "target — C_SLO",
    ));
    f.push(fact(
        "Workload",
        "Weight precision",
        None,
        format!(
            "{}{}",
            w.weight_precision.label(),
            if w.is_hypothetical_weight {
                " (hypothetical)"
            } else {
                " (as checkpointed)"
            }
        ),
        "P_weight — M_checkpoint, compute peak",
    ));
    f.push(fact(
        "Workload",
        "KV-cache precision",
        None,
        w.kv_precision.label().to_string(),
        "B_kv — KV_seq",
    ));

    // --- Engine constants ---
    f.push(fact(
        "Engine",
        "KV block size",
        None,
        format!("{} tokens", c.block_tokens),
        "KV_seq rounding",
    ));
    f.push(fact(
        "Engine",
        "Weight load factor",
        None,
        format!("{:.2}×", c.load_factor),
        "M_weights",
    ));
    if w.weight_precision == crate::precision::Precision::Nvfp4 {
        f.push(fact(
            "Engine",
            "NVFP4 group size",
            None,
            format!("{} weights per FP8 scale", w.nvfp4_group_size),
            "G — M_checkpoint scale bytes",
        ));
    }
    f.push(fact(
        "Engine",
        "Bandwidth efficiency tiers",
        None,
        "40% / 55% / 70% of peak".to_string(),
        "pessimistic / expected / optimistic ranges",
    ));
    f.push(fact(
        "Engine",
        "Compute efficiency tiers",
        None,
        "30% / 50% / 65% of peak".to_string(),
        "pessimistic / expected / optimistic ranges",
    ));

    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commas_groups_by_three() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1_000), "1,000");
        assert_eq!(commas(843_055_104), "843,055,104");
    }

    #[test]
    fn big_uses_engineering_suffixes() {
        assert_eq!(big(4.5e11), "450.00B");
        assert_eq!(big(1.2e12), "1.20T");
        assert_eq!(big(512.0), "512");
    }

    /// Small KV footprints must not render as "0.00 GiB" — the whole point of
    /// showing the substitution is that the reader can check the division.
    #[test]
    fn gib_precise_keeps_small_values_visible() {
        assert_ne!(gib_precise(1_048_576), "0.00 GiB");
        assert!(gib_precise(1_048_576).starts_with("0.000"));
    }
}
