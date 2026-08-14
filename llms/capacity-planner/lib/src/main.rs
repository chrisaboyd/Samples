//! CLI front-end for the capacity-planner calculation library (PRD §31 Phase 1).
//!
//! Reads a model (`--url`, `--file`, or pasted JSON on stdin), evaluates memory
//! fit + KV-cache capacity against one or more GPUs, and prints a structured
//! [`ScenarioResult`] as JSON (PRD §25).
//!
//! Example:
//! ```text
//! capacity-planner --url https://huggingface.co/poolside/Laguna-S-2.1 \
//!   --gpu "RTX PRO 6000 Blackwell" --count 2 --tp 1
//! ```

use std::path::PathBuf;

use capacity_planner::adapter;
use capacity_planner::hardware::{GpuConfig, Topology};
use capacity_planner::memory::{Inputs, Workload};
use capacity_planner::precision::Precision;
use capacity_planner::runtime::MemoryProfile;
#[cfg(feature = "sources")]
use capacity_planner::sources::SourceService;
use capacity_planner::ScenarioResult;
use clap::{Parser, ValueEnum};

#[derive(Debug, ValueEnum, Clone, Copy)]
enum PrecArg {
    Fp32,
    Fp16,
    Bf16,
    Fp8,
    Nvfp4,
    Int8,
    Int4,
}

impl PrecArg {
    fn to_precision(self) -> Precision {
        match self {
            PrecArg::Fp32 => Precision::Fp32,
            PrecArg::Fp16 => Precision::Fp16,
            PrecArg::Bf16 => Precision::Bf16,
            PrecArg::Fp8 => Precision::Fp8,
            PrecArg::Nvfp4 => Precision::Nvfp4,
            PrecArg::Int8 => Precision::Int8,
            PrecArg::Int4 => Precision::Int4,
        }
    }
}

#[derive(Debug, ValueEnum, Clone, Copy)]
enum ProfileArg {
    Conservative,
    Balanced,
    Aggressive,
}

impl ProfileArg {
    fn to_profile(self) -> MemoryProfile {
        match self {
            ProfileArg::Conservative => MemoryProfile::Conservative,
            ProfileArg::Balanced => MemoryProfile::Balanced,
            ProfileArg::Aggressive => MemoryProfile::Aggressive,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "capacity-planner",
    about = "LLM capacity & performance planner — calculation core (Phase 1).",
    long_about = "Parses a model config.json (local file, stdin paste, or Hugging Face URL), \
                  normalizes it, and reports memory fit + KV-cache capacity as a structured \
                  JSON ScenarioResult (PRD §25). Performance/SLO/topology blocks are Phase-3 defers."
)]
struct Cli {
    /// Hugging Face model URL to fetch config.json from (requires the `sources`
    /// feature; reads an optional `HF_TOKEN` env var for gated repos).
    #[arg(long)]
    url: Option<String>,

    /// Path to a local config.json or model directory.
    #[arg(long)]
    file: Option<PathBuf>,

    /// Path to a local `model.safetensors.index.json`. Its `metadata.total_size`
    /// is the checkpoint's exact byte total and replaces the architecture-derived
    /// estimate. With `--url` the index is fetched automatically.
    #[arg(long)]
    index_file: Option<PathBuf>,

    /// GPU SKU to evaluate (substring match on catalog names).
    #[arg(long, default_value = "RTX PRO 6000 Blackwell Workstation Edition")]
    gpu: String,

    /// Number of GPUs.
    #[arg(long, default_value_t = 1)]
    count: u32,

    /// Tensor-parallel size (1 = no TP; weights & KV sharded by this).
    #[arg(long, default_value_t = 1)]
    tp: u32,

    /// Independent model replicas, each on its own group of `--tp` GPUs.
    /// Defaults to filling the machine: floor(count / tp).
    #[arg(long)]
    replicas: Option<u32>,

    /// Weight/quantization precision to evaluate.
    #[arg(long, value_enum, default_value_t = PrecArg::Nvfp4)]
    weight_precision: PrecArg,

    /// KV-cache precision.
    #[arg(long, value_enum, default_value_t = PrecArg::Fp8)]
    kv_precision: PrecArg,

    /// Average context length in tokens.
    #[arg(long, default_value_t = 32_768)]
    avg_context: u64,

    /// Maximum context length in tokens.
    #[arg(long, default_value_t = 1_048_576)]
    max_context: u64,

    /// Expected average output tokens per request (PRD §8).
    #[arg(long, default_value_t = 512)]
    avg_output: u64,

    /// Target model-step completion time in seconds (PRD §8).
    #[arg(long, default_value_t = 10.0)]
    slo_target: f64,

    /// Engine `max_num_batched_tokens`. Sets the widest scheduler step, which is
    /// what transient activation memory scales with (PRD §14).
    #[arg(long, default_value_t = 8_192)]
    max_num_batched_tokens: u64,

    /// Engine `max_num_seqs`. Both reserves per-sequence logits and sampling
    /// buffers and caps the reported concurrency.
    #[arg(long, default_value_t = 256)]
    max_num_seqs: u64,

    /// Runtime memory profile (PRD §14): conservative for procurement,
    /// aggressive for maximum technical fit.
    #[arg(long, value_enum, default_value_t = ProfileArg::Balanced)]
    memory_profile: ProfileArg,

    /// Override the checkpoint's own precision with `--weight-precision`,
    /// answering "what if this model were quantized to X?". The result is
    /// labelled hypothetical per PRD §12.2.
    ///
    /// Off by default: the checkpoint's `quantization_config` describes what is
    /// actually on disk, including which tensors it left unquantized, so
    /// overriding it silently would report a model that does not exist.
    ///
    /// Takes an explicit value (`--hypothetical true`) rather than acting as a
    /// bare flag, so both paths are reachable.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
    hypothetical: bool,

    /// Ignore any speculative drafter the checkpoint declares.
    ///
    /// Answers "what would this cost without speculative decoding?" A drafter's
    /// layers are billed at the full context, so on Laguna-S turning it off is
    /// the difference between 18 and 12 full-context layers.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
    no_speculator: bool,

    /// Supply a drafter the checkpoint does not declare, as a HuggingFace repo
    /// id or a local directory.
    ///
    /// `generation_config.json` is fetched automatically with `--url` and read
    /// from the model directory with `--file`, so this is only needed for a
    /// deployment that passes `--speculative-config` to the engine by hand, or
    /// for a checkpoint that bundles a drafter without declaring it.
    #[arg(long)]
    speculator: Option<String>,

    /// Speculative method for `--speculator`, deciding whether the drafter's
    /// declared sliding window applies to KV allocation. EAGLE-family methods
    /// (`dflash`, `eagle`, `mtp`, `medusa`) allocate the full context.
    #[arg(long, default_value = "dflash")]
    speculator_method: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config_text = load_config_text(&cli)?;
    let raw: serde_json::Value = serde_json::from_str(&config_text)?;
    let mut model = adapter::normalize(&raw)?;
    model.weights.checkpoint_total_size_bytes = load_index_total_size(&cli)?;
    model.speculator = load_speculator(&cli)?;

    let gpu = GpuConfig {
        sku: cli.gpu.clone(),
        count: cli.count,
        topology: Topology::PciE,
        tensor_parallel: cli.tp,
        replicas: cli.replicas,
        utilization: None,
        runtime_reserve_gib: None,
    };

    let workload = Workload {
        avg_context_tokens: cli.avg_context,
        max_context_tokens: cli.max_context,
        weight_precision: cli.weight_precision.to_precision(),
        kv_precision: cli.kv_precision.to_precision(),
        is_hypothetical_weight: cli.hypothetical,
        nvfp4_group_size: 16,
        tensor_parallel: cli.tp,
        prefix_cache_enabled: true,
        draft_kv_bytes_per_seq: 0,
        avg_output_tokens: cli.avg_output,
        slo_target_seconds: cli.slo_target,
        max_num_batched_tokens: cli.max_num_batched_tokens,
        max_num_seqs: cli.max_num_seqs,
        memory_profile: cli.memory_profile.to_profile(),
    };

    let inputs = Inputs {
        model: &model,
        gpu,
        workload,
    };
    let result: ScenarioResult = capacity_planner::memory::evaluate(&inputs)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Read the model config text from URL / file / stdin.
fn load_config_text(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(url) = &cli.url {
        #[cfg(feature = "sources")]
        {
            // Token is read from the environment and never logged (PRD §23 secrets).
            let token = std::env::var("HF_TOKEN").ok();
            let svc = SourceService::new(token);
            let text = svc.fetch_config(url)?;
            if text.is_empty() {
                return Err(format!("no config.json at {url}").into());
            }
            return Ok(text);
        }
        #[cfg(not(feature = "sources"))]
        {
            let _ = url;
            return Err(
                "built without the `sources` feature; rebuild with `--features sources` to use --url".into(),
            );
        }
    }
    if let Some(path) = &cli.file {
        if path.is_dir() {
            let cfg = path.join("config.json");
            return Ok(std::fs::read_to_string(cfg)?);
        }
        return Ok(std::fs::read_to_string(path)?);
    }
    // Paste path: read stdin.
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
    if buf.trim().is_empty() {
        eprintln!("Pass --file <path>, --url <hf_url>, or paste JSON on stdin.");
        std::process::exit(2);
    }
    Ok(buf)
}

/// `metadata.total_size` from an explicit `--index-file`, from the model
/// directory given to `--file`, or fetched alongside `--url`.
///
/// A missing index is not an error — most of the time there is no index to read,
/// and the architecture-derived total is the documented fallback.
fn load_index_total_size(cli: &Cli) -> Result<Option<u128>, Box<dyn std::error::Error>> {
    let read = |path: std::path::PathBuf| -> Result<Option<u128>, Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(None);
        }
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        Ok(capacity_planner::sources::index_total_size(&v))
    };

    if let Some(path) = &cli.index_file {
        return read(path.clone());
    }
    if let Some(path) = &cli.file {
        if path.is_dir() {
            return read(path.join("model.safetensors.index.json"));
        }
        if let Some(dir) = path.parent() {
            return read(dir.join("model.safetensors.index.json"));
        }
    }
    if let Some(url) = &cli.url {
        #[cfg(feature = "sources")]
        {
            let svc = SourceService::new(std::env::var("HF_TOKEN").ok());
            // A repository with no index (single-shard checkpoints have none)
            // returns Ok(None) rather than failing the run.
            return Ok(svc
                .fetch_index(url)?
                .as_ref()
                .and_then(capacity_planner::sources::index_total_size));
        }
        #[cfg(not(feature = "sources"))]
        {
            let _ = url;
        }
    }
    Ok(None)
}

/// Resolve the speculative drafter for this run.
///
/// Three sources, in priority order: `--no-speculator` suppresses everything,
/// `--speculator` supplies one by hand, and otherwise the checkpoint's own
/// `generation_config.json` is consulted. That file is where the declaration
/// lives — `config.json` has no idea a drafter exists, which is why a planner
/// reading only `config.json` silently under-counts every speculative
/// deployment.
fn load_speculator(
    cli: &Cli,
) -> Result<Option<capacity_planner::model::Speculator>, Box<dyn std::error::Error>> {
    use capacity_planner::sources::{parse_speculator_ref, SpeculatorRef};

    if cli.no_speculator {
        return Ok(None);
    }

    // Explicit override, or the checkpoint's own declaration.
    let declared: Option<(SpeculatorRef, String)> = if let Some(m) = &cli.speculator {
        Some((
            SpeculatorRef {
                method: cli.speculator_method.clone(),
                source: None,
                model: Some(m.clone()),
                num_speculative_tokens: None,
            },
            m.clone(),
        ))
    } else {
        let gc: Option<serde_json::Value> = if let Some(path) = &cli.file {
            let dir = if path.is_dir() {
                Some(path.clone())
            } else {
                path.parent().map(|p| p.to_path_buf())
            };
            match dir.map(|d| d.join("generation_config.json")) {
                Some(p) if p.exists() => Some(serde_json::from_str(&std::fs::read_to_string(p)?)?),
                _ => None,
            }
        } else {
            #[cfg(feature = "sources")]
            {
                match &cli.url {
                    Some(url) => SourceService::new(std::env::var("HF_TOKEN").ok())
                        .fetch_generation_config(url)?,
                    None => None,
                }
            }
            #[cfg(not(feature = "sources"))]
            {
                None
            }
        };
        gc.as_ref()
            .and_then(parse_speculator_ref)
            .map(|s| (s, String::new()))
    };

    let Some((spec, _)) = declared else {
        return Ok(None);
    };

    // Local directory: read the drafter's config and weights off disk.
    if let Some(m) = &cli.speculator {
        let dir = std::path::PathBuf::from(m);
        if dir.is_dir() {
            return Ok(Some(speculator_from_dir(&dir, &spec.method)?));
        }
    }

    #[cfg(feature = "sources")]
    {
        // A bundled drafter resolves against the target repo, so the target URL
        // is needed even when the drafter was named by hand.
        if let Some(url) = &cli.url {
            return Ok(
                SourceService::new(std::env::var("HF_TOKEN").ok()).fetch_speculator(url, &spec)?
            );
        }
        // Named a repo without a --url target: resolve it as a bare repo id.
        if let Some(m) = &cli.speculator {
            let url = format!("https://huggingface.co/{m}");
            return Ok(
                SourceService::new(std::env::var("HF_TOKEN").ok()).fetch_speculator(&url, &spec)?
            );
        }
    }

    eprintln!(
        "note: checkpoint declares a '{}' speculator but it could not be resolved offline; \
         pass --speculator <dir> or rebuild with --features sources",
        spec.method
    );
    Ok(None)
}

/// Build a `Speculator` from a local drafter directory.
fn speculator_from_dir(
    dir: &std::path::Path,
    method: &str,
) -> Result<capacity_planner::model::Speculator, Box<dyn std::error::Error>> {
    use capacity_planner::model::method_allocates_full_context;

    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.json"))?)?;
    let layers = cfg
        .get("num_hidden_layers")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let full_context_layers = if method_allocates_full_context(method) {
        layers
    } else {
        cfg.get("layer_types")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter(|t| t.as_str() == Some("full_attention"))
                    .count() as u32
            })
            .unwrap_or(layers)
    };
    let weight_bytes: u128 = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("safetensors"))
        })
        .filter_map(|e| e.metadata().ok().map(|m| m.len() as u128))
        .sum();

    Ok(capacity_planner::model::Speculator {
        method: method.to_string(),
        source: Some(dir.display().to_string()),
        num_speculative_tokens: None,
        full_context_layers,
        kv_heads: cfg
            .get("num_key_value_heads")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
        head_dimension: cfg
            .get("head_dim")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
        weight_bytes: (weight_bytes > 0).then_some(weight_bytes),
        weight_precision: cfg
            .get("torch_dtype")
            .and_then(|v| v.as_str())
            .and_then(capacity_planner::precision::Precision::from_torch_dtype),
    })
}
