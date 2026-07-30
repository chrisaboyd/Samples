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

    /// GPU SKU to evaluate (substring match on catalog names).
    #[arg(long, default_value = "RTX PRO 6000 Blackwell Workstation Edition")]
    gpu: String,

    /// Number of GPUs.
    #[arg(long, default_value_t = 1)]
    count: u32,

    /// Tensor-parallel size (1 = no TP; weights & KV sharded by this).
    #[arg(long, default_value_t = 1)]
    tp: u32,

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

    /// Treat the selected weight precision as hypothetical (not present in the
    /// checkpoint). When true the result is labelled per PRD §12.2.
    #[arg(long, default_value_t = true)]
    hypothetical: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config_text = load_config_text(&cli)?;
    let raw: serde_json::Value = serde_json::from_str(&config_text)?;
    let model = adapter::normalize(&raw)?;

    let gpu = GpuConfig {
        sku: cli.gpu.clone(),
        count: cli.count,
        topology: Topology::PciE,
        tensor_parallel: cli.tp,
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
