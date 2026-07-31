// Tauri command surface for the capacity-planner UI.
//
// A single typed command, `analyze`, is exposed to the frontend. It delegates to
// a pure, AppHandle-free `analyze_core` so the wiring (config parsing + memory
// fit) is unit-testable without a Tauri runtime.

use capacity_planner::hardware::{GpuConfig, Topology};
use capacity_planner::memory::{Inputs, Workload};
use capacity_planner::precision::Precision;
use capacity_planner::{adapter, memory, ScenarioResult};
use serde::Deserialize;

/// Everything the frontend needs to run a memory-fit calculation. `Precision`
/// round-trips through serde as lowercase tokens (e.g. `"nvfp4"`), matching the
/// lib's `Precision` enum, so no adapter enum is required here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeCommand {
    config_json: String,
    gpu: String,
    count: u32,
    tensor_parallel: u32,
    weight_precision: Precision,
    kv_precision: Precision,
    avg_context_tokens: u64,
    max_context_tokens: u64,
    is_hypothetical_weight: bool,
}

/// Pure calculation behind the `analyze` command (no `AppHandle` needed).
pub fn analyze_core(cmd: &AnalyzeCommand) -> capacity_planner::Result<ScenarioResult> {
    let raw: serde_json::Value = serde_json::from_str(&cmd.config_json)?;
    let model = adapter::normalize(&raw)?;

    let gpu = GpuConfig {
        sku: cmd.gpu.clone(),
        count: cmd.count,
        topology: Topology::PciE,
        tensor_parallel: cmd.tensor_parallel,
        utilization: None,
        runtime_reserve_gib: None,
    };

    let workload = Workload {
        avg_context_tokens: cmd.avg_context_tokens,
        max_context_tokens: cmd.max_context_tokens,
        weight_precision: cmd.weight_precision,
        kv_precision: cmd.kv_precision,
        is_hypothetical_weight: cmd.is_hypothetical_weight,
        nvfp4_group_size: 16,
        tensor_parallel: cmd.tensor_parallel,
        prefix_cache_enabled: true,
        draft_kv_bytes_per_seq: 0,
    };

    memory::evaluate(&Inputs {
        model: &model,
        gpu,
        workload,
    })
}

#[tauri::command]
fn analyze(cmd: AnalyzeCommand) -> Result<ScenarioResult, String> {
    analyze_core(&cmd).map_err(|e| e.to_string())
}

/// Fetch `config.json` for a HuggingFace model URL. Reads `HF_TOKEN` from the
/// environment for gated repos (never logged). Exposed so the frontend can
/// support the URL input method without shipping tokens to the renderer.
#[tauri::command]
fn fetch_config(url: String) -> Result<String, String> {
    let token = std::env::var("HF_TOKEN").ok();
    let svc = capacity_planner::sources::SourceService::new(token);
    svc.fetch_config(&url).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![analyze, fetch_config])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAGUNA_JSON: &str = include_str!("../../../lib/tests/assets/laguna-config.json");

    fn laguna_cmd() -> AnalyzeCommand {
        AnalyzeCommand {
            config_json: LAGUNA_JSON.to_string(),
            gpu: "B200 SXM 180 GB".to_string(),
            count: 1,
            tensor_parallel: 1,
            weight_precision: Precision::Nvfp4,
            kv_precision: Precision::Fp8,
            avg_context_tokens: 32_768,
            max_context_tokens: 1_048_576,
            is_hypothetical_weight: true,
        }
    }

    #[test]
    fn analyze_core_laguna_b200_matches_golden_numbers() {
        let r = analyze_core(&laguna_cmd()).expect("evaluates");
        assert_eq!(r.verdict, capacity_planner::result::Verdict::Comfortable);
        assert_eq!(r.memory.memory_concurrency_average, 107);
        assert_eq!(r.memory.memory_concurrency_maximum, 3);
        assert!(r
            .memory
            .checkpoint_precision_label
            .contains("Hypothetical quantization estimate"));
    }

    #[test]
    fn analyze_core_rejects_bad_json() {
        let mut cmd = laguna_cmd();
        cmd.config_json = "{ not json".to_string();
        assert!(analyze_core(&cmd).is_err());
    }

    /// Wire-contract test: the exact camelCase payload the React frontend sends
    /// via `invoke("analyze", {...})` must deserialize into `AnalyzeCommand` and
    /// produce the same Laguna/B200 numbers. Catches field-name drift between
    /// `ui/src/types.ts` and the Rust struct.
    #[test]
    fn analyze_command_round_trips_camelcase_payload() {
        let config_json = serde_json::to_string(LAGUNA_JSON).unwrap();
        let payload = format!(
            r#"{{
              "configJson": {config_json},
              "gpu": "B200 SXM 180 GB",
              "count": 1,
              "tensorParallel": 1,
              "weightPrecision": "nvfp4",
              "kvPrecision": "fp8",
              "avgContextTokens": 32768,
              "maxContextTokens": 1048576,
              "isHypotheticalWeight": true
            }}"#
        );
        let cmd: AnalyzeCommand = serde_json::from_str(&payload).expect("payload deserializes");
        let r = analyze_core(&cmd).expect("evaluates");
        assert_eq!(r.memory.memory_concurrency_average, 107);
        assert_eq!(r.memory.memory_concurrency_maximum, 3);
        assert_eq!(r.provenance.gpu_sku, "B200 SXM 180 GB");
    }
}
