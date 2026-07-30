//! Versioned local hardware database (PRD §9).
//!
//! Seed catalog with the exact SKUs and figures from PRD §9 lines 390–432. Each
//! entry carries the per-SKU topology default and a typical runtime reserve so
//! the memory-fit engine (PRD §15) does not conflate hardware fit with runtime
//! headroom.
//!
//! Units: `memory_marketed_gb` is decimal (10^9 bytes) as vendors advertise;
//! `usable_gib` is the exact binary-GiB conversion (`GB->GiB`, PRD §33
//! "GPU memory unit conversion: exact"). f64 is lossless here (< 2^53 bytes).

use serde::{Deserialize, Serialize};

use crate::error::{CalcError, Result};

/// Network topology assumed when no explicit user override is given.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Topology {
    PciE,
    #[serde(rename = "nvlink4")]
    NvLink4,
    #[serde(rename = "nvlink5")]
    NvLink5,
}

impl Topology {
    pub fn label(self) -> &'static str {
        match self {
            Topology::PciE => "PCIe",
            Topology::NvLink4 => "NVLink 4",
            Topology::NvLink5 => "NVLink 5",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Gpu {
    pub manufacturer: &'static str,
    pub product_family: &'static str,
    pub sku: &'static str,
    pub architecture: &'static str,
    /// Marketed memory capacity in decimal GB (10^9 bytes).
    pub memory_marketed_gb: f64,
    /// Usable capacity in GiB (exact GB->GiB conversion).
    pub usable_gib: f64,
    /// Memory bandwidth in GB/s (decimal).
    pub memory_bandwidth_gbs: f64,
    /// BF16/FP16 peak throughput in TFLOPS (theoretical).
    pub bf16_fp16_tflops: f64,
    /// FP8 peak throughput in TFLOPS (theoretical).
    pub fp8_tflops: Option<f64>,
    /// NVFP4 peak throughput in TFLOPS (theoretical).
    pub nvfp4_tflops: Option<f64>,
    pub pcie_gen: u32,
    pub pcie_width: u32,
    /// NVLink generation, if any.
    pub nvlink: Option<Topology>,
    /// Per-GPU NVLink bandwidth in GB/s.
    pub nvlink_bandwidth_gbs: Option<f64>,
    pub mig_support: bool,
    /// Quantization formats the hardware + engines are known to support.
    pub supported_quantizations: &'static [&'static str],
    /// Conservative fixed runtime reserve (CUDA context, allocator, kernels)
    /// in GiB, subtracted before KV budgeting (PRD §14/§15).
    pub typical_runtime_reserve_gib: f64,
    /// Default memory-utilization ceiling (PRD §15 `M_physical * U`).
    pub default_utilization: f64,
    pub default_topology: Topology,
    /// Provenance for the figures (PRD §9).
    pub source: &'static str,
}

/// GPU memory constants. 1 GB (decimal) = 1e9 bytes; 1 GiB = 2^30 bytes.
pub const GB: f64 = 1_000_000_000.0;
pub const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Exact marketed-GB -> GiB conversion, usable in `const` context.
const fn gib_from_gb(marketed_gb: f64) -> f64 {
    (marketed_gb * GB) / GIB
}

/// Seed catalog from PRD §9 + §420–§432. `const` so `catalog()` can hand back a
/// `&'static [Gpu]` without undefined behaviour.
pub const GPU_CATALOG: &[Gpu] = &[
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "GeForce RTX",
        sku: "RTX 6000 Ada Generation",
        architecture: "Ada Lovelace",
        memory_marketed_gb: 48.0,
        usable_gib: gib_from_gb(48.0),
        memory_bandwidth_gbs: 960.0,
        bf16_fp16_tflops: 130.0,
        fp8_tflops: None,
        nvfp4_tflops: None,
        pcie_gen: 4,
        pcie_width: 16,
        nvlink: None,
        nvlink_bandwidth_gbs: None,
        mig_support: false,
        supported_quantizations: &["fp16", "bf16", "fp8", "int8", "int4", "nvfp4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::PciE,
        source: "PRD §9 / NVIDIA spec sheet",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "RTX PRO",
        sku: "RTX PRO 6000 Blackwell Workstation Edition",
        architecture: "Blackwell",
        memory_marketed_gb: 96.0,
        usable_gib: gib_from_gb(96.0),
        memory_bandwidth_gbs: 1_792.0,
        bf16_fp16_tflops: 130.0,
        fp8_tflops: Some(260.0),
        nvfp4_tflops: Some(520.0),
        pcie_gen: 5,
        pcie_width: 16,
        nvlink: None,
        nvlink_bandwidth_gbs: None,
        mig_support: false,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::PciE,
        source: "PRD §9 lines 413, 420",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "H100",
        sku: "H100 SXM 80 GB",
        architecture: "Hopper",
        memory_marketed_gb: 80.0,
        usable_gib: gib_from_gb(80.0),
        memory_bandwidth_gbs: 3_300.0, // 3.3 TB/s, PRD §422
        bf16_fp16_tflops: 1_000.0,
        fp8_tflops: Some(1_000.0),
        nvfp4_tflops: None,
        pcie_gen: 4,
        pcie_width: 16,
        nvlink: Some(Topology::NvLink4),
        nvlink_bandwidth_gbs: Some(900.0),
        mig_support: true,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::NvLink4,
        source: "PRD §9 lines 416, 422",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "H200",
        sku: "H200 SXM 141 GB",
        architecture: "Blackwell",
        memory_marketed_gb: 141.0,
        usable_gib: gib_from_gb(141.0),
        memory_bandwidth_gbs: 4_800.0,
        bf16_fp16_tflops: 1_000.0,
        fp8_tflops: Some(2_000.0),
        nvfp4_tflops: Some(4_000.0),
        pcie_gen: 4,
        pcie_width: 16,
        nvlink: Some(Topology::NvLink4),
        nvlink_bandwidth_gbs: Some(900.0),
        mig_support: true,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::NvLink4,
        source: "PRD §9 lines 417, 422",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "B200",
        sku: "B200 SXM 180 GB",
        architecture: "Blackwell",
        memory_marketed_gb: 180.0,
        usable_gib: gib_from_gb(180.0),
        memory_bandwidth_gbs: 8_000.0, // 8 TB/s per GPU, PRD §422
        bf16_fp16_tflops: 1_000.0,
        fp8_tflops: Some(2_000.0),
        nvfp4_tflops: Some(4_000.0),
        pcie_gen: 5,
        pcie_width: 16,
        nvlink: Some(Topology::NvLink5),
        nvlink_bandwidth_gbs: Some(1_440.0), // per-node NVLink, PRD §422
        mig_support: true,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::NvLink5,
        source: "PRD §9 lines 418, 422",
    },
];

/// The seed catalog (PRD §9). Case-insensitive substring match on SKU.
pub fn catalog() -> &'static [Gpu] {
    GPU_CATALOG
}

/// Case-insensitive substring match on SKU (e.g. "RTX PRO 6000" matches the
/// workstation edition). Returns the first match.
pub fn find(sku_query: &str) -> Result<&'static Gpu> {
    let needle = sku_query.to_ascii_lowercase();
    catalog()
        .iter()
        .find(|g| g.sku.to_ascii_lowercase().contains(&needle))
        .ok_or_else(|| CalcError::UnknownGpu(sku_query.to_string()))
}

/// A configured GPU quantity + topology for a scenario.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuConfig {
    pub sku: String,
    pub count: u32,
    pub topology: Topology,
    /// Tensor-parallel size (1 = no TP). Drives weight + KV sharding.
    #[serde(default = "default_one")]
    pub tensor_parallel: u32,
    /// User-overridable memory utilization ceiling (default from SKU).
    pub utilization: Option<f64>,
    /// User-overridable fixed runtime reserve in GiB.
    pub runtime_reserve_gib: Option<f64>,
}

fn default_one() -> u32 {
    1
}

impl GpuConfig {
    pub fn gpu(&self) -> Result<&'static Gpu> {
        find(&self.sku)
    }

    pub fn utilization(&self) -> Result<f64> {
        Ok(self
            .utilization
            .or_else(|| self.gpu().ok().map(|g| g.default_utilization))
            .unwrap_or(0.90))
    }

    pub fn runtime_reserve_gib(&self) -> Result<f64> {
        Ok(self
            .runtime_reserve_gib
            .or_else(|| self.gpu().ok().map(|g| g.typical_runtime_reserve_gib))
            .unwrap_or(1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{GB, GIB};

    #[test]
    fn rtx_pro_6000_specs_match_prd() {
        let g = find("RTX PRO 6000 Blackwell Workstation").unwrap();
        assert_eq!(g.memory_marketed_gb, 96.0);
        assert!((g.memory_bandwidth_gbs - 1_792.0).abs() < 1e-6);
        // exact decimal->GiB
        assert!((g.usable_gib - (96.0 * GB / GIB)).abs() < 1e-9);
    }

    #[test]
    fn h200_specs_match_prd() {
        let g = find("H200 SXM").unwrap();
        assert_eq!(g.memory_marketed_gb, 141.0);
        assert!((g.memory_bandwidth_gbs - 4_800.0).abs() < 1e-6);
    }

    #[test]
    fn missing_sku_errors() {
        assert!(matches!(find("nope"), Err(CalcError::UnknownGpu(_))));
    }
}
