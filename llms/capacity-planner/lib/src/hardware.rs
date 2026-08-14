//! Versioned local hardware database (PRD §9).
//!
//! Seed catalog with the exact SKUs and figures from PRD §9 lines 390–432. Each
//! entry carries the per-SKU topology default and a typical runtime reserve so
//! the memory-fit engine (PRD §15) does not conflate hardware fit with runtime
//! headroom.
//!
//! Units: `memory_marketed_gb` is the number on the spec sheet and is used for
//! labels only. `usable_gib` is the total the driver actually reports
//! (`nvidia-smi --query-gpu=memory.total`), which is what an engine's
//! utilization ceiling multiplies against.
//!
//! It is not derived from the marketed figure, because no single conversion
//! reproduces it. Marketed capacity sits ~0.63% below the driver total on
//! Ada-class parts and ~6.9–7.4% below it on HBM parts and on GDDR7 Blackwell:
//! NVIDIA overprovisions each die by however much that product needs to survive
//! row-remapping of bad cells over its service life, so the gap is a per-SKU
//! manufacturing decision rather than a GB-vs-GiB unit question. Treating the
//! marketed number as decimal GB and converting understated the RTX PRO 6000 by
//! 6.2 GiB and the B200 by 11.4 GiB.
//!
//! Where ECC costs capacity (GDDR6 parts, which lack on-die ECC and reserve
//! ~6.25% of the framebuffer for it) the ECC-enabled figure is used, since that
//! is the shipping default. GDDR7 and HBM parts do ECC on-die at no capacity
//! cost. f64 is lossless here (< 2^53 bytes).

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
    /// Marketed memory capacity as printed on the spec sheet. Display only —
    /// never the basis for a capacity calculation (see module docs).
    pub memory_marketed_gb: f64,
    /// Total capacity the driver reports, in GiB. Measured, not derived.
    pub usable_gib: f64,
    /// Memory bandwidth in GB/s (decimal).
    pub memory_bandwidth_gbs: f64,
    /// BF16/FP16 peak throughput in TFLOPS (theoretical).
    ///
    /// These are vendor peak figures and follow one convention consistently
    /// across the catalog (each precision step doubles where the hardware
    /// supports it). They are ceilings, never achieved rates — the roofline
    /// applies efficiency tiers on top (PRD §16.3).
    pub bf16_fp16_tflops: f64,
    /// FP8 peak throughput in TFLOPS (theoretical). `None` when the architecture
    /// has no FP8 tensor cores, in which case the BF16 path is used.
    pub fp8_tflops: Option<f64>,
    /// NVFP4 peak throughput in TFLOPS (theoretical). `None` on pre-Blackwell
    /// parts, which can store NVFP4 weights but must dequantize to compute.
    pub nvfp4_tflops: Option<f64>,
    pub pcie_gen: u32,
    pub pcie_width: u32,
    /// NVLink generation, if any.
    pub nvlink: Option<Topology>,
    /// Per-GPU NVLink bandwidth in GB/s.
    pub nvlink_bandwidth_gbs: Option<f64>,
    pub mig_support: bool,
    /// The accelerator shares one physical memory pool with the CPU (Grace
    /// Blackwell desktop parts) rather than owning dedicated VRAM.
    ///
    /// The capacity math is unchanged in form — it is still
    /// `available − weights − runtime` — but two inputs move: the OS, page
    /// cache and host-side process memory come out of the same pool (so the
    /// utilization ceiling is lower and the runtime reserve larger), and the
    /// marketed capacity is system memory, not a private frame buffer.
    pub unified_memory: bool,
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

/// Exact MiB -> GiB conversion for driver-reported totals, `const`-usable.
const fn gib_from_mib(driver_total_mib: f64) -> f64 {
    driver_total_mib / 1024.0
}

/// Fallback for SKUs with no driver figure on record. Only the unified-memory
/// parts use this, and only because `nvidia-smi` reports `N/A` on them.
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
        // GDDR6 without on-die ECC: enabling ECC (the shipping default, and not
        // reliably disableable on this card) costs ~6.25% of the framebuffer.
        // 49_140 MiB with ECC off.
        usable_gib: gib_from_mib(46_068.0),
        memory_bandwidth_gbs: 960.0,
        bf16_fp16_tflops: 130.0,
        fp8_tflops: None,
        nvfp4_tflops: None,
        pcie_gen: 4,
        pcie_width: 16,
        nvlink: None,
        nvlink_bandwidth_gbs: None,
        mig_support: false,
        unified_memory: false,
        supported_quantizations: &["fp16", "bf16", "fp8", "int8", "int4", "nvfp4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::PciE,
        source: "PRD §9 / NVIDIA spec sheet; memory.total 46068 MiB (ECC on)",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "RTX PRO",
        sku: "RTX PRO 6000 Blackwell Workstation Edition",
        architecture: "Blackwell",
        memory_marketed_gb: 96.0,
        // GDDR7 ECC is on-die, so this figure already has ECC enabled.
        usable_gib: gib_from_mib(97_887.0),
        memory_bandwidth_gbs: 1_792.0,
        bf16_fp16_tflops: 130.0,
        fp8_tflops: Some(260.0),
        nvfp4_tflops: Some(520.0),
        pcie_gen: 5,
        pcie_width: 16,
        nvlink: None,
        nvlink_bandwidth_gbs: None,
        mig_support: false,
        unified_memory: false,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::PciE,
        source: "PRD §9 lines 413, 420; memory.total 97887 MiB",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "H100",
        sku: "H100 SXM 80 GB",
        architecture: "Hopper",
        memory_marketed_gb: 80.0,
        usable_gib: gib_from_mib(81_559.0),
        memory_bandwidth_gbs: 3_300.0, // 3.3 TB/s, PRD §422
        bf16_fp16_tflops: 1_000.0,
        // Hopper's FP8 tensor cores run at 2× the BF16 rate. This was previously
        // 1_000.0, which flattened FP8 to BF16 and disagreed with the H200 entry
        // for the same architecture.
        fp8_tflops: Some(2_000.0),
        // Hopper has no FP4 tensor cores — NVFP4 falls back to the FP8 path.
        nvfp4_tflops: None,
        pcie_gen: 4,
        pcie_width: 16,
        nvlink: Some(Topology::NvLink4),
        nvlink_bandwidth_gbs: Some(900.0),
        mig_support: true,
        unified_memory: false,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::NvLink4,
        source: "PRD §9 lines 416, 422; memory.total 81559 MiB",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "H200",
        sku: "H200 SXM 141 GB",
        // H200 is Hopper (an H100 die with HBM3e), not Blackwell. The previous
        // "Blackwell" label came with an invented NVFP4 figure that made the
        // part look 4× faster than it is on FP4 workloads it cannot run.
        architecture: "Hopper",
        memory_marketed_gb: 141.0,
        usable_gib: gib_from_mib(143_771.0),
        memory_bandwidth_gbs: 4_800.0,
        bf16_fp16_tflops: 1_000.0,
        fp8_tflops: Some(2_000.0),
        // No FP4 tensor cores on Hopper — NVFP4 falls back to the FP8 path.
        nvfp4_tflops: None,
        pcie_gen: 4,
        pcie_width: 16,
        nvlink: Some(Topology::NvLink4),
        nvlink_bandwidth_gbs: Some(900.0),
        mig_support: true,
        unified_memory: false,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::NvLink4,
        source: "PRD §9 lines 417, 422; memory.total 143771 MiB",
    },
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "B200",
        sku: "B200 SXM 180 GB",
        architecture: "Blackwell",
        memory_marketed_gb: 180.0,
        usable_gib: gib_from_mib(183_359.0),
        memory_bandwidth_gbs: 8_000.0, // 8 TB/s per GPU, PRD §422
        bf16_fp16_tflops: 1_000.0,
        fp8_tflops: Some(2_000.0),
        nvfp4_tflops: Some(4_000.0),
        pcie_gen: 5,
        pcie_width: 16,
        nvlink: Some(Topology::NvLink5),
        nvlink_bandwidth_gbs: Some(1_440.0), // per-node NVLink, PRD §422
        mig_support: true,
        unified_memory: false,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        typical_runtime_reserve_gib: 1.0,
        default_utilization: 0.90,
        default_topology: Topology::NvLink5,
        source: "PRD §9 lines 418, 422; memory.total 183359 MiB",
    },
    // ---- Grace Blackwell desktop parts (unified memory) --------------------
    //
    // GB10 pairs a Blackwell GPU with a Grace CPU over NVLink-C2C behind a
    // single 128 GB LPDDR5X pool. Two consequences the catalog encodes:
    //
    //  - Bandwidth is ~273 GB/s, roughly 1/29th of a B200. Decode is bandwidth
    //    bound, so this — not capacity — is what caps tokens/s on these boxes.
    //  - The 128 GB is system memory. The OS, page cache and the serving
    //    process all live in it, so the utilization ceiling is well below the
    //    0.90 a discrete card gets and the runtime reserve is larger.
    //
    // NVIDIA markets "1 PFLOP" at FP4 *with sparsity*; the dense figure is half
    // that, and this catalog quotes dense throughout.
    Gpu {
        manufacturer: "NVIDIA",
        product_family: "DGX",
        sku: "DGX Spark (GB10)",
        architecture: "Grace Blackwell",
        memory_marketed_gb: 128.0,
        // UNVERIFIED. `nvidia-smi` reports memory.total as N/A on unified-memory
        // parts — there is no private frame buffer to report — so the driver
        // figure that every other entry uses does not exist here. Falling back
        // to the decimal conversion, which the discrete SKUs have now shown to
        // run 0.6-7.4% low. Replace with `free -b` MemTotal from a real GB10.
        usable_gib: gib_from_gb(128.0),
        memory_bandwidth_gbs: 273.0,
        bf16_fp16_tflops: 125.0,
        fp8_tflops: Some(250.0),
        nvfp4_tflops: Some(500.0),
        pcie_gen: 5,
        pcie_width: 16,
        nvlink: None,
        nvlink_bandwidth_gbs: None,
        mig_support: false,
        unified_memory: true,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        // Host OS + serving process share the pool; 4 GiB is a conservative
        // desktop-Linux floor rather than the 1 GiB a discrete card needs.
        typical_runtime_reserve_gib: 4.0,
        default_utilization: 0.75,
        default_topology: Topology::PciE,
        source: "NVIDIA GB10 / DGX Spark product spec (dense FP4; vendor quotes sparse)",
    },
    Gpu {
        manufacturer: "Dell",
        product_family: "Pro Max",
        sku: "Dell Pro Max with GB10",
        architecture: "Grace Blackwell",
        memory_marketed_gb: 128.0,
        // UNVERIFIED — same GB10 superchip, same missing driver figure.
        usable_gib: gib_from_gb(128.0),
        memory_bandwidth_gbs: 273.0,
        bf16_fp16_tflops: 125.0,
        fp8_tflops: Some(250.0),
        nvfp4_tflops: Some(500.0),
        pcie_gen: 5,
        pcie_width: 16,
        nvlink: None,
        nvlink_bandwidth_gbs: None,
        mig_support: false,
        unified_memory: true,
        supported_quantizations: &["fp16", "bf16", "fp8", "nvfp4", "int8", "int4"],
        typical_runtime_reserve_gib: 4.0,
        default_utilization: 0.75,
        default_topology: Topology::PciE,
        source: "Dell Pro Max GB10 spec — same GB10 superchip as DGX Spark",
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
    /// Independent model copies to run, each occupying `tensor_parallel` GPUs.
    ///
    /// `None` means "fill the machine": `floor(count / tensor_parallel)`. Set it
    /// explicitly to model a deployment that deliberately leaves GPUs idle —
    /// 8 cards at TP=4 can be 2 replicas or 1 replica with 4 spare, and those
    /// are different answers for aggregate throughput.
    #[serde(default)]
    pub replicas: Option<u32>,
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

    /// Replicas actually deployed: the explicit setting, else as many whole
    /// TP groups as the GPU count allows.
    pub fn replicas(&self) -> u32 {
        let max_replicas = (self.count / self.tensor_parallel.max(1)).max(1);
        self.replicas.unwrap_or(max_replicas).max(1)
    }

    /// GPUs carrying a model copy (`replicas × TP`). The remainder are idle.
    pub fn gpus_in_use(&self) -> u32 {
        self.replicas() * self.tensor_parallel.max(1)
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
        // The driver reports 97887 MiB, not the 89.41 GiB a decimal GB->GiB
        // conversion of the marketed 96 GB produces.
        assert!((g.usable_gib - 97_887.0 / 1024.0).abs() < 1e-9);
        assert!((g.usable_gib - 95.5928).abs() < 1e-4, "{}", g.usable_gib);
    }

    /// Marketed capacity is not the driver total, and no conversion turns one
    /// into the other: every discrete part is overprovisioned relative to its
    /// decimal-GB reading, by 0.6% on Ada and ~7% on HBM and GDDR7. Deriving
    /// `usable_gib` instead of measuring it cost 5-11 GiB per card.
    #[test]
    fn discrete_capacity_is_measured_not_converted_from_marketed_gb() {
        for g in catalog().iter().filter(|g| !g.unified_memory) {
            let decimal = g.memory_marketed_gb * GB / GIB;
            assert!(
                g.usable_gib > decimal,
                "{}: usable {:.4} GiB is not above the {:.4} GiB decimal conversion — \
                 looks like a derived value crept back in",
                g.sku,
                g.usable_gib,
                decimal
            );
            // Driver totals also stay under the marketed number read as binary
            // GiB; a few hundred MiB is always carved out.
            assert!(
                g.usable_gib < g.memory_marketed_gb,
                "{}: usable {:.4} GiB exceeds {} GiB of physical DRAM",
                g.sku,
                g.usable_gib,
                g.memory_marketed_gb
            );
        }
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
